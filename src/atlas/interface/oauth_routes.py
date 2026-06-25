"""OAuth connect/callback/revoke HTTP routes (M4.3)."""

from __future__ import annotations

import json
from base64 import urlsafe_b64decode
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from atlas.config import Settings
from atlas.governance.credentials import (
    CredentialAccessError,
    CredentialVault,
    OAuthProvider,
)
from atlas.governance.rbac import Principal
from atlas.interface.auth import AuthDependencyError, AuthError
from atlas.interface.oauth_pending import (
    OAUTH_PENDING_COOKIE,
    pending_cookie_kwargs,
    sign_pending_nonce,
    verify_oauth_pending_cookie,
)
from atlas.interface.oauth_state import (
    OAuthStateError,
    consume_oauth_state,
    issue_oauth_state,
    principal_from_payload,
    principal_from_state,
)
from atlas.interface.rate_limit import RateLimited
from atlas.interface.security import RequestPrincipal, _bearer_token, _principal_from_headers
from atlas.integrations.oauth import (
    OAuthExchangeResult,
    build_google_oauth_client,
    build_slack_oauth_client,
)
from atlas.integrations.oauth_binding import (
    OAuthBindingError,
    assert_provider_email_binding,
    require_binding_email,
    resolve_binding_email,
)

router = APIRouter(prefix="/oauth", tags=["oauth"])

_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost"})
_CALLBACK_AUTH_HINT = (
    "Complete OAuth via authenticated POST /oauth/{provider}/callback "
    "or restart connect to receive a pending cookie."
)


class OAuthCallbackBody(BaseModel):
    code: str
    state: str


def _settings(request: Request) -> Settings:
    return getattr(request.app.state, "settings", Settings())


def _vault(request: Request) -> CredentialVault:
    vault: CredentialVault | None = getattr(request.app.state, "credential_vault", None)
    if vault is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Credential vault not configured.")
    return vault


def _provider(name: str) -> OAuthProvider:
    try:
        return OAuthProvider(name.lower())
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unknown provider: {name}") from exc


def _request_is_secure(request: Request) -> bool:
    host = (request.url.hostname or "").lower()
    return host not in _LOCAL_HOSTS


def _raise_vault_error(exc: CredentialAccessError) -> None:
    if "temporarily unavailable" in str(exc):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc
    raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc


def _nonce_from_state(state: str) -> str:
    body = state.rsplit(".", 1)[0]
    payload: dict[str, Any] = json.loads(urlsafe_b64decode(body.encode()))
    nonce = payload.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise OAuthStateError("state missing nonce")
    return nonce


def _authorization_url(settings: Settings, oauth_provider: OAuthProvider, state: str) -> str:
    if oauth_provider is OAuthProvider.GOOGLE:
        google_client = build_google_oauth_client(settings)
        if google_client is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Google OAuth not configured.")
        return google_client.authorization_url(state)
    slack_client = build_slack_oauth_client(settings)
    if slack_client is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Slack OAuth not configured.")
    return slack_client.authorization_url(state)


def _attach_pending_cookie(
    response: Response, settings: Settings, state: str, *, secure: bool
) -> None:
    nonce = _nonce_from_state(state)
    response.set_cookie(
        OAUTH_PENDING_COOKIE,
        sign_pending_nonce(settings, nonce),
        **pending_cookie_kwargs(secure=secure),
    )


def _resolve_callback_principal(
    request: Request,
    settings: Settings,
    payload: dict[str, Any],
    *,
    provider: str,
) -> Principal:
    authenticator = getattr(request.app.state, "authenticator", None)
    token = _bearer_token(request)

    if token is not None and authenticator is not None:
        try:
            caller = authenticator.principal_from_token(token)
        except AuthDependencyError as exc:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Authentication service temporarily unavailable.",
            ) from exc
        except AuthError as exc:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "Invalid or expired token.",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        return principal_from_state(payload, caller)

    cookie = request.cookies.get(OAUTH_PENDING_COOKIE)
    if cookie and verify_oauth_pending_cookie(settings, cookie, payload):
        return principal_from_payload(payload)

    if authenticator is not None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            _CALLBACK_AUTH_HINT.format(provider=provider),
            headers={"WWW-Authenticate": "Bearer"},
        )

    caller = _principal_from_headers(request, settings)
    if caller != Principal.anonymous():
        return principal_from_state(payload, caller)

    raise HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        _CALLBACK_AUTH_HINT.format(provider=provider),
    )


def _exchange_code(
    settings: Settings, oauth_provider: OAuthProvider, code: str
) -> OAuthExchangeResult:
    if oauth_provider is OAuthProvider.GOOGLE:
        google_client = build_google_oauth_client(settings)
        if google_client is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Google OAuth not configured.")
        return google_client.exchange_code(code)
    slack_client = build_slack_oauth_client(settings)
    if slack_client is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Slack OAuth not configured.")
    return slack_client.exchange_code(code)


def _complete_oauth_callback(
    settings: Settings,
    vault: CredentialVault,
    oauth_provider: OAuthProvider,
    code: str,
    state: str,
    bound: Principal,
) -> str:
    try:
        payload = consume_oauth_state(settings, state)
        if payload.get("provider") != oauth_provider.value:
            raise OAuthStateError("provider mismatch")
        if payload.get("user_id") != bound.user_id or payload.get("org_id") != bound.org_id:
            raise OAuthStateError("state principal mismatch")
        binding_email = require_binding_email(payload)
    except OAuthStateError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    except OAuthBindingError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    exchange = _exchange_code(settings, oauth_provider, code)
    google_client = (
        build_google_oauth_client(settings)
        if oauth_provider is OAuthProvider.GOOGLE
        else None
    )
    try:
        credential = assert_provider_email_binding(
            oauth_provider,
            binding_email=binding_email,
            credential=exchange.credential,
            token_response=exchange.token_response,
            google_client=google_client,
        )
    except OAuthBindingError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    try:
        vault.put(bound, oauth_provider, credential)
    except CredentialAccessError as exc:
        _raise_vault_error(exc)
    return settings.oauth_success_url or "/oauth/connections"


def _success_redirect(success: str, *, clear_pending: bool) -> RedirectResponse:
    response = RedirectResponse(success, status_code=status.HTTP_302_FOUND)
    if clear_pending:
        response.delete_cookie(OAUTH_PENDING_COOKIE)
    return response


@router.get("/connections")
def list_connections(
    principal: RequestPrincipal,
    vault: Annotated[CredentialVault, Depends(_vault)],
) -> dict[str, list[str]]:
    try:
        connected = vault.list_connected(principal)
    except CredentialAccessError as exc:
        _raise_vault_error(exc)
    return {"providers": [p.value for p in connected]}


@router.get("/{provider}/connect", dependencies=[RateLimited])
def oauth_connect(
    provider: str,
    request: Request,
    principal: RequestPrincipal,
) -> Response:
    settings = _settings(request)
    oauth_provider = _provider(provider)
    if principal.org_id is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "org_id is required for OAuth connect.")
    try:
        binding_email = resolve_binding_email(request, settings)
    except OAuthBindingError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    state = issue_oauth_state(
        settings, principal, oauth_provider, binding_email=binding_email
    )
    url = _authorization_url(settings, oauth_provider, state)
    secure = _request_is_secure(request)
    accept = request.headers.get("accept", "")
    if "application/json" in accept:
        response: Response = JSONResponse({"authorization_url": url})
        _attach_pending_cookie(response, settings, state, secure=secure)
        return response
    redirect = RedirectResponse(url, status_code=status.HTTP_302_FOUND)
    _attach_pending_cookie(redirect, settings, state, secure=secure)
    return redirect


@router.get("/{provider}/callback", dependencies=[RateLimited])
def oauth_callback_get(
    provider: str,
    request: Request,
    code: str,
    state: str,
) -> RedirectResponse:
    settings = _settings(request)
    vault = _vault(request)
    oauth_provider = _provider(provider)
    try:
        payload = consume_oauth_state(settings, state)
    except OAuthStateError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    bound = _resolve_callback_principal(request, settings, payload, provider=provider)
    success = _complete_oauth_callback(settings, vault, oauth_provider, code, state, bound)
    return _success_redirect(success, clear_pending=True)


@router.post("/{provider}/callback", dependencies=[RateLimited])
def oauth_callback_post(
    provider: str,
    request: Request,
    body: OAuthCallbackBody,
    principal: RequestPrincipal,
) -> RedirectResponse:
    settings = _settings(request)
    vault = _vault(request)
    oauth_provider = _provider(provider)
    try:
        payload = consume_oauth_state(settings, body.state)
        bound = principal_from_state(payload, principal)
    except OAuthStateError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    success = _complete_oauth_callback(
        settings, vault, oauth_provider, body.code, body.state, bound
    )
    return _success_redirect(success, clear_pending=True)


@router.delete("/{provider}", dependencies=[RateLimited])
def oauth_revoke(
    provider: str,
    principal: RequestPrincipal,
    vault: Annotated[CredentialVault, Depends(_vault)],
) -> dict[str, Any]:
    oauth_provider = _provider(provider)
    try:
        vault.delete(principal, oauth_provider)
    except CredentialAccessError as exc:
        _raise_vault_error(exc)
    return {"revoked": oauth_provider.value}
