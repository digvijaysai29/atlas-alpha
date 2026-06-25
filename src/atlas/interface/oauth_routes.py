"""OAuth connect/callback/revoke HTTP routes (M4.3)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse

from atlas.config import Settings
from atlas.governance.credentials import CredentialAccessError, CredentialVault, OAuthProvider
from atlas.interface.oauth_state import (
    OAuthStateError,
    consume_oauth_state,
    issue_oauth_state,
    principal_from_state,
)
from atlas.interface.rate_limit import RateLimited
from atlas.interface.security import RequestPrincipal
from atlas.integrations.oauth import build_google_oauth_client, build_slack_oauth_client

router = APIRouter(prefix="/oauth", tags=["oauth"])


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


@router.get("/connections")
def list_connections(
    principal: RequestPrincipal,
    vault: Annotated[CredentialVault, Depends(_vault)],
) -> dict[str, list[str]]:
    try:
        connected = vault.list_connected(principal)
    except CredentialAccessError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    return {"providers": [p.value for p in connected]}


@router.get("/{provider}/connect", dependencies=[RateLimited])
def oauth_connect(
    provider: str,
    request: Request,
    principal: RequestPrincipal,
) -> RedirectResponse:
    settings = _settings(request)
    oauth_provider = _provider(provider)
    if principal.org_id is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "org_id is required for OAuth connect.")
    state = issue_oauth_state(settings, principal, oauth_provider)
    if oauth_provider is OAuthProvider.GOOGLE:
        google_client = build_google_oauth_client(settings)
        if google_client is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Google OAuth not configured.")
        url = google_client.authorization_url(state)
    else:
        slack_client = build_slack_oauth_client(settings)
        if slack_client is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Slack OAuth not configured.")
        url = slack_client.authorization_url(state)
    return RedirectResponse(url, status_code=status.HTTP_302_FOUND)


@router.get("/{provider}/callback", dependencies=[RateLimited])
def oauth_callback(
    provider: str,
    request: Request,
    principal: RequestPrincipal,
    code: str,
    state: str,
) -> RedirectResponse:
    settings = _settings(request)
    vault = _vault(request)
    oauth_provider = _provider(provider)
    try:
        payload = consume_oauth_state(settings, state)
        bound = principal_from_state(payload, principal)
        if payload.get("provider") != oauth_provider.value:
            raise OAuthStateError("provider mismatch")
    except OAuthStateError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    if oauth_provider is OAuthProvider.GOOGLE:
        google_client = build_google_oauth_client(settings)
        if google_client is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Google OAuth not configured.")
        credential = google_client.exchange_code(code)
    else:
        slack_client = build_slack_oauth_client(settings)
        if slack_client is None:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Slack OAuth not configured.")
        credential = slack_client.exchange_code(code)

    try:
        vault.put(bound, oauth_provider, credential)
    except CredentialAccessError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc

    success = settings.oauth_success_url or "/oauth/connections"
    return RedirectResponse(success, status_code=status.HTTP_302_FOUND)


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
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    return {"revoked": oauth_provider.value}
