"""Request identity + thread-owner binding for the HTTP interface.

================================  SECURITY: READ ME  ================================
:func:`get_request_principal` resolves the request :class:`~atlas.governance.rbac.Principal` in one
of two modes, decided at app startup by whether OIDC is configured (``settings.oidc_enabled``):

- **OIDC mode (production):** a verified **bearer JWT** is required. The token is validated by the
  :class:`~atlas.interface.auth.OidcAuthenticator` on ``app.state``; a missing/invalid/expired token
  yields **401** (`WWW-Authenticate: Bearer`). This is the real-identity path (M3.3).

- **Dev / header-shim mode (OIDC not configured):** identity comes from plain HTTP **headers** which
  are trusted blindly. That is safe *only* behind a reverse proxy / ingress that authenticates the
  caller and sets these headers itself (stripping client-supplied copies). **Never expose the header
  shim directly to the public internet** — without a header-validating proxy a client can spoof any
  identity. The header *names* are configurable via :class:`~atlas.config.Settings`; changing them in
  production requires a coordinated change at the proxy that sets them.
====================================================================================
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, HTTPException, Request, status

from atlas.config import Settings, get_settings
from atlas.governance.rbac import Principal
from atlas.interface.auth import AuthDependencyError, AuthError, OidcAuthenticator

if TYPE_CHECKING:
    from langgraph.types import StateSnapshot

_UNAUTHENTICATED = {"WWW-Authenticate": "Bearer"}


def _settings_for(request: Request) -> Settings:
    """The Settings on app.state (set by create_app), falling back to the process singleton."""
    return getattr(request.app.state, "settings", None) or get_settings()


def _bearer_token(request: Request) -> str | None:
    """Extract the token from an ``Authorization: Bearer <token>`` header, or None."""
    scheme, _, token = (request.headers.get("Authorization") or "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def _principal_from_headers(request: Request, settings: Settings) -> Principal:
    """Dev header-shim resolution (fail-closed). See the module SECURITY note."""
    user_id = (request.headers.get(settings.api_user_header) or "").strip()
    if not user_id or user_id == Principal.anonymous().user_id:
        return Principal.anonymous()
    roles_raw = request.headers.get(settings.api_roles_header) or ""
    roles = tuple(role.strip() for role in roles_raw.split(",") if role.strip())
    org_id = (request.headers.get(settings.api_org_header) or "").strip() or None
    return Principal(user_id=user_id, roles=roles, org_id=org_id)


def get_request_principal(request: Request) -> Principal:
    """Resolve the caller's :class:`Principal` — verified OIDC token if configured, else header shim.

    (Named distinctly from :func:`atlas.governance.rbac.get_current_principal`, which extracts the
    principal from *graph state* — this one reads the *HTTP request*.)
    """
    authenticator: OidcAuthenticator | None = getattr(request.app.state, "authenticator", None)
    if authenticator is not None:
        token = _bearer_token(request)
        if token is None:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "Missing bearer token.", headers=_UNAUTHENTICATED
            )
        try:
            return authenticator.principal_from_token(token)
        except AuthDependencyError as exc:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Authentication service temporarily unavailable.",
            ) from exc
        except AuthError as exc:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "Invalid or expired token.", headers=_UNAUTHENTICATED
            ) from exc
    return _principal_from_headers(request, _settings_for(request))


# A handler parameter type: `principal: RequestPrincipal`.
RequestPrincipal = Annotated[Principal, Depends(get_request_principal)]


def thread_owner(snapshot: StateSnapshot) -> Principal | None:
    """The principal that created/owns a thread, read from its checkpointed state."""
    return snapshot.values.get("principal")


def verify_thread_owner(owner: Principal | None, caller: Principal) -> None:
    """Enforce resume-time principal/thread binding: raise 403 unless ``caller`` owns the thread.

    Strict **creator-only** for M3.2 — the caller's ``user_id`` *and* ``org_id`` must match the
    thread's owner. This is the control that stops attacker B from approving Alice's pending action
    over the network (the executor itself trusts whatever principal is in the checkpoint).

    TODO(M3.3+): support org-level delegation / role-based or org-visible threads (e.g. an org admin
    resuming a teammate's thread). Intentionally not allowed yet.
    """
    # Fail-closed: the anonymous principal is "no verified identity" — it must never own-bind to a
    # thread for cross-request access just because two unauthenticated callers share the sentinel id.
    if caller == Principal.anonymous():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authentication required for thread access.",
        )
    if owner == Principal.anonymous():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authentication required for thread access.",
        )
    if owner is None or owner.user_id != caller.user_id or owner.org_id != caller.org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have access to this thread.",
        )
