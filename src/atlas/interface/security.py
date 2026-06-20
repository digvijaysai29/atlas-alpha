"""Request identity + thread-owner binding for the HTTP interface.

================================  SECURITY: READ ME  ================================
This module is an **interim, TRUSTED-NETWORK / DEVELOPMENT-ONLY** identity shim. It derives the
request :class:`~atlas.governance.rbac.Principal` from plain HTTP **headers** and trusts them
blindly. That is safe *only* when the API is reached exclusively through a reverse proxy / ingress
that authenticates the caller and sets these headers itself (stripping any client-supplied copies).

**Never expose this directly to the public internet** — without a header-validating proxy a client
can spoof any identity simply by setting the header. Real, verified identity (SSO / OIDC token
validation) arrives in **M3.3**; :func:`get_request_principal` is the single seam it will replace.

The header *names* are configurable via :class:`~atlas.config.Settings` so a deployment can align
them with its proxy. Changing them in production therefore requires a **coordinated** change at the
reverse proxy / ingress that sets them, or every request will fall back to the anonymous principal.
====================================================================================
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, HTTPException, Request, status

from atlas.config import Settings, get_settings
from atlas.governance.rbac import Principal

if TYPE_CHECKING:
    from langgraph.types import StateSnapshot


def _settings_for(request: Request) -> Settings:
    """The Settings on app.state (set by create_app), falling back to the process singleton."""
    return getattr(request.app.state, "settings", None) or get_settings()


def get_request_principal(request: Request) -> Principal:
    """Build the caller's :class:`Principal` from the configured identity headers.

    Fail-closed: a missing/blank user header yields :meth:`Principal.anonymous` (no roles). The
    sentinel user id ``"anonymous"`` is reserved and always maps to unauthenticated — roles on that
    id are ignored. Roles are a comma-separated list; an empty/blank value contributes nothing.
    (Named distinctly from :func:`atlas.governance.rbac.get_current_principal`, which extracts the
    principal from *graph state* — this one reads the *HTTP request*.)
    """
    settings = _settings_for(request)
    user_id = (request.headers.get(settings.api_user_header) or "").strip()
    if not user_id or user_id == Principal.anonymous().user_id:
        return Principal.anonymous()
    roles_raw = request.headers.get(settings.api_roles_header) or ""
    roles = tuple(role.strip() for role in roles_raw.split(",") if role.strip())
    org_id = (request.headers.get(settings.api_org_header) or "").strip() or None
    return Principal(user_id=user_id, roles=roles, org_id=org_id)


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
