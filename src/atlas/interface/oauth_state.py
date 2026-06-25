"""Signed OAuth CSRF state tokens (M4.3)."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Any

from atlas.config import Settings
from atlas.governance.credentials import OAuthProvider
from atlas.governance.rbac import Principal


class OAuthStateError(ValueError):
    """Invalid or expired OAuth state."""


def oauth_state_key(settings: Settings) -> bytes:
    """Derive the HMAC key for OAuth state signing."""
    if settings.oauth_state_secret is not None:
        return settings.oauth_state_secret.get_secret_value().encode()
    if settings.vault_token is not None:
        return settings.vault_token.get_secret_value().encode()
    return b"atlas-dev-oauth-state-not-for-production"


def issue_oauth_state(
    settings: Settings,
    principal: Principal,
    provider: OAuthProvider,
    *,
    ttl_seconds: int = 600,
) -> str:
    payload = {
        "user_id": principal.user_id,
        "org_id": principal.org_id,
        "provider": provider.value,
        "nonce": secrets.token_urlsafe(16),
        "exp": int(time.time()) + ttl_seconds,
    }
    body = urlsafe_b64encode(json.dumps(payload, sort_keys=True).encode()).decode()
    sig = hmac.new(oauth_state_key(settings), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def consume_oauth_state(settings: Settings, state: str) -> dict[str, Any]:
    try:
        body, sig = state.rsplit(".", 1)
    except ValueError as exc:
        raise OAuthStateError("malformed state") from exc
    expected = hmac.new(oauth_state_key(settings), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise OAuthStateError("invalid state signature")
    try:
        payload: dict[str, Any] = json.loads(urlsafe_b64decode(body.encode()))
    except (json.JSONDecodeError, ValueError) as exc:
        raise OAuthStateError("invalid state payload") from exc
    if int(payload.get("exp", 0)) < int(time.time()):
        raise OAuthStateError("expired state")
    return payload


def principal_from_state(payload: dict[str, Any], caller: Principal) -> Principal:
    """Bind callback to the authenticated caller — anti-IDOR."""
    if caller == Principal.anonymous():
        raise OAuthStateError("authentication required")
    if payload.get("user_id") != caller.user_id or payload.get("org_id") != caller.org_id:
        raise OAuthStateError("state principal mismatch")
    if not caller.org_id:
        raise OAuthStateError("org_id required")
    return caller
