"""Short-lived pending cookie binding OAuth connect to browser callback (M4.3)."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from atlas.config import Settings
from atlas.interface.oauth_state import oauth_state_key

OAUTH_PENDING_COOKIE = "atlas_oauth_pending"
_PENDING_COOKIE_MAX_AGE = 600


def sign_pending_nonce(settings: Settings, nonce: str) -> str:
    """HMAC-SHA256 hex digest of the OAuth state nonce for the pending cookie value."""
    return hmac.new(oauth_state_key(settings), nonce.encode(), hashlib.sha256).hexdigest()


def verify_oauth_pending_cookie(settings: Settings, cookie: str, payload: dict[str, Any]) -> bool:
    """True when the pending cookie matches the nonce in a verified state payload."""
    nonce = payload.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        return False
    expected = sign_pending_nonce(settings, nonce)
    return hmac.compare_digest(expected, cookie)


def pending_cookie_kwargs(*, secure: bool) -> dict[str, Any]:
    """Shared cookie attributes for the OAuth pending flow."""
    return {
        "httponly": True,
        "samesite": "lax",
        "secure": secure,
        "max_age": _PENDING_COOKIE_MAX_AGE,
    }
