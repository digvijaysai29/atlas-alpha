"""OIDC / JWT bearer-token verification (M3.3) — the real-identity replacement for the dev shim.

:class:`OidcAuthenticator` validates a bearer token and maps its claims onto a
:class:`~atlas.governance.rbac.Principal`. Security choices:

- **Asymmetric, algorithm-pinned:** ``algorithms=["RS256"]`` only — never ``none`` / HS256, which
  blocks algorithm-confusion and key-confusion attacks. Signing keys come from the issuer's JWKS.
- **Fail-closed:** signature, ``exp`` (within ``leeway``), ``iss`` and ``aud`` are all verified and
  required; any failure raises :class:`AuthError` (the seam maps it to a generic ``401`` — token
  internals are never returned to the client or logged).
- **Reserved sentinel:** a token whose subject is the ``anonymous`` sentinel is rejected.

The signing-key lookup is injected (``get_signing_key``) so tests verify against a local public key
with no network; production wraps :class:`jwt.PyJWKClient` (which caches keys across requests).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import jwt

from atlas.governance.rbac import Principal

if TYPE_CHECKING:
    from atlas.config import Settings

# Asymmetric only — pinning the algorithm is the primary defense against alg/key confusion.
_ALGORITHMS = ["RS256"]
_REQUIRED_CLAIMS = ["exp", "iss", "aud"]
_ROLE_SPLIT = re.compile(r"[,\s]+")


class AuthError(Exception):
    """Token verification failed. Carries only a generic, client-safe message."""


class AuthDependencyError(Exception):
    """JWKS / identity-provider dependency unavailable. Mapped to HTTP 503 at the seam."""


def _parse_roles(raw: Any) -> tuple[str, ...]:
    """Defensively normalize a roles claim into a tuple of role strings.

    Accepts a JSON list, a comma/whitespace-delimited string, or nothing; anything else → ``()``.
    """
    if raw is None:
        return ()
    if isinstance(raw, str):
        return tuple(part for part in (p.strip() for p in _ROLE_SPLIT.split(raw)) if part)
    if isinstance(raw, (list, tuple)):
        return tuple(role for role in (str(item).strip() for item in raw) if role)
    return ()


class OidcAuthenticator:
    """Validates bearer tokens and maps claims → Principal."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        get_signing_key: Callable[[str], Any],
        user_claim: str = "sub",
        roles_claim: str = "roles",
        org_claim: str = "org_id",
        email_claim: str = "email",
        leeway: int = 60,
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._get_signing_key = get_signing_key
        self._user_claim = user_claim
        self._roles_claim = roles_claim
        self._org_claim = org_claim
        self._email_claim = email_claim
        self._leeway = leeway

    def _verified_claims(self, token: str) -> dict[str, Any]:
        try:
            key = self._get_signing_key(token)
        except jwt.PyJWKClientError as exc:
            raise AuthDependencyError("authentication service unavailable") from exc

        try:
            return jwt.decode(
                token,
                key,
                algorithms=_ALGORITHMS,
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": _REQUIRED_CLAIMS},
            )
        except jwt.PyJWTError as exc:
            raise AuthError("invalid or expired token") from exc

    def email_from_token(self, token: str) -> str | None:
        """Return the normalized email claim from a verified bearer token, or None if absent."""
        claims = self._verified_claims(token)
        raw = claims.get(self._email_claim)
        if raw is None:
            return None
        email = str(raw).strip()
        return email or None

    def principal_from_token(self, token: str) -> Principal:
        """Verify ``token`` and return the caller's Principal, or raise :class:`AuthError`."""
        claims = self._verified_claims(token)

        user_id = str(claims.get(self._user_claim) or "").strip()
        if not user_id:
            raise AuthError("token missing subject")
        if user_id == Principal.anonymous().user_id:
            raise AuthError("reserved subject")
        org_raw = claims.get(self._org_claim)
        # Match header-shim semantics: missing, empty, and whitespace-only → None (not "").
        org_id = (str(org_raw) if org_raw is not None else "").strip() or None
        return Principal(
            user_id=user_id, roles=_parse_roles(claims.get(self._roles_claim)), org_id=org_id
        )


def build_authenticator(settings: Settings) -> OidcAuthenticator | None:
    """Return an authenticator when OIDC is fully configured, else ``None`` (dev header-shim mode)."""
    issuer, audience, jwks_uri = (
        settings.oidc_issuer,
        settings.oidc_audience,
        settings.oidc_jwks_uri,
    )
    if not (issuer and audience and jwks_uri):
        return None
    jwks_client = jwt.PyJWKClient(jwks_uri)  # caches signing keys across requests

    def _get_signing_key(token: str) -> Any:
        return jwks_client.get_signing_key_from_jwt(token).key

    return OidcAuthenticator(
        issuer=issuer,
        audience=audience,
        get_signing_key=_get_signing_key,
        user_claim=settings.oidc_user_claim,
        roles_claim=settings.oidc_roles_claim,
        org_claim=settings.oidc_org_claim,
        email_claim=settings.oidc_email_claim,
        leeway=settings.oidc_leeway,
    )
