"""Application configuration.

Secrets and environment-specific values are read **exclusively** from the environment via Pydantic
Settings. Nothing here is ever hardcoded, and these objects are immutable (``frozen=True``).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Self
from urllib.parse import urlparse

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# LangSmith reads these names directly from the process environment to enable tracing. We surface
# them in Settings for visibility/validation; setting LANGSMITH_TRACING=true is all that is needed.
_DEFAULT_MODEL = "claude-opus-4-8"
_LOCAL_HTTP_HOSTS = frozenset({"127.0.0.1", "localhost"})


def _is_secure_oidc_url(url: str) -> bool:
    """True for https URLs or http://127.0.0.1 / http://localhost (local mock IdPs)."""
    parsed = urlparse(url.strip())
    if parsed.scheme == "https":
        return True
    return parsed.scheme == "http" and parsed.hostname in _LOCAL_HTTP_HOSTS


class Settings(BaseSettings):
    """Typed, immutable view of the runtime environment.

    All fields are optional so the system boots (and the test suite runs) without any secrets. When
    a secret is absent the relevant feature degrades safely — e.g. no ``ANTHROPIC_API_KEY`` makes
    the planner fall back to a deterministic, offline heuristic.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    # --- LLM (Claude) -------------------------------------------------------
    anthropic_api_key: SecretStr | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    model: str = Field(default=_DEFAULT_MODEL, alias="ATLAS_MODEL")

    # --- Observability (LangSmith) -----------------------------------------
    langsmith_tracing: bool = Field(default=False, alias="LANGSMITH_TRACING")
    langsmith_project: str = Field(default="atlas", alias="LANGSMITH_PROJECT")

    # --- Persistence --------------------------------------------------------
    # Empty => in-memory checkpointer. A path => SQLite. ``database_url`` is reserved for M2/Postgres.
    sqlite_path: str | None = Field(default=None, alias="ATLAS_SQLITE_PATH")
    database_url: SecretStr | None = Field(default=None, alias="DATABASE_URL")

    # --- Interface (M3.2 FastAPI) ------------------------------------------
    # Bind address for the dev server (scripts/run_api.py).
    api_host: str = Field(default="127.0.0.1", alias="ATLAS_API_HOST")
    api_port: int = Field(default=8000, alias="ATLAS_API_PORT")
    # Header names the trusted-network identity shim reads to build the request Principal. They are
    # configurable so a deployment can align them with whatever its reverse proxy / ingress sets.
    # SECURITY: these headers are trusted blindly — see atlas.interface.security. Real auth is M3.3.
    api_user_header: str = Field(default="X-Atlas-User-Id", alias="ATLAS_API_USER_HEADER")
    api_roles_header: str = Field(default="X-Atlas-Roles", alias="ATLAS_API_ROLES_HEADER")
    api_org_header: str = Field(default="X-Atlas-Org", alias="ATLAS_API_ORG_HEADER")

    # --- Authentication (M3.3 OIDC) ----------------------------------------
    # When issuer + audience + jwks_uri are ALL set (see ``oidc_enabled``), bearer-token validation
    # replaces the dev header shim. Leave them blank for dev/test (header shim). Use HTTPS in prod.
    oidc_issuer: str | None = Field(default=None, alias="ATLAS_OIDC_ISSUER")
    oidc_audience: str | None = Field(default=None, alias="ATLAS_OIDC_AUDIENCE")
    oidc_jwks_uri: str | None = Field(default=None, alias="ATLAS_OIDC_JWKS_URI")
    # Token claim names mapped onto the Principal.
    oidc_user_claim: str = Field(default="sub", alias="ATLAS_OIDC_USER_CLAIM")
    oidc_roles_claim: str = Field(default="roles", alias="ATLAS_OIDC_ROLES_CLAIM")
    oidc_org_claim: str = Field(default="org_id", alias="ATLAS_OIDC_ORG_CLAIM")
    # Clock-skew tolerance (seconds) for exp/nbf. 60s is the common default: large enough to absorb
    # normal client/IdP NTP drift, small enough not to meaningfully extend an expired token.
    oidc_leeway: int = Field(default=60, alias="ATLAS_OIDC_LEEWAY")
    # Allow http:// (non-localhost) issuer/JWKS URLs — dev/integration only; default false.
    oidc_allow_insecure_http: bool = Field(default=False, alias="ATLAS_OIDC_ALLOW_INSECURE_HTTP")

    @model_validator(mode="after")
    def validate_oidc_config(self) -> Self:
        """OIDC vars must be all set or all unset — partial config must not fall back to the header shim."""
        oidc_fields = {
            "ATLAS_OIDC_ISSUER": self.oidc_issuer,
            "ATLAS_OIDC_AUDIENCE": self.oidc_audience,
            "ATLAS_OIDC_JWKS_URI": self.oidc_jwks_uri,
        }
        is_set = {name: bool(val and str(val).strip()) for name, val in oidc_fields.items()}
        set_names = [name for name, present in is_set.items() if present]
        unset_names = [name for name, present in is_set.items() if not present]
        if set_names and unset_names:
            msg = (
                f"Partial OIDC configuration: {', '.join(set_names)} set but "
                f"{', '.join(unset_names)} missing. Set all three or leave all blank."
            )
            raise ValueError(msg)
        if self.oidc_enabled and not self.oidc_allow_insecure_http:
            for env_name, url in (
                ("ATLAS_OIDC_ISSUER", self.oidc_issuer),
                ("ATLAS_OIDC_JWKS_URI", self.oidc_jwks_uri),
            ):
                if url is None:
                    continue
                if not _is_secure_oidc_url(url):
                    msg = (
                        f"{env_name} must use https:// (or http://127.0.0.1 / http://localhost). "
                        "Set ATLAS_OIDC_ALLOW_INSECURE_HTTP=true only for dev/integration."
                    )
                    raise ValueError(msg)
        return self

    @property
    def oidc_enabled(self) -> bool:
        """True when OIDC is fully configured; otherwise the dev header shim is used."""
        return bool(self.oidc_issuer and self.oidc_audience and self.oidc_jwks_uri)

    @property
    def has_anthropic_key(self) -> bool:
        """True when a real Claude API key is available."""
        return self.anthropic_api_key is not None and bool(
            self.anthropic_api_key.get_secret_value()
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton (cached)."""
    return Settings()
