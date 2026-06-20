"""Application configuration.

Secrets and environment-specific values are read **exclusively** from the environment via Pydantic
Settings. Nothing here is ever hardcoded, and these objects are immutable (``frozen=True``).
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

# LangSmith reads these names directly from the process environment to enable tracing. We surface
# them in Settings for visibility/validation; setting LANGSMITH_TRACING=true is all that is needed.
_DEFAULT_MODEL = "claude-opus-4-8"


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
