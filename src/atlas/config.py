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
