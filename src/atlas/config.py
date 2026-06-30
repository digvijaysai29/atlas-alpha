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
_SUPPORTED_EMBEDDING_MODELS = frozenset({"voyage-3"})
_EMBEDDING_MODEL_DIMS: dict[str, int] = {"voyage-3": 1024}


def _is_secure_oidc_url(url: str) -> bool:
    """True for https URLs or http://127.0.0.1 / http://localhost (local mock IdPs)."""
    parsed = urlparse(url.strip())
    if parsed.scheme == "https":
        return True
    return parsed.scheme == "http" and parsed.hostname in _LOCAL_HTTP_HOSTS


def _nonempty_str(value: str | None) -> bool:
    """True when ``value`` contains non-whitespace content."""
    return bool(value and value.strip())


def _nonempty_secret(value: SecretStr | None) -> bool:
    """True when ``value`` is present and contains non-whitespace content."""
    return value is not None and bool(value.get_secret_value().strip())


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

    # --- Knowledge embeddings (M4.6 — pgvector semantic retrieval) ----------
    # When VOYAGE_API_KEY is set the Postgres KG embeds entities + queries with Voyage AI for semantic
    # retrieval; otherwise a deterministic offline embedder is used (CI/dev stays hermetic). The model
    # and dim MUST agree (voyage-3 => 1024); the dim drives both the vector column width and the
    # embedder, so a mismatch fails fast rather than writing a wrong-width vector.
    voyage_api_key: SecretStr | None = Field(default=None, alias="VOYAGE_API_KEY")
    embedding_model: str = Field(default="voyage-3", alias="ATLAS_EMBEDDING_MODEL")
    embedding_dim: int = Field(default=1024, alias="ATLAS_EMBEDDING_DIM")

    # --- Knowledge extraction (M4.5 — LLM entity/relation extraction) -------
    # When ATLAS_KG_EXTRACTION_ENABLED is true AND OPENROUTER_API_KEY is set, the ingestion pipeline
    # asks an LLM (via OpenRouter, primary model + fallback chain) to extract typed concept entities
    # and relations from each document; otherwise a deterministic no-op extractor is used so CI and
    # the eval gate stay hermetic. The model never influences authorization — scope/ACL are always
    # resolved server-side. Caps bound how much untrusted model output is persisted per document.
    openrouter_api_key: SecretStr | None = Field(default=None, alias="OPENROUTER_API_KEY")
    kg_extraction_enabled: bool = Field(default=False, alias="ATLAS_KG_EXTRACTION_ENABLED")
    extraction_model: str = Field(default="openai/gpt-4o-mini", alias="ATLAS_EXTRACTION_MODEL")
    # Comma-separated OpenRouter model ids tried in order when the primary fails (e.g.
    # "openai/gpt-4o-mini,google/gemini-flash-1.5"). Blank => no fallbacks.
    extraction_fallback_models: str = Field(default="", alias="ATLAS_EXTRACTION_FALLBACK_MODELS")
    extraction_max_entities: int = Field(default=64, alias="ATLAS_EXTRACTION_MAX_ENTITIES")
    extraction_max_relations: int = Field(default=128, alias="ATLAS_EXTRACTION_MAX_RELATIONS")

    # --- Adapter engine (M4.8a — metadata-driven tools) --------------------
    # When ATLAS_ADAPTER_ENGINE_ENABLED is true, trusted, version-controlled JSON tool schemas are
    # loaded at startup and registered as tools (replacing their hand-written twins). The schema files
    # are a code-reviewed build artifact — never user/network/LLM-supplied. Every schema endpoint host
    # must appear in the egress allowlist (SSRF defense); a schema can never mark a mutating tool as an
    # auto-run READ. Flag defaults off so CI and the deterministic eval gate stay byte-for-byte M4.7.
    adapter_engine_enabled: bool = Field(default=False, alias="ATLAS_ADAPTER_ENGINE_ENABLED")
    # Comma-separated hostnames schema-driven tools may call. Defaults to the hosts the bundled schemas
    # use; an operator widens it only as connectors are added.
    adapter_egress_allowlist: str = Field(
        default="slack.com", alias="ATLAS_ADAPTER_EGRESS_ALLOWLIST"
    )
    # Override the bundled schema directory (blank => the packaged ``atlas/tool_schemas`` dir).
    adapter_schema_dir: str = Field(default="", alias="ATLAS_ADAPTER_SCHEMA_DIR")

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
    api_email_header: str = Field(default="X-Atlas-Email", alias="ATLAS_API_EMAIL_HEADER")

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
    oidc_email_claim: str = Field(default="email", alias="ATLAS_OIDC_EMAIL_CLAIM")
    # Clock-skew tolerance (seconds) for exp/nbf. 60s is the common default: large enough to absorb
    # normal client/IdP NTP drift, small enough not to meaningfully extend an expired token.
    oidc_leeway: int = Field(default=60, alias="ATLAS_OIDC_LEEWAY")
    # Allow http:// (non-localhost) issuer/JWKS URLs — dev/integration only; default false.
    oidc_allow_insecure_http: bool = Field(default=False, alias="ATLAS_OIDC_ALLOW_INSECURE_HTTP")

    # --- Rate limiting (M3.6 — per-principal, Upstash-backed) ---------------
    # When enabled AND the Upstash REST creds are set (see ``rate_limit_configured``), /chat and
    # /approve are throttled per principal. Unset creds => limiting is OFF (fail-open; dev default).
    rate_limit_enabled: bool = Field(default=True, alias="ATLAS_RATE_LIMIT_ENABLED")
    rate_limit_requests: int = Field(default=60, alias="ATLAS_RATE_LIMIT_REQUESTS")
    rate_limit_window_seconds: int = Field(default=60, alias="ATLAS_RATE_LIMIT_WINDOW_SECONDS")
    # Upstash Redis REST endpoint + token (the token is secret; never logged). Standard Upstash names.
    upstash_redis_rest_url: str | None = Field(default=None, alias="UPSTASH_REDIS_REST_URL")
    upstash_redis_rest_token: SecretStr | None = Field(
        default=None, alias="UPSTASH_REDIS_REST_TOKEN"
    )

    # --- Email (M4.1 — Resend transactional send) ---------------------------
    resend_api_key: SecretStr | None = Field(default=None, alias="RESEND_API_KEY")
    email_from: str | None = Field(default=None, alias="ATLAS_EMAIL_FROM")

    # --- Slack (M4.2 — managed bot post) ------------------------------------
    slack_bot_token: SecretStr | None = Field(default=None, alias="SLACK_BOT_TOKEN")

    # --- Credential vault (M4.3 — HashiCorp Vault KV v2) ----------------------
    vault_addr: str | None = Field(default=None, alias="VAULT_ADDR")
    vault_token: SecretStr | None = Field(default=None, alias="VAULT_TOKEN")
    vault_mount: str = Field(default="secret", alias="VAULT_MOUNT")
    vault_namespace: str | None = Field(default=None, alias="VAULT_NAMESPACE")
    vault_role_id: str | None = Field(default=None, alias="VAULT_ROLE_ID")
    vault_secret_id: SecretStr | None = Field(default=None, alias="VAULT_SECRET_ID")

    # --- Outbound OAuth (M4.3 — per-user integrations) ------------------------
    google_oauth_client_id: str | None = Field(default=None, alias="GOOGLE_OAUTH_CLIENT_ID")
    google_oauth_client_secret: SecretStr | None = Field(
        default=None, alias="GOOGLE_OAUTH_CLIENT_SECRET"
    )
    google_oauth_redirect_uri: str | None = Field(default=None, alias="GOOGLE_OAUTH_REDIRECT_URI")
    slack_oauth_client_id: str | None = Field(default=None, alias="SLACK_OAUTH_CLIENT_ID")
    slack_oauth_client_secret: SecretStr | None = Field(
        default=None, alias="SLACK_OAUTH_CLIENT_SECRET"
    )
    slack_oauth_redirect_uri: str | None = Field(default=None, alias="SLACK_OAUTH_REDIRECT_URI")
    oauth_success_url: str | None = Field(default=None, alias="ATLAS_OAUTH_SUCCESS_URL")
    oauth_state_secret: SecretStr | None = Field(default=None, alias="ATLAS_OAUTH_STATE_SECRET")
    oauth_allow_insecure_state: bool = Field(
        default=False, alias="ATLAS_OAUTH_ALLOW_INSECURE_STATE"
    )

    @model_validator(mode="after")
    def validate_vault_config(self) -> Self:
        """Vault auth must be token-based or AppRole — partial AppRole is rejected."""
        has_token = _nonempty_secret(self.vault_token)
        has_role = _nonempty_str(self.vault_role_id) and _nonempty_secret(self.vault_secret_id)
        partial_role = (
            _nonempty_str(self.vault_role_id) or _nonempty_secret(self.vault_secret_id)
        ) and not has_role
        if partial_role:
            raise ValueError(
                "Partial Vault AppRole configuration: set both VAULT_ROLE_ID and "
                "VAULT_SECRET_ID or leave both blank."
            )
        if _nonempty_str(self.vault_addr) and not has_token and not has_role:
            raise ValueError(
                "VAULT_ADDR is set but neither VAULT_TOKEN nor AppRole credentials are configured."
            )
        return self

    @model_validator(mode="after")
    def validate_google_oauth_config(self) -> Self:
        google_fields = {
            "GOOGLE_OAUTH_CLIENT_ID": _nonempty_str(self.google_oauth_client_id),
            "GOOGLE_OAUTH_CLIENT_SECRET": _nonempty_secret(self.google_oauth_client_secret),
            "GOOGLE_OAUTH_REDIRECT_URI": _nonempty_str(self.google_oauth_redirect_uri),
        }
        set_names = [name for name, present in google_fields.items() if present]
        unset_names = [name for name, present in google_fields.items() if not present]
        if set_names and unset_names:
            msg = (
                f"Partial Google OAuth configuration: {', '.join(set_names)} set but "
                f"{', '.join(unset_names)} missing. Set all three or leave all blank."
            )
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def validate_slack_oauth_config(self) -> Self:
        slack_fields = {
            "SLACK_OAUTH_CLIENT_ID": _nonempty_str(self.slack_oauth_client_id),
            "SLACK_OAUTH_CLIENT_SECRET": _nonempty_secret(self.slack_oauth_client_secret),
            "SLACK_OAUTH_REDIRECT_URI": _nonempty_str(self.slack_oauth_redirect_uri),
        }
        set_names = [name for name, present in slack_fields.items() if present]
        unset_names = [name for name, present in slack_fields.items() if not present]
        if set_names and unset_names:
            msg = (
                f"Partial Slack OAuth configuration: {', '.join(set_names)} set but "
                f"{', '.join(unset_names)} missing. Set all three or leave all blank."
            )
            raise ValueError(msg)
        return self

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

    @model_validator(mode="after")
    def validate_rate_limit_config(self) -> Self:
        """Rate-limit budget must be positive; Upstash creds must be all set or all unset."""
        if self.rate_limit_requests <= 0:
            raise ValueError("ATLAS_RATE_LIMIT_REQUESTS must be a positive integer.")
        if self.rate_limit_window_seconds <= 0:
            raise ValueError("ATLAS_RATE_LIMIT_WINDOW_SECONDS must be a positive integer.")
        if not self.rate_limit_enabled:
            return self
        upstash_fields = {
            "UPSTASH_REDIS_REST_URL": _nonempty_str(self.upstash_redis_rest_url),
            "UPSTASH_REDIS_REST_TOKEN": _nonempty_secret(self.upstash_redis_rest_token),
        }
        set_names = [name for name, present in upstash_fields.items() if present]
        unset_names = [name for name, present in upstash_fields.items() if not present]
        if set_names and unset_names:
            msg = (
                f"Partial Upstash rate-limit configuration: {', '.join(set_names)} set but "
                f"{', '.join(unset_names)} missing. Set both or leave both blank."
            )
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def validate_embedding_config(self) -> Self:
        """Fail fast when the embedding model and dimension disagree (drives column width and embedder)."""
        if self.embedding_dim <= 0:
            raise ValueError("ATLAS_EMBEDDING_DIM must be a positive integer.")
        model = self.embedding_model.strip()
        if not model:
            raise ValueError("ATLAS_EMBEDDING_MODEL must not be blank.")
        expected_dim = _EMBEDDING_MODEL_DIMS.get(model)
        if expected_dim is not None and self.embedding_dim != expected_dim:
            raise ValueError(
                f"ATLAS_EMBEDDING_MODEL {model!r} requires ATLAS_EMBEDDING_DIM={expected_dim}."
            )
        if self.embeddings_configured and model not in _SUPPORTED_EMBEDDING_MODELS:
            supported = ", ".join(sorted(_SUPPORTED_EMBEDDING_MODELS))
            raise ValueError(
                f"Unsupported ATLAS_EMBEDDING_MODEL {model!r}; supported when VOYAGE_API_KEY is set: "
                f"{supported}."
            )
        return self

    @model_validator(mode="after")
    def validate_extraction_config(self) -> Self:
        """Extraction caps must be positive; enabling the flag requires an OpenRouter key (all-or-nothing)."""
        if self.extraction_max_entities <= 0:
            raise ValueError("ATLAS_EXTRACTION_MAX_ENTITIES must be a positive integer.")
        if self.extraction_max_relations <= 0:
            raise ValueError("ATLAS_EXTRACTION_MAX_RELATIONS must be a positive integer.")
        if self.kg_extraction_enabled:
            if not _nonempty_secret(self.openrouter_api_key):
                raise ValueError(
                    "ATLAS_KG_EXTRACTION_ENABLED is true but OPENROUTER_API_KEY is not set. "
                    "Provide a key or leave extraction disabled (the deterministic default)."
                )
            if not self.extraction_model.strip():
                raise ValueError(
                    "ATLAS_EXTRACTION_MODEL must not be blank when extraction is enabled."
                )
        return self

    @model_validator(mode="after")
    def validate_email_config(self) -> Self:
        """Email creds must be all set or all unset — mirror validate_rate_limit_config."""
        email_fields = {
            "RESEND_API_KEY": _nonempty_secret(self.resend_api_key),
            "ATLAS_EMAIL_FROM": _nonempty_str(self.email_from),
        }
        set_names = [name for name, present in email_fields.items() if present]
        unset_names = [name for name, present in email_fields.items() if not present]
        if set_names and unset_names:
            msg = (
                f"Partial email configuration: {', '.join(set_names)} set but "
                f"{', '.join(unset_names)} missing. Set both or leave both blank."
            )
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def validate_oauth_state_secret(self) -> Self:
        """OAuth routes require a dedicated state HMAC secret unless dev insecure flag is set."""
        if self.oauth_routes_enabled and not _nonempty_secret(self.oauth_state_secret):
            if not self.oauth_allow_insecure_state:
                raise ValueError(
                    "OAuth is enabled but ATLAS_OAUTH_STATE_SECRET is not set. "
                    "Set a strong secret (openssl rand -base64 32) or "
                    "ATLAS_OAUTH_ALLOW_INSECURE_STATE=true for dev/test only."
                )
        return self

    @model_validator(mode="after")
    def validate_oauth_vault_config(self) -> Self:
        """Durable Postgres + OAuth requires HashiCorp Vault — in-memory vault is not allowed."""
        if (
            self.oauth_routes_enabled
            and _nonempty_secret(self.database_url)
            and not self.credential_vault_enabled
        ):
            raise ValueError(
                "OAuth is enabled with DATABASE_URL but Vault is not configured. "
                "Set VAULT_ADDR + VAULT_TOKEN (or AppRole) — in-memory vault is not allowed "
                "with durable persistence."
            )
        return self

    @property
    def oidc_enabled(self) -> bool:
        """True when OIDC is fully configured; otherwise the dev header shim is used."""
        return bool(self.oidc_issuer and self.oidc_audience and self.oidc_jwks_uri)

    @property
    def rate_limit_configured(self) -> bool:
        """True when rate limiting is enabled AND Upstash REST creds are present.

        When False the limiter factory returns None and the interface is unthrottled (fail-open) —
        the dev/CI default, since the suite runs without Upstash.
        """
        return (
            self.rate_limit_enabled
            and _nonempty_str(self.upstash_redis_rest_url)
            and _nonempty_secret(self.upstash_redis_rest_token)
        )

    @property
    def email_configured(self) -> bool:
        """True when Resend API key and from-address are both present."""
        return _nonempty_secret(self.resend_api_key) and _nonempty_str(self.email_from)

    @property
    def slack_configured(self) -> bool:
        """True when a Slack bot token is present."""
        return _nonempty_secret(self.slack_bot_token)

    @property
    def embeddings_configured(self) -> bool:
        """True when a Voyage API key is present (else the deterministic offline embedder is used)."""
        return _nonempty_secret(self.voyage_api_key)

    @property
    def openrouter_configured(self) -> bool:
        """True when an OpenRouter API key is present (required to enable LLM extraction)."""
        return _nonempty_secret(self.openrouter_api_key)

    @property
    def extraction_enabled(self) -> bool:
        """True when LLM entity/relation extraction should run (flag on AND OpenRouter key present).

        When False the ingestion pipeline uses the deterministic no-op extractor, so CI and the
        deterministic eval gate stay hermetic (ingestion behaves exactly as M4.4).
        """
        return self.kg_extraction_enabled and self.openrouter_configured

    @property
    def extraction_fallback_model_list(self) -> tuple[str, ...]:
        """The configured fallback model ids, in order (comma-separated; blanks dropped)."""
        return tuple(
            model.strip() for model in self.extraction_fallback_models.split(",") if model.strip()
        )

    @property
    def adapter_egress_allowlist_hosts(self) -> frozenset[str]:
        """The lowercased hostnames schema-driven tools may call (comma-separated; blanks dropped)."""
        return frozenset(
            host.strip().lower()
            for host in self.adapter_egress_allowlist.split(",")
            if host.strip()
        )

    @property
    def vault_configured(self) -> bool:
        """True when Vault address and authentication are present."""
        has_token = _nonempty_secret(self.vault_token)
        has_role = _nonempty_str(self.vault_role_id) and _nonempty_secret(self.vault_secret_id)
        return _nonempty_str(self.vault_addr) and (has_token or has_role)

    @property
    def oauth_google_configured(self) -> bool:
        return (
            _nonempty_str(self.google_oauth_client_id)
            and _nonempty_secret(self.google_oauth_client_secret)
            and _nonempty_str(self.google_oauth_redirect_uri)
        )

    @property
    def oauth_slack_configured(self) -> bool:
        return (
            _nonempty_str(self.slack_oauth_client_id)
            and _nonempty_secret(self.slack_oauth_client_secret)
            and _nonempty_str(self.slack_oauth_redirect_uri)
        )

    @property
    def credential_vault_enabled(self) -> bool:
        """True when a durable Vault backend is configured for user OAuth tokens."""
        return self.vault_configured

    @property
    def oauth_routes_enabled(self) -> bool:
        return self.oauth_google_configured or self.oauth_slack_configured

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
