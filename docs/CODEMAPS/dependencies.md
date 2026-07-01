<!-- Generated: 2026-07-01 | Files scanned: 10 | Token estimate: ~850 -->

# Dependencies Codemap — external services & integrations

Source of truth: `pyproject.toml`, `.env.example`, `docker-compose.yml`. Every feature is **all-or-nothing
and fail-closed** (`config.py` `model_validator`s reject partial credential sets).

## External services

| Service | Used for | Enabled when | Off-mode fallback |
|---|---|---|---|
| **Anthropic (Claude)** | LLM planner | `ANTHROPIC_API_KEY` set | deterministic `heuristic_plan` (offline) |
| **Postgres** (self-hosted or Neon) | checkpointer, audit, KG, policy | `DATABASE_URL` set | SQLite (`ATLAS_SQLITE_PATH`) → in-memory |
| **HashiCorp Vault** | per-user OAuth token storage | `VAULT_ADDR` + token/AppRole | `InMemoryCredentialVault` (rejected if `DATABASE_URL` also set) |
| **Google OAuth** | Gmail send, Calendar create | `GOOGLE_OAUTH_CLIENT_ID/SECRET/REDIRECT_URI` (all 3) | those tools unavailable |
| **Slack OAuth** | `slack_post_as_user` | `SLACK_OAUTH_CLIENT_ID/SECRET/REDIRECT_URI` (all 3) | tool unavailable |
| **Slack (bot token)** | `slack_post` (managed, not per-user) | `SLACK_BOT_TOKEN` | fails closed after approval |
| **Resend** | `send_email` | `RESEND_API_KEY` + `ATLAS_EMAIL_FROM` | fails closed after approval |
| **Voyage AI** | KG semantic embeddings | `VOYAGE_API_KEY` | `DeterministicEmbedder` (offline) |
| **OpenRouter** | LLM entity/relation extraction | `ATLAS_KG_EXTRACTION_ENABLED=true` + `OPENROUTER_API_KEY` | `DeterministicExtractor`/no-op |
| **Upstash Redis** | per-principal rate limiting | `UPSTASH_REDIS_REST_URL/TOKEN` + `ATLAS_RATE_LIMIT_ENABLED` | unthrottled (fail-open) |
| **OIDC IdP** (Auth0/Okta/Clerk/etc.) | verified bearer-JWT auth | `ATLAS_OIDC_ISSUER/AUDIENCE/JWKS_URI` (all 3) | dev header shim (trusted-network only) |
| **LangSmith** | tracing + non-blocking quality evals | `LANGSMITH_TRACING=true` + `LANGSMITH_API_KEY` | no tracing; eval gate stays deterministic-only |
| **Forward proxy** (Squid/Envoy/etc.) | adapter-engine egress routing | `ATLAS_ADAPTER_EGRESS_PROXY_URL` | direct IP-pinned `HttpxTransport` |

## Key third-party libraries (`pyproject.toml`)

| Package | Role |
|---|---|
| `langgraph` / `langgraph-checkpoint-postgres` / `-sqlite` | orchestration graph + durable checkpointers |
| `langchain-anthropic` | Claude model client |
| `langchain-openrouter` | OpenRouter LLM client (M4.5 extraction) |
| `fastapi` + `uvicorn` | HTTP interface |
| `psycopg[binary]` + `psycopg-pool` | Postgres driver + shared connection pool |
| `pgvector` | vector column adapter for semantic KG retrieval |
| `pyjwt[crypto]` | OIDC bearer-JWT verification (RS256+JWKS) |
| `authlib` | outbound OAuth authorization-code + refresh flows |
| `hvac` | HashiCorp Vault KV v2 client |
| `httpx` | sync HTTP (Gmail/Calendar API calls, adapter-engine egress) |
| `resend` / `slack-sdk` | email / Slack sends |
| `sse-starlette` | managed SSE transport for `/chat/stream` |
| `upstash-ratelimit` | per-principal HTTP rate limiting |
| `voyageai` | Voyage AI embeddings client |

## Local dev backing services (`docker-compose.yml`)

| Service | Image | Purpose |
|---|---|---|
| `postgres` | `pgvector/pgvector:pg16` | checkpointer/audit/KG/policy (pgvector preinstalled) |
| `vault` | `hashicorp/vault:1.17` (dev mode) | per-user OAuth token storage |

## CI-only tooling (`.github/workflows/ci.yml`)

`ruff`, `mypy --strict`, `pytest --cov-fail-under=80`, `semgrep` (community + custom rulesets),
`bandit`, `pip-audit`, `gitleaks`, `actionlint`. `contracts` job runs `tests/test_ci_contracts.py`
(serde allowlist). `agent-eval` job runs `evals/run_gate.py` (deterministic blocking gate + optional
LangSmith judge) on every push/PR.
