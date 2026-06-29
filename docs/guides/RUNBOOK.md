# atlas Runbook — operate the service

Operational guide for running, configuring, and troubleshooting atlas. For pre-release validation see
[`RELEASE.md`](./RELEASE.md); for the auth/identity model see [`AUTH.md`](./AUTH.md); for design see
[`../architecture/ARCHITECTURE.md`](../architecture/ARCHITECTURE.md).

> Sections marked `<!-- AUTO-GENERATED -->` are derived from `.env.example`, `docker-compose.yml`, and
> the route files. Regenerate with `/ecc:update-docs` rather than hand-editing them.

## Run the API

```bash
uv sync
uv run python scripts/run_api.py     # binds ATLAS_API_HOST:ATLAS_API_PORT (default 127.0.0.1:8000)
```

The compiled agent is built once at startup and shared via `app.state` (`interface/app.py`). Handlers
are synchronous and run in Starlette's threadpool (the graph and psycopg pool are blocking).

## Backing services

<!-- AUTO-GENERATED: from docker-compose.yml -->

| Service | Purpose | Local start |
|---------|---------|-------------|
| `postgres` | Durable LangGraph checkpoints, hash-chained audit log, KG, policy store | `docker compose up -d postgres` |
| `vault` | HashiCorp Vault (KV v2) for per-user OAuth tokens (M4.3) | `docker compose up -d vault` |

**Persistence precedence:** `DATABASE_URL` (Postgres) > `ATLAS_SQLITE_PATH` (SQLite) > in-memory.
Durable Postgres is **required** for any live side-effecting tool (email/Slack/OAuth) because
idempotency (`has_executed(action_id)`) must survive restarts.

## Endpoints

<!-- AUTO-GENERATED: from interface/routes.py, kg_routes.py, oauth_routes.py -->

| Method · Path | Purpose | Auth | Rate limited |
|---|---|---|---|
| `GET /healthz` | Liveness probe → `{"ok": true}` | none | no |
| `POST /chat` | Run the agent on a message | principal | yes (per principal) |
| `POST /approve` | Resume a thread paused at the approval gate | principal + thread owner | yes |
| `GET /threads/{id}` | Read a thread's current state | principal + thread owner | no |
| `POST /kg/ingest` | Write a document into the PKG/OKG (M4.4) | principal; `org` needs `kg:write:org` | yes |
| `/oauth/{provider}/connect`,`/callback`,`/oauth/connections` | Per-user OAuth binding (M4.3) | principal | no |

**Health check:** `GET /healthz` for liveness. Readiness is implied by a successful boot (DB pool
opens + checkpointer `setup()` runs at startup); a failed DB connection fails startup loudly.

## Configuration

All config is environment-driven via `Settings` (`src/atlas/config.py`); copy `.env.example` → `.env`.
Feature flags are all-or-nothing and **fail-closed**: a feature is off (not half-configured) unless its
full credential set is present. Key groups:

| Group | Vars (see `.env.example`) | Effect when unset |
|---|---|---|
| LLM | `ANTHROPIC_API_KEY`, `ATLAS_MODEL` | deterministic heuristic planner (offline) |
| Persistence | `DATABASE_URL`, `ATLAS_SQLITE_PATH` | in-memory (non-durable) |
| Auth (OIDC) | `ATLAS_OIDC_ISSUER`/`AUDIENCE`/`JWKS_URI` (+ claim overrides) | dev header-shim identity (trusted-proxy only) |
| Rate limiting | `ATLAS_RATE_LIMIT_*`, `UPSTASH_REDIS_REST_URL`/`TOKEN` | unthrottled (fail-open) |
| Policy store | `DATABASE_URL` | in-memory `ROLE_PERMISSIONS` defaults |
| KG embeddings (M4.6) | `VOYAGE_API_KEY`, `ATLAS_EMBEDDING_MODEL`/`DIM` | deterministic offline embedder (hybrid vector search still works on Postgres) |
| Email / Slack | `RESEND_API_KEY`+`ATLAS_EMAIL_FROM` / `SLACK_BOT_TOKEN` | tool fail-closed after approval |
| Vault / OAuth | `VAULT_ADDR`+auth, `GOOGLE_*`/`SLACK_OAUTH_*`, `ATLAS_OAUTH_STATE_SECRET` | per-user integrations disabled |

**Secrets** are `SecretStr`, sourced only from env, never logged. `.env.example` documents names only.

## Observability

LangSmith tracing is **env-driven, zero-code**: set `LANGSMITH_TRACING=true` + `LANGSMITH_API_KEY`
(+ optional `LANGSMITH_PROJECT`). The non-blocking LLM-judge evals also run only when a key is present.
The **audit log** is the system of record: append-only, hash-chained; verify integrity with
`AuditLog.verify()`. Knowledge ingestion emits a content-free `INGESTED` event (counts/scope/actor).

## Common issues

| Symptom | Likely cause | Fix |
|---|---|---|
| All roles denied / empty KG-policy | Fresh Postgres `atlas_role_permissions` is **deny-all** (no auto-seed) | `uv run python scripts/manage_policy.py seed` |
| `send_email`/`slack_post` fail after approval | Creds set but `DATABASE_URL` unset (no durable audit) | configure Postgres; both are required |
| `POST /kg/ingest` → 403 on `scope=org` | Principal lacks `kg:write:org` (admin-only by default) | grant via policy store, or use `scope=personal` |
| Anyone can spoof identity | Dev header shim exposed without a trusted proxy | configure OIDC (`ATLAS_OIDC_*`) for any real deployment |
| Rate limits not enforced | Upstash creds unset ⇒ fail-open by design | set `UPSTASH_REDIS_REST_URL`/`TOKEN` |
| 401 on `/chat` | OIDC configured, missing/invalid bearer token | send `Authorization: Bearer <jwt>` |

## Rollback & release

The repo ships per-milestone PR branches into `main`; a regression is rolled back by reverting the
offending merge commit (`git revert <sha>`) and re-running the gate. Run the full local gate
(`pytest` + `ruff` + `mypy` + `bandit` + `pip-audit` + `evals/run_gate.py`) before any release —
see [`RELEASE.md`](./RELEASE.md) for the validation checklist. This is an alpha; there is no on-call
escalation path yet.
