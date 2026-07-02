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
| `POST /chat/stream` | SSE stream of a turn's lifecycle (M4.7) | principal | yes |
| `POST /approve` | Resume a thread paused at the approval gate | principal + thread owner | yes |
| `GET /threads/{id}` | Read a thread's current state | principal + thread owner | no |
| `POST /kg/ingest` | Write a document into the PKG/OKG (M4.4) | principal; `org` needs `kg:write:org` | yes |
| `GET /oauth/connections` | List a principal's connected OAuth providers (M4.3) | principal | no |
| `GET /oauth/{provider}/connect` | Start the OAuth authorization-code flow | principal | yes |
| `GET`/`POST /oauth/{provider}/callback` | Complete OAuth (IdP redirect / SPA exchange) | signed state (+ principal for POST) | yes |
| `DELETE /oauth/{provider}` | Revoke a connected provider's stored credential | principal | yes |

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
| Adapter engine | `ATLAS_ADAPTER_ENGINE_ENABLED`, `ATLAS_ADAPTER_EGRESS_*` | schema tools off / direct IP-pinned egress | See [Adapter engine / egress proxy](#adapter-engine--egress-proxy-m48a--m48b) |

**Secrets** are `SecretStr`, sourced only from env, never logged. `.env.example` documents names only.

## Adapter engine / egress proxy (M4.8a / M4.8b)

Schema-driven tools (`ATLAS_ADAPTER_ENGINE_ENABLED=true`) call outbound APIs through a pluggable
transport selected at startup:

| Mode | When | Behavior |
|---|---|---|
| **Direct** (default) | `ATLAS_ADAPTER_EGRESS_PROXY_URL` blank | IP-pinned `HttpxTransport` — DNS resolve + block private/metadata ranges |
| **Proxy** | Proxy URL set | `ProxyTransport` — forward proxy tunnel; destination `EgressPolicy` still enforced in-app |

**When to enable proxy:** corporate egress requires a central forward proxy (Squid/Envoy/gateway).
Set `ATLAS_ADAPTER_EGRESS_PROXY_URL` (plaintext `http://` is fine for unauthenticated proxies; use
`https://` when static proxy auth is configured). Optional credentials via
`ATLAS_ADAPTER_EGRESS_PROXY_USERNAME` + `ATLAS_ADAPTER_EGRESS_PROXY_PASSWORD` — never embed them in
the proxy URL. Per-user OAuth Bearer tokens stay on the **destination** API request (app layer);
proxy auth is deployment-static only.

**Trade-off:** proxy mode skips destination IP pinning (the proxy resolves/reaches the target). The
app-layer host + route allowlist still applies before any network I/O. `HTTP_PROXY`/`HTTPS_PROXY`
process env vars are **never** honored (`trust_env=False`).

Hand-written tools (`send_email`, `slack_post`) are unchanged — proxy applies only to the adapter
engine path.


## Streaming + responder narration (M4.8d)

`POST /chat/stream` and `POST /approve/stream` are the SSE siblings of `/chat` and `/approve` — same
OIDC/rate-limit spine, same `AgentResponse` shaping, delivered as `open → node*/token* →
(awaiting_approval | completed) → done`. `/approve/stream` performs the identical ownership check
`/approve` does (403 before the 409 awaiting-approval check) before any byte streams.

`token` events only appear when `ATLAS_RESPONDER_LLM_ENABLED=true` and `OPENROUTER_API_KEY` is set —
otherwise the responder is the deterministic summary and the stream is unchanged from M4.7 (just
`open → node* → completed/awaiting_approval → done`, no `token` events). Enabling it makes an
OpenRouter call on **every** `/chat`, `/chat/stream`, `/approve`, and `/approve/stream` turn (not just
streamed ones) — a real per-turn cost/latency addition; a failed call falls back to the deterministic
summary rather than failing the turn.

```bash
uv run python scripts/run_api.py &
curl -N -X POST localhost:8000/chat/stream -H 'X-Atlas-User-Id: alice' \
  -H 'X-Atlas-Roles: member' -H 'Content-Type: application/json' \
  -d '{"message":"find the latest roadmap"}'
curl -N -X POST localhost:8000/approve/stream -H 'X-Atlas-User-Id: alice' \
  -H 'X-Atlas-Roles: member' -H 'Content-Type: application/json' \
  -d '{"thread_id":"thr_...","approve":true}'
```

## Observability

LangSmith tracing is **env-driven, zero-code**: set `LANGSMITH_TRACING=true` + `LANGSMITH_API_KEY`
(+ optional `LANGSMITH_PROJECT`). The non-blocking LLM-judge evals also run only when a key is present.
The **audit log** is the system of record: append-only, hash-chained; verify integrity with
`AuditLog.verify()`. Knowledge ingestion emits a content-free `INGESTED` event (counts/scope/actor).

## Common issues

| Symptom | Likely cause | Fix |
|---|---|---|
| All roles denied / empty KG-policy | Fresh Postgres `atlas_role_permissions` is **deny-all** (no auto-seed) | `uv run python scripts/manage_policy.py seed` |
| `slack_post`/`send_email`/`gmail_send` start being denied after upgrading to M4.8c | Postgres was seeded **before** M4.8c with the old bare grants (`tool:slack:post`, etc.); those don't satisfy the now resource-scoped required permissions | `uv run python scripts/manage_policy.py seed` (additive/idempotent — safe to re-run) |
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
