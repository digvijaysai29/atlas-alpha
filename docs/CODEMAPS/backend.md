<!-- Generated: 2026-07-01 | Files scanned: 30 | Token estimate: ~980 -->

# Backend Codemap — `src/atlas/interface/`, orchestration, tools

FastAPI app: `interface/app.py:create_app()` (sync handlers → threadpool; graph built once, shared via
`app.state`). Full endpoint semantics + auth model: [`RUNBOOK.md`](../guides/RUNBOOK.md) ·
[`AUTH.md`](../guides/AUTH.md).

## Routes

| Method · Path | File | Auth dep | Rate limited |
|---|---|---|---|
| `GET /healthz` | `routes.py` | none | no |
| `POST /chat` | `routes.py` | `RequestPrincipal` | yes (per principal) |
| `POST /chat/stream` (SSE) | `routes.py` + `sse.py` | `RequestPrincipal` | yes |
| `POST /approve` | `routes.py` | `RequestPrincipal` + `verify_thread_owner` | yes |
| `GET /threads/{thread_id}` | `routes.py` | `RequestPrincipal` + `verify_thread_owner` | no |
| `POST /kg/ingest` | `kg_routes.py` | `RequestPrincipal`; `scope=org` needs `kg:write:org` | yes |
| `GET /oauth/connections` | `oauth_routes.py` | `RequestPrincipal` | no |
| `GET /oauth/{provider}/connect` | `oauth_routes.py` | `RequestPrincipal` | yes |
| `GET /oauth/{provider}/callback` | `oauth_routes.py` | signed state (no principal; IdP redirect) | yes (by IP) |
| `POST /oauth/{provider}/callback` | `oauth_routes.py` | `RequestPrincipal` + signed state | yes |
| `DELETE /oauth/{provider}` | `oauth_routes.py` | `RequestPrincipal` | yes |

## Middleware / dependency chain

`security.py` → `get_request_principal` (OIDC bearer via `auth.py:OidcAuthenticator` if configured,
else dev header shim) → `rate_limit.py` → `enforce_rate_limit` (`RateLimited`/`RateLimitedByIp` deps,
Upstash-backed, fail-open) → route handler → (for `/approve`, `/threads`) `verify_thread_owner` (403 on
checkpointed-owner mismatch). `schemas.py` holds transport-only Pydantic models (no domain logic).

## Orchestration → tool service mapping

| Tool | `RiskTier` | `required_permission` | Backing service |
|---|---|---|---|
| `search` | READ | — | `KnowledgeGraph.query` |
| `send_email` | SEND | `tool:send` | `integrations/email.py` (Resend) |
| `slack_post` | SEND | `tool:slack:post` | `integrations/slack.py` (bot token) |
| `gmail_send` | SEND | `tool:gmail:send` | `integrations/gmail.py` (per-user OAuth) |
| `calendar_create_event` | SEND | `tool:calendar:write` | `integrations/calendar.py` (per-user OAuth) |
| `slack_post_as_user` | SEND | `tool:slack:post_as_user` | `integrations/slack_user.py` (per-user OAuth) |
| schema-driven tools | schema-declared (never `read` auto-run) | schema-declared | `adapter_engine.py` + `tool_egress.py` |

All `RiskTier != READ` actions run through `execution.py:GuardedExecutor` for idempotent, audited
execution (`REPLAY_SKIPPED`/`FAILED`/`EXECUTED`).

## Governance layer (`src/atlas/governance/`)

- `rbac.py` — `Principal` (frozen), `expand_roles`/`permission_satisfied` (hierarchical `:*` wildcard
  matching, single source of truth), `can()`.
- `policy.py` — `PolicyStore` ABC + `InMemoryPolicyStore`; Postgres backend in `persistence/policy_store.py`.
- `audit.py` — `AuditEvent`/`AuditEventType`, hash-chained `AuditLog`, `InMemoryAuditLog`.
- `confidence.py` — grounding-aware confidence scoring + `Source` attribution.
- `credentials.py` — `CredentialVault` ABC, `OAuthProvider`, `CredentialResolver` (per-user OAuth token
  resolution for tools); Vault backend in `persistence/hashicorp_vault.py`.

## Adapter engine (M4.8a/b — `adapter_engine.py`, `tool_egress.py`)

Trusted JSON `ToolSchema` files (`src/atlas/tool_schemas/*.json`, CODEOWNERS-reviewed) are compiled at
startup into `BaseTool`s (`_SchemaTool`) behind the same approval/RBAC/audit gate. Egress is
SSRF-hardened: single-parsed `httpx.URL`, host + exact `(method,host,path)` route allowlist
(`EgressPolicy`), IP-pinned direct transport (`HttpxTransport`) or an optional forward proxy
(`ProxyTransport`, `make_adapter_transport`), redirects never followed. Guide:
[`CUSTOM_CONNECTORS.md`](../guides/CUSTOM_CONNECTORS.md).

## Scripts (`scripts/*.py`)

`run_api.py` (dev server) · `manage_policy.py` (seed/grant/revoke policy) · `manage_credentials.py`
(Vault CLI) · `demo_approval.py`/`demo_persistence.py`/`demo_rbac.py`/`demo_knowledge.py`/
`demo_knowledge_postgres.py` (hermetic demos).
