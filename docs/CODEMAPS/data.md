<!-- Generated: 2026-07-01 | Files scanned: 15 | Token estimate: ~900 -->

# Data Codemap — persistence, checkpointing, Knowledge Graph

Precedence everywhere: **Postgres** (`DATABASE_URL`) › **SQLite** (`ATLAS_SQLITE_PATH`) › in-memory.
Shared `psycopg_pool.ConnectionPool` (`autocommit=True`, `row_factory=dict_row`) backs the
checkpointer, audit log, KG, and policy store. Local dev: `docker-compose.yml` (`pgvector/pgvector:pg16`
+ `hashicorp/vault:1.17`).

## Tables (Postgres, static DDL, parameterized SQL only)

| Table | Owner module | Purpose |
|---|---|---|
| LangGraph checkpoint tables | `langgraph-checkpoint-postgres` (official saver) | durable graph state per `thread_id` |
| audit log table | `persistence/audit_store.py` (`PostgresAuditLog`) | append-only, hash-chained (`sha256(prev_hash‖canonical(event))`); advisory-lock-serialized appends |
| `atlas_role_permissions` | `persistence/policy_store.py` (`PostgresPolicyStore`) | role→permission grants; **empty = deny-all**, never auto-seeded |
| KG entities table | `persistence/knowledge_store.py` (`PostgresKnowledgeGraph`) | `tsvector` full-text + `vector` column (pgvector) for hybrid retrieval; ACL column enforces RBAC in the `WHERE` |

## Knowledge Graph (`src/atlas/knowledge/`)

- `interfaces.py` — `Entity`/`Relation` (frozen), `can_read()`, `KnowledgeGraph` ABC
  (`query(principal, text, limit)` — RBAC-filtered **before** returning).
- `memory_store.py` — `InMemoryKnowledgeGraph` (keyword match; offline/test backend); `seed_demo_graph()`.
- `ingestion.py` — `IngestionService`: chunking (`chunk_text`), dedup, RBAC-scoped upsert. PKG isolation
  via per-user identity ACLs (`kg:read:user:<uid>`); OKG writes gated by `kg:write:org`.
- `extraction.py` (M4.5) — optional LLM entity/relation extraction (`LLMExtractor` via OpenRouter,
  primary + fallback chain); `DeterministicExtractor`/`FakeExtractor` for hermetic default. Scope/ACL
  always server-resolved — the model never sets authorization.
- `embeddings.py` (M4.6) — `EmbeddingProvider` ABC; `VoyageEmbedder` (Voyage AI) when
  `VOYAGE_API_KEY` set, else `DeterministicEmbedder` (offline, CI-safe). Model/dim pair validated in
  `config.py` (`voyage-3` ⇒ 1024).
- Retrieval: hybrid FTS + vector cosine, fused via RRF, on `PostgresKnowledgeGraph`; identical RBAC
  predicate on both branches (no IDOR via embeddings).

## Audit chain (`governance/audit.py` + `persistence/audit_store.py`)

`AuditEventType`: `PROPOSED`/`APPROVED`/`REJECTED`/`EXECUTED`/`SKIPPED`/`DENIED`/`REPLAY_SKIPPED`/
`FAILED`/`INGESTED`. Canonical serialization (sorted-keys JSON, UTC timestamps) → `sha256` chain;
`verify_chain()` detects mutate/insert/delete/reorder. `has_executed(action_id)` backs
`execution.py:GuardedExecutor` idempotency — **durable Postgres audit is required** for any live
side-effecting tool (email/Slack/Gmail/Calendar), since SQLite/in-memory audit doesn't survive restarts
reliably enough for that guarantee.

## Credential storage (M4.3 — per-user OAuth)

`governance/credentials.py` — `CredentialVault` ABC, `StoredCredential`, `InMemoryCredentialVault`
(dev/test). `persistence/hashicorp_vault.py` — `HashiCorpCredentialVault` (KV v2 via `hvac`), path
`secret/<org_id>/<user_id>/<provider>`. Durable Postgres + OAuth **requires** Vault (`config.py`
`validate_oauth_vault_config` — in-memory vault is rejected with durable persistence).

## Migration history

No formal migration framework (Alembic, etc.) — each store's `setup()`/DDL is idempotent
(`CREATE TABLE IF NOT EXISTS`, `CREATE EXTENSION IF NOT EXISTS vector`) and runs at process startup
against the shared connection pool. Schema changes ship as code changes to the relevant
`persistence/*.py` module, milestone-gated (see `docs/plans/M*_PLAN.md`).
