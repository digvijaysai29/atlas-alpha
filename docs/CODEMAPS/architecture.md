<!-- Generated: 2026-07-01 | Files scanned: 50 | Token estimate: ~950 -->

# Architecture Codemap

Full design docs: [`ARCHITECTURE.md`](../architecture/ARCHITECTURE.md) · [`CLAUDE.md`](../constitution/CLAUDE.md) §4-5.

## System diagram

```
┌─────────────────────────────────────────────────────────────────┐
│ INTERFACE (FastAPI)   /chat /chat/stream /approve /threads /kg/* │
│                        /oauth/*  · OIDC or dev-header identity   │
├─────────────────────────────────────────────────────────────────┤
│ AGENT ORCHESTRATION (LangGraph)  ◄── THE CORE                    │
│   planner → [gated?] → approval(interrupt) → executor → responder│
├─────────────────────────────────────────────────────────────────┤
│ INTEGRATION (tools)   email · slack · gmail · calendar ·         │
│                        slack_post_as_user · adapter engine (JSON)│
├─────────────────────────────────────────────────────────────────┤
│ KNOWLEDGE (PKG/OKG)   KnowledgeGraph ABC · ingestion · extraction│
│                        · embeddings (hybrid FTS + pgvector)      │
├─────────────────────────────────────────────────────────────────┤
│ DATA   Postgres checkpointer · hash-chained audit · policy store│
│         · Vault (OAuth creds)                                    │
└─────────────────────────────────────────────────────────────────┘
      cross-cutting: governance (RBAC/policy/audit/confidence),
      egress SSRF guard (tool_egress.py), observability (LangSmith)
```

## Orchestration graph (`src/atlas/orchestration/`)

```
START → planner → [route] → approval(interrupt) → executor → responder → END
```
- **planner** (`nodes.py`): `heuristic_plan` (offline/deterministic) or `llm_plan` (Claude, grounded
  on top-5 KG hits). Denies RBAC-unauthorized actions **early**. Risk tier always tool-declared.
- **approval**: `interrupt({pending_actions})`; resumes via `Command(resume=[{action_id, approved}])`.
- **executor**: re-checks policy + a matching `action_id`-bound approval **late**; runs via
  `GuardedExecutor` (`execution.py`) for idempotency.
- **responder**: synthesizes answer + `sources` + grounding-aware `confidence`.
- **state.py**: `AgentState` TypedDict (`messages`, `principal`, `kg_context`, proposed/approved/
  rejected actions, `action_results`, `sources`, `confidence`).
- **serde.py**: `atlas_serde()` — explicit msgpack allowlist (`_ATLAS_TYPES`) for checkpointed state.
- **graph.py**: `build_graph()`; `make_checkpointer`/`make_audit_log`/`make_knowledge_graph`/
  `make_policy_store` factories select Postgres when `DATABASE_URL` is set, else fall back.

## Request flow (typical `/chat` → gated action)

```
client → OIDC/header auth → rate limit → planner (RBAC deny-early)
       → interrupt (durable pause, Postgres checkpoint)
       → client POST /approve → verify_thread_owner (403 on mismatch)
       → executor (RBAC re-check + GuardedExecutor idempotency) → audit EXECUTED
       → responder (sources + confidence) → client
```

## Data flow (Knowledge Graph read)

```
query → KnowledgeGraph.query(principal, text) → RBAC filter pushed into SQL WHERE
      → can_read() re-check (defense-in-depth) → hybrid FTS+vector rank (RRF)
      → bounded top-5 → planner prompt / responder sources (never unfiltered)
```

## Milestone status (see `CLAUDE.md` §2 for the authoritative table)

Merged through **M4.8b** (proxy-bound egress for the adapter engine). Next: **M4.8c**
(resource/argument-aware `ToolPermission`), **M4.8d** (new connector purely via schema + `/approve/stream`).

## Locked decisions (do not weaken — `CLAUDE.md` §5-6)

Postgres-first persistence (official LangGraph savers only) · append-only hash-chained audit ·
default-deny RBAC via pluggable `PolicyStore` with hierarchical `:*` wildcards · KG reads RBAC-filtered
before reaching the LLM · risk tier is always tool-declared · serde allowlist for any new checkpointed
type · fail-closed feature flags (all-or-nothing env config, validated in `config.py`).
