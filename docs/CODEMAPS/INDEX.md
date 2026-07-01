<!-- Generated: 2026-07-01 | Files scanned: 130 | Token estimate: ~350 -->

# atlas — Codemap Index

**atlas** is an agent-first enterprise workspace: one LangGraph agent orchestrates tools (email,
Slack, Gmail, Calendar, custom connectors) over a RBAC-scoped Knowledge Graph, gated by a
human-in-the-loop approval step and an append-only audit log. Python 3.13, FastAPI, LangGraph 1.x,
Postgres. No frontend yet (API-only).

## Map

| Codemap | Covers |
|---|---|
| [`architecture.md`](./architecture.md) | Layered design, orchestration graph, request/data flow |
| [`backend.md`](./backend.md) | FastAPI routes, middleware/deps, service-layer mapping |
| [`frontend.md`](./frontend.md) | N/A — no frontend exists yet |
| [`data.md`](./data.md) | Postgres schema, checkpointer, audit chain, KG storage |
| [`dependencies.md`](./dependencies.md) | External services, third-party SDKs, feature-flag matrix |

## Ground truth

- Law: [`docs/constitution/CLAUDE.md`](../constitution/CLAUDE.md)
- Map/plan: [`docs/guides/HANDOFF.md`](../guides/HANDOFF.md)
- Design prose: [`docs/architecture/ARCHITECTURE.md`](../architecture/ARCHITECTURE.md)
- Ops: [`docs/guides/RUNBOOK.md`](../guides/RUNBOOK.md)

These codemaps are generated summaries for fast AI/human orientation — the linked docs above remain
the source of truth when they disagree.
