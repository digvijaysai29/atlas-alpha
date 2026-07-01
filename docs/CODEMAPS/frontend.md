<!-- Generated: 2026-07-01 | Files scanned: 0 | Token estimate: ~120 -->

# Frontend Codemap

**No frontend exists in this repository.** atlas is currently an API-only backend (FastAPI over a
LangGraph agent); there is no `frontend/`, `web/`, `ui/`, or SPA package anywhere in the tree, and
`pyproject.toml` has no JS/TS build tooling.

Clients interact via HTTP: `POST /chat`, `POST /chat/stream` (SSE), `POST /approve`,
`GET /threads/{id}`, `POST /kg/ingest`, `/oauth/*`. See [`backend.md`](./backend.md) for the full
route table and [`RUNBOOK.md`](../guides/RUNBOOK.md) for how to run the API.

If a frontend is added, regenerate this codemap to cover its page tree, component hierarchy, and
state management.
