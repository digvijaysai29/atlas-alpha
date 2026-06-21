# atlas

[![CI](https://github.com/digvijaysai29/atlas-alpha/actions/workflows/ci.yml/badge.svg)](https://github.com/digvijaysai29/atlas-alpha/actions/workflows/ci.yml)

An **agent-first enterprise workspace**. One unified agent sits at the center and uses apps as
tools, powered by a Personal + Organizational Knowledge Graph. Security, human-in-the-loop approval,
and auditability are first-class.

- 📜 Project constitution: [`CLAUDE.md`](./docs/constitution/CLAUDE.md)
- 🏛️ System design: [`ARCHITECTURE.md`](./docs/architecture/ARCHITECTURE.md)
- 🧭 Onboarding + next-milestone plan: [`HANDOFF.md`](./docs/guides/HANDOFF.md)

## Status — Milestone 1 (runnable HITL core)

A working LangGraph orchestration layer with a **fail-closed, human-in-the-loop approval gate**:

```
planner → (approval / interrupt) → executor → responder
```

- Risk tiers are **declared by tools**, never inferred by the LLM.
- Irreversible actions (send / write / delete / pay) require explicit human approval.
- Approvals are bound to a specific `action_id`; the executor enforces the gate in code.
- Every propose / approve / reject / execute event is recorded in an append-only audit log.

## Quickstart

```bash
uv sync                                   # Python 3.13
uv run pytest                             # policy + approval (approve & reject) + tools
uv run python scripts/demo_approval.py    # watch the HITL gate in action
```

No `ANTHROPIC_API_KEY` is required for M1 — the planner falls back to a deterministic heuristic so
everything runs offline. Set the key (and `LANGSMITH_*`) in `.env` to use real Claude + tracing.

### Email (M4.1)

Real gated email send via Resend requires **all three** (see `.env.example`):

```bash
docker compose up -d
export DATABASE_URL=postgresql://atlas:atlas@localhost:5432/atlas
export RESEND_API_KEY=re_...
export ATLAS_EMAIL_FROM=atlas@yourdomain.com
```

`DATABASE_URL` is mandatory for live sends: idempotency is enforced by the **durable Postgres audit
log** (`has_executed` on `action_id`). With only `RESEND_API_KEY` + `ATLAS_EMAIL_FROM` set — or with
only `ATLAS_SQLITE_PATH` for checkpoints — `send_email` still fails closed after approval
(`email not configured`). Offline demos/tests use `offline_registry()` (fake sender).

For an intentional live Resend integration test: also set `ATLAS_EMAIL_LIVE_TEST=1`.

## Project layout

```
src/atlas/
  config.py              # Pydantic Settings (env-only secrets)
  llm.py                 # Claude model factory
  actions.py             # RiskTier, action contracts (frozen), requires_approval policy
  tools.py               # Tool protocol + registry + send_email (Resend when configured)
  integrations/email.py  # EmailSender ABC + ResendEmailSender
  execution.py           # GuardedExecutor (idempotent side effects)
  governance.py          # append-only audit log
  orchestration/
    state.py             # AgentState (graph channels)
    nodes.py             # planner · approval · executor · responder
    graph.py             # build_graph() + checkpointer factory
scripts/demo_approval.py # end-to-end approve/reject demo
tests/                   # policy, approval paths, tools
```

See [`ARCHITECTURE.md`](./docs/architecture/ARCHITECTURE.md) §Roadmap for Milestone 2 (Postgres, RBAC, Knowledge
Graph, evaluation).
