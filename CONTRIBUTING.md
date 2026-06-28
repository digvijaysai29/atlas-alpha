# Contributing to atlas

atlas is an agent-first enterprise workspace (LangGraph + Claude). Before contributing, read the
project constitution — [`docs/constitution/CLAUDE.md`](docs/constitution/CLAUDE.md) — and the
onboarding guide [`docs/guides/HANDOFF.md`](docs/guides/HANDOFF.md). **Trust and safety are the
product**, so security invariants are non-negotiable (see [Code style & invariants](#code-style--invariants)).

> Sections marked `<!-- AUTO-GENERATED -->` are derived from `pyproject.toml`, `.env.example`, and
> `.github/workflows/ci.yml`. Regenerate with `/ecc:update-docs` rather than hand-editing them.

## Prerequisites

| Tool | Version | Why |
|------|---------|-----|
| Python | **3.13+** | `requires-python = ">=3.13"` |
| [uv](https://docs.astral.sh/uv/) | latest | dependency + venv manager (the repo commits `uv.lock`) |
| Docker | recent | local Postgres + Vault via `docker compose` (optional; in-memory works offline) |

## Setup

```bash
uv sync                       # create .venv and install deps + dev group from uv.lock
cp .env.example .env          # configure as needed; everything is optional for offline dev
docker compose up -d          # optional: local Postgres (and Vault) for durable/integration runs
```

With no `.env` and no Postgres, atlas runs fully offline: the planner falls back to a deterministic
heuristic and integrations use fake senders, so the demos, tests, and eval gate all pass without any
API key or network.

## Commands

<!-- AUTO-GENERATED: from pyproject.toml dev group + .github/workflows/ci.yml + scripts/ -->

| Command | Description |
|---------|-------------|
| `uv sync` | Install/refresh dependencies from `uv.lock` |
| `uv run python scripts/run_api.py` | Start the FastAPI dev server (`ATLAS_API_HOST`/`PORT`) |
| `uv run pytest` | Run the test suite (offline; integration tests skip without `DATABASE_URL`) |
| `uv run pytest --cov=atlas --cov-fail-under=80` | Tests with the 80% coverage gate (CI `fast-fail`) |
| `uv run pytest -m integration` | Postgres integration tests (requires `DATABASE_URL`) |
| `uv run ruff check src tests scripts evals` | Lint (CI `fast-fail`) |
| `uv run ruff format --check src tests scripts evals` | Formatting check (line length 100) |
| `uv run mypy src tests` | Strict type checking |
| `uv run bandit -r src -q` | Static security scan (CI `security`) |
| `uv run pip-audit -l` | Dependency vulnerability audit (CI `security`) |
| `uv run python evals/run_gate.py` | Deterministic agent-eval gate (CI `agent-eval`; must score ≥ 0.90) |
| `uv run python scripts/manage_policy.py seed` | Seed the Postgres role→permission table (deny-all until seeded) |
| `uv run python scripts/demo_*.py` | Hermetic demos (approval, RBAC, knowledge, persistence) |

## Testing

- **Framework:** `pytest` (`pytest-asyncio` in `auto` mode), tests live in `tests/`.
- **Style:** Arrange-Act-Assert; descriptive names (`test_<behavior>`); inject in-memory collaborators
  (`InMemoryKnowledgeGraph`, `InMemoryPolicyStore`, `InMemoryAuditLog`, fake senders) so unit tests are
  hermetic — no API key, no network, no Postgres.
- **Integration tests** are marked `@pytest.mark.integration` and **skip** when `DATABASE_URL` is unset
  (CI's `integration` job provides one). Never make the default `uv run pytest` require Postgres.
- **Coverage:** keep total ≥ **80%** (`--cov-fail-under=80`).
- **Security behavior** is additionally guarded by deterministic eval oracles in
  `evals/deterministic/oracles.py`; a new security-relevant behavior should add an oracle there.

## Code style & invariants

- **Formatter/linter:** `ruff` (line length 100, target `py313`). **Types:** `mypy --strict`.
- **Immutability:** domain records are frozen Pydantic models; graph nodes return new partial-state
  updates — never mutate in place.
- **Fail-closed everywhere:** unknown risk tier ⇒ gated; unknown permission ⇒ denied; unknown KG entity
  ⇒ filtered. Authorization is **data-driven, never model-driven** (the LLM picks tools/args only).
- **Parameterized SQL only**; secrets via `Settings`/env, never logged; `.env.example` documents names
  only. See `docs/constitution/CLAUDE.md` §6 for the full security posture.

## Submitting a PR

Milestone discipline: branch off `main` → keep CI green → open one PR into `main`.

- [ ] Branched off `main`; focused, conventional commits (`feat:`, `fix:`, `docs:`, …)
- [ ] `uv run pytest --cov=atlas --cov-fail-under=80` passes
- [ ] `ruff check`, `ruff format --check`, `mypy src tests` clean
- [ ] `bandit -r src` and `pip-audit -l` clean
- [ ] `uv run python evals/run_gate.py` scores **1.00** (no security-oracle regression)
- [ ] New security-relevant behavior has a deterministic eval oracle and/or test
- [ ] Docs updated for any new endpoint/env/script (`/ecc:update-docs`)
- [ ] For a milestone, a committed `docs/plans/M<x>_PLAN.md` accompanies the change

CI mirrors these locally as the `workflow-lint`, `fast-fail`, `security`, `contracts`, `integration`,
and `agent-eval` jobs — all are required before merge.
