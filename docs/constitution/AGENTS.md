# AGENTS.md — atlas Project Constitution & Context

> Agent-facing context for **atlas**. Read by Cursor Cloud agents and other automated contributors.
> For the full project constitution, see [`CLAUDE.md`](./CLAUDE.md). Companion docs:
> [`ARCHITECTURE.md`](../architecture/ARCHITECTURE.md), [`HANDOFF.md`](../guides/HANDOFF.md),
> [`CONTRIBUTING.md`](../../CONTRIBUTING.md).

## Cursor Cloud specific instructions

- **Toolchain:** Python **3.13** managed by **`uv`** (installed at `~/.local/bin`, already on the login-shell PATH via `~/.bashrc`). `uv sync` provisions the interpreter — the system `python3` is 3.12 and must not be used directly. The startup update script runs `uv sync --all-extras --dev --frozen`; run other commands with `uv run ...`.
- **Everything runs fully offline by default.** With no `.env`, no API keys, and no Postgres, the planner falls back to a deterministic heuristic and integrations use fake senders. Lint, tests, the eval gate, demos, and the HTTP API all work with zero secrets/network. Do not treat missing secrets as a blocker for normal dev.
- **Standard commands** are documented in `CONTRIBUTING.md` (Commands table) and `docs/guides/HANDOFF.md` §3 — reference those rather than duplicating. Key ones: `uv run pytest --cov=atlas --cov-fail-under=80`, `uv run ruff check src tests scripts evals`, `uv run mypy src tests`, `uv run python evals/run_gate.py` (must score ≥ 0.90).
- **Run the API:** `uv run python scripts/run_api.py` binds `127.0.0.1:8000`. When OIDC is not configured, identity comes from the **dev header shim** (`X-Atlas-User-Id`, `X-Atlas-Roles`, `X-Atlas-Org`). Approving a paused thread as a different user returns **403** (resume-time owner binding) — this is expected, not a bug.
- **Gated actions fail-closed offline:** e.g. approving a `send_email` returns `"email not configured"` because Resend creds are unset. That is correct behavior — the approval gate and executor still ran. Read-only actions (e.g. `search`) auto-execute and return `sources` + `confidence`.
- **Integration tests are skipped by default** (~45 tests marked `@pytest.mark.integration`); they need a live Postgres via `DATABASE_URL`. Docker is **not** preinstalled on the base VM — install it (and run `docker compose up -d` for Postgres + Vault, `pgvector/pgvector:pg16`) only if you specifically need to run the integration suite. Never make the default `uv run pytest` require Postgres.
