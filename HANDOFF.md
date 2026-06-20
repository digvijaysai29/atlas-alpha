# HANDOFF.md — atlas

> Onboarding + forward plan for the **next implementer** (human or agent). Read this to pick up
> **M2.3** and the **future phases (M3+)** without re-deriving context.
>
> **Read `CLAUDE.md` first** — it is the binding constitution (rules, guardrails, the hard "never" list).
> This doc is the *map and the plan*; `CLAUDE.md` is the *law*; [`ARCHITECTURE.md`](./ARCHITECTURE.md)
> is the *design*; [`README.md`](./README.md) is the *quickstart*.

---

## 1. Current state (what's on / heading to `main`)

Private repo `digvijaysai29/atlas-alpha`. Work ships in small, independently-green sub-phases:
branch → PR into `main` → CI must be green.

| Milestone | What it delivered | Status |
|---|---|---|
| **M1** | Runnable HITL core (`planner → approval(interrupt) → executor → responder`); fail-closed risk-tiered approval; append-only audit; mock tools; CI/CD | ✅ merged |
| **M2.1** | Durable **Postgres checkpointer** + **hash-chained tamper-evident audit store**; docker-compose Postgres + CI `integration` job | ✅ merged (PR #1) |
| **M2.2a** | **RBAC + `Principal` threading**: default-deny `can()`, tool `required_permission`, deny-early + re-check-late; `governance/` package | ✅ merged (PR #2) |
| **M2.2b** | **RBAC-scoped Knowledge Graph** wired into the planner (`kg_context`) | ✅ merged (PR #3) |
| **M2.2c** | Structured `Source` attribution + grounding-aware confidence (`governance/confidence.py`) | ✅ PR #5 (CI green; merge it) |
| **M2.3** | Real `agent-eval` gate (deterministic blocking + optional LangSmith) | ✅ merged (PR #7) |
| **M3.1** | Durable **`PostgresKnowledgeGraph`** (full-text search; RBAC filter in SQL) behind the `KnowledgeGraph` ABC | ✅ merged (PR #8) |
| **M3.2** | FastAPI Interface (`/chat`, `/approve`, `/threads/{id}`) + **resume-time principal/thread binding**; trusted-network header identity shim | ✅ merged (PR #9) |
| **M3.3** | Real **OIDC/JWT bearer auth** (RS256+JWKS, claims→`Principal`); header shim → dev fallback. See `AUTH.md` | ✅ merged (PR #10) |
| **M3.4** | Pluggable **`PolicyStore`** (ABC + in-memory + Postgres) replacing hardcoded `ROLE_PERMISSIONS`; `manage_policy.py` CLI. See `AUTH.md` | ✅ merged (PR #16) |
| **M3.5** | Fine-grained RBAC: **hierarchical wildcard permissions** (`kg:read:*` ⇒ `kg:read:org`) via shared `permission_satisfied`. Guide: **[`M3.5_PLAN.md`](./M3.5_PLAN.md)** | ✅ merged (PR #19) |
| **M3.6** | **Per-principal rate limiting** on `/chat` + `/approve` (Upstash + `upstash-ratelimit`); 429 + `Retry-After`; fail-open; per-IP for anonymous | ✅ this PR |
| **M4+** | **← NEXT.** Real integrations, pgvector semantic retrieval, sessions/provisioning, SSE streaming | future |

**Net:** atlas is a secure, durable, identity-aware, knowledge-grounded HITL agent with a transparent
sources+confidence layer, a real blocking eval gate, and now a **network interface** with resume-time
owner binding — all behind a fail-closed security model. What's missing is *verified* identity (real
SSO, M3.3 — the header shim is trusted-network/dev-only), real tool integrations, and semantic
retrieval.

## 2. System recap (pointers, not prose)

Five layers + cross-cutting governance (`ARCHITECTURE.md`): `Interface → Agent Orchestration →
Integration(tools) → Knowledge(PKG/OKG) → Data(persistence)`. The core is the LangGraph state machine
`START → planner → [route] → approval(interrupt) → executor → responder → END`.

Hard invariants (full list in `CLAUDE.md` §6 — do not weaken any):
- **Fail-closed everywhere** (approval policy, RBAC `can`/`can_read`, KG retrieval).
- **Gate enforced in code** — the executor re-checks policy + a matching, `action_id`-bound approval
  before every run; deleting the approval node must make a test fail.
- **Risk tier is tool-declared, never LLM-assigned.** The model picks tool+args only.
- **RBAC default-deny**; `Principal` is immutable, threaded through state + serde allowlist; `can()` is
  re-evaluated every call (persisted ACLs are never trusted as authz).
- **KG reads are RBAC-filtered before content reaches the planner/LLM/sources** (IDOR defense).
- **Append-only hash-chained audit**; parameterized SQL only; secrets via env/Settings.

Codebase map: `CLAUDE.md` §4. Locked M2 decisions: `CLAUDE.md` §5.

## 3. Dev loop & conventions

```bash
uv sync                                              # Python 3.13, uv-managed
uv run pytest                                        # unit; integration tests SKIP without DATABASE_URL
docker compose up -d                                 # local Postgres for integration
export DATABASE_URL=postgresql://atlas:atlas@localhost:5432/atlas
uv run pytest -m integration                         # Postgres-backed
uv run ruff check . && uv run ruff format --check .  # lint + format
uv run mypy src tests                                # strict (keep the 2 scoped overrides; don't broaden)
uv run bandit -r src                                 # SAST
uv run --with semgrep semgrep scan --config p/python --config p/security-audit --config p/secrets --error src tests scripts evals main.py
uv run python scripts/demo_rbac.py                   # demos: approval / persistence / rbac / knowledge
```

- **Branch per sub-phase** off `main` → **PR into `main`**. CI jobs: **fast-fail** (ruff/mypy/pytest,
  `--cov-fail-under=80`), **security** (semgrep/bandit/pip-audit/gitleaks), **integration** (Postgres
  service), **agent-eval** (PR→main only, currently a no-op).
- **Corridor `analyzePlan` runs BOTH before and after writing code** (once on the plan, again on the
  diff); resolve findings before the PR.
- **Conventional commits** (`feat/fix/refactor/docs/...`), no attribution lines. Coverage ≥80%.
- Keep the full local gate green before pushing.

## 4. Environment gotchas (will bite you)

- **⚠️ Conductor worktree resets HEAD to `main` between shell calls.** This repo is under a Conductor
  worktree; a `git checkout -b feature` in one shell call can silently revert to `main` by the next,
  so a later `git commit` lands on `main` and `git push -u origin feature` pushes an *empty* branch
  (→ `gh pr create` fails: "No commits between main and feature"). **Mitigation: put
  `git checkout <branch>` in the SAME Bash call as `git add`/`commit`/`push`.** Recovery if it already
  happened (no `reset --hard` needed): `git branch -f <feature> <commit-sha>; git checkout <feature>;
  git branch -f main origin/main; git push origin <feature>`. (`origin/main` is never pushed by the
  mistake, so the remote stays safe.)
- **Stale `.cursorrules`** (untracked, root) — written during M2.2b ("don't start M2.2c yet"). Refresh
  it (it can mostly point at `CLAUDE.md` + this doc) or `.gitignore` it.
- **Local Postgres** stays up after integration runs: `docker compose down` (add `-v` to wipe volume).
- **`LANGSMITH_API_KEY` repo secret is already configured** — M2.3's LangSmith part can use it.
- **Scoped mypy overrides** exist only for LangGraph's overloaded generics (`atlas.orchestration.graph`,
  `tests.*`). Don't broaden them to hide real type errors.
- **Python 3.13** (3.14 deferred). Use `uv`, not bare `pip`.

---

## 5. NEXT — M2.3: real evaluation gate (ready to execute)

**Goal:** turn the dormant `agent-eval` job into a *real* gate that **blocks** on security-behavior
regressions, and **uses LangSmith** for quality telemetry. Today `evals/run_evals.py` is a no-op
(skips without the key, no-ops with it). The TODO(M2) stubs in that file + `evals/README.md` already
describe the intended golden flows — reuse them.

**Architecture — hybrid (decided):**

```
evals/
├── deterministic/      # BLOCKING gate: hermetic security oracles (no key/network; runs on forks)
├── llm_judge/          # NON-BLOCKING quality evals via LangSmith (only when LANGSMITH_API_KEY set)
└── run_gate.py         # entrypoint: deterministic (blocking) → then llm_judge (non-blocking)
```

### 5a. `evals/deterministic/` — the blocking gate (do this first)
Hermetic, deterministic gate-correctness oracles. Each "golden trace" is **data** (input + expected
outcome). A small runner drives the real graph and asserts exact behavior, producing an aggregate
pass/fail score compared to `MIN_PASS_SCORE` (currently `0.90` in `run_evals.py`). Build the graph the
same way the tests do — fully offline, deterministic:
```python
from atlas.orchestration import build_graph
from atlas.orchestration.nodes import heuristic_plan
from atlas.orchestration.serde import atlas_serde
from atlas.knowledge import seed_demo_graph
from langgraph.checkpoint.memory import InMemorySaver
atlas = build_graph(plan_fn=heuristic_plan, knowledge=seed_demo_graph(),
                    checkpointer=InMemorySaver(serde=atlas_serde()))
```
Scenarios (each = input + principal + resume decision + expected outcome). These mirror existing
tests (`tests/test_graph_approval.py`, `test_rbac.py`, `test_knowledge_rbac.py`, `test_confidence.py`)
but are framed as scored, named golden traces the gate enforces over time:
- **approval/approve** → `__interrupt__` then `Command(resume=True)` → tool executes; audit has `EXECUTED`.
- **approval/reject** → `Command(resume=False)` → action skipped; audit has `REJECTED`; no fabricated result.
- **anti-replay** → resume with a wrong/stale `action_id` → action is **not** executed.
- **rbac/deny-before-approval** → a principal lacking `tool:send` → action `DENIED` at planning, **no** interrupt.
- **rbac/kg-idor** → `guest` query returns no `org` entity a `member` gets; responder cites only readable `Source`s.
- **read-only/auto** → `RiskTier.READ` runs with **no** interrupt; response has structured `sources` + a confidence.
- **confidence** → grounded vs ungrounded scores differ (`GROUNDED_ANSWER` > `UNGROUNDED_ANSWER`).

A failed oracle (e.g. a gated action auto-executes, or `guest` sees an `org` entity) drops the score
below `MIN_PASS_SCORE` → **`exit 1` → blocks merge**. This is a *correctness oracle for a security
control*, not a vibes score.

### 5b. `evals/llm_judge/` — optional, non-blocking quality
Runs **only when `LANGSMITH_API_KEY` is set**. Uses `langsmith` + an LLM judge to score softer
qualities on the read-only flow (source faithfulness, confidence calibration), uploads/refreshes the
datasets (`atlas-approval-gate`, `atlas-readonly-search`), and logs traces for dashboards. **Never
blocks** the gate (telemetry, not a security control) — a LangSmith outage must not fail a correct PR.
> Before coding this, **verify the current `langsmith.evaluation.evaluate` / `Client` API via Context7**
> (the SDK moves). Never print/log the key.

### 5c. `evals/run_gate.py` — entrypoint
1. Run the deterministic suite. If score `< MIN_PASS_SCORE` → print a clear (secret-free) failure → `exit 1`.
2. If `LANGSMITH_API_KEY` present → run `llm_judge` (best-effort, non-blocking; swallow/telemetry-log
   its errors, never change the exit code).
3. Replace `run_evals.py` as the entrypoint (keep a thin shim, or update CI to call `run_gate.py`).

### 5d. CI + branch protection
- `.github/workflows/ci.yml`: the deterministic gate no longer needs the key, so **run it broadly**
  (all PRs, not just PR→main); keep the `llm_judge` step keyed on the secret; keep `ANTHROPIC_API_KEY`
  available for the judge. Update the `agent-eval` job's command to `run_gate.py`.
- **Make the gate a required status check** on `main` (GitHub branch protection / ruleset) — a
  repo-settings action for the owner once the gate is real.

### 5e. Verify
- `uv run python evals/run_gate.py` → `exit 0` on healthy `main`.
- Temporarily break a gate (e.g. delete the executor's RBAC re-check or the approval check) →
  `exit 1`. Restore.
- With the key set, `llm_judge` runs + logs to LangSmith without affecting the exit code.
- Full local gate green; **Corridor `analyzePlan` before + after**.

---

## 6. Future phases (M3+)

Each is a separate milestone; keep the sub-phase discipline (small PRs, green CI, Corridor both ends).

- **M3.1 — Concrete Knowledge Graph backend.** ✅ **DONE (this PR).** `PostgresKnowledgeGraph`
  (`src/atlas/persistence/knowledge_store.py`) implements `KnowledgeGraph` behind the existing
  interface (`src/atlas/knowledge/interfaces.py`) — no orchestration changes. Durable **Postgres
  full-text search** (tsvector + ILIKE substring fallback; **no vectors yet**); the RBAC filter is
  pushed **into the SQL `WHERE`** (unreadable rows never fetched) and re-checked via `can_read`
  (defense-in-depth, backend parity). Permission set derived from `get_effective_permissions`.
  Wired by `make_knowledge_graph` (Postgres when `DATABASE_URL` set, never auto-seeds). Integration
  tests in `tests/test_knowledge_postgres.py` (`-m integration`); demo `scripts/demo_knowledge_postgres.py`.
  **Still open:** fail-closed default `Entity.acl` — deferred to when an *untrusted* (API/network)
  `upsert_entity` write path exists in M3.2; today `acl=()` = world-readable is safe because the only
  writers are trusted (seeds/demos). **Future:** swap full-text for pgvector semantic retrieval.
- **M3.2 — FastAPI Interface layer.** ✅ **DONE (this PR).** `src/atlas/interface/` exposes `/chat`,
  `/approve` (→ `Command(resume=…)`), `/threads/{id}`, `/healthz` over the compiled graph via
  `create_app()` (sync handlers → threadpool; demo `scripts/run_api.py`). **Security: resume-time
  principal/thread binding** — `verify_thread_owner` rejects a caller whose `user_id`+`org_id` doesn't
  match the thread's checkpointed owner → **403** (closes the resume IDOR). Interim identity is a
  **trusted-network/dev-only header shim** (`get_request_principal`, configurable header names);
  fail-closed anonymous; request validation + consistent `ErrorResponse` envelope; no internal leaks.
  **Carried to M3.3:** the header shim must be replaced by *verified* SSO/OIDC (today it trusts
  headers and must sit behind a header-validating proxy). SSE streaming deferred.
- **M3.3 — AuthN (OIDC).** ✅ **DONE (this PR).** `src/atlas/interface/auth.py` (`OidcAuthenticator`,
  `PyJWT[crypto]`) validates bearer JWTs (RS256 + JWKS; `iss`/`aud`/`exp` required; alg-pinned),
  maps claims→`Principal`, and returns 401 on missing/invalid; the header shim is now the dev-only
  fallback (`settings.oidc_enabled` selects). Hermetic tests in `tests/test_interface_auth.py`.
  **Full config + deferred-work guide: [`AUTH.md`](./AUTH.md).**
- **M3.4 — Pluggable PolicyStore.** ✅ **DONE (this PR).** `governance/policy.py` (`PolicyStore` ABC +
  `InMemoryPolicyStore`, seeded from `ROLE_PERMISSIONS`) + `persistence/policy_store.py`
  (`PostgresPolicyStore`, `atlas_role_permissions` table). `make_policy_store` selects by
  `DATABASE_URL` and injects via `build_graph` into planner/executor/KG. **Empty Postgres table =
  deny-all** (no auto-seed; startup warning); seed/list/grant/revoke/export via
  `scripts/manage_policy.py` from `config/default_policies.json`. Tests: `tests/test_policy_store.py`
  (+ a no-legacy-fallback guard), `tests/test_policy_postgres.py`.
- **M3.5 — Hierarchical wildcard RBAC.** ✅ **DONE (this PR).** A granted `kg:read:*` satisfies a
  required `kg:read:org`; `tool:*` satisfies any `tool:...`. One matching rule —
  `governance/rbac.py:permission_satisfied` — shared by `InMemoryPolicyStore`, `PostgresPolicyStore`,
  the Postgres KG SQL read filter (`persistence/knowledge_store.py`, `LIKE`-prefix expansion of `:*`
  grants, `_like_escape`-d), and `can_read` (backend parity). Wildcards expand **only on the granted
  side**; the LLM still can never self-grant. Full guide: `M3.5_PLAN.md`. **Deferred → M3.6/M4 (in
  AUTH.md):** per-principal rate limiting, resource/argument-aware `ToolPermission`, sessions/refresh,
  provisioning, admin UI, policy versioning/caching, OAuth login flows.
- **M3.6 — Per-principal rate limiting.** ✅ **DONE (this PR).** `/chat` + `/approve` are throttled
  per principal (per client IP for the anonymous dev shim) by **Upstash** via `upstash-ratelimit`
  (`interface/rate_limit.py`: `RateLimiter` ABC + `UpstashRateLimiter`, `build_rate_limiter`,
  `rate_limit_key`, `enforce_rate_limit` dep wired on the two routes). Over budget → **429** +
  `Retry-After` through the `ErrorResponse` envelope. **Fail-open** (limiter outage / unset creds ⇒
  allow); **off** in dev/CI (no creds). Config: `ATLAS_RATE_LIMIT_*` + `UPSTASH_REDIS_REST_*`. Tests:
  `tests/test_rate_limit.py` (hermetic via an injected stub limiter; real Upstash gated on
  `-m integration` + env creds). See `AUTH.md`. **Deferred → M4:** per-route tiers, anti-brute-force
  IP limiting on 401s.
- **M4 — Real tool integrations** (Gmail / Slack / Jira / Calendar). Swap mock tools for real adapters
  behind `BaseTool`; per-integration OAuth + secret management; correct per-tool `risk_tier` +
  `required_permission`; **idempotency** for sends (avoid double-send on retry); sandboxing; webhook
  ingestion. Treat all tool output as adversarial.
- **Cross-cutting hardening.** Merkle / external anchoring of the audit chain; a richer
  `ToolPermission`/ACL model (replace the placeholder strings); LangSmith observability dashboards;
  multi-tenancy; PII / data-retention / DSAR; perf + load; secret rotation.

## 7. Open security items (tracked — address when the phase lands)

These came out of the `/security-review` passes as *out-of-scope-for-now*; they become real when their
enabling phase arrives:
1. **Resume-time principal/thread binding** → ✅ **DONE in M3.2** (`verify_thread_owner`).
2. **Verified identity (replace the trusted-network header shim)** → ✅ **DONE in M3.3** (OIDC bearer
   auth; `interface/auth.py`). The header shim remains a dev-only fallback — real deployments set
   `ATLAS_OIDC_*` (see `AUTH.md`).
3. **Fail-closed default `Entity.acl`** → **M3.3+** (still no *untrusted* `upsert_entity` write path —
   M3.2 added no KG write endpoint; revisit when an API write path lands).
3. **Richer `ToolPermission`/ACL model** (resource/argument-aware) → M4 (M3.5 added hierarchical
   `:*` wildcard matching on plain strings; structured permissions are still a placeholder).
4. **Merkle / external anchoring** of the hash-chained audit → cross-cutting hardening.

## 8. Key file index

See `CLAUDE.md` §4 for the full codebase map. Fast pointers: orchestration = `src/atlas/orchestration/`
(`graph.py` wiring, `nodes.py` behavior, `state.py`, `serde.py`); governance = `src/atlas/governance/`
(`audit.py`, `rbac.py`, `confidence.py`); knowledge = `src/atlas/knowledge/`; persistence =
`src/atlas/persistence/audit_store.py`; eval = `evals/`; CI = `.github/workflows/ci.yml`.
