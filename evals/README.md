# Evaluation Gate (M2.3)

The atlas **agent-eval gate** — a hybrid evaluation that protects security-critical agent behavior.
It is run by the `agent-eval` job in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) via
`evals/run_gate.py`.

## Architecture

```
evals/
├── deterministic/      # BLOCKING gate: hermetic security oracles (no key/network; runs on forks)
│   ├── scenarios.py    #   golden-trace inputs as data (principals + scripted planners)
│   └── oracles.py      #   one correctness oracle per trace + run_suite() aggregator
├── llm_judge/          # NON-BLOCKING quality evals via LangSmith (only when LANGSMITH_API_KEY set)
│   ├── datasets.py     #   idempotent dataset upload/refresh
│   └── judge.py        #   evaluate() with confidence-calibration + LLM source-faithfulness
├── run_gate.py         # entrypoint: deterministic (blocking) → then llm_judge (non-blocking)
└── run_evals.py        # thin back-compat shim → run_gate.main()
```

## 1. Deterministic suite — the blocking gate

A **correctness oracle for security controls**, not a fuzzy quality score. Each golden trace is
*data* (input + principal + resume decision + expected outcome); a small runner drives the **real**
compiled graph fully offline (scripted planner + `InMemorySaver` with the `atlas_serde()` allowlist
+ `InMemoryAuditLog`) and asserts exact behavior. The aggregate pass ratio is compared against
`MIN_PASS_SCORE` (`0.90` in `run_gate.py`); below it, the gate exits non-zero and **blocks the
merge**. A crashing oracle counts as a failure (fail-closed).

Golden traces (mirroring the unit tests, but enforced as scored, named regressions):

| Trace | Asserts |
|---|---|
| `approval/approve` | gated action pauses, then `resume=True` → tool executes; audit has `EXECUTED` |
| `approval/reject` | `resume=False` → action skipped; audit has `REJECTED`; no fabricated result |
| `anti-replay` | resume with a wrong/stale `action_id` → action is **not** executed |
| `rbac/deny-before-approval` | a principal lacking `tool:send` → `DENIED` at planning, **no** interrupt |
| `rbac/kg-idor` | a `guest` never sees an `org` entity a `member` gets; sources cite only readable entities |
| `read-only/auto` | `RiskTier.READ` runs with **no** interrupt; response has `sources` + a confidence |
| `confidence` | a grounded answer scores strictly higher than an ungrounded one |

A failed oracle (e.g. a gated action auto-executes, or `guest` sees an `org` entity) drops the score
below `MIN_PASS_SCORE` → `exit 1`.

## 2. LLM-judge — optional, non-blocking quality

Runs **only when `LANGSMITH_API_KEY` is set**, and **never** changes the exit code (telemetry, not a
security control — a LangSmith/Anthropic outage must not fail a correct PR). It idempotently ensures
the `atlas-readonly-search` and `atlas-approval-gate` datasets exist, runs the real graph as the
`evaluate(...)` target, and scores the read-only flow with a deterministic confidence-calibration
evaluator plus an LLM **source-faithfulness** judge (the latter self-skips without an
`ANTHROPIC_API_KEY`). No secret is ever read, printed, or logged by this code; on error it logs only
the exception *type*.

## Running locally

```bash
# Blocking deterministic gate only (no key): runs the 7 oracles, exits 0 when green.
uv run python evals/run_gate.py

# With LANGSMITH_API_KEY (+ optional ANTHROPIC_API_KEY) set: also runs the non-blocking quality evals.
LANGSMITH_API_KEY=... uv run python evals/run_gate.py
```

## CI + branch protection

The `agent-eval` job runs `run_gate.py` on every push/PR (the deterministic gate is hermetic, so it
no longer needs to be gated to PRs into `main`). To enforce it, make **`agent-eval`** a required
status check on `main` via GitHub branch protection / rulesets (a repo-settings action for the
owner). The job never echoes the value of any secret.
