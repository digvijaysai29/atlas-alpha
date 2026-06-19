"""Durability + tamper-evidence proof (requires Postgres).

  docker compose up -d
  export DATABASE_URL=postgresql://atlas:atlas@localhost:5432/atlas
  uv run python scripts/demo_persistence.py

Shows: a gated approval pauses → the graph object is destroyed and rebuilt (simulating a process
restart) → the approval resumes from Postgres and executes → the audit chain verifies → tampering
with one row is detected.
"""

from __future__ import annotations

import os
import sys
import uuid

from langgraph.types import Command

from atlas.config import Settings
from atlas.governance.rbac import Principal
from atlas.orchestration import build_graph
from atlas.orchestration.graph import _pg_pool
from atlas.orchestration.nodes import heuristic_plan
from atlas.orchestration.state import initial_state
from atlas.persistence import PostgresAuditLog


def main() -> None:
    url = os.environ.get("DATABASE_URL")
    if not url:
        print("DATABASE_URL is not set. Start Postgres and export it, e.g.:")
        print("  docker compose up -d")
        print("  export DATABASE_URL=postgresql://atlas:atlas@localhost:5432/atlas")
        sys.exit(0)

    settings = Settings(DATABASE_URL=url, ANTHROPIC_API_KEY=None)  # type: ignore[arg-type]
    thread = {"configurable": {"thread_id": f"demo-{uuid.uuid4().hex[:8]}"}}
    pool = _pg_pool(url)

    # Clean slate so the demo is deterministic (drop any audit rows from prior runs/tests).
    with pool.connection() as conn:
        conn.execute("DROP TABLE IF EXISTS atlas_audit_log")

    try:
        print("=" * 72)
        print("1) First 'process': run until the approval gate, then crash")
        print("=" * 72)
        atlas1 = build_graph(plan_fn=heuristic_plan, settings=settings)
        sender = Principal(user_id="alice", roles=("member",))  # permitted to send email
        paused = atlas1.graph.invoke(
            initial_state("Please email alice@example.com the status update", principal=sender),
            config=thread,
        )
        interrupts = paused.get("__interrupt__")
        assert interrupts, "expected the graph to pause at the approval gate"
        print(f"  ⏸  PAUSED — pending: {interrupts[0].value['pending_actions'][0]['tool']}")
        print("  💥 destroying the graph object (state now lives only in Postgres)")
        del atlas1

        print("\n" + "=" * 72)
        print("2) Second 'process': rebuild from scratch, resume from Postgres, approve")
        print("=" * 72)
        atlas2 = build_graph(plan_fn=heuristic_plan, settings=settings)
        final = atlas2.graph.invoke(Command(resume=True), config=thread)
        result = final["action_results"][0]
        print(f"  ✅ resumed from Postgres and executed: {result.tool} -> {result.output}")

        print("\n" + "=" * 72)
        print("3) Audit chain: verify, then tamper, then re-verify")
        print("=" * 72)
        audit = PostgresAuditLog(pool, setup=False)
        print(f"  events recorded: {len(audit.events())}")
        print(f"  verify() before tampering: ok={audit.verify().ok}")
        with pool.connection() as conn:
            conn.execute("UPDATE atlas_audit_log SET actor = 'attacker' WHERE seq = 0")
        verdict = audit.verify()
        print(
            f"  verify() after tampering:  ok={verdict.ok}  "
            f"broken_at={verdict.broken_at}  ({verdict.reason})"
        )
    finally:
        pool.close()
        _pg_pool.cache_clear()


if __name__ == "__main__":
    main()
