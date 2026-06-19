"""End-to-end demo of the human-in-the-loop approval gate.

Runs three scenarios against the orchestration graph using the offline heuristic planner, so it
works with no API key and no network:

  1. A *send* (gated) request → graph pauses → we APPROVE → the action executes.
  2. A *send* (gated) request → graph pauses → we REJECT → the action is skipped.
  3. A *read* (auto) request → runs straight through with no interrupt.

Run:  uv run python scripts/demo_approval.py
"""

from __future__ import annotations

from typing import Any

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from atlas.governance import AuditLog
from atlas.governance.rbac import Principal
from atlas.orchestration import build_graph
from atlas.orchestration.nodes import heuristic_plan
from atlas.orchestration.serde import atlas_serde
from atlas.orchestration.state import initial_state

# A logged-in user permitted to send email ("tool:send" via the "member" role).
ALICE = Principal(user_id="alice", roles=("member",))


def _rule(title: str) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def _print_interrupt(result: dict[str, Any]) -> None:
    interrupts = result.get("__interrupt__")
    if not interrupts:
        print("  (no interrupt — nothing required approval)")
        return
    payload = interrupts[0].value
    print(f"  ⏸  PAUSED — {payload['question']}")
    for action in payload["pending_actions"]:
        print(f"     • {action['tool']} [{action['risk_tier']}]  args={action['args']}")


def _print_outcome(state: dict[str, Any]) -> None:
    for result in state.get("action_results", []):
        status = "✅ executed" if result.ok else f"❌ failed: {result.error}"
        print(f"  {status}: {result.tool} -> {result.output if result.ok else ''}")
    if not state.get("action_results"):
        print("  (no actions executed)")
    sources = [f"{s.kind}:{s.ref}" for s in state.get("sources") or []]
    print(f"  confidence={state.get('confidence')}  sources={sources}")


def _print_audit(audit: AuditLog) -> None:
    print("  audit trail:")
    for event in audit.events():
        print(f"     {event.event_type.value:<9} {event.action_id}  {event.tool or ''}")


def _new_thread(n: int) -> dict[str, Any]:
    return {"configurable": {"thread_id": f"demo-{n}"}}


def main() -> None:
    # Scenario 1 — gated action, APPROVED.
    _rule("Scenario 1: send email (gated) → APPROVE")
    atlas = build_graph(plan_fn=heuristic_plan, checkpointer=InMemorySaver(serde=atlas_serde()))
    config = _new_thread(1)
    paused = atlas.graph.invoke(
        initial_state("Please email alice@example.com the status update", principal=ALICE),
        config=config,
    )
    _print_interrupt(paused)
    print("  → human approves")
    final = atlas.graph.invoke(Command(resume=True), config=config)
    _print_outcome(final)
    _print_audit(atlas.audit)

    # Scenario 2 — gated action, REJECTED.
    _rule("Scenario 2: send email (gated) → REJECT")
    atlas = build_graph(plan_fn=heuristic_plan, checkpointer=InMemorySaver(serde=atlas_serde()))
    config = _new_thread(2)
    paused = atlas.graph.invoke(
        initial_state("Email bob@example.com to cancel the contract", principal=ALICE),
        config=config,
    )
    _print_interrupt(paused)
    print("  → human rejects")
    final = atlas.graph.invoke(Command(resume=False), config=config)
    _print_outcome(final)
    _print_audit(atlas.audit)

    # Scenario 3 — read-only action, no approval needed.
    _rule("Scenario 3: search (read-only) → runs automatically")
    atlas = build_graph(plan_fn=heuristic_plan, checkpointer=InMemorySaver(serde=atlas_serde()))
    config = _new_thread(3)
    final = atlas.graph.invoke(initial_state("Find the latest revenue figures"), config=config)
    _print_interrupt(final)
    _print_outcome(final)
    _print_audit(atlas.audit)


if __name__ == "__main__":
    main()
