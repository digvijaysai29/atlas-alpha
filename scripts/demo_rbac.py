"""Demo of RBAC enforcement (deny-early, before the approval gate).

Runs the same "send an email" request as two different principals:
  - a `member` (has "tool:send")  -> reaches the human approval gate.
  - `anonymous()` (no roles)       -> denied at planning, never surfaced for approval, audited DENIED.

Offline (no API key / network).  Run:  uv run python scripts/demo_rbac.py
"""

from __future__ import annotations

from typing import Any

from langgraph.checkpoint.memory import InMemorySaver

from atlas.governance import AuditLog
from atlas.governance.rbac import Principal
from atlas.orchestration import build_graph
from atlas.orchestration.nodes import heuristic_plan
from atlas.orchestration.serde import atlas_serde
from atlas.orchestration.state import initial_state


def _print_audit(audit: AuditLog) -> None:
    for event in audit.events():
        print(
            f"     {event.event_type.value:<9} {event.action_id}  {event.tool or ''}  actor={event.actor}"
        )


def _run(label: str, principal: Principal, thread_id: str) -> None:
    print(f"\n{'=' * 72}\n{label}  (roles={principal.roles or '()'})\n{'=' * 72}")
    atlas = build_graph(plan_fn=heuristic_plan, checkpointer=InMemorySaver(serde=atlas_serde()))
    config: dict[str, Any] = {"configurable": {"thread_id": thread_id}}
    result = atlas.graph.invoke(
        initial_state("Please email alice@example.com the status update", principal=principal),
        config=config,
    )
    if "__interrupt__" in result:
        pending = result["__interrupt__"][0].value["pending_actions"][0]["tool"]
        print(f"  ⏸  reached APPROVAL gate for: {pending}")
    else:
        print("  ⛔ no approval requested — the action was denied or not proposed")
    _print_audit(atlas.audit)


def main() -> None:
    _run(
        "Principal WITH tool:send (member)",
        Principal(user_id="alice", roles=("member",)),
        "rbac-ok",
    )
    _run("Principal WITHOUT tool:send (anonymous)", Principal.anonymous(), "rbac-deny")


if __name__ == "__main__":
    main()
