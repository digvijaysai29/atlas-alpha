"""End-to-end HITL approval behavior — the core security guarantee of atlas.

Uses a scripted planner + an in-memory checkpointer for determinism (no API key, no network).
Covers: gated action pauses → approve executes it; gated action pauses → reject skips it; a
read-only action runs with no interrupt at all.
"""

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from atlas.actions import ProposedAction
from atlas.governance.rbac import Principal
from atlas.orchestration import build_graph
from atlas.orchestration.graph import Atlas
from atlas.orchestration.nodes import PlanFn
from atlas.orchestration.serde import atlas_serde
from atlas.orchestration.state import initial_state
from atlas.tools import ToolRegistry

THREAD = {"configurable": {"thread_id": "test"}}
# A principal permitted to use send_email ("tool:send"), so these tests exercise the APPROVAL gate
# rather than the RBAC gate (RBAC denial is covered in test_rbac.py).
SENDER = Principal(user_id="alice", roles=("member",))


def _send_plan(_request: str, registry: ToolRegistry, _context: object) -> list[ProposedAction]:
    return [registry.propose("send_email", {"to": "a@b.com", "subject": "hi", "body": "x"})]


def _search_plan(_request: str, registry: ToolRegistry, _context: object) -> list[ProposedAction]:
    return [registry.propose("search", {"query": "quarterly numbers"})]


def _fresh(plan_fn: PlanFn) -> Atlas:
    return build_graph(plan_fn=plan_fn, checkpointer=InMemorySaver(serde=atlas_serde()))


def test_gated_action_pauses_for_approval() -> None:
    atlas = _fresh(_send_plan)
    result = atlas.graph.invoke(initial_state("email a@b.com", principal=SENDER), config=THREAD)
    assert "__interrupt__" in result  # the graph paused at the approval gate
    # Nothing has executed yet.
    assert not result.get("action_results")


def test_approve_executes_the_action() -> None:
    atlas = _fresh(_send_plan)
    atlas.graph.invoke(initial_state("email a@b.com", principal=SENDER), config=THREAD)
    final = atlas.graph.invoke(Command(resume=True), config=THREAD)

    results = final["action_results"]
    assert len(results) == 1
    assert results[0].ok is True
    assert results[0].tool == "send_email"

    event_types = [event.event_type.value for event in atlas.audit.events()]
    assert event_types.count("proposed") == 1
    assert "approved" in event_types
    assert "executed" in event_types


def test_reject_skips_the_action() -> None:
    atlas = _fresh(_send_plan)
    atlas.graph.invoke(initial_state("email a@b.com", principal=SENDER), config=THREAD)
    final = atlas.graph.invoke(Command(resume=False), config=THREAD)

    assert final["action_results"] == []  # the send never happened
    event_types = [event.event_type.value for event in atlas.audit.events()]
    assert "rejected" in event_types
    assert "executed" not in event_types
    assert "skipped" in event_types


def test_read_only_action_runs_without_any_interrupt() -> None:
    atlas = _fresh(_search_plan)
    result = atlas.graph.invoke(initial_state("find the quarterly numbers"), config=THREAD)

    assert "__interrupt__" not in result
    results = result["action_results"]
    assert len(results) == 1 and results[0].ok is True
    assert result["sources"]  # provenance was captured


def test_approval_is_bound_to_action_id_unknown_ids_ignored() -> None:
    # Resuming with a decision for a different action id must NOT authorize the real action.
    atlas = _fresh(_send_plan)
    atlas.graph.invoke(initial_state("email a@b.com", principal=SENDER), config=THREAD)
    final = atlas.graph.invoke(
        Command(resume=[{"action_id": "act_not_a_real_id", "approved": True}]),
        config=THREAD,
    )
    assert final["action_results"] == []  # stale/foreign approval did nothing
