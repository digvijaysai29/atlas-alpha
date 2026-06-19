"""RBAC: the default-deny policy and the deny-early / re-check-late enforcement.

These are the privilege-escalation / IDOR guards. The key end-to-end property: an unauthorized
principal's permissioned tool is denied *before* it is ever surfaced for human approval, and the
denial is audited.
"""

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from atlas.actions import ProposedAction
from atlas.governance.rbac import Principal, can, get_current_principal
from atlas.orchestration import build_graph
from atlas.orchestration.graph import Atlas
from atlas.orchestration.nodes import PlanFn
from atlas.orchestration.serde import atlas_serde
from atlas.orchestration.state import initial_state
from atlas.tools import ToolRegistry

THREAD: RunnableConfig = {"configurable": {"thread_id": "rbac-test"}}
MEMBER = Principal(user_id="alice", roles=("member",))  # has "tool:send"
GUEST = Principal(user_id="bob", roles=("guest",))  # no "tool:send"


def _send_plan(_request: str, registry: ToolRegistry) -> list[ProposedAction]:
    return [registry.propose("send_email", {"to": "a@b.com", "subject": "hi", "body": "x"})]


def _fresh(plan_fn: PlanFn) -> Atlas:
    return build_graph(plan_fn=plan_fn, checkpointer=InMemorySaver(serde=atlas_serde()))


# --- policy unit tests ------------------------------------------------------
def test_no_permission_required_is_always_allowed() -> None:
    assert can(Principal.anonymous(), None) is True


def test_default_deny_for_anonymous_and_guest() -> None:
    assert can(Principal.anonymous(), "tool:send") is False
    assert can(GUEST, "tool:send") is False


def test_role_grant_allows() -> None:
    assert can(MEMBER, "tool:send") is True


def test_admin_wildcard_grants_everything() -> None:
    admin = Principal(user_id="root", roles=("admin",))
    assert can(admin, "tool:send") is True
    assert can(admin, "some:unlisted:permission") is True


def test_unknown_role_grants_nothing() -> None:
    assert can(Principal(user_id="x", roles=("wizard",)), "tool:send") is False


def test_get_current_principal_defaults_to_anonymous() -> None:
    assert get_current_principal({}).user_id == "anonymous"


# --- end-to-end enforcement -------------------------------------------------
def test_unauthorized_principal_is_denied_before_approval() -> None:
    atlas = _fresh(_send_plan)
    # GUEST lacks "tool:send": the send is dropped at planning, so the graph never pauses.
    result = atlas.graph.invoke(initial_state("email a@b.com", principal=GUEST), config=THREAD)

    assert "__interrupt__" not in result  # never surfaced for approval
    assert result.get("action_results") == []
    event_types = [e.event_type.value for e in atlas.audit.events()]
    assert "proposed" in event_types
    assert "denied" in event_types
    assert "approved" not in event_types and "executed" not in event_types


def test_authorized_principal_reaches_the_approval_gate() -> None:
    atlas = _fresh(_send_plan)
    result = atlas.graph.invoke(initial_state("email a@b.com", principal=MEMBER), config=THREAD)
    assert "__interrupt__" in result  # MEMBER has tool:send -> normal approval flow
    event_types = [e.event_type.value for e in atlas.audit.events()]
    assert "denied" not in event_types


def test_principal_survives_checkpoint_resume() -> None:
    # Pause at approval, then resume — the principal must still be intact in checkpointed state.
    atlas = _fresh(_send_plan)
    atlas.graph.invoke(initial_state("email a@b.com", principal=MEMBER), config=THREAD)

    snapshot = atlas.graph.get_state(THREAD)
    assert snapshot.values["principal"] == MEMBER

    final = atlas.graph.invoke(Command(resume=True), config=THREAD)
    assert final["action_results"][0].ok is True
    assert final["principal"] == MEMBER
