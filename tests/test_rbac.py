"""RBAC: the default-deny policy and the deny-early / re-check-late enforcement.

These are the privilege-escalation / IDOR guards. The key end-to-end property: an unauthorized
principal's permissioned tool is denied *before* it is ever surfaced for human approval, and the
denial is audited.
"""

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from atlas.actions import ProposedAction
from atlas.governance.rbac import (
    Principal,
    can,
    expand_roles,
    get_current_principal,
    get_effective_permissions,
    permission_satisfied,
)
from atlas.orchestration import build_graph
from atlas.orchestration.graph import Atlas
from atlas.orchestration.nodes import PlanFn
from atlas.orchestration.serde import atlas_serde
from atlas.orchestration.state import initial_state
from atlas.tools import ToolRegistry
from tests.helpers import offline_registry

THREAD: RunnableConfig = {"configurable": {"thread_id": "rbac-test"}}
# has tool:send:* + tool:slack:post:* (M4.8c: resource-scoped wildcards) + tool:calendar:write
MEMBER = Principal(user_id="alice", roles=("member",))
GUEST = Principal(user_id="bob", roles=("guest",))  # no tool:send / tool:slack:post


def _send_plan(_request: str, registry: ToolRegistry, _context: object) -> list[ProposedAction]:
    return [registry.propose("send_email", {"to": "a@b.com", "subject": "hi", "body": "x"})]


def _fresh(plan_fn: PlanFn) -> Atlas:
    return build_graph(
        plan_fn=plan_fn,
        registry=offline_registry(),
        checkpointer=InMemorySaver(serde=atlas_serde()),
    )


# --- policy unit tests ------------------------------------------------------
def test_no_permission_required_is_always_allowed() -> None:
    assert can(Principal.anonymous(), None) is True


def test_default_deny_for_anonymous_and_guest() -> None:
    assert can(Principal.anonymous(), "tool:send") is False
    assert can(GUEST, "tool:send") is False


def test_role_grant_allows() -> None:
    assert can(MEMBER, "tool:calendar:write") is True


def test_wildcard_grant_satisfies_resource_scoped_permission() -> None:
    """M4.8c: a member's tool:send:* / tool:slack:post:* wildcard covers any resource segment."""
    assert can(MEMBER, "tool:send:domain:example.com") is True
    assert can(MEMBER, "tool:slack:post:channel:general") is True


def test_wildcard_grant_does_not_satisfy_bare_unscoped_string() -> None:
    """A granted "tool:send:*" does not cover the bare "tool:send" itself (no partial-prefix
    collapse — only the explicit ":*" suffix expands, and it always requires at least one more
    segment after the colon, per permission_satisfied's documented contract)."""
    assert can(MEMBER, "tool:send") is False


def test_narrowed_grant_restricts_to_one_domain() -> None:
    """M4.8c real-world example: an operator can grant a single recipient domain instead of the
    default wildcard, e.g. to stop a role from emailing outside the company — a genuine
    data-exfiltration control, not just a demo of the string format."""
    restricted = {"member": frozenset({"tool:gmail:send:domain:company.com"})}
    granted = expand_roles(("member",), restricted)
    assert permission_satisfied(granted, "tool:gmail:send:domain:company.com") is True
    assert permission_satisfied(granted, "tool:gmail:send:domain:evil.example") is False


def test_admin_wildcard_grants_everything() -> None:
    admin = Principal(user_id="root", roles=("admin",))
    assert can(admin, "tool:send") is True
    assert can(admin, "some:unlisted:permission") is True


def test_unknown_role_grants_nothing() -> None:
    assert can(Principal(user_id="x", roles=("wizard",)), "tool:send") is False


def test_get_current_principal_defaults_to_anonymous() -> None:
    assert get_current_principal({}).user_id == "anonymous"


# --- effective-permission expansion (the source of truth reused by the KG store) -------------
def test_effective_permissions_none_principal_is_empty() -> None:
    assert get_effective_permissions(None) == frozenset()
    assert get_effective_permissions(Principal.anonymous()) == frozenset()


def test_effective_permissions_expands_role_grants() -> None:
    assert get_effective_permissions(MEMBER) == frozenset(
        {
            "tool:send:*",
            "tool:slack:post:*",
            "tool:gmail:send:*",
            "tool:calendar:write",
            "tool:slack:post_as_user",
            "tool:slack:delete_message",
            "kg:read:org",
            "kg:read:personal",
        }
    )
    assert get_effective_permissions(GUEST) == frozenset({"kg:read:personal"})


def test_effective_permissions_admin_collapses_to_wildcard() -> None:
    admin = Principal(user_id="root", roles=("admin",))
    assert get_effective_permissions(admin) == frozenset({"*"})


def test_effective_permissions_unknown_role_contributes_nothing() -> None:
    assert get_effective_permissions(Principal(user_id="x", roles=("wizard",))) == frozenset()


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


def _legacy_executor_state(registry: ToolRegistry) -> tuple[ProposedAction, dict[str, object]]:
    """An approved send_email action whose ``required_permission`` deserialized to ``None`` —
    exactly what a checkpoint written before M4.8c looks like after resume."""
    stamped = registry.propose("send_email", {"to": "a@b.com", "subject": "hi", "body": "x"})
    legacy = stamped.model_copy(update={"required_permission": None})
    state = {
        "principal": MEMBER,
        "proposed_actions": [legacy],
        "approved_action_ids": [legacy.action_id],
    }
    return legacy, state


def test_executor_rederives_permission_for_pre_m48c_actions() -> None:
    """A policy tightened while a thread was paused at approval must still apply on resume: the
    executor may not treat a legacy action's ``required_permission=None`` as "nothing required"."""
    from typing import cast

    from atlas.governance import InMemoryAuditLog, InMemoryPolicyStore
    from atlas.orchestration.nodes import make_executor_node
    from atlas.orchestration.state import AgentState

    registry = offline_registry()
    _, state = _legacy_executor_state(registry)
    audit = InMemoryAuditLog()
    # Tightened while paused: members may now only email company.com — b.com must be denied.
    tightened = InMemoryPolicyStore({"member": frozenset({"tool:send:domain:company.com"})})
    node = make_executor_node(registry, audit, tightened)

    result = node(cast(AgentState, state))

    assert result["action_results"] == []
    assert audit.events()[-1].event_type.value == "denied"


def test_executor_rederived_permission_still_allows_authorized_legacy_action() -> None:
    """The fallback must not over-deny: under the default policy the same legacy action runs."""
    from typing import cast

    from atlas.governance import InMemoryAuditLog, InMemoryPolicyStore
    from atlas.orchestration.nodes import make_executor_node
    from atlas.orchestration.state import AgentState

    registry = offline_registry()
    _, state = _legacy_executor_state(registry)
    node = make_executor_node(registry, InMemoryAuditLog(), InMemoryPolicyStore())

    result = node(cast(AgentState, state))

    assert len(result["action_results"]) == 1
    assert result["action_results"][0].ok is True


def _slack_plan(_request: str, registry: ToolRegistry, _context: object) -> list[ProposedAction]:
    return [registry.propose("slack_post", {"channel": "#general", "text": "hi"})]


def test_guest_denied_slack_before_approval() -> None:
    atlas = _fresh(_slack_plan)
    result = atlas.graph.invoke(initial_state("post to slack", principal=GUEST), config=THREAD)

    assert "__interrupt__" not in result
    assert result.get("action_results") == []
    event_types = [e.event_type.value for e in atlas.audit.events()]
    assert "denied" in event_types


def test_member_reaches_approval_for_slack_post() -> None:
    atlas = _fresh(_slack_plan)
    result = atlas.graph.invoke(initial_state("post to slack", principal=MEMBER), config=THREAD)
    assert "__interrupt__" in result
    event_types = [e.event_type.value for e in atlas.audit.events()]
    assert "denied" not in event_types


def _other_channel_plan(
    _request: str, registry: ToolRegistry, _context: object
) -> list[ProposedAction]:
    return [registry.propose("slack_post", {"channel": "#other", "text": "hi"})]


def test_channel_scoped_grant_denies_a_different_channel_before_approval() -> None:
    """M4.8c end-to-end: a role granted only "tool:slack:post:channel:general" (no wildcard) may
    post to #general but is denied — before ever reaching human approval — for any other channel."""
    from atlas.governance.policy import InMemoryPolicyStore

    narrow_policy = InMemoryPolicyStore({"member": frozenset({"tool:slack:post:channel:general"})})
    atlas = build_graph(
        plan_fn=_slack_plan,
        registry=offline_registry(),
        policy=narrow_policy,
        checkpointer=InMemorySaver(serde=atlas_serde()),
    )
    result = atlas.graph.invoke(
        initial_state("post to slack", principal=MEMBER),
        config={"configurable": {"thread_id": "t1"}},
    )
    assert "__interrupt__" in result  # #general is granted -> normal approval flow

    atlas_denied = build_graph(
        plan_fn=_other_channel_plan,
        registry=offline_registry(),
        policy=narrow_policy,
        checkpointer=InMemorySaver(serde=atlas_serde()),
    )
    denied_result = atlas_denied.graph.invoke(
        initial_state("post to slack", principal=MEMBER),
        config={"configurable": {"thread_id": "t2"}},
    )
    assert "__interrupt__" not in denied_result  # #other is not granted -> denied at planning
    assert denied_result.get("action_results") == []
    event_types = [e.event_type.value for e in atlas_denied.audit.events()]
    assert "denied" in event_types
