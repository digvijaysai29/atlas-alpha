"""PolicyStore unit tests (offline).

Covers in-memory parity with the legacy ``ROLE_PERMISSIONS`` behavior, the pure ``expand_roles``
helper, that ``config/default_policies.json`` matches the built-in defaults, and — critically — that
the orchestration graph honors the *injected* policy rather than silently falling back to the global
``ROLE_PERMISSIONS`` (a policy-bypass guard).
"""

from __future__ import annotations

import json
from pathlib import Path

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import InMemorySaver

from atlas.actions import ProposedAction
from atlas.governance import (
    ROLE_PERMISSIONS,
    InMemoryPolicyStore,
    Principal,
    expand_roles,
    permission_satisfied,
)
from atlas.knowledge import seed_demo_graph
from atlas.orchestration import build_graph, initial_state
from atlas.orchestration.serde import atlas_serde
from atlas.tools import ToolRegistry

MEMBER = Principal(user_id="alice", roles=("member",))
GUEST = Principal(user_id="bob", roles=("guest",))
ADMIN = Principal(user_id="root", roles=("admin",))


# --- expand_roles (the shared source of truth) -------------------------------
def test_expand_roles_unions_known_roles() -> None:
    assert expand_roles(("guest",), ROLE_PERMISSIONS) == frozenset({"kg:read:personal"})


def test_expand_roles_wildcard_short_circuits() -> None:
    assert expand_roles(("admin", "member"), ROLE_PERMISSIONS) == frozenset({"*"})


def test_expand_roles_unknown_role_grants_nothing() -> None:
    assert expand_roles(("wizard",), ROLE_PERMISSIONS) == frozenset()


# --- permission_satisfied (the shared wildcard matching rule, M3.5) ----------
def test_permission_satisfied_exact_match() -> None:
    assert permission_satisfied(frozenset({"kg:read:org"}), "kg:read:org") is True


def test_permission_satisfied_global_admin_wildcard() -> None:
    assert permission_satisfied(frozenset({"*"}), "anything:at:all") is True


def test_permission_satisfied_hierarchical_prefix_wildcard() -> None:
    assert permission_satisfied(frozenset({"kg:read:*"}), "kg:read:org") is True
    assert permission_satisfied(frozenset({"kg:read:*"}), "kg:read:personal") is True
    assert permission_satisfied(frozenset({"tool:*"}), "tool:send") is True
    assert permission_satisfied(frozenset({"kg:*"}), "kg:read:org") is True


def test_permission_satisfied_non_matches() -> None:
    # A bare segment (no trailing ":*") does NOT cover a deeper leaf — no silent hierarchy.
    assert permission_satisfied(frozenset({"kg:read"}), "kg:read:org") is False
    # A wildcard only expands within its own prefix.
    assert permission_satisfied(frozenset({"kg:read:*"}), "kg:write:secret") is False
    assert permission_satisfied(frozenset({"tool:*"}), "kg:read:org") is False
    # Empty grant set denies everything (fail-closed).
    assert permission_satisfied(frozenset(), "kg:read:org") is False


def test_in_memory_store_honors_wildcard_grant() -> None:
    store = InMemoryPolicyStore({"member": frozenset({"kg:read:*"})})
    assert store.can(MEMBER, "kg:read:org") is True
    assert store.can(MEMBER, "kg:read:personal") is True
    assert store.can(MEMBER, "kg:write:org") is False  # wildcard does not leak across prefixes
    assert store.can(MEMBER, "tool:send") is False


# --- InMemoryPolicyStore parity with the legacy behavior ---------------------
def test_in_memory_store_effective_permissions() -> None:
    store = InMemoryPolicyStore()
    assert store.effective_permissions(MEMBER) == ROLE_PERMISSIONS["member"]
    assert store.effective_permissions(GUEST) == frozenset({"kg:read:personal"})
    assert store.effective_permissions(ADMIN) == frozenset({"*"})
    assert store.effective_permissions(None) == frozenset()


def test_in_memory_store_can() -> None:
    store = InMemoryPolicyStore()
    assert store.can(MEMBER, "tool:send") is True
    assert store.can(GUEST, "tool:send") is False
    assert store.can(ADMIN, "anything:at:all") is True  # wildcard
    assert store.can(GUEST, None) is True  # no permission required


def test_in_memory_store_accepts_a_custom_mapping() -> None:
    store = InMemoryPolicyStore({"agent": frozenset({"tool:send"})})
    assert store.can(Principal(user_id="x", roles=("agent",)), "tool:send") is True
    assert store.can(MEMBER, "tool:send") is False  # "member" not in this custom mapping


# --- default_policies.json must match the built-in defaults (no drift) -------
def test_default_policies_json_matches_role_permissions() -> None:
    raw = json.loads(Path("config/default_policies.json").read_text(encoding="utf-8"))
    from_json = {role: frozenset(perms) for role, perms in raw.items()}
    assert from_json == dict(ROLE_PERMISSIONS)


# --- the graph honors the INJECTED store (no legacy ROLE_PERMISSIONS fallback) ----
def _send_plan(_req: str, registry: ToolRegistry, _ctx: object) -> list[ProposedAction]:
    return [registry.propose("send_email", {"to": "a@b.com", "subject": "hi", "body": "x"})]


def _run(policy: InMemoryPolicyStore, principal: Principal, thread_id: str) -> dict[str, object]:
    atlas = build_graph(
        plan_fn=_send_plan, policy=policy, checkpointer=InMemorySaver(serde=atlas_serde())
    )
    config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
    return atlas.graph.invoke(initial_state("email a@b.com", principal=principal), config=config)


def test_injected_policy_can_deny_an_otherwise_allowed_action() -> None:
    # A policy that grants `member` nothing must deny send — proving the injected store governs,
    # not the global ROLE_PERMISSIONS (which would allow it).
    result = _run(InMemoryPolicyStore({"member": frozenset()}), MEMBER, "deny")
    assert "__interrupt__" not in result  # denied-early; never reaches the approval gate
    assert result.get("action_results") == []


def test_injected_policy_can_allow_a_custom_role() -> None:
    # A role unknown to the defaults ("agent") is allowed by the injected store → reaches approval.
    result = _run(
        InMemoryPolicyStore({"agent": frozenset({"tool:send"})}),
        Principal(user_id="z", roles=("agent",)),
        "allow",
    )
    assert "__interrupt__" in result  # authorized → paused at the approval gate


def _search_plan(_request: str, registry: ToolRegistry, _context: object) -> list[ProposedAction]:
    return [registry.propose("search", {"query": "x"})]


def test_injected_policy_scopes_kg_context_on_prebuilt_graph() -> None:
    # member has tool:send but NOT kg:read:org — without bind_policy, KG would use DEFAULT_POLICY
    # and incorrectly include doc-1 in kg_context.
    custom = InMemoryPolicyStore({"member": frozenset({"tool:send"})})
    atlas = build_graph(
        plan_fn=_search_plan,
        knowledge=seed_demo_graph(),
        policy=custom,
        checkpointer=InMemorySaver(serde=atlas_serde()),
    )
    config: RunnableConfig = {"configurable": {"thread_id": "kg-policy-bind"}}
    result = atlas.graph.invoke(
        initial_state("find the revenue and onboarding", principal=MEMBER), config=config
    )
    kg_ids = {e.id for e in result["kg_context"]}
    assert "doc-1" not in kg_ids
    assert "note-1" not in kg_ids
