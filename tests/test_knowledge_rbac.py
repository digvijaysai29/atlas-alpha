"""Knowledge-graph RBAC scoping — the IDOR / privilege-escalation guard at the retrieval layer.

The key property: an org-restricted entity is never returned to (and never reaches the planner/LLM
for) a principal that lacks `kg:read:org`. Also covers the planner attaching an RBAC-filtered
`kg_context` to state and that `Entity` survives checkpoint resume.
"""

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from atlas.actions import ProposedAction
from atlas.governance.rbac import Principal
from atlas.knowledge import seed_demo_graph
from atlas.knowledge.interfaces import Entity, can_read
from atlas.orchestration import build_graph
from atlas.orchestration.graph import Atlas
from atlas.orchestration.serde import atlas_serde
from atlas.orchestration.state import initial_state
from atlas.tools import ToolRegistry

MEMBER = Principal(user_id="alice", roles=("member",))  # has kg:read:org + kg:read:personal
GUEST = Principal(user_id="bob", roles=("guest",))  # has only kg:read:personal


def _search_plan(_request: str, registry: ToolRegistry, _context: object) -> list[ProposedAction]:
    return [registry.propose("search", {"query": "x"})]


def _fresh() -> Atlas:
    return build_graph(
        plan_fn=_search_plan,
        knowledge=seed_demo_graph(),
        checkpointer=InMemorySaver(serde=atlas_serde()),
    )


# --- KG-layer RBAC -----------------------------------------------------------
def test_can_read_world_readable_when_no_acl() -> None:
    assert can_read(GUEST, Entity(id="x", type="note", name="n", acl=())) is True


def test_org_entity_hidden_from_guest_visible_to_member() -> None:
    graph = seed_demo_graph()
    member_ids = {e.id for e in graph.query(MEMBER, "revenue onboarding")}
    guest_ids = {e.id for e in graph.query(GUEST, "revenue onboarding")}
    assert "doc-1" in member_ids  # org doc visible to member
    assert "doc-1" not in guest_ids  # IDOR guard: org doc hidden from guest
    assert "note-1" in guest_ids  # personal note still visible to guest


def test_query_keyword_match_is_scoped_to_terms() -> None:
    graph = seed_demo_graph()
    assert {e.id for e in graph.query(MEMBER, "revenue")} == {"doc-1"}


def test_query_respects_limit() -> None:
    graph = seed_demo_graph()
    assert len(graph.query(MEMBER, "", limit=1)) == 1


# --- planner wiring (RBAC-filtered kg_context flows into state) ---------------
def test_planner_attaches_full_context_for_member() -> None:
    atlas = _fresh()
    config: RunnableConfig = {"configurable": {"thread_id": "kg-member"}}
    result = atlas.graph.invoke(
        initial_state("find the revenue and onboarding", principal=MEMBER), config=config
    )
    assert {e.id for e in result["kg_context"]} == {"doc-1", "note-1"}
    assert "kg:doc-1" in result["sources"]


def test_planner_context_is_rbac_scoped_for_guest() -> None:
    atlas = _fresh()
    config: RunnableConfig = {"configurable": {"thread_id": "kg-guest"}}
    result = atlas.graph.invoke(
        initial_state("find the revenue and onboarding", principal=GUEST), config=config
    )
    assert {e.id for e in result["kg_context"]} == {"note-1"}  # org doc never retrieved
    assert "kg:doc-1" not in result["sources"]


# --- checkpoint resume preserves Entities ------------------------------------
def _send_plan(_request: str, registry: ToolRegistry, _context: object) -> list[ProposedAction]:
    return [registry.propose("send_email", {"to": "a@b.com"})]


def test_kg_context_entities_survive_checkpoint_resume() -> None:
    atlas = build_graph(
        plan_fn=_send_plan,
        knowledge=seed_demo_graph(),
        checkpointer=InMemorySaver(serde=atlas_serde()),
    )
    config: RunnableConfig = {"configurable": {"thread_id": "kg-resume"}}
    atlas.graph.invoke(initial_state("email the revenue numbers", principal=MEMBER), config=config)

    snapshot = atlas.graph.get_state(config)
    kg = snapshot.values["kg_context"]
    assert kg and all(isinstance(e, Entity) for e in kg)  # Entities survived (de)serialization

    final = atlas.graph.invoke(Command(resume=True), config=config)
    assert {e.id for e in final["kg_context"]}  # still present after resume
