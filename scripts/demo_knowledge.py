"""Demo: RBAC-scoped knowledge retrieval.

The same request, run as two principals against the seeded knowledge graph (a personal note + an
org-restricted doc):
  - MEMBER (kg:read:org + kg:read:personal) → retrieves the org doc *and* the personal note.
  - GUEST  (kg:read:personal only)          → retrieves only the personal note; the org doc is
    filtered out at the retrieval layer and never reaches the planner/LLM.

Offline (no API key / network).  Run:  uv run python scripts/demo_knowledge.py
"""

from __future__ import annotations

from typing import Any

from langgraph.checkpoint.memory import InMemorySaver

from atlas.actions import ProposedAction
from atlas.governance.rbac import Principal
from atlas.knowledge import seed_demo_graph
from atlas.orchestration import build_graph
from atlas.orchestration.serde import atlas_serde
from atlas.orchestration.state import initial_state
from atlas.tools import ToolRegistry


def _search_plan(_request: str, registry: ToolRegistry, _context: object) -> list[ProposedAction]:
    return [registry.propose("search", {"query": "knowledge"})]


def _run(label: str, principal: Principal, thread_id: str) -> None:
    print(f"\n{'=' * 72}\n{label}\n{'=' * 72}")
    atlas = build_graph(
        plan_fn=_search_plan,
        knowledge=seed_demo_graph(),
        checkpointer=InMemorySaver(serde=atlas_serde()),
    )
    config: dict[str, Any] = {"configurable": {"thread_id": thread_id}}
    result = atlas.graph.invoke(
        initial_state("find revenue and onboarding info", principal=principal), config=config
    )
    print("  retrieved knowledge (RBAC-scoped):")
    for entity in result["kg_context"]:
        print(f"     • [{entity.scope:8}] {entity.id}  {entity.name}")
    print(f"  responder sources: {result['sources']}")


def main() -> None:
    _run(
        "MEMBER  (kg:read:org + kg:read:personal)",
        Principal(user_id="alice", roles=("member",)),
        "kg-member",
    )
    _run(
        "GUEST   (kg:read:personal only)",
        Principal(user_id="bob", roles=("guest",)),
        "kg-guest",
    )


if __name__ == "__main__":
    main()
