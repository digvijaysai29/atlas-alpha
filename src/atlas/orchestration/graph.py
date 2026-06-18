"""Graph assembly + the checkpointer factory.

``build_graph`` wires the four nodes into a LangGraph ``StateGraph`` and compiles it with a
checkpointer (required for the approval ``interrupt``/resume to work). Dependencies — the tool
registry, audit log, planning strategy, and checkpointer — are injected so the graph is easy to test
and to reconfigure per environment.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import TYPE_CHECKING

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from atlas.config import Settings, get_settings
from atlas.governance import AuditLog, InMemoryAuditLog
from atlas.orchestration.nodes import (
    PlanFn,
    default_plan_fn,
    make_approval_node,
    make_executor_node,
    make_planner_node,
    make_responder_node,
    route_after_planner,
)
from atlas.orchestration.serde import atlas_serde
from atlas.orchestration.state import AgentState
from atlas.tools import ToolRegistry, default_registry

if TYPE_CHECKING:
    from langgraph.checkpoint.base import BaseCheckpointSaver
    from langgraph.graph.state import CompiledStateGraph


def make_checkpointer(settings: Settings | None = None) -> "BaseCheckpointSaver":
    """Return a checkpointer: SQLite if a path is configured, else in-memory.

    Postgres (``DATABASE_URL``) is wired in M2. A checkpointer is mandatory for durable interrupts.
    """
    settings = settings or get_settings()
    serde = atlas_serde()  # explicit allowlist — no arbitrary type deserialization from checkpoints
    if settings.sqlite_path:
        from langgraph.checkpoint.sqlite import SqliteSaver

        # check_same_thread=False: the saver may be used across threads in a server context.
        conn = sqlite3.connect(settings.sqlite_path, check_same_thread=False)
        return SqliteSaver(conn, serde=serde)
    return InMemorySaver(serde=serde)


@dataclass(frozen=True)
class Atlas:
    """A compiled agent plus the collaborators a caller may want to inspect."""

    graph: "CompiledStateGraph"
    audit: AuditLog
    registry: ToolRegistry


def build_graph(
    *,
    registry: ToolRegistry | None = None,
    audit: AuditLog | None = None,
    plan_fn: PlanFn | None = None,
    checkpointer: "BaseCheckpointSaver | None" = None,
    settings: Settings | None = None,
) -> Atlas:
    """Build and compile the orchestration graph.

    All collaborators default to sensible production values but can be overridden — tests inject a
    scripted ``plan_fn`` and an ``InMemorySaver`` for determinism.
    """
    settings = settings or get_settings()
    registry = registry or default_registry()
    audit = audit or InMemoryAuditLog()
    plan_fn = plan_fn or default_plan_fn(settings)
    checkpointer = checkpointer or make_checkpointer(settings)

    builder: StateGraph = StateGraph(AgentState)
    builder.add_node("planner", make_planner_node(plan_fn, registry, audit))
    builder.add_node("approval", make_approval_node(audit))
    builder.add_node("executor", make_executor_node(registry, audit))
    builder.add_node("responder", make_responder_node())

    builder.add_edge(START, "planner")
    builder.add_conditional_edges(
        "planner",
        route_after_planner,
        {"approval": "approval", "executor": "executor", "responder": "responder"},
    )
    builder.add_edge("approval", "executor")
    builder.add_edge("executor", "responder")
    builder.add_edge("responder", END)

    graph = builder.compile(checkpointer=checkpointer)
    return Atlas(graph=graph, audit=audit, registry=registry)
