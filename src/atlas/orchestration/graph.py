"""Graph assembly + the checkpointer factory.

``build_graph`` wires the four nodes into a LangGraph ``StateGraph`` and compiles it with a
checkpointer (required for the approval ``interrupt``/resume to work). Dependencies — the tool
registry, audit log, planning strategy, and checkpointer — are injected so the graph is easy to test
and to reconfigure per environment.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from atlas.config import Settings, get_settings
from atlas.governance import AuditLog, InMemoryAuditLog
from atlas.knowledge.interfaces import KnowledgeGraph
from atlas.knowledge.memory_store import InMemoryKnowledgeGraph
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
    from psycopg_pool import ConnectionPool


@lru_cache(maxsize=8)
def _pg_pool(conninfo: str) -> "ConnectionPool":
    """One open connection pool per DSN (shared by the checkpointer and the audit store).

    LangGraph's PostgresSaver requires connections with ``autocommit=True`` and the ``dict_row`` row
    factory; the pool sets both for every connection it hands out.
    """
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool

    pool = ConnectionPool(
        conninfo,
        min_size=1,
        max_size=5,
        kwargs={"autocommit": True, "row_factory": dict_row},
        open=False,
    )
    pool.open()
    return pool


def make_checkpointer(settings: Settings | None = None) -> "BaseCheckpointSaver":
    """Return a checkpointer: Postgres if ``DATABASE_URL`` set, else SQLite if a path is set, else
    in-memory. A checkpointer is mandatory for durable interrupts.
    """
    settings = settings or get_settings()
    serde = atlas_serde()  # explicit allowlist — no arbitrary type deserialization from checkpoints
    if settings.database_url:
        from langgraph.checkpoint.postgres import PostgresSaver

        pool = _pg_pool(settings.database_url.get_secret_value())
        # pool carries dict_row + autocommit at runtime; psycopg's static row type doesn't reflect it.
        saver = PostgresSaver(pool, serde=serde)  # type: ignore[arg-type]
        saver.setup()  # idempotent: creates checkpoint tables if absent
        return saver
    if settings.sqlite_path:
        from langgraph.checkpoint.sqlite import SqliteSaver

        # check_same_thread=False: the saver may be used across threads in a server context.
        conn = sqlite3.connect(settings.sqlite_path, check_same_thread=False)
        return SqliteSaver(conn, serde=serde)
    return InMemorySaver(serde=serde)


def make_audit_log(settings: Settings | None = None) -> AuditLog:
    """Return the audit log: Postgres-backed (durable, hash-chained) if ``DATABASE_URL`` set, else
    in-memory. Shares the connection pool with the checkpointer.
    """
    settings = settings or get_settings()
    if settings.database_url:
        from atlas.persistence import PostgresAuditLog

        return PostgresAuditLog(_pg_pool(settings.database_url.get_secret_value()))
    return InMemoryAuditLog()


def make_knowledge_graph(settings: Settings | None = None) -> KnowledgeGraph:
    """Return the knowledge graph. M2.2b: an empty in-memory stub (demos/tests seed it); a concrete
    Neo4j/pgvector backend slots behind this interface in M3.
    """
    return InMemoryKnowledgeGraph()


@dataclass(frozen=True)
class Atlas:
    """A compiled agent plus the collaborators a caller may want to inspect."""

    graph: "CompiledStateGraph"
    audit: AuditLog
    registry: ToolRegistry
    knowledge: KnowledgeGraph


def build_graph(
    *,
    registry: ToolRegistry | None = None,
    audit: AuditLog | None = None,
    plan_fn: PlanFn | None = None,
    knowledge: KnowledgeGraph | None = None,
    checkpointer: "BaseCheckpointSaver | None" = None,
    settings: Settings | None = None,
) -> Atlas:
    """Build and compile the orchestration graph.

    All collaborators default to sensible production values but can be overridden — tests inject a
    scripted ``plan_fn``, a seeded ``knowledge`` graph, and an ``InMemorySaver`` for determinism.
    """
    settings = settings or get_settings()
    registry = registry or default_registry()
    audit = audit or make_audit_log(settings)
    plan_fn = plan_fn or default_plan_fn(settings)
    knowledge = knowledge or make_knowledge_graph(settings)
    checkpointer = checkpointer or make_checkpointer(settings)

    builder: StateGraph = StateGraph(AgentState)
    builder.add_node("planner", make_planner_node(plan_fn, registry, audit, knowledge))
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
    return Atlas(graph=graph, audit=audit, registry=registry, knowledge=knowledge)
