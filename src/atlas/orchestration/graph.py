"""Graph assembly + the checkpointer factory.

``build_graph`` wires the four nodes into a LangGraph ``StateGraph`` and compiles it with a
checkpointer (required for the approval ``interrupt``/resume to work). Dependencies — the tool
registry, audit log, planning strategy, and checkpointer — are injected so the graph is easy to test
and to reconfigure per environment.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from atlas.config import Settings, get_settings
from atlas.governance import AuditLog, InMemoryAuditLog, InMemoryPolicyStore, PolicyStore
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


logger = logging.getLogger("atlas.orchestration")


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


def make_knowledge_graph(
    settings: Settings | None = None, policy: PolicyStore | None = None
) -> KnowledgeGraph:
    """Return the knowledge graph: a durable, RBAC-scoped Postgres backend if ``DATABASE_URL`` is
    set, else the in-memory stub (demos/tests seed it). The ``policy`` store governs RBAC read
    filtering. The factory never seeds — seeding is an explicit caller/demo step so CI and production
    never mutate the KG on connect.
    """
    settings = settings or get_settings()
    if settings.database_url:
        from atlas.persistence import PostgresKnowledgeGraph

        return PostgresKnowledgeGraph(
            _pg_pool(settings.database_url.get_secret_value()), policy=policy
        )
    return InMemoryKnowledgeGraph(policy=policy)


def make_policy_store(settings: Settings | None = None) -> PolicyStore:
    """Return the authorization policy store: durable Postgres if ``DATABASE_URL`` set, else the
    in-memory default (seeded from ``ROLE_PERMISSIONS``). Mirrors ``make_audit_log``.

    The Postgres backend is **never auto-seeded** (consistent with the KG factory): an empty
    ``atlas_role_permissions`` table grants nothing (fail-closed). A warning is logged so an operator
    knows to run ``scripts/manage_policy.py seed``.
    """
    settings = settings or get_settings()
    if settings.database_url:
        from atlas.persistence import PostgresPolicyStore

        store = PostgresPolicyStore(_pg_pool(settings.database_url.get_secret_value()))
        if store.is_empty():
            logger.warning(
                "atlas_role_permissions is empty — all roles are denied until seeded. "
                "Run: python scripts/manage_policy.py seed"
            )
        return store
    return InMemoryPolicyStore()


@dataclass(frozen=True)
class Atlas:
    """A compiled agent plus the collaborators a caller may want to inspect."""

    graph: "CompiledStateGraph"
    audit: AuditLog
    registry: ToolRegistry
    knowledge: KnowledgeGraph
    policy: PolicyStore


def build_graph(
    *,
    registry: ToolRegistry | None = None,
    audit: AuditLog | None = None,
    plan_fn: PlanFn | None = None,
    knowledge: KnowledgeGraph | None = None,
    policy: PolicyStore | None = None,
    checkpointer: "BaseCheckpointSaver | None" = None,
    settings: Settings | None = None,
) -> Atlas:
    """Build and compile the orchestration graph.

    All collaborators default to sensible production values but can be overridden — tests inject a
    scripted ``plan_fn``, a seeded ``knowledge`` graph, a custom ``policy``, and an ``InMemorySaver``.
    """
    settings = settings or get_settings()
    if settings.database_url and not settings.email_configured:
        logger.warning(
            "DATABASE_URL is set but email is not configured — send_email will fail until "
            "RESEND_API_KEY and ATLAS_EMAIL_FROM are set."
        )
    registry = registry or default_registry(settings)
    audit = audit or make_audit_log(settings)
    plan_fn = plan_fn or default_plan_fn(settings)
    policy = policy or make_policy_store(settings)
    if knowledge is None:
        knowledge = make_knowledge_graph(settings, policy)
    else:
        knowledge.bind_policy(policy)
    checkpointer = checkpointer or make_checkpointer(settings)

    builder: StateGraph = StateGraph(AgentState)
    builder.add_node("planner", make_planner_node(plan_fn, registry, audit, knowledge, policy))
    builder.add_node("approval", make_approval_node(audit))
    builder.add_node("executor", make_executor_node(registry, audit, policy))
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
    return Atlas(graph=graph, audit=audit, registry=registry, knowledge=knowledge, policy=policy)
