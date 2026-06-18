"""Agent Orchestration Layer — the core of atlas.

A LangGraph state machine: ``planner → (approval / interrupt) → executor → responder``.
"""

from atlas.orchestration.graph import build_graph
from atlas.orchestration.state import AgentState, initial_state

__all__ = ["AgentState", "build_graph", "initial_state"]
