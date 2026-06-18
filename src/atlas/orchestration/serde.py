"""Checkpoint serialization with an explicit type allowlist.

atlas stores its own immutable Pydantic action records in graph state. When those are persisted by a
checkpointer, the serializer must know how to revive them. Rather than allowing *arbitrary* types to
be deserialized from a checkpoint (a real deserialization-attack surface), we build a serializer
whose msgpack allowlist contains **only** atlas's own action types. Everything else falls back to
the library's known-safe builtins.
"""

from __future__ import annotations

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

from atlas.actions import ActionResult, ApprovalDecision, ProposedAction, RiskTier

# The complete set of custom types that may legitimately appear in checkpointed state.
_ATLAS_TYPES = [RiskTier, ProposedAction, ApprovalDecision, ActionResult]


def atlas_serde() -> JsonPlusSerializer:
    """A serializer that revives atlas's types and nothing else custom (strict base + allowlist)."""
    return JsonPlusSerializer(allowed_msgpack_modules=()).with_msgpack_allowlist(_ATLAS_TYPES)
