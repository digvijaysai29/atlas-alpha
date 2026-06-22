"""CI contract tests — repo invariants that must never drift silently."""

from __future__ import annotations

import enum
import types
import typing
from typing import Annotated, Union, get_args, get_origin, get_type_hints

from pydantic import BaseModel

from atlas.orchestration.serde import _ATLAS_TYPES
from atlas.orchestration.state import AgentState

_ALLOWLIST = frozenset(_ATLAS_TYPES)


def _unwrap_annotation(tp: object, *, seen: set[type] | None = None) -> set[type]:
    """Collect custom types reachable from a checkpoint annotation (nested models + enums)."""
    if seen is None:
        seen = set()

    if tp is type(None) or tp is typing.Any:
        return set()

    origin = get_origin(tp)
    if origin is not None:
        if origin is Annotated:
            return _unwrap_annotation(get_args(tp)[0], seen=seen)
        if origin in (Union, types.UnionType):
            result: set[type] = set()
            for arg in get_args(tp):
                result |= _unwrap_annotation(arg, seen=seen)
            return result
        if origin in (list, tuple, frozenset, set):
            args = get_args(tp)
            if args:
                return _unwrap_annotation(args[0], seen=seen)
            return set()
        return set()

    if not isinstance(tp, type):
        return set()

    if issubclass(tp, enum.Enum):
        return {tp} if tp.__module__.startswith("atlas.") and tp not in seen else set()

    if issubclass(tp, BaseModel):
        if tp in seen or not tp.__module__.startswith("atlas."):
            return set()
        seen.add(tp)
        result = {tp}
        for field_ann in get_type_hints(tp, include_extras=True).values():
            result |= _unwrap_annotation(field_ann, seen=seen)
        return result

    return set()


def test_checkpointed_state_types_are_in_serde_allowlist() -> None:
    """Every atlas-owned type reachable from AgentState must be in atlas_serde()'s allowlist.

    LangChain ``AnyMessage`` subtypes are serialized by LangGraph's built-in path, not
    ``_ATLAS_TYPES`` — exclude the ``messages`` channel and non-atlas types.
    """
    checkpointed: set[type] = set()
    for field, ann in get_type_hints(AgentState, include_extras=True).items():
        if field == "messages":
            continue
        checkpointed |= _unwrap_annotation(ann)

    atlas_owned = {t for t in checkpointed if t.__module__.startswith("atlas.")}
    missing = atlas_owned - _ALLOWLIST
    assert not missing, (
        "AgentState checkpoint types missing from _ATLAS_TYPES: "
        f"{sorted(f'{t.__module__}.{t.__qualname__}' for t in missing)}. "
        "Add them to orchestration/serde.py."
    )
