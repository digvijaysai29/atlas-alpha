"""Confidence scoring + structured source attribution (the transparency layer)."""

from atlas.actions import ActionResult
from atlas.governance.confidence import (
    GROUNDED_ANSWER,
    UNGROUNDED_ANSWER,
    Source,
    collect_sources,
    score_confidence,
)
from atlas.knowledge.interfaces import Entity
from atlas.orchestration.serde import atlas_serde

_OK = ActionResult(action_id="a", tool="search", ok=True, output={"source": "mock-knowledge-base"})
_FAIL = ActionResult(action_id="b", tool="send_email", ok=False, error="boom")
_ENTITY = Entity(id="doc-1", type="doc", name="Q3 revenue", acl=("kg:read:org",), scope="org")


# --- score_confidence -------------------------------------------------------
def test_all_ok_actions_score_one() -> None:
    assert score_confidence([_OK], []) == 1.0


def test_partial_failure_scores_success_ratio() -> None:
    assert score_confidence([_OK, _FAIL], []) == 0.5


def test_no_actions_grounded_uses_grounded_constant() -> None:
    assert score_confidence([], [_ENTITY]) == GROUNDED_ANSWER


def test_no_actions_ungrounded_uses_ungrounded_constant() -> None:
    assert score_confidence([], []) == UNGROUNDED_ANSWER
    assert UNGROUNDED_ANSWER < GROUNDED_ANSWER  # low confidence is surfaced, not hidden


# --- collect_sources --------------------------------------------------------
def test_collects_tool_and_knowledge_sources() -> None:
    pairs = {(s.kind, s.ref) for s in collect_sources([_OK], [_ENTITY])}
    assert ("tool", "search") in pairs
    assert ("knowledge", "doc-1") in pairs


def test_dedups_by_kind_and_ref() -> None:
    sources = collect_sources([_OK, _OK], [_ENTITY, _ENTITY])
    assert len(sources) == 2  # one tool + one knowledge; duplicates collapsed


def test_ignores_results_without_a_source_field() -> None:
    sent = ActionResult(action_id="c", tool="send_email", ok=True, output={"status": "sent"})
    assert collect_sources([sent], []) == []


def test_failed_results_are_not_sources() -> None:
    assert collect_sources([_FAIL], []) == []


def test_source_survives_serde_roundtrip() -> None:
    serde = atlas_serde()
    source = Source(kind="knowledge", ref="doc-1", label="Q3 revenue")
    assert serde.loads_typed(serde.dumps_typed(source)) == source
