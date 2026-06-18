"""Hash-chain integrity — the tamper-evidence guarantee, tested before any Postgres work.

These are pure unit tests (no DB). They pin the two things that are easy to get subtly wrong:
deterministic canonical serialization, and a verifier that actually catches every kind of tampering.
"""

from atlas.governance import (
    GENESIS_HASH,
    AuditEvent,
    AuditEventType,
    ChainedAuditRecord,
    InMemoryAuditLog,
    canonical_event_bytes,
    compute_event_hash,
    verify_chain,
)


def _event(action_id: str = "act_1", actor: str = "system") -> AuditEvent:
    # Fixed event_id/timestamp so equal-content events serialize identically.
    return AuditEvent(
        event_id="evt_fixed",
        timestamp="2026-06-19T00:00:00+00:00",  # type: ignore[arg-type]
        event_type=AuditEventType.PROPOSED,
        action_id=action_id,
        actor=actor,
    )


def _chain_of(n: int) -> list[ChainedAuditRecord]:
    log = InMemoryAuditLog()
    for i in range(n):
        log.record(_event(action_id=f"act_{i}"))
    return list(log.records())


def test_canonical_bytes_are_deterministic_for_equal_events() -> None:
    event = _event()
    assert canonical_event_bytes(event) == canonical_event_bytes(event.model_copy())


def test_canonical_bytes_change_when_any_field_changes() -> None:
    event = _event()
    assert canonical_event_bytes(event) != canonical_event_bytes(
        event.model_copy(update={"actor": "attacker"})
    )


def test_event_hash_is_deterministic() -> None:
    event = _event()
    assert compute_event_hash(GENESIS_HASH, event) == compute_event_hash(GENESIS_HASH, event)


def test_inmemory_log_builds_a_valid_contiguous_chain() -> None:
    records = _chain_of(3)
    assert records[0].prev_hash == GENESIS_HASH
    assert [r.seq for r in records] == [0, 1, 2]
    assert all(records[i].prev_hash == records[i - 1].event_hash for i in range(1, 3))
    assert verify_chain(records).ok is True


def test_verify_detects_a_mutated_event() -> None:
    records = _chain_of(3)
    records[1] = records[1].model_copy(
        update={"event": records[1].event.model_copy(update={"actor": "attacker"})}
    )
    result = verify_chain(records)
    assert result.ok is False
    assert result.broken_at == 1


def test_verify_detects_a_forged_hash() -> None:
    records = _chain_of(3)
    records[1] = records[1].model_copy(update={"event_hash": "f" * 64})
    assert verify_chain(records).ok is False


def test_verify_detects_a_deleted_record() -> None:
    records = _chain_of(3)
    del records[1]  # leaves seq 0, 2 — broken continuity + linkage
    assert verify_chain(records).ok is False


def test_verify_detects_reordered_records() -> None:
    records = _chain_of(3)
    records[1], records[2] = records[2], records[1]
    assert verify_chain(records).ok is False


def test_empty_chain_is_valid() -> None:
    assert verify_chain([]).ok is True
