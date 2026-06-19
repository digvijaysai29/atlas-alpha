"""Governance: the append-only hash-chained audit log + RBAC.

Re-exports keep the public surface stable (`from atlas.governance import AuditLog, Principal, ...`)
even though the implementation is split across :mod:`atlas.governance.audit` and
:mod:`atlas.governance.rbac`.
"""

from atlas.governance.audit import (
    GENESIS_HASH,
    AuditEvent,
    AuditEventType,
    AuditLog,
    ChainedAuditRecord,
    ChainVerification,
    InMemoryAuditLog,
    canonical_event_bytes,
    compute_event_hash,
    verify_chain,
)
from atlas.governance.confidence import (
    GROUNDED_ANSWER,
    UNGROUNDED_ANSWER,
    Source,
    collect_sources,
    score_confidence,
)
from atlas.governance.rbac import (
    ROLE_PERMISSIONS,
    Principal,
    can,
    get_current_principal,
)

__all__ = [
    # audit
    "GENESIS_HASH",
    "AuditEvent",
    "AuditEventType",
    "AuditLog",
    "ChainedAuditRecord",
    "ChainVerification",
    "InMemoryAuditLog",
    "canonical_event_bytes",
    "compute_event_hash",
    "verify_chain",
    # rbac
    "ROLE_PERMISSIONS",
    "Principal",
    "can",
    "get_current_principal",
    # confidence + sources
    "GROUNDED_ANSWER",
    "UNGROUNDED_ANSWER",
    "Source",
    "collect_sources",
    "score_confidence",
]
