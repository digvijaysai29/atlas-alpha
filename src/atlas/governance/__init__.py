"""Governance: the append-only hash-chained audit log + RBAC.

Re-exports keep the public surface stable (`from atlas.governance import AuditLog, Principal, ...`)
even though the implementation is split across :mod:`atlas.governance.audit` and
:mod:`atlas.governance.rbac`.
"""

from atlas.governance.credentials import (
    CredentialAccessError,
    CredentialResolver,
    CredentialVault,
    InMemoryCredentialVault,
    OAuthProvider,
    StoredCredential,
)
from atlas.governance.audit import (
    GENESIS_HASH,
    AuditEvent,
    AuditEventType,
    AuditLog,
    AuditToolContext,
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
from atlas.governance.policy import DEFAULT_POLICY, InMemoryPolicyStore, PolicyStore
from atlas.governance.rbac import (
    ROLE_PERMISSIONS,
    WILDCARD,
    Principal,
    can,
    expand_roles,
    get_current_principal,
    get_effective_permissions,
    permission_satisfied,
)

__all__ = [
    # audit
    "GENESIS_HASH",
    "AuditEvent",
    "AuditEventType",
    "AuditLog",
    "AuditToolContext",
    "ChainedAuditRecord",
    "ChainVerification",
    "InMemoryAuditLog",
    "canonical_event_bytes",
    "compute_event_hash",
    "verify_chain",
    # rbac
    "ROLE_PERMISSIONS",
    "WILDCARD",
    "Principal",
    "can",
    "expand_roles",
    "get_current_principal",
    "get_effective_permissions",
    "permission_satisfied",
    # policy store
    "DEFAULT_POLICY",
    "InMemoryPolicyStore",
    "PolicyStore",
    # confidence + sources
    "GROUNDED_ANSWER",
    "UNGROUNDED_ANSWER",
    "Source",
    "collect_sources",
    "score_confidence",
    # credentials
    "CredentialAccessError",
    "CredentialResolver",
    "CredentialVault",
    "InMemoryCredentialVault",
    "OAuthProvider",
    "StoredCredential",
]
