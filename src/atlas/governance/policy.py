"""Pluggable authorization policy (M3.4).

A :class:`PolicyStore` owns the role→permission mapping that backs RBAC. It is injected like the
other collaborators (audit, knowledge) so the mapping can be hardcoded (dev/tests), or durable and
runtime-editable (Postgres) — without changing any enforcement code.

Semantics are unchanged from the original hardcoded dict: default-deny / fail-closed, role expansion
with the ``"*"`` admin wildcard (see :func:`atlas.governance.rbac.expand_roles`, the shared source of
truth). This module imports **only** from :mod:`atlas.governance.rbac` (one-way) to avoid a cycle.
"""

from __future__ import annotations

import abc
from collections.abc import Mapping

from atlas.governance.rbac import ROLE_PERMISSIONS, WILDCARD, Principal, expand_roles


class PolicyStore(abc.ABC):
    """A role→permission policy backend. Concrete stores implement :meth:`effective_permissions`."""

    @abc.abstractmethod
    def effective_permissions(self, principal: Principal | None) -> frozenset[str]:
        """The concrete permissions a principal holds (fail-closed: ``None`` principal → empty)."""
        raise NotImplementedError

    def can(self, principal: Principal | None, permission: str | None) -> bool:
        """Default-deny authorization check shared by every backend.

        ``permission is None`` means "no special permission required" → allowed. The ``"*"`` wildcard
        grants everything.
        """
        if permission is None:
            return True
        granted = self.effective_permissions(principal)
        return WILDCARD in granted or permission in granted


class InMemoryPolicyStore(PolicyStore):
    """Policy backed by an in-process mapping (defaults to the built-in :data:`ROLE_PERMISSIONS`)."""

    def __init__(self, mapping: Mapping[str, frozenset[str]] | None = None) -> None:
        # Copy into an immutable-ish snapshot so external mutation can't change authz mid-flight.
        self._mapping: dict[str, frozenset[str]] = dict(
            ROLE_PERMISSIONS if mapping is None else mapping
        )

    def effective_permissions(self, principal: Principal | None) -> frozenset[str]:
        if principal is None:
            return frozenset()
        return expand_roles(principal.roles, self._mapping)


# Process-wide default used by the free `can`/`can_read` when no store is injected (dev/tests).
DEFAULT_POLICY: PolicyStore = InMemoryPolicyStore()
