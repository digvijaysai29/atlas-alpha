"""Role-based access control (RBAC).

A request runs as a :class:`Principal` (an identity + roles). Capabilities are coarse permission
**strings** (e.g. ``"tool:send"``, ``"kg:read:org"``). The policy is **default-deny / fail-closed**:
:func:`can` returns True only when one of the principal's roles explicitly grants the permission —
unknown roles, unknown permissions, and the anonymous principal are all denied.

Like the approval policy, authorization is **data-driven, never model-driven**: the LLM can choose
tools, but it can never grant itself a permission.

Note: permissions are plain strings for now. A richer ``ToolPermission`` model (resource scoping,
hierarchies) is a deliberate M3/M4 placeholder.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from atlas.orchestration.state import AgentState

# The admin wildcard: a role granting "*" is authorized for every permission.
WILDCARD = "*"


class Principal(BaseModel):
    """The identity a request runs as. Immutable — never mutated in place or via state tampering."""

    model_config = ConfigDict(frozen=True)

    user_id: str
    roles: tuple[str, ...] = Field(default_factory=tuple)
    org_id: str | None = None

    @classmethod
    def anonymous(cls) -> Principal:
        """The fail-closed default: a principal with no roles (and therefore no permissions)."""
        return cls(user_id="anonymous", roles=(), org_id=None)


# Default role → permission policy. Deliberately small; the source of truth for what a role may do.
# ``admin`` is intentionally given the wildcard "*" (see ``can`` for how that is interpreted).
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "admin": frozenset({"*"}),
    "member": frozenset({"tool:send", "kg:read:org", "kg:read:personal"}),
    "guest": frozenset({"kg:read:personal"}),
}


def expand_roles(roles: tuple[str, ...], mapping: Mapping[str, frozenset[str]]) -> frozenset[str]:
    """Expand role names into a concrete permission set against ``mapping`` (pure; fail-closed).

    The single source of truth for role expansion — reused by every :class:`PolicyStore` backend
    (:mod:`atlas.governance.policy`) so in-memory and Postgres agree exactly.

    - Unknown roles contribute nothing.
    - If any role grants the wildcard ``"*"`` the result is ``frozenset({"*"})`` (admin: grants all).
    """
    permissions: set[str] = set()
    for role in roles:
        granted = mapping.get(role)
        if granted is None:
            continue  # unknown role grants nothing (fail-closed)
        if WILDCARD in granted:
            return frozenset({WILDCARD})
        permissions.update(granted)
    return frozenset(permissions)


def get_effective_permissions(principal: Principal | None) -> frozenset[str]:
    """Expand a principal's roles via the built-in :data:`ROLE_PERMISSIONS` default.

    Back-compat default used by the free :func:`can` and :func:`can_read` when no explicit
    :class:`PolicyStore` is supplied. A ``None`` principal has no permissions (fail-closed).
    """
    if principal is None:
        return frozenset()
    return expand_roles(principal.roles, ROLE_PERMISSIONS)


def can(principal: Principal | None, permission: str | None) -> bool:
    """Return True iff ``principal`` is authorized for ``permission`` (default-deny).

    - ``permission is None`` means "no special permission required" → always allowed.
    - A ``None`` principal, an unknown role, or a role that doesn't grant the permission → denied.
    - The ``admin`` wildcard ``"*"`` grants everything.
    """
    if permission is None:
        return True
    granted = get_effective_permissions(principal)
    return WILDCARD in granted or permission in granted


def get_current_principal(state: AgentState) -> Principal:
    """Return the request's principal, or the fail-closed anonymous principal if none is set."""
    return state.get("principal") or Principal.anonymous()
