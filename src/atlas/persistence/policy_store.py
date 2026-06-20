"""Postgres-backed, durable authorization policy store (M3.4).

A :class:`atlas.governance.PolicyStore` whose role→permission mapping lives in the
``atlas_role_permissions`` table, so permissions are editable at runtime (via
``scripts/manage_policy.py``) without a code deploy. Mirrors the audit/knowledge stores.

Security:
- **Fail-closed:** an empty table grants nothing (deny-all). The factory never auto-seeds; seeding is
  an explicit, idempotent step.
- **No SQL injection:** every value (the principal's roles, role/permission for grant/revoke) is bound
  via ``psycopg`` placeholders; the only static SQL is the table DDL.
"""

from __future__ import annotations

from collections import defaultdict

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from atlas.governance.policy import PolicyStore
from atlas.governance.rbac import WILDCARD, Principal

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS atlas_role_permissions (
    role       TEXT NOT NULL,
    permission TEXT NOT NULL,
    PRIMARY KEY (role, permission)
)
"""

_SELECT_FOR_ROLES = (
    "SELECT permission FROM atlas_role_permissions WHERE role = ANY(%(roles)s::text[])"
)
_SELECT_ALL = "SELECT role, permission FROM atlas_role_permissions ORDER BY role, permission"
_GRANT = (
    "INSERT INTO atlas_role_permissions (role, permission) VALUES (%s, %s) ON CONFLICT DO NOTHING"
)
_REVOKE = "DELETE FROM atlas_role_permissions WHERE role = %s AND permission = %s"
_COUNT = "SELECT 1 FROM atlas_role_permissions LIMIT 1"


class PostgresPolicyStore(PolicyStore):
    """Durable, runtime-editable role→permission policy stored in Postgres."""

    def __init__(self, pool: ConnectionPool, *, setup: bool = True) -> None:
        self._pool = pool
        if setup:
            self.setup()

    def setup(self) -> None:
        """Create the policy table if absent (idempotent, static DDL)."""
        with self._pool.connection() as conn:
            conn.execute(_CREATE_TABLE)

    def effective_permissions(self, principal: Principal | None) -> frozenset[str]:
        if principal is None or not principal.roles:
            return frozenset()  # fail-closed
        with self._pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_SELECT_FOR_ROLES, {"roles": list(principal.roles)})
            perms = {row["permission"] for row in cur.fetchall()}
        # An empty result (e.g. unseeded table) grants nothing. Wildcard short-circuits to "all".
        return frozenset({WILDCARD}) if WILDCARD in perms else frozenset(perms)

    # --- management (used by scripts/manage_policy.py) ----------------------
    def grant(self, role: str, permission: str) -> None:
        with self._pool.connection() as conn:
            conn.execute(_GRANT, (role, permission))

    def revoke(self, role: str, permission: str) -> None:
        with self._pool.connection() as conn:
            conn.execute(_REVOKE, (role, permission))

    def list_policies(self) -> dict[str, frozenset[str]]:
        grouped: dict[str, set[str]] = defaultdict(set)
        with self._pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(_SELECT_ALL)
            for row in cur.fetchall():
                grouped[row["role"]].add(row["permission"])
        return {role: frozenset(perms) for role, perms in grouped.items()}

    def is_empty(self) -> bool:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(_COUNT)
            return cur.fetchone() is None
