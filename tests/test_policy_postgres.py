"""PostgresPolicyStore integration tests (run only when DATABASE_URL is set).

Proves the M3.4 guarantees: an empty table is deny-all (fail-closed), seeding resolves roles
correctly, grant/revoke round-trips and is idempotent, and policy is durable across a fresh store
instance.
"""

from __future__ import annotations

import pytest

from atlas.governance import ROLE_PERMISSIONS, Principal
from atlas.persistence import PostgresPolicyStore

pytestmark = pytest.mark.integration

MEMBER = Principal(user_id="alice", roles=("member",))
GUEST = Principal(user_id="bob", roles=("guest",))
ADMIN = Principal(user_id="root", roles=("admin",))


def _seed(store: PostgresPolicyStore) -> None:
    for role, permissions in ROLE_PERMISSIONS.items():
        for permission in permissions:
            store.grant(role, permission)


def test_empty_table_denies_all(pg_pool: object) -> None:
    store = PostgresPolicyStore(pg_pool)  # type: ignore[arg-type]
    assert store.is_empty() is True
    assert store.effective_permissions(MEMBER) == frozenset()  # fail-closed
    assert store.can(MEMBER, "tool:send") is False


def test_seed_then_roles_resolve(pg_pool: object) -> None:
    store = PostgresPolicyStore(pg_pool)  # type: ignore[arg-type]
    _seed(store)
    assert store.is_empty() is False
    assert store.effective_permissions(MEMBER) == ROLE_PERMISSIONS["member"]
    assert store.can(GUEST, "kg:read:personal") is True
    assert store.can(GUEST, "tool:send") is False  # guest lacks send
    assert store.effective_permissions(ADMIN) == frozenset({"*"})  # wildcard
    assert store.can(ADMIN, "any:permission") is True


def test_grant_is_idempotent_and_revoke_removes(pg_pool: object) -> None:
    store = PostgresPolicyStore(pg_pool)  # type: ignore[arg-type]
    store.grant("member", "tool:send")
    store.grant("member", "tool:send")  # ON CONFLICT DO NOTHING — no duplicate, no error
    assert store.can(MEMBER, "tool:send") is True
    store.revoke("member", "tool:send")
    assert store.can(MEMBER, "tool:send") is False


def test_wildcard_grant_resolves_and_round_trips(pg_pool: object) -> None:
    # M3.5: a hierarchical `kg:read:*` grant satisfies concrete leaves and survives grant/revoke.
    store = PostgresPolicyStore(pg_pool)  # type: ignore[arg-type]
    store.grant("member", "kg:read:*")
    assert store.effective_permissions(MEMBER) == frozenset({"kg:read:*"})
    assert store.can(MEMBER, "kg:read:org") is True
    assert store.can(MEMBER, "kg:read:personal") is True
    assert store.can(MEMBER, "kg:write:org") is False  # wildcard stays within its prefix
    store.revoke("member", "kg:read:*")
    assert store.can(MEMBER, "kg:read:org") is False  # back to deny


def test_policy_is_durable_across_a_fresh_store_instance(pg_pool: object) -> None:
    PostgresPolicyStore(pg_pool).grant("member", "tool:send")  # type: ignore[arg-type]
    reloaded = PostgresPolicyStore(pg_pool, setup=False)  # type: ignore[arg-type]
    assert reloaded.can(MEMBER, "tool:send") is True
    assert reloaded.list_policies() == {"member": frozenset({"tool:send"})}


def test_missing_default_grants_reports_absent_permissions(pg_pool: object) -> None:
    store = PostgresPolicyStore(pg_pool)  # type: ignore[arg-type]
    store.grant("member", "tool:send")
    drift = store.missing_default_grants()
    # M4.8c: the member default is the resource-scoped wildcard, not the bare grant.
    assert "tool:slack:post:*" in drift.get("member", frozenset())


def test_missing_default_grants_empty_when_fully_seeded(pg_pool: object) -> None:
    store = PostgresPolicyStore(pg_pool)  # type: ignore[arg-type]
    _seed(store)
    assert store.missing_default_grants() == {}
