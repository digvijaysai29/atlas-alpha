"""Shared test fixtures.

Integration tests require a live Postgres reachable via ``DATABASE_URL``; when it is unset they skip
(so the default ``uv run pytest`` stays green offline, and CI's ``integration`` job provides one).
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from psycopg_pool import ConnectionPool


def reset_kg_tables(database_url: str) -> None:
    """Drop KG tables only — clears vector-dim pollution from M4.6 integration tests."""
    import psycopg

    with psycopg.connect(database_url, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS atlas_kg_entities")
        conn.execute("DROP TABLE IF EXISTS atlas_kg_relations")


def reset_atlas_tables(database_url: str) -> None:
    """Drop atlas tables so ``database_url``-only tests start from a clean schema."""
    import psycopg

    with psycopg.connect(database_url, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS atlas_audit_log")
        conn.execute("DROP TABLE IF EXISTS atlas_kg_entities")
        conn.execute("DROP TABLE IF EXISTS atlas_kg_relations")
        conn.execute("DROP TABLE IF EXISTS atlas_role_permissions")


@pytest.fixture
def database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        pytest.skip("DATABASE_URL not set; skipping Postgres integration test")
    return url


@pytest.fixture
def pg_pool(database_url: str) -> Iterator[ConnectionPool]:
    """An open pool with freshly-reset atlas tables (audit + knowledge graph), isolated per test."""
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool

    pool = ConnectionPool(
        database_url,
        min_size=1,
        max_size=3,
        kwargs={"autocommit": True, "row_factory": dict_row},
        open=False,
    )
    pool.open()
    with pool.connection() as conn:
        conn.execute("DROP TABLE IF EXISTS atlas_audit_log")
        conn.execute("DROP TABLE IF EXISTS atlas_kg_entities")
        conn.execute("DROP TABLE IF EXISTS atlas_kg_relations")
        conn.execute("DROP TABLE IF EXISTS atlas_role_permissions")
    try:
        yield pool
    finally:
        pool.close()
