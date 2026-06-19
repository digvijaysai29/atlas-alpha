"""Unit tests for the Postgres knowledge store's pure helpers (no DB required).

The DB-backed behavior (RBAC scoping, full-text search, durability) lives in
``tests/test_knowledge_postgres.py`` (``-m integration``); here we cover the logic that doesn't
need a connection — chiefly LIKE-wildcard escaping, which keeps the ILIKE fallback's substring
semantics identical to the in-memory backend.
"""

from __future__ import annotations

from atlas.persistence.knowledge_store import _like_escape


def test_like_escape_neutralizes_wildcards() -> None:
    assert _like_escape("100%") == "100\\%"
    assert _like_escape("a_b") == "a\\_b"


def test_like_escape_escapes_backslash_first() -> None:
    # The backslash must be doubled before % / _ so the escape characters aren't themselves escaped.
    assert _like_escape("a\\%b") == "a\\\\\\%b"


def test_like_escape_leaves_plain_terms_untouched() -> None:
    assert _like_escape("revenue") == "revenue"
