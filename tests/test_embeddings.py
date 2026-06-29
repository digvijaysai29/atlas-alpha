"""Offline unit tests for the M4.6 embedding providers + RRF fusion.

These run without any API key: they cover the deterministic embedder (the CI/dev fallback), the
factory's provider selection, and the rank-fusion helper. The Voyage path is only constructed (never
called) so no network is touched.
"""

from __future__ import annotations

import math

import pytest
from pydantic import SecretStr

from atlas.config import Settings
from atlas.knowledge.embeddings import (
    DeterministicEmbedder,
    VoyageEmbedder,
    make_embedder,
)
from atlas.persistence.knowledge_store import (
    _QUERY,
    _RBAC_PREDICATE,
    _VECTOR_QUERY,
    _rrf_fuse,
    _vector_literal,
)

DIM = 1024


# --- DeterministicEmbedder --------------------------------------------------
def test_deterministic_embedder_is_reproducible() -> None:
    embedder = DeterministicEmbedder(DIM)
    assert embedder.embed_one("alice onboarding") == embedder.embed_one("alice onboarding")


def test_deterministic_embedder_returns_configured_dim() -> None:
    embedder = DeterministicEmbedder(DIM)
    vector = embedder.embed_one("anything")
    assert len(vector) == DIM


def test_deterministic_embedder_l2_normalizes() -> None:
    embedder = DeterministicEmbedder(DIM)
    vector = embedder.embed_one("revenue figures for the quarter")
    assert math.isclose(math.sqrt(sum(v * v for v in vector)), 1.0, rel_tol=1e-9)


def test_deterministic_embedder_distinguishes_text() -> None:
    embedder = DeterministicEmbedder(DIM)
    assert embedder.embed_one("laptop setup") != embedder.embed_one("quarterly revenue")


def test_deterministic_embedder_handles_empty_string() -> None:
    embedder = DeterministicEmbedder(DIM)
    vector = embedder.embed_one("")
    assert len(vector) == DIM  # still a well-formed, reproducible, normalized vector
    assert math.isclose(math.sqrt(sum(v * v for v in vector)), 1.0, rel_tol=1e-9)
    assert vector == embedder.embed_one("")


def test_deterministic_embedder_batch_matches_singles() -> None:
    embedder = DeterministicEmbedder(8)
    batch = embedder.embed(["a", "b"])
    assert batch == [embedder.embed_one("a"), embedder.embed_one("b")]


def test_deterministic_embedder_rejects_nonpositive_dim() -> None:
    with pytest.raises(ValueError):
        DeterministicEmbedder(0)


# --- make_embedder factory --------------------------------------------------
def test_make_embedder_falls_back_to_deterministic_without_key() -> None:
    settings = Settings(VOYAGE_API_KEY=None, ATLAS_EMBEDDING_DIM=DIM)
    embedder = make_embedder(settings)
    assert isinstance(embedder, DeterministicEmbedder)
    assert embedder.dim == DIM


def test_make_embedder_selects_voyage_when_key_present() -> None:
    settings = Settings(
        VOYAGE_API_KEY=SecretStr("vk-test"),
        ATLAS_EMBEDDING_MODEL="voyage-3",
        ATLAS_EMBEDDING_DIM=DIM,
    )
    embedder = make_embedder(settings)
    assert isinstance(embedder, VoyageEmbedder)
    assert embedder.dim == DIM  # constructed only; no network call


def test_voyage_embedder_rejects_blank_key() -> None:
    with pytest.raises(ValueError):
        VoyageEmbedder("   ", "voyage-3", DIM)


# --- helpers ----------------------------------------------------------------
def test_vector_literal_format() -> None:
    assert _vector_literal([0.0, 1.5, -2.0]) == "[0.0,1.5,-2.0]"


def test_rrf_fuse_rewards_agreement_across_rankings() -> None:
    # "b" appears high in both lists; it should win even though "a" is rank-0 in one list.
    fts = ["a", "b", "c"]
    vec = ["b", "d", "a"]
    fused = _rrf_fuse([fts, vec], k=60)
    assert fused[0] == "b"
    assert set(fused) == {"a", "b", "c", "d"}


def test_rrf_fuse_single_ranking_preserves_order() -> None:
    assert _rrf_fuse([["x", "y", "z"]], k=60) == ["x", "y", "z"]


def test_rbac_predicate_is_shared_by_both_query_branches() -> None:
    # Security invariant: the FTS and vector queries must enforce the IDENTICAL RBAC predicate, so
    # semantic search can never widen read access (no IDOR via embeddings).
    assert _RBAC_PREDICATE in _QUERY
    assert _RBAC_PREDICATE in _VECTOR_QUERY


# --- Settings embedding validation (M4.6) -----------------------------------
def test_default_embedding_config_boots_cleanly() -> None:
    settings = Settings(ANTHROPIC_API_KEY=None)
    assert settings.embedding_model == "voyage-3"
    assert settings.embedding_dim == 1024


@pytest.mark.parametrize("model", ["", "   "])
def test_blank_embedding_model_rejected(model: str) -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="ATLAS_EMBEDDING_MODEL must not be blank"):
        Settings(ANTHROPIC_API_KEY=None, ATLAS_EMBEDDING_MODEL=model)


def test_voyage_3_requires_1024_dim() -> None:
    from pydantic import ValidationError

    with pytest.raises(
        ValidationError,
        match=r"ATLAS_EMBEDDING_MODEL 'voyage-3' requires ATLAS_EMBEDDING_DIM=1024",
    ):
        Settings(
            ANTHROPIC_API_KEY=None,
            ATLAS_EMBEDDING_MODEL="voyage-3",
            ATLAS_EMBEDDING_DIM=512,
        )


def test_unsupported_model_rejected_when_voyage_configured() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="Unsupported ATLAS_EMBEDDING_MODEL"):
        Settings(
            ANTHROPIC_API_KEY=None,
            VOYAGE_API_KEY=SecretStr("vk-test"),
            ATLAS_EMBEDDING_MODEL="voyage-2",
            ATLAS_EMBEDDING_DIM=1024,
        )
