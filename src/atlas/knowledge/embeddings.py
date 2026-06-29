"""Embedding providers for semantic knowledge retrieval (M4.6).

The :class:`~atlas.persistence.knowledge_store.PostgresKnowledgeGraph` turns an entity's text into a
dense vector so retrieval can rank by *meaning* (pgvector cosine distance), not just keyword overlap.
This module supplies the embedder behind a small interface so the backend never depends on a concrete
provider:

- :class:`VoyageEmbedder` — the production provider (Voyage AI, Anthropic's recommended embedding
  partner). Used only when ``VOYAGE_API_KEY`` is configured; the SDK is imported lazily so the
  dependency is never touched on the offline path.
- :class:`DeterministicEmbedder` — a pure, hash-seeded, L2-normalized fallback with **no network and
  no randomness**. It is the default when no API key is set, so CI and the deterministic eval gate
  exercise the vector path hermetically and at zero cost. The same input always yields the same vector.

Security posture (mirrors the rest of atlas):

- The embedding **source text is never logged** here (consistent with the content-free M4.4 audit).
- The Voyage API key comes only from :class:`~atlas.config.Settings` (environment) and is never logged.
- A single ``dim`` flows from settings into both the column type and every embedder, so a vector can
  never be written at the wrong width.
"""

from __future__ import annotations

import abc
import hashlib
import math
from collections.abc import Sequence
from typing import Literal

from atlas.config import Settings, get_settings

# Voyage maps our two retrieval contexts onto its ``input_type`` parameter, which meaningfully improves
# asymmetric query↔document retrieval. The deterministic fallback ignores it (symmetric by construction).
InputType = Literal["document", "query"]

# One sha256 digest yields 32 bytes; we expand deterministically by counter to reach ``dim`` floats.
_BYTE_MIDPOINT = 127.5


class EmbeddingProvider(abc.ABC):
    """Turns text into fixed-width dense vectors. Implementations must return ``dim``-length vectors."""

    @property
    @abc.abstractmethod
    def dim(self) -> int:
        """The dimensionality of every vector this provider returns (matches the DB column width)."""
        raise NotImplementedError

    @abc.abstractmethod
    def embed(
        self, texts: Sequence[str], *, input_type: InputType = "document"
    ) -> list[list[float]]:
        """Embed ``texts`` into a list of ``dim``-length float vectors (order-preserving)."""
        raise NotImplementedError

    def embed_one(self, text: str, *, input_type: InputType = "document") -> list[float]:
        """Convenience wrapper to embed a single string."""
        return self.embed([text], input_type=input_type)[0]


class DeterministicEmbedder(EmbeddingProvider):
    """A pure, offline, L2-normalized pseudo-embedder for CI/tests (no network, no randomness).

    It is **not** semantically meaningful — it exists so the vector storage + retrieval *plumbing* can
    be exercised end-to-end without an API key, and so identical text deduplicates to an identical
    vector (required by the deterministic eval gate). ``input_type`` is ignored by design.
    """

    def __init__(self, dim: int) -> None:
        if dim <= 0:
            raise ValueError("embedding dim must be a positive integer")
        self._dim = dim

    @property
    def dim(self) -> int:
        return self._dim

    def embed(
        self, texts: Sequence[str], *, input_type: InputType = "document"
    ) -> list[list[float]]:
        return [self._vector(text) for text in texts]

    def _vector(self, text: str) -> list[float]:
        """Expand ``text`` into ``dim`` L2-normalized floats via counter-mode sha256 (deterministic)."""
        values: list[float] = []
        counter = 0
        while len(values) < self._dim:
            digest = hashlib.sha256(f"{counter}:{text}".encode("utf-8")).digest()
            for byte in digest:
                values.append(byte / _BYTE_MIDPOINT - 1.0)  # map [0,255] -> [-1, 1)
                if len(values) >= self._dim:
                    break
            counter += 1
        norm = math.sqrt(sum(value * value for value in values))
        if norm == 0.0:  # defensive: never reached for real input (guards against divide-by-zero)
            return values
        return [value / norm for value in values]


class VoyageEmbedder(EmbeddingProvider):
    """Production embedder backed by Voyage AI (lazy-imports the SDK; key never logged)."""

    def __init__(self, api_key: str, model: str, dim: int) -> None:
        if not api_key.strip():
            raise ValueError("VoyageEmbedder requires a non-empty API key")
        if dim <= 0:
            raise ValueError("embedding dim must be a positive integer")
        self._model = model
        self._dim = dim
        self._api_key = api_key

    @property
    def dim(self) -> int:
        return self._dim

    def embed(
        self, texts: Sequence[str], *, input_type: InputType = "document"
    ) -> list[list[float]]:
        if not texts:
            return []
        # Lazy import: the offline path (DeterministicEmbedder) never pays for the SDK or its weight.
        import voyageai

        client = voyageai.Client(api_key=self._api_key)  # type: ignore[attr-defined]
        result = client.embed(list(texts), model=self._model, input_type=input_type)
        vectors = [list(vector) for vector in result.embeddings]
        for vector in vectors:
            if len(vector) != self._dim:
                raise ValueError(
                    f"Voyage model {self._model!r} returned dim {len(vector)}, expected {self._dim}. "
                    "Set ATLAS_EMBEDDING_DIM to match the model."
                )
        return vectors


def make_embedder(settings: Settings | None = None) -> EmbeddingProvider:
    """Return the embedder: Voyage when ``VOYAGE_API_KEY`` is set, else the deterministic fallback.

    Mirrors the other factories in :mod:`atlas.orchestration.graph` — a real provider when configured,
    a hermetic offline stub otherwise.
    """
    settings = settings or get_settings()
    if settings.embeddings_configured:
        # embeddings_configured guarantees the key is present and non-empty.
        key = settings.voyage_api_key.get_secret_value()  # type: ignore[union-attr]
        return VoyageEmbedder(key, settings.embedding_model, settings.embedding_dim)
    return DeterministicEmbedder(settings.embedding_dim)
