"""HTTP request/response contracts for the interface layer.

These are **transport-only** Pydantic models — they are never checkpointed, so they are deliberately
*not* in the ``atlas_serde()`` allowlist (`orchestration/serde.py`). Validation happens here at the
boundary; every error path returns the structured :class:`ErrorResponse` envelope (never a bare
status code).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from atlas.knowledge.ingestion import NonEmptyText


# --- errors (consistent envelope) -------------------------------------------
class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    ok: Literal[False] = False
    error: ErrorDetail


# --- requests ----------------------------------------------------------------
class ChatRequest(BaseModel):
    message: str = Field(min_length=1, description="The user's natural-language request.")


class IngestRequest(BaseModel):
    """A document submitted to ``POST /kg/ingest``.

    The caller may *request* a ``scope``; the server resolves the actual ACL and authorizes the write
    (``org`` requires ``kg:write:org``). ``org_acl`` is only meaningful for ``org`` scope.
    """

    text: NonEmptyText = Field(description="The raw document text to ingest.")
    title: str = Field(min_length=1, description="Human-readable title.")
    type: str = "doc"
    scope: Literal["personal", "org"] = "personal"
    source_id: str | None = Field(
        default=None,
        description="Stable id for idempotent re-ingest; derived from title if omitted.",
    )
    org_acl: list[str] | None = Field(
        default=None, description="Optional read ACL for org scope only."
    )


class ApproveRequest(BaseModel):
    """A human's decision for a thread paused at the approval gate.

    Provide **either** ``approve`` (apply to all pending actions) **or** the granular
    ``approved_ids`` / ``rejected_ids`` lists — not both. At least one decision must be present.
    """

    thread_id: str = Field(min_length=1)
    approve: bool | None = Field(default=None, description="Approve/reject ALL pending actions.")
    approved_ids: list[str] = Field(default_factory=list)
    rejected_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_decisions(self) -> ApproveRequest:
        if self.approve is None and not self.approved_ids and not self.rejected_ids:
            raise ValueError("provide `approve` or `approved_ids`/`rejected_ids`")
        if self.approve is not None and (self.approved_ids or self.rejected_ids):
            raise ValueError("use either `approve` or `approved_ids`/`rejected_ids`, not both")
        if set(self.approved_ids) & set(self.rejected_ids):
            raise ValueError("an action_id cannot appear in both `approved_ids` and `rejected_ids`")
        return self


# --- responses ---------------------------------------------------------------
class IngestResponse(BaseModel):
    """The successful response for ``POST /kg/ingest``: which entities were written."""

    ok: Literal[True] = True
    scope: str
    source_id: str
    chunk_count: int
    entity_ids: list[str] = Field(default_factory=list)


class AgentResponse(BaseModel):
    """The unified successful response for /chat, /approve, and /threads/{id}."""

    ok: Literal[True] = True
    status: Literal["completed", "awaiting_approval", "in_progress"]
    thread_id: str
    response: str | None = None
    pending_actions: list[dict[str, Any]] = Field(default_factory=list)
    sources: list[dict[str, Any]] = Field(default_factory=list)
    confidence: float | None = None
    action_results: list[dict[str, Any]] = Field(default_factory=list)
