"""HTTP request/response contracts for the interface layer.

These are **transport-only** Pydantic models — they are never checkpointed, so they are deliberately
*not* in the ``atlas_serde()`` allowlist (`orchestration/serde.py`). Validation happens here at the
boundary; every error path returns the structured :class:`ErrorResponse` envelope (never a bare
status code).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


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


class ApproveRequest(BaseModel):
    """A human's decision for a thread paused at the approval gate.

    Provide either ``approve`` (apply to all pending actions) or the granular ``approved_ids`` /
    ``rejected_ids`` lists. At least one decision must be present.
    """

    thread_id: str = Field(min_length=1)
    approve: bool | None = Field(default=None, description="Approve/reject ALL pending actions.")
    approved_ids: list[str] = Field(default_factory=list)
    rejected_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _require_a_decision(self) -> ApproveRequest:
        if self.approve is None and not self.approved_ids and not self.rejected_ids:
            raise ValueError("provide `approve` or `approved_ids`/`rejected_ids`")
        return self


# --- responses ---------------------------------------------------------------
class AgentResponse(BaseModel):
    """The unified successful response for /chat, /approve, and /threads/{id}."""

    ok: Literal[True] = True
    status: Literal["completed", "awaiting_approval"]
    thread_id: str
    response: str | None = None
    pending_actions: list[dict[str, Any]] = Field(default_factory=list)
    sources: list[dict[str, Any]] = Field(default_factory=list)
    confidence: float | None = None
    action_results: list[dict[str, Any]] = Field(default_factory=list)
