"""Knowledge-graph ingestion endpoint (M4.4).

``POST /kg/ingest`` is the trusted write path into the Personal/Organizational Knowledge Graph. Like
the other handlers it is synchronous (the KG/psycopg calls are blocking) and resolves the caller's
:class:`~atlas.governance.rbac.Principal` via the shared :data:`RequestPrincipal` dependency — so an
unauthenticated caller is rejected at the boundary (401 in OIDC mode).

Authorization and scope/ACL resolution live in :class:`~atlas.knowledge.ingestion.IngestionService`
(server-side, fail-closed). A refused write surfaces as a 403 through the structured
:class:`~atlas.interface.schemas.ErrorResponse` envelope; Pydantic validation failures are a 422.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from atlas.interface.schemas import IngestRequest, IngestResponse
from atlas.interface.security import RequestPrincipal
from atlas.knowledge.ingestion import IngestDocument, IngestionDenied, IngestionService

router = APIRouter()


def get_ingestion(request: Request) -> IngestionService:
    """The ingestion service built once and stored on app.state via the shared ``Atlas``."""
    service: IngestionService = request.app.state.atlas.ingestion
    return service


IngestionDep = Annotated[IngestionService, Depends(get_ingestion)]


@router.post("/kg/ingest", response_model=IngestResponse)
def ingest(
    body: IngestRequest, principal: RequestPrincipal, ingestion: IngestionDep
) -> IngestResponse:
    document = IngestDocument(
        text=body.text,
        title=body.title,
        type=body.type,
        scope=body.scope,
        source_id=body.source_id,
        org_acl=tuple(body.org_acl) if body.org_acl is not None else None,
    )
    try:
        result = ingestion.ingest(principal, document)
    except IngestionDenied as exc:
        # Fail-closed: the principal may not perform this write. Message is content-free and safe.
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    return IngestResponse(
        scope=result.scope,
        source_id=result.source_id,
        chunk_count=result.chunk_count,
        entity_ids=list(result.entity_ids),
    )
