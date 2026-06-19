"""FastAPI application factory for the atlas interface layer.

``create_app`` mirrors the ``build_graph`` dependency-injection pattern: it builds the compiled agent
once and stores it on ``app.state`` (tests inject a hermetic ``Atlas`` instead). Every error path is
funnelled through the structured :class:`~atlas.interface.schemas.ErrorResponse` envelope — unexpected
errors return a generic 500 and are logged server-side only, never leaking internals to the client.
"""

from __future__ import annotations

import logging
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from atlas.config import Settings, get_settings
from atlas.interface.routes import router
from atlas.interface.schemas import ErrorDetail, ErrorResponse
from atlas.orchestration.graph import Atlas, build_graph

logger = logging.getLogger("atlas.interface")


def _error(status_code: int, code: str, message: str) -> JSONResponse:
    body = ErrorResponse(error=ErrorDetail(code=code, message=message))
    return JSONResponse(status_code=status_code, content=body.model_dump())


def create_app(*, atlas: Atlas | None = None, settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(title="atlas", version="0.3.2")
    app.state.settings = settings
    app.state.atlas = atlas or build_graph(settings=settings)
    app.include_router(router)

    @app.exception_handler(StarletteHTTPException)
    def _on_http_exception(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        try:
            code = HTTPStatus(exc.status_code).name.lower()
        except ValueError:
            code = "error"
        return _error(exc.status_code, code, str(exc.detail))

    @app.exception_handler(RequestValidationError)
    def _on_validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        # Surface that validation failed without dumping internal structures.
        message = (
            exc.errors()[0].get("msg", "Request validation failed.")
            if exc.errors()
            else ("Request validation failed.")
        )
        return _error(HTTPStatus.UNPROCESSABLE_ENTITY, "validation_error", str(message))

    @app.exception_handler(Exception)
    def _on_unhandled(_request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error in interface layer")  # server-side detail only
        return _error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error", "Internal server error.")

    return app
