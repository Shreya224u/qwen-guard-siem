"""HTTP error handling shared by the FastAPI application."""

import logging
from uuid import uuid4

from fastapi import Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("siem.api")


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Return a safe, consistent 500 response while retaining server diagnostics."""
    request_id = uuid4().hex
    logger.exception(
        "Unhandled API exception request_id=%s method=%s path=%s",
        request_id,
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error.", "code": "internal_error", "request_id": request_id},
        headers={"X-Request-ID": request_id},
    )
