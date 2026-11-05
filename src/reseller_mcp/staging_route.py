from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from starlette.datastructures import UploadFile
from starlette.requests import Request
from starlette.responses import JSONResponse

from .auth import AuthenticationError
from .cpanel import CPanelError
from .image_staging import MAX_BATCH_BYTES, MAX_BATCH_FILES, MAX_FILE_BYTES
from .models import Role

if TYPE_CHECKING:
    from .runtime import Runtime

# Room for multipart boundaries and part headers on top of the image bytes.
_MULTIPART_OVERHEAD = 1024 * 1024


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=status)


def staging_images_endpoint(runtime: Runtime) -> Callable[[Request], Awaitable[JSONResponse]]:
    """POST /staging/images: receive images for a later workflow.images_publish.

    Custom routes bypass the MCP token verifier, so the bearer token is checked here. Each file
    is validated on its own; a rejected file does not stop the others.
    """

    async def endpoint(request: Request) -> JSONResponse:
        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            return _error(401, "UNAUTHENTICATED", "a bearer token is required")
        try:
            principal = runtime.tokens.authenticate(token.strip())
        except AuthenticationError:
            return _error(401, "UNAUTHENTICATED", "invalid, expired or revoked bearer token")
        if principal.role.rank < Role.OPERATOR.rank:
            return _error(403, "FORBIDDEN", "staging images requires the operator role")
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BATCH_BYTES + _MULTIPART_OVERHEAD:
            return _error(
                413, "BATCH_TOO_LARGE", f"a batch may carry up to {MAX_BATCH_BYTES} bytes"
            )
        try:
            form = await request.form(max_files=MAX_BATCH_FILES, max_fields=10)
        except Exception:
            return _error(
                400, "INVALID_MULTIPART", f"send up to {MAX_BATCH_FILES} files as multipart"
            )
        staging = runtime.harness.image_staging
        items: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        total = 0
        try:
            uploads = [value for _, value in form.multi_items() if isinstance(value, UploadFile)]
            if not uploads:
                return _error(400, "INVALID_MULTIPART", "no files in the request")
            for upload in uploads:
                name = upload.filename or ""
                data = await upload.read(MAX_FILE_BYTES + 1)
                total += len(data)
                if total > MAX_BATCH_BYTES:
                    for item in items:
                        staging.discard(str(item["staging_id"]))
                    return _error(
                        413, "BATCH_TOO_LARGE", f"a batch may carry up to {MAX_BATCH_BYTES} bytes"
                    )
                try:
                    items.append(staging.store(principal.user_id, name, data).public())
                except CPanelError as exc:
                    rejected.append({"name": name, "code": exc.code, "message": str(exc)})
        finally:
            await form.close()
        runtime.harness.audit.append(
            principal=principal,
            capability_id="staging.images",
            account=None,
            phase="staging",
            outcome="success" if items else "failed",
            details={
                "items": [
                    {key: item[key] for key in ("staging_id", "name", "format", "size", "sha256")}
                    for item in items
                ],
                "rejected": rejected,
            },
        )
        return JSONResponse({"items": items, "rejected": rejected}, status_code=200)

    return endpoint
