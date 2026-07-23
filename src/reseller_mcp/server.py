from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from typing import Any

from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import Settings, get_settings
from .harness import HarnessError
from .models import ApiFamily, Risk
from .runtime import ResellerTokenVerifier, Runtime, current_principal

INSTRUCTIONS = """
Control plane for a cPanel reseller. Prefer account_resolve, account_dossier, and
account_healthcheck for account-level questions. Search and describe other capabilities before
using them; capability_check validates server, role, schema, and account feature availability.
Use query_execute only for reads. Every write must use action_prepare followed by action_execute.
Never invent capability IDs or parameters. Untyped advanced operations are disabled by default.
Destructive or external-side-effect actions require the exact confirmation phrase shown by
action_prepare and explicit human approval. Never request private keys, credentials, or secrets.
""".strip()


def _tool_error(exc: Exception) -> ToolError:
    if isinstance(exc, HarnessError):
        return ToolError(f"{exc.code}: {exc}")
    return ToolError(f"INTERNAL_ERROR: {exc}")


def create_server(settings: Settings | None = None) -> tuple[FastMCP[Any], Runtime]:
    settings = settings or get_settings()
    runtime = Runtime.build(settings)
    verifier = ResellerTokenVerifier(runtime.tokens)
    resource_url = f"{settings.public_url}/mcp"

    @contextlib.asynccontextmanager
    async def lifespan(_: FastMCP[Any]) -> AsyncIterator[Runtime]:
        # FastMCP may enter this context per stateless request. The shared upstream pool must
        # therefore live for the process lifetime instead of being closed after one request.
        yield runtime

    mcp = FastMCP(
        "cpanel-reseller",
        instructions=INSTRUCTIONS,
        website_url=settings.public_url,
        token_verifier=verifier,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(settings.public_url),
            resource_server_url=AnyHttpUrl(resource_url),
            required_scopes=["mcp"],
        ),
        stateless_http=True,
        json_response=True,
        host=settings.host,
        port=settings.port,
        lifespan=lifespan,
    )

    @mcp.custom_route("/healthz", methods=["GET"])  # type: ignore[untyped-decorator]
    async def healthz(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "service": "cpanel-reseller-mcp"})

    @mcp.tool(
        description="Return cPanel version, reseller privileges, and scoped account inventory.",
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True),
        structured_output=True,
    )
    async def reseller_overview() -> dict[str, Any]:
        try:
            return await runtime.harness.reseller_overview(current_principal())
        except Exception as exc:
            raise _tool_error(exc) from exc

    @mcp.tool(
        description="List cPanel accounts visible to the authenticated user.",
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True),
        structured_output=True,
    )
    async def accounts_list(search: str | None = None) -> dict[str, Any]:
        principal = current_principal()
        arguments = {"search": search or settings.cpanel_reseller, "searchtype": "owner"}
        try:
            result = await runtime.harness.query_execute(
                principal, "whm.listaccts", None, arguments
            )
            return result.model_dump(mode="json")
        except Exception as exc:
            raise _tool_error(exc) from exc

    @mcp.tool(
        description=(
            "Resolve a cPanel account by UID, username, domain, contact email, or IP. "
            "Only accounts in the caller's scope are considered."
        ),
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True),
        structured_output=True,
    )
    async def account_resolve(identifier: str) -> dict[str, Any]:
        try:
            return await runtime.harness.accounts.resolve(current_principal(), identifier)
        except Exception as exc:
            raise _tool_error(exc) from exc

    @mcp.tool(
        description=(
            "Inspect one cPanel account identified by UID, username, domain, contact email, or IP."
        ),
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True),
        structured_output=True,
    )
    async def account_inspect(account: str) -> dict[str, Any]:
        try:
            resolved = await runtime.harness.accounts.resolve(current_principal(), account)
            canonical_account = str(resolved["canonical_username"])
            result = await runtime.harness.query_execute(
                current_principal(),
                "whm.accountsummary",
                canonical_account,
                {"user": canonical_account},
            )
            payload = result.model_dump(mode="json")
            payload["resolved"] = resolved
            return payload
        except Exception as exc:
            raise _tool_error(exc) from exc

    @mcp.tool(
        description=(
            "Build a correlated, normalized, read-only technical dossier for a cPanel account. "
            "The identifier may be a UID, username, domain, contact email, or IP."
        ),
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True),
        structured_output=True,
    )
    async def account_dossier(identifier: str, sections: list[str] | None = None) -> dict[str, Any]:
        try:
            return await runtime.harness.accounts.dossier(current_principal(), identifier, sections)
        except Exception as exc:
            raise _tool_error(exc) from exc

    @mcp.tool(
        description=(
            "Run a correlated read-only health check for account status, capacity, backups, "
            "email authentication, FTP, PHP, and SSL."
        ),
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True),
        structured_output=True,
    )
    async def account_healthcheck(identifier: str) -> dict[str, Any]:
        try:
            return await runtime.harness.accounts.healthcheck(current_principal(), identifier)
        except Exception as exc:
            raise _tool_error(exc) from exc

    @mcp.tool(
        description=(
            "Search the live WHM/UAPI capability catalog by natural-language terms. "
            "Call capability_describe before execution."
        ),
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False),
        structured_output=True,
    )
    def capabilities_search(
        query: str,
        limit: int = 10,
        risk: str | None = None,
        api: str | None = None,
        intent: str | None = None,
    ) -> dict[str, Any]:
        try:
            items = runtime.harness.search_capabilities(
                current_principal(),
                query,
                limit=limit,
                risk=Risk(risk) if risk else None,
                api=ApiFamily(api) if api else None,
                intent=intent,
            )
            return {"items": items, "count": len(items)}
        except Exception as exc:
            raise _tool_error(exc) from exc

    @mcp.tool(
        description="Return the exact schema, risk, permissions, and examples for one capability.",
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False),
        structured_output=True,
    )
    def capability_describe(capability_id: str) -> dict[str, Any]:
        try:
            return runtime.harness.describe_capability(current_principal(), capability_id)
        except Exception as exc:
            raise _tool_error(exc) from exc

    @mcp.tool(
        description=(
            "Check server availability, role authorization, schema readiness, and account "
            "features before executing a capability."
        ),
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True),
        structured_output=True,
    )
    async def capability_check(capability_id: str, identifier: str | None = None) -> dict[str, Any]:
        try:
            return await runtime.harness.accounts.capability_check(
                current_principal(), capability_id, identifier
            )
        except Exception as exc:
            raise _tool_error(exc) from exc

    @mcp.tool(
        description=(
            "Execute a capability classified as read-only. Writes are rejected and must use "
            "action_prepare then action_execute."
        ),
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True),
        structured_output=False,
    )
    async def query_execute(
        capability_id: str, account: str | None = None, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        try:
            result = await runtime.harness.query_execute(
                current_principal(), capability_id, account, arguments or {}
            )
            return result.model_dump(mode="json")
        except Exception as exc:
            raise _tool_error(exc) from exc

    @mcp.tool(
        description=(
            "Validate and prepare a write without applying it. Returns impact, expiry, "
            "and an exact confirmation phrase when human approval is required."
        ),
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
        ),
        structured_output=True,
    )
    async def action_prepare(
        capability_id: str,
        account: str | None = None,
        arguments: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        try:
            return await runtime.harness.prepare_action(
                current_principal(),
                capability_id,
                account,
                arguments or {},
                idempotency_key,
            )
        except Exception as exc:
            raise _tool_error(exc) from exc

    @mcp.tool(
        description=(
            "Execute one previously prepared write. For destructive operations, pass the exact "
            "human-approved confirmation phrase returned by action_prepare."
        ),
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True
        ),
        structured_output=True,
    )
    async def action_execute(
        preparation_id: str,
        confirmation_phrase: str | None = None,
        as_job: bool = False,
    ) -> dict[str, Any]:
        try:
            if as_job:
                return runtime.harness.start_action_job(
                    current_principal(), preparation_id, confirmation_phrase
                )
            result = await runtime.harness.execute_action(
                current_principal(), preparation_id, confirmation_phrase
            )
            return result.model_dump(mode="json")
        except Exception as exc:
            raise _tool_error(exc) from exc

    @mcp.tool(
        description="Cancel an action that is still in prepared state.",
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False
        ),
        structured_output=True,
    )
    def action_cancel(preparation_id: str) -> dict[str, Any]:
        try:
            return runtime.harness.cancel_action(current_principal(), preparation_id)
        except Exception as exc:
            raise _tool_error(exc) from exc

    @mcp.tool(
        description=(
            "Register an independent administrator approval for a destructive action when "
            "two-person approval is enabled. The action author cannot self-approve."
        ),
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False
        ),
        structured_output=True,
    )
    def action_approve(preparation_id: str) -> dict[str, Any]:
        try:
            return runtime.harness.approve_action(current_principal(), preparation_id)
        except Exception as exc:
            raise _tool_error(exc) from exc

    @mcp.tool(
        description="Return the state and sanitized result of a long-running job.",
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False),
        structured_output=True,
    )
    def job_get(job_id: str) -> dict[str, Any]:
        try:
            return runtime.harness.get_job(current_principal(), job_id)
        except Exception as exc:
            raise _tool_error(exc) from exc

    @mcp.tool(
        description=(
            "Search sanitized audit events. Administrators see all events; other roles see only "
            "their own activity."
        ),
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False),
        structured_output=True,
    )
    def audit_search(limit: int = 50, correlation_id: str | None = None) -> dict[str, Any]:
        try:
            items = runtime.harness.audit_search(current_principal(), limit, correlation_id)
            return {"items": items, "count": len(items)}
        except Exception as exc:
            raise _tool_error(exc) from exc

    @mcp.tool(
        description=(
            "Return sanitized process-local operation counts and latency aggregates. "
            "Administrator only; no account names or payloads are exposed."
        ),
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False),
        structured_output=True,
    )
    def observability_snapshot() -> dict[str, Any]:
        try:
            return runtime.harness.observability_snapshot(current_principal())
        except Exception as exc:
            raise _tool_error(exc) from exc

    return mcp, runtime


def main() -> None:
    settings = get_settings()
    settings.ensure_runtime_secrets()
    mcp, _ = create_server(settings)
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
