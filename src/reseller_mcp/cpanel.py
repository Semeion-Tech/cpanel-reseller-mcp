from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from .config import Settings
from .models import ApiFamily, Capability


class CPanelError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        code: str = "CPANEL_ERROR",
        details: Any = None,
        category: str = "upstream",
        retryable: bool = False,
        hint: str | None = None,
    ):
        super().__init__(message)
        self.code = code
        self.details = details
        self.category = category
        self.retryable = retryable
        self.hint = hint

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": str(self),
            "category": self.category,
            "retryable": self.retryable,
            "hint": self.hint,
            "details": self.details,
        }


def _operation_error(message: str) -> CPanelError:
    normalized = message.casefold()
    if "do not have the feature" in normalized or (
        "feature" in normalized and "disabled" in normalized
    ):
        return CPanelError(
            message,
            code="ACCOUNT_FEATURE_UNAVAILABLE",
            category="account_configuration",
            hint="Use capability_check for this account before retrying.",
        )
    if "provide" in normalized and "argument" in normalized:
        return CPanelError(
            message,
            code="UPSTREAM_INVALID_ARGUMENTS",
            category="validation",
            hint="The curated capability schema must declare this required argument.",
        )
    if "custom apache vhost templates" in normalized:
        return CPanelError(
            message,
            code="ACCOUNT_CONFIGURATION_UNSUPPORTED",
            category="account_configuration",
            hint="Inspect the custom Apache virtual-host configuration outside this capability.",
        )
    return CPanelError(message, code="UPSTREAM_OPERATION_FAILED")


def _query_items(values: dict[str, Any]) -> list[tuple[str, str | int | float | bool | None]]:
    items: list[tuple[str, str | int | float | bool | None]] = []
    for key, value in values.items():
        if value is None:
            continue
        if isinstance(value, bool):
            items.append((key, "1" if value else "0"))
        elif isinstance(value, list):
            items.extend((key, str(item)) for item in value)
        else:
            items.append((key, str(value)))
    return items


class CPanelClient:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        self.settings = settings
        self._client = httpx.AsyncClient(
            base_url=settings.cpanel_base_url,
            verify=settings.cpanel_verify_tls,
            timeout=settings.cpanel_timeout_seconds,
            transport=transport,
        )
        self._failures = 0
        self._circuit_opened_at: float | None = None

    async def close(self) -> None:
        await self._client.aclose()

    def _check_circuit(self) -> None:
        if self._circuit_opened_at is None:
            return
        if time.monotonic() - self._circuit_opened_at >= 30:
            self._circuit_opened_at = None
            self._failures = 0
            return
        raise CPanelError(
            "cPanel circuit breaker is open after repeated upstream failures",
            code="UPSTREAM_UNAVAILABLE",
        )

    async def call(
        self,
        capability: Capability,
        account: str | None,
        arguments: dict[str, Any],
        *,
        retry_safe: bool = False,
    ) -> Any:
        self._check_circuit()
        attempts = 3 if retry_safe else 1
        last_error: Exception | None = None
        for attempt in range(attempts):
            try:
                result = await self._call_once(capability, account, arguments)
                self._failures = 0
                self._circuit_opened_at = None
                return result
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_error = exc
                self._failures += 1
                if self._failures >= 5:
                    self._circuit_opened_at = time.monotonic()
                if attempt + 1 < attempts:
                    await asyncio.sleep(0.25 * (2**attempt))
        raise CPanelError(
            "cPanel network request failed",
            code="UPSTREAM_NETWORK_ERROR",
            details={"type": type(last_error).__name__ if last_error else "unknown"},
            retryable=True,
        ) from last_error

    async def _call_once(
        self, capability: Capability, account: str | None, arguments: dict[str, Any]
    ) -> Any:
        token = self.settings.upstream_token(capability.upstream_profile)
        headers = {"Authorization": f"whm {self.settings.cpanel_reseller}:{token}"}
        if capability.api == ApiFamily.WHM:
            function = capability.function
            params = {"api.version": 1, **arguments}
        elif capability.api == ApiFamily.UAPI:
            if not account:
                raise CPanelError("UAPI operations require an account", code="ACCOUNT_REQUIRED")
            function = "uapi_cpanel"
            params = {
                "api.version": 1,
                "cpanel.user": account,
                "cpanel.module": capability.module,
                "cpanel.function": capability.function,
                **arguments,
            }
        else:
            raise CPanelError("workflow cannot be sent directly to cPanel", code="INVALID_API")

        response = await self._client.get(
            f"/json-api/{function}", headers=headers, params=_query_items(params)
        )
        if response.status_code in {401, 403}:
            raise CPanelError(
                "cPanel rejected the upstream credential",
                code="UPSTREAM_AUTH_ERROR",
                details={"status": response.status_code},
            )
        if response.status_code >= 500:
            raise httpx.NetworkError(f"cPanel returned HTTP {response.status_code}")
        if response.status_code >= 400:
            raise CPanelError(
                "cPanel returned an HTTP error",
                code="UPSTREAM_HTTP_ERROR",
                details={"status": response.status_code},
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise CPanelError("cPanel returned invalid JSON", code="UPSTREAM_INVALID_JSON") from exc

        metadata = payload.get("metadata", {})
        if metadata and int(metadata.get("result", 0)) != 1:
            error = _operation_error(metadata.get("reason") or "cPanel operation failed")
            error.details = {"command": metadata.get("command")}
            raise error
        if capability.api == ApiFamily.UAPI:
            uapi = payload.get("data", {}).get("uapi", {})
            result = uapi.get("result", uapi)
            if isinstance(result, dict) and int(result.get("status", 1)) != 1:
                errors = result.get("errors") or ["UAPI operation failed"]
                raise _operation_error("; ".join(str(item) for item in errors))
            return result
        return payload.get("data", payload)
