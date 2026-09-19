from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from .cpanel import CPanelError
from .dns_workflows import _HOSTNAME
from .models import ApiFamily, Capability, Preparation, Risk, Role

if TYPE_CHECKING:
    from .harness import Harness

# redirect_www of Mime::add_redirect: 0 = with and without www, 1 = without, 2 = with.
WWW_MODES = {"both": 0, "without_www": 1, "with_www": 2}
_TEMPORARY = {"temp", "temporary", "302", "307"}
_PERMANENT = {"permanent", "301", "308"}


class RedirectWorkflows:
    """Typed, account-scoped domain redirects backed by cPanel UAPI Mime functions.

    cPanel has no edit operation, so replacing a destination is a delete plus an add; the old
    redirect is restored if the add fails after the delete succeeded.
    """

    def __init__(self, harness: Harness):
        self.harness = harness

    async def prepare_ensure(
        self, account: str | None, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        if not account:
            raise CPanelError("redirect workflows require an account", code="ACCOUNT_REQUIRED")
        request = self._request(arguments)
        current = await self._list(account)
        same_domain = [r for r in current if self._same_domain(r["domain"], request["domain"])]
        matches = [r for r in same_domain if r["src"] == request["src"]]
        plan: dict[str, Any]
        if len(matches) > 1:
            raise CPanelError(
                "more than one redirect exists for this domain and source path",
                code="REDIRECT_NOT_UNIQUE",
                category="validation",
            )
        if not matches:
            plan = {"operation": "add"}
        elif self._matches(matches[0], request):
            plan = {"operation": "noop", "reason": "the redirect already exists"}
        elif arguments.get("replace_existing", False):
            plan = {"operation": "replace", "existing": matches[0]}
        else:
            raise CPanelError(
                "a different redirect already exists for this source; set replace_existing "
                "to replace it",
                code="REDIRECT_CONFLICT",
                category="validation",
                details={"existing": matches[0]},
            )
        return {
            "domain": request["domain"],
            "src": request["src"],
            "records": same_domain,
            "request": request,
            "plan": plan,
        }

    async def execute_ensure(self, preparation: Preparation) -> dict[str, Any]:
        account = preparation.account
        before = preparation.before_state or {}
        plan = before["plan"]
        request = before["request"]
        if plan["operation"] == "noop":
            after = await self._list(account)
            return {
                "data": {"changed": False, "reason": plan["reason"]},
                "after_state": self._for_domain(after, request["domain"]),
                "verified": self._present(after, request),
                "warnings": [],
            }

        warnings: list[str] = []
        if plan["operation"] == "replace":
            existing = plan["existing"]
            await self._delete_reconciled(account, existing)
            try:
                await self._add(account, request)
            except CPanelError as exc:
                restored = await self._restore(account, existing)
                raise CPanelError(
                    "the old redirect was removed but the new one could not be created",
                    code="REDIRECT_REPLACE_FAILED",
                    details={"old_redirect_restored": restored, "cause": exc.code},
                    hint="Read the redirects of the domain before retrying.",
                ) from exc
        else:
            try:
                await self._add(account, request)
            except CPanelError as exc:
                if exc.code != "UPSTREAM_NETWORK_ERROR":
                    raise
                after = await self._list_after_ambiguous_write(account)
                if self._present(after, request):
                    return {
                        "data": {"changed": True, "reconciled_after_transport_error": True},
                        "after_state": self._for_domain(after, request["domain"]),
                        "verified": True,
                        "warnings": ["redirect write response was lost; state was reconciled"],
                    }
                raise self._unknown_write_error() from exc

        after = await self._list(account)
        verified = self._present(after, request)
        if not verified:
            warnings.append("the redirect was not found after the write")
        return {
            "data": {"changed": True},
            "after_state": self._for_domain(after, request["domain"]),
            "verified": verified,
            "warnings": warnings,
        }

    async def prepare_remove(
        self, account: str | None, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        if not account:
            raise CPanelError("redirect workflows require an account", code="ACCOUNT_REQUIRED")
        domain = self._domain(str(arguments["domain"]))
        src = self._src(str(arguments.get("src", "/")))
        destination = self._destination(str(arguments["destination"]))
        current = await self._list(account)
        same_domain = [r for r in current if self._same_domain(r["domain"], domain)]
        matches = [
            r
            for r in same_domain
            if r["src"] == src and self._same_destination(r["destination"], destination)
        ]
        if len(matches) != 1:
            raise CPanelError(
                "the redirect is not uniquely identified by domain, source and destination",
                code="REDIRECT_NOT_FOUND",
                category="validation",
            )
        return {
            "domain": domain,
            "src": src,
            "records": same_domain,
            "plan": {"operation": "remove", "existing": matches[0]},
        }

    async def execute_remove(self, preparation: Preparation) -> dict[str, Any]:
        account = preparation.account
        before = preparation.before_state or {}
        existing = before["plan"]["existing"]
        await self._delete_reconciled(account, existing)
        after = await self._list(account)
        verified = not any(self._identical(r, existing) for r in after)
        return {
            "data": {"changed": True},
            "after_state": self._for_domain(after, existing["domain"]),
            "verified": verified,
            "warnings": [] if verified else ["the redirect is still listed after the removal"],
        }

    # -- cPanel calls ---------------------------------------------------------------------

    async def _list(self, account: str | None) -> list[dict[str, Any]]:
        capability = self.harness._get_capability("uapi.Mime.list_redirects")
        result = await self.harness.cpanel.call(capability, account, {}, retry_safe=True)
        return self._records(result)

    async def _list_after_ambiguous_write(self, account: str | None) -> list[dict[str, Any]]:
        try:
            return await self._list(account)
        except CPanelError as exc:
            if exc.code != "UPSTREAM_NETWORK_ERROR":
                raise
            raise self._unknown_write_error() from exc

    async def _add(self, account: str | None, request: dict[str, Any]) -> Any:
        arguments = {
            "domain": request["domain"],
            "redirect": request["destination"],
            "src": request["src"],
            "type": request["type"],
            "redirect_wildcard": 1 if request["wildcard"] else 0,
            "redirect_www": WWW_MODES[request["www"]],
        }
        return await self.harness.cpanel.call(
            self._capability("add_redirect", Risk.REVERSIBLE_WRITE), account, arguments
        )

    async def _delete(self, account: str | None, record: dict[str, Any]) -> Any:
        arguments: dict[str, Any] = {
            "domain": record["domain"],
            "src": record["src"],
            "redirect": record["destination"],
        }
        if record.get("docroot"):
            arguments["docroot"] = record["docroot"]
        return await self.harness.cpanel.call(
            self._capability("delete_redirect", Risk.DESTRUCTIVE), account, arguments
        )

    async def _delete_reconciled(self, account: str | None, record: dict[str, Any]) -> None:
        try:
            await self._delete(account, record)
        except CPanelError as exc:
            if exc.code != "UPSTREAM_NETWORK_ERROR":
                raise
            after = await self._list_after_ambiguous_write(account)
            if any(self._identical(r, record) for r in after):
                raise self._unknown_write_error() from exc

    async def _restore(self, account: str | None, record: dict[str, Any]) -> bool:
        request = {
            "domain": record["domain"],
            "destination": record["destination"],
            "src": record["src"],
            "type": record["kind"],
            "wildcard": bool(record["wildcard"]),
            "www": "both",
        }
        try:
            await self._add(account, request)
            return self._present(await self._list(account), request)
        except CPanelError:
            return False

    @staticmethod
    def _capability(function: str, risk: Risk) -> Capability:
        return Capability(
            id=f"uapi.Mime.{function}",
            api=ApiFamily.UAPI,
            module="Mime",
            function=function,
            title=function.replace("_", " "),
            description="Internal typed workflow operation.",
            risk=risk,
            required_role=Role.OPERATOR,
            upstream_profile="operator",
            input_schema={"type": "object", "additionalProperties": True},
            schema_source="official_cpanel_docs",
            curated=True,
        )

    @staticmethod
    def _unknown_write_error() -> CPanelError:
        return CPanelError(
            "redirect write outcome could not be reconciled",
            code="REDIRECT_WRITE_STATE_UNKNOWN",
            details={"state_unknown": True},
            retryable=False,
            hint="List the redirects of the domain before retrying the write.",
        )

    # -- parsing and comparison -----------------------------------------------------------

    @classmethod
    def _request(cls, arguments: dict[str, Any]) -> dict[str, Any]:
        request = {
            "domain": cls._domain(str(arguments["domain"])),
            "destination": cls._destination(str(arguments["destination"])),
            "src": cls._src(str(arguments.get("src", "/"))),
            "type": str(arguments.get("type", "permanent")),
            "wildcard": bool(arguments.get("wildcard", False)),
            "www": str(arguments.get("www", "both")),
        }
        if request["type"] not in {"permanent", "temp"}:
            raise cls._invalid("type must be permanent or temp")
        if request["www"] not in WWW_MODES:
            raise cls._invalid(f"www must be one of {', '.join(WWW_MODES)}")
        cls._reject_loop(request)
        return request

    @staticmethod
    def _invalid(message: str) -> CPanelError:
        return CPanelError(message, code="REDIRECT_INVALID_VALUE", category="validation")

    @classmethod
    def _domain(cls, value: str) -> str:
        domain = value.strip().rstrip(".").casefold()
        if not _HOSTNAME.match(domain) or "." not in domain:
            raise cls._invalid(f"{value!r} is not a valid domain name")
        return domain

    @classmethod
    def _src(cls, value: str) -> str:
        src = value.strip()
        if not src.startswith("/") or any(ch.isspace() or ord(ch) < 32 for ch in src):
            raise cls._invalid("src must be a path starting with / and without whitespace")
        if any(part == ".." for part in src.split("/")) or "?" in src or "#" in src:
            raise cls._invalid("src must be a plain path without .., query or fragment")
        return src

    @classmethod
    def _destination(cls, value: str) -> str:
        destination = value.strip()
        if not destination or len(destination) > 2048:
            raise cls._invalid("destination must be a URL of at most 2048 characters")
        if any(ch.isspace() or ord(ch) < 32 for ch in destination):
            raise cls._invalid("destination must not contain whitespace or control characters")
        parts = urlsplit(destination)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            raise cls._invalid("destination must be an absolute http or https URL")
        if parts.username or parts.password:
            raise cls._invalid("destination must not embed credentials")
        return destination

    @classmethod
    def _reject_loop(cls, request: dict[str, Any]) -> None:
        target = urlsplit(request["destination"])
        host = (target.hostname or "").casefold()
        domain = request["domain"]
        if host not in {domain, f"www.{domain}"}:
            return
        path = target.path or "/"
        src = request["src"]
        if path == src or (request["wildcard"] and path.startswith(src.rstrip("/") + "/")):
            raise cls._invalid("the destination points back to the redirected source (loop)")

    @staticmethod
    def _same_domain(left: str, right: str) -> bool:
        return left.rstrip(".").casefold() == right.rstrip(".").casefold()

    @staticmethod
    def _same_destination(left: str, right: str) -> bool:
        def key(value: str) -> tuple[str, str, int | None, str, str]:
            parts = urlsplit(value.strip())
            return (
                parts.scheme.lower(),
                (parts.hostname or "").casefold(),
                parts.port,
                parts.path.rstrip("/") or "/",
                parts.query,
            )

        return key(left) == key(right)

    @staticmethod
    def _kind(record: dict[str, Any]) -> str:
        for field in ("type", "statuscode"):
            value = str(record.get(field, "")).casefold()
            if value in _TEMPORARY:
                return "temp"
            if value in _PERMANENT:
                return "permanent"
        return str(record.get("type", "")).casefold()

    @classmethod
    def _matches(cls, record: dict[str, Any], request: dict[str, Any]) -> bool:
        return (
            cls._same_domain(record["domain"], request["domain"])
            and record["src"] == request["src"]
            and cls._same_destination(record["destination"], request["destination"])
            and record["kind"] == request["type"]
            and bool(record["wildcard"]) == request["wildcard"]
        )

    @classmethod
    def _identical(cls, left: dict[str, Any], right: dict[str, Any]) -> bool:
        return (
            cls._same_domain(left["domain"], right["domain"])
            and left["src"] == right["src"]
            and cls._same_destination(left["destination"], right["destination"])
        )

    def _present(self, records: list[dict[str, Any]], request: dict[str, Any]) -> bool:
        return any(self._matches(record, request) for record in records)

    def _for_domain(self, records: list[dict[str, Any]], domain: str) -> list[dict[str, Any]]:
        return [r for r in records if self._same_domain(r["domain"], domain)]

    @classmethod
    def _records(cls, result: Any) -> list[dict[str, Any]]:
        data = result.get("data") if isinstance(result, dict) else result
        if not isinstance(data, list):
            return []
        records: list[dict[str, Any]] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            domain = item.get("urldomain") or item.get("domain")
            source = item.get("sourceurl") or item.get("source")
            destination = item.get("destination") or item.get("targeturl")
            if not (isinstance(domain, str) and isinstance(source, str)):
                continue
            if not isinstance(destination, str):
                continue
            try:
                wildcard = int(item.get("wildcard", 0) or 0)
            except (TypeError, ValueError):
                wildcard = 0
            records.append(
                {
                    "domain": domain,
                    "src": source if source.startswith("/") else f"/{source}",
                    "destination": destination,
                    "kind": cls._kind(item),
                    "wildcard": wildcard,
                    "www": item.get("matchwww"),
                    "docroot": item.get("docroot"),
                }
            )
        return records
