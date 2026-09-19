from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .cpanel import CPanelError
from .dns_workflows import _HOSTNAME
from .models import ApiFamily, Capability, Preparation, Risk, Role

if TYPE_CHECKING:
    from .harness import Harness


class SubdomainWorkflows:
    """Removal of a subdomain of the account, confirmed against the account's own domain list.

    The removal goes through cPanel API 2 (there is no UAPI function for it). Only a domain
    listed under the account's sub_domains can be removed: the main, addon and parked domains
    are refused. The document root is left in place and reported, so it can be trashed
    separately.
    """

    def __init__(self, harness: Harness):
        self.harness = harness

    async def prepare_remove(
        self, account: str | None, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        if not account:
            raise CPanelError("subdomain workflows require an account", code="ACCOUNT_REQUIRED")
        domain = self._domain(str(arguments["domain"]))
        entries = await self._subdomains(account)
        match = next((e for e in entries if e["domain"] == domain), None)
        if match is None:
            raise CPanelError(
                f"{domain} is not a subdomain of this account",
                code="SUBDOMAIN_NOT_FOUND",
                category="validation",
                details={"subdomains": [e["domain"] for e in entries]},
            )
        return {"domain": domain, "subdomain": match, "subdomains": entries}

    async def execute_remove(self, preparation: Preparation) -> dict[str, Any]:
        account = preparation.account
        before = preparation.before_state or {}
        domain = before["domain"]
        subdomain = before["subdomain"]
        tried: list[str] = []
        error: CPanelError | None = None
        for form in self._forms(domain):
            tried.append(form)
            try:
                await self.harness.cpanel.call(
                    self._capability(), account, {"domain": form}, retry_safe=False
                )
                error = None
                break
            except CPanelError as exc:
                error = exc
                if exc.code == "UPSTREAM_NETWORK_ERROR":
                    after = await self._list_after_ambiguous_write(account)
                    if not any(e["domain"] == domain for e in after):
                        return self._result(domain, subdomain, after, reconciled=True)
                    raise self._unknown_write_error() from exc
        if error is not None:
            raise CPanelError(
                str(error),
                code=error.code,
                category=error.category,
                details={"domain_formats_tried": tried},
                hint="cPanel refused every accepted spelling of the subdomain name.",
            ) from error
        after = await self._subdomains(account)
        return self._result(domain, subdomain, after, reconciled=False)

    def _result(
        self,
        domain: str,
        subdomain: dict[str, Any],
        after: list[dict[str, Any]],
        *,
        reconciled: bool,
    ) -> dict[str, Any]:
        verified = not any(e["domain"] == domain for e in after)
        data: dict[str, Any] = {
            "changed": True,
            "documentroot_left_in_place": subdomain.get("documentroot"),
        }
        if reconciled:
            data["reconciled_after_transport_error"] = True
        return {
            "data": data,
            "after_state": after,
            "verified": verified,
            "warnings": ([] if verified else ["the subdomain is still listed after the removal"]),
        }

    async def _subdomains(self, account: str | None) -> list[dict[str, Any]]:
        capability = self.harness._get_capability("uapi.DomainInfo.domains_data")
        result = await self.harness.cpanel.call(
            capability, account, {"format": "hash"}, retry_safe=True
        )
        return self._entries(result)

    async def _list_after_ambiguous_write(self, account: str | None) -> list[dict[str, Any]]:
        try:
            return await self._subdomains(account)
        except CPanelError as exc:
            if exc.code != "UPSTREAM_NETWORK_ERROR":
                raise
            raise self._unknown_write_error() from exc

    @staticmethod
    def _capability() -> Capability:
        return Capability(
            id="api2.SubDomain.delsubdomain",
            api=ApiFamily.API2,
            module="SubDomain",
            function="delsubdomain",
            title="delsubdomain",
            description="Internal typed workflow operation.",
            risk=Risk.DESTRUCTIVE,
            required_role=Role.OPERATOR,
            upstream_profile="operator",
            input_schema={"type": "object", "additionalProperties": True},
            schema_source="official_cpanel_docs",
            curated=True,
        )

    @staticmethod
    def _unknown_write_error() -> CPanelError:
        return CPanelError(
            "subdomain removal outcome could not be reconciled",
            code="SUBDOMAIN_WRITE_STATE_UNKNOWN",
            details={"state_unknown": True},
            retryable=False,
            hint="List the account's domains before retrying the removal.",
        )

    @staticmethod
    def _forms(domain: str) -> list[str]:
        """The spellings cPanel accepts: sub_example.com first, then sub.example.com."""
        label, _, root = domain.partition(".")
        return [f"{label}_{root}", domain]

    @staticmethod
    def _domain(value: str) -> str:
        domain = value.strip().rstrip(".").casefold()
        if domain.count(".") < 2 or not _HOSTNAME.match(domain):
            raise CPanelError(
                f"{value!r} is not a subdomain name (expected label.example.com)",
                code="SUBDOMAIN_INVALID_VALUE",
                category="validation",
            )
        return domain

    @classmethod
    def _entries(cls, result: Any) -> list[dict[str, Any]]:
        data = result.get("data") if isinstance(result, dict) else None
        subs = data.get("sub_domains") if isinstance(data, dict) else None
        entries: list[dict[str, Any]] = []
        for item in subs if isinstance(subs, list) else []:
            if isinstance(item, str):
                entries.append({"domain": item.strip().rstrip(".").casefold()})
            elif isinstance(item, dict) and isinstance(item.get("domain"), str):
                entries.append(
                    {
                        "domain": item["domain"].strip().rstrip(".").casefold(),
                        "documentroot": item.get("documentroot"),
                    }
                )
        return entries
