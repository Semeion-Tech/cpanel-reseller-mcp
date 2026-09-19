from __future__ import annotations

from typing import Any

import pytest

from reseller_mcp.catalog import Catalog
from reseller_mcp.cpanel import CPanelError
from reseller_mcp.harness import HarnessError
from reseller_mcp.models import Preparation, Risk, Role
from reseller_mcp.subdomain_workflows import SubdomainWorkflows

MAIN = {"domain": "example.com", "documentroot": "/home/acct/public_html", "type": "main_domain"}


def _sub(domain: str, root: str | None = None) -> dict[str, Any]:
    return {
        "domain": domain,
        "documentroot": root or f"/home/acct/public_html/{domain.split('.')[0]}",
        "type": "sub_domain",
    }


class SubdomainCPanel:
    """domains_data plus API 2 delsubdomain, which accepts only some spellings."""

    def __init__(self, subdomains: list[str], accepts: tuple[str, ...] = ("underscore",)) -> None:
        self.subdomains = list(subdomains)
        self.accepts = accepts
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.lose_response = False
        self.lose_and_keep = False

    async def call(self, capability, account, arguments, *, retry_safe=False):
        name = capability.id.rsplit(".", 1)[-1]
        self.calls.append((name, dict(arguments)))
        if name == "domains_data":
            return {
                "status": 1,
                "data": {
                    "main_domain": MAIN,
                    "addon_domains": [_sub("addon.net")],
                    "parked_domains": [],
                    "sub_domains": [_sub(item) for item in self.subdomains],
                },
            }
        if name == "delsubdomain":
            requested = arguments["domain"]
            label, _, root = next(
                (item.partition(".") for item in self.subdomains if requested in self._forms(item)),
                (None, None, None),
            )
            if label is None or self._form_of(requested) not in self.accepts:
                raise CPanelError(
                    f"The subdomain {requested} does not exist.",
                    code="UPSTREAM_OPERATION_FAILED",
                )
            if self.lose_and_keep:
                raise CPanelError("connection lost", code="UPSTREAM_NETWORK_ERROR")
            self.subdomains = [s for s in self.subdomains if s != f"{label}.{root}"]
            if self.lose_response:
                raise CPanelError("connection lost", code="UPSTREAM_NETWORK_ERROR")
            return [{"result": 1}]
        raise AssertionError(f"unexpected call: {name}")

    @staticmethod
    def _forms(domain: str) -> list[str]:
        label, _, root = domain.partition(".")
        return [f"{label}_{root}", domain]

    @staticmethod
    def _form_of(value: str) -> str:
        return "underscore" if "_" in value.split(".")[0] else "dot"


class WorkflowHarness:
    def __init__(self, cpanel: SubdomainCPanel) -> None:
        self.cpanel = cpanel

    def _get_capability(self, capability_id: str) -> Any:
        return type("CapabilityRef", (), {"id": capability_id})()


async def _remove(cpanel: SubdomainCPanel, domain: str) -> tuple[dict[str, Any], dict[str, Any]]:
    workflows = SubdomainWorkflows(WorkflowHarness(cpanel))
    arguments = {"domain": domain}
    before = await workflows.prepare_remove("acct", arguments)
    preparation = Preparation.model_construct(
        account="acct", arguments=arguments, before_state=before
    )
    return before, await workflows.execute_remove(preparation)


@pytest.mark.asyncio
async def test_subdomain_is_removed_with_the_underscore_spelling_and_verified() -> None:
    cpanel = SubdomainCPanel(["app.example.com", "blog.example.com"])
    before, result = await _remove(cpanel, "app.example.com")

    assert before["subdomain"]["documentroot"] == "/home/acct/public_html/app"
    assert result["verified"] is True
    assert result["data"]["documentroot_left_in_place"] == "/home/acct/public_html/app"
    assert cpanel.subdomains == ["blog.example.com"]
    assert [args for name, args in cpanel.calls if name == "delsubdomain"] == [
        {"domain": "app_example.com"}
    ]


@pytest.mark.asyncio
async def test_the_dotted_spelling_is_tried_when_the_underscore_one_is_refused() -> None:
    cpanel = SubdomainCPanel(["app.example.com"], accepts=("dot",))
    _, result = await _remove(cpanel, "APP.example.com.")

    assert result["verified"] is True
    assert [args["domain"] for name, args in cpanel.calls if name == "delsubdomain"] == [
        "app_example.com",
        "app.example.com",
    ]


@pytest.mark.asyncio
async def test_a_refusal_of_both_spellings_reports_what_was_tried() -> None:
    cpanel = SubdomainCPanel(["app.example.com"], accepts=())
    with pytest.raises(CPanelError) as error:
        await _remove(cpanel, "app.example.com")

    assert error.value.code == "UPSTREAM_OPERATION_FAILED"
    assert error.value.details == {"domain_formats_tried": ["app_example.com", "app.example.com"]}
    assert cpanel.subdomains == ["app.example.com"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "domain", ["example.com", "addon.net", "other.example.com", "www.addon.net"]
)
async def test_only_a_listed_subdomain_can_be_removed(domain: str) -> None:
    cpanel = SubdomainCPanel(["app.example.com"])
    workflows = SubdomainWorkflows(WorkflowHarness(cpanel))

    with pytest.raises(CPanelError) as error:
        await workflows.prepare_remove("acct", {"domain": domain})

    assert error.value.code in {"SUBDOMAIN_NOT_FOUND", "SUBDOMAIN_INVALID_VALUE"}
    assert not any(name == "delsubdomain" for name, _ in cpanel.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("domain", ["", "app", "bad domain.example.com", "a..example.com"])
async def test_malformed_names_are_rejected(domain: str) -> None:
    workflows = SubdomainWorkflows(WorkflowHarness(SubdomainCPanel([])))
    with pytest.raises(CPanelError) as error:
        await workflows.prepare_remove("acct", {"domain": domain})
    assert error.value.code == "SUBDOMAIN_INVALID_VALUE"


@pytest.mark.asyncio
async def test_a_lost_response_after_the_removal_is_reconciled() -> None:
    cpanel = SubdomainCPanel(["app.example.com"])
    cpanel.lose_response = True
    _, result = await _remove(cpanel, "app.example.com")

    assert result["verified"] is True
    assert result["data"]["reconciled_after_transport_error"] is True


@pytest.mark.asyncio
async def test_a_lost_response_without_a_removal_reports_unknown_state() -> None:
    cpanel = SubdomainCPanel(["app.example.com"])
    cpanel.lose_and_keep = True
    with pytest.raises(CPanelError) as error:
        await _remove(cpanel, "app.example.com")
    assert error.value.code == "SUBDOMAIN_WRITE_STATE_UNKNOWN"


def test_the_capability_is_destructive_and_typed(tmp_path) -> None:
    capability = {c.id: c for c in Catalog(tmp_path / "missing.json").load()}[
        "workflow.subdomain_remove"
    ]
    assert (capability.risk, capability.required_role) == (Risk.DESTRUCTIVE, Role.ADMIN)
    assert capability.input_schema["required"] == ["domain"]
    assert capability.input_schema["additionalProperties"] is False


@pytest.mark.asyncio
async def test_removal_runs_through_the_harness_with_the_confirmation_phrase(
    harness, admin
) -> None:
    harness.cpanel = SubdomainCPanel(["app.example.com"])
    prepared = await harness.prepare_action(
        admin, "workflow.subdomain_remove", "acctalpha", {"domain": "app.example.com"}
    )

    assert prepared["risk"] == "destructive"
    assert prepared["confirmation_phrase"] == "CONFIRM subdomain_remove acctalpha"
    with pytest.raises(HarnessError) as error:
        await harness.execute_action(admin, prepared["preparation_id"], "wrong")
    assert error.value.code == "CONFIRMATION_REQUIRED"

    result = await harness.execute_action(
        admin, prepared["preparation_id"], prepared["confirmation_phrase"]
    )
    assert (result.ok, result.verified) == (True, True)
    assert harness.cpanel.subdomains == []
