from __future__ import annotations

from typing import Any

import pytest

from reseller_mcp.catalog import Catalog
from reseller_mcp.cpanel import CPanelError
from reseller_mcp.harness import HarnessError
from reseller_mcp.models import Preparation, Risk, Role
from reseller_mcp.redirect_workflows import RedirectWorkflows

# Shape returned by uapi.Mime.list_redirects on the live server (captured 2026-09-19).
REAL_RECORD = {
    "domain": "promocaosaborquevaleouro.com.br",
    "sourceurl": "/",
    "wildcard_text": "",
    "wildcard": 0,
    "displaysourceurl": "/",
    "displaydomain": "promocaosaborquevaleouro.com.br",
    "docroot": "/home1/promocaosaborque/public_html",
    "source": "/",
    "urldomain": "promocaosaborquevaleouro.com.br",
    "statuscode": "301",
    "matchwww_text": "checked",
    "matchwww": 1,
    "kind": "rewrite",
    "type": "permanent",
    "targeturl": "https://www.saborquevaleouro.com.br/",
    "destination": "https://www.saborquevaleouro.com.br/",
    "opts": "L",
}


class RedirectCPanel:
    """In-memory Mime redirects with the response shape of the live server."""

    def __init__(self, records: list[dict[str, Any]] | None = None) -> None:
        self.records = [dict(record) for record in records or []]
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.fail_add_after_delete = False
        self.lose_add_response = False
        self.lose_add_and_drop = False
        self._deleted = False

    async def call(self, capability, account, arguments, *, retry_safe=False):
        name = capability.id.rsplit(".", 1)[-1]
        self.calls.append((name, dict(arguments)))
        if name == "list_redirects":
            return {"status": 1, "data": [dict(record) for record in self.records]}
        if name == "add_redirect":
            if self.fail_add_after_delete and self._deleted:
                self.fail_add_after_delete = False
                raise CPanelError("add failed", code="UPSTREAM_OPERATION_FAILED")
            if self.lose_add_and_drop:
                raise CPanelError("connection lost", code="UPSTREAM_NETWORK_ERROR")
            self.records.append(self._record(arguments))
            if self.lose_add_response:
                raise CPanelError("connection lost", code="UPSTREAM_NETWORK_ERROR")
            return {"status": 1, "data": None}
        if name == "delete_redirect":
            self._deleted = True
            self.records = [
                r
                for r in self.records
                if not (r["domain"] == arguments["domain"] and r["sourceurl"] == arguments["src"])
            ]
            return {"status": 1, "data": None}
        raise AssertionError(f"unexpected call: {name}")

    @staticmethod
    def _record(arguments: dict[str, Any]) -> dict[str, Any]:
        temporary = arguments["type"] == "temp"
        return {
            **REAL_RECORD,
            "domain": arguments["domain"],
            "urldomain": arguments["domain"],
            "displaydomain": arguments["domain"],
            "sourceurl": arguments["src"],
            "displaysourceurl": arguments["src"],
            "source": arguments["src"],
            "destination": arguments["redirect"],
            "targeturl": arguments["redirect"],
            "wildcard": arguments["redirect_wildcard"],
            # Observed on the live server: 0 for without_www, 1 for both and with_www.
            "matchwww": 0 if arguments["redirect_www"] == 1 else 1,
            "type": "temporary" if temporary else "permanent",
            "statuscode": "302" if temporary else "301",
        }

    def names(self) -> list[str]:
        return [name for name, _ in self.calls]


class WorkflowHarness:
    def __init__(self, cpanel: RedirectCPanel) -> None:
        self.cpanel = cpanel

    def _get_capability(self, capability_id: str) -> Any:
        return type("CapabilityRef", (), {"id": capability_id})()


ARGS = {"domain": "example.com", "destination": "https://www.example.org/"}


def _workflows(cpanel: RedirectCPanel) -> RedirectWorkflows:
    return RedirectWorkflows(WorkflowHarness(cpanel))


async def _ensure(
    cpanel: RedirectCPanel, arguments: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    workflows = _workflows(cpanel)
    before = await workflows.prepare_ensure("acct", arguments)
    preparation = Preparation.model_construct(
        account="acct", arguments=arguments, before_state=before
    )
    return before, await workflows.execute_ensure(preparation)


def test_real_list_redirects_shape_is_parsed() -> None:
    records = RedirectWorkflows._records({"status": 1, "data": [REAL_RECORD, "junk", {"x": 1}]})

    assert records == [
        {
            "domain": "promocaosaborquevaleouro.com.br",
            "src": "/",
            "destination": "https://www.saborquevaleouro.com.br/",
            "kind": "permanent",
            "wildcard": 0,
            "www": 1,
            "docroot": "/home1/promocaosaborque/public_html",
        }
    ]
    assert RedirectWorkflows._records({"status": 1, "data": []}) == []


@pytest.mark.asyncio
async def test_redirect_is_added_and_verified_with_the_documented_arguments() -> None:
    cpanel = RedirectCPanel()
    before, result = await _ensure(cpanel, ARGS)

    assert before["plan"]["operation"] == "add"
    assert result["verified"] is True
    assert cpanel.calls[1] == (
        "add_redirect",
        {
            "domain": "example.com",
            "redirect": "https://www.example.org/",
            "src": "/",
            "type": "permanent",
            "redirect_wildcard": 0,
            "redirect_www": 0,
        },
    )


@pytest.mark.asyncio
async def test_temporary_wildcard_redirect_and_www_mode_are_sent() -> None:
    cpanel = RedirectCPanel()
    arguments = {
        **ARGS,
        "src": "/old",
        "destination": "https://example.com/new",
        "type": "temp",
        "wildcard": True,
        "www": "with_www",
    }
    _, result = await _ensure(cpanel, arguments)

    sent = cpanel.calls[1][1]
    assert (sent["type"], sent["redirect_wildcard"], sent["redirect_www"]) == ("temp", 1, 2)
    assert result["verified"] is True


@pytest.mark.asyncio
async def test_same_redirect_is_a_noop_even_with_a_different_spelling() -> None:
    cpanel = RedirectCPanel([{**REAL_RECORD, "domain": "example.com", "urldomain": "example.com"}])
    arguments = {**ARGS, "destination": "HTTPS://WWW.SABORQUEVALEOURO.COM.BR"}
    before, result = await _ensure(cpanel, arguments)

    assert before["plan"]["operation"] == "noop"
    assert result["verified"] is True
    assert cpanel.names() == ["list_redirects", "list_redirects"]


@pytest.mark.asyncio
async def test_different_destination_needs_replace_existing() -> None:
    cpanel = RedirectCPanel([{**REAL_RECORD, "domain": "example.com", "urldomain": "example.com"}])
    with pytest.raises(CPanelError) as error:
        await _workflows(cpanel).prepare_ensure("acct", ARGS)
    assert error.value.code == "REDIRECT_CONFLICT"

    before, result = await _ensure(cpanel, {**ARGS, "replace_existing": True})
    assert before["plan"]["operation"] == "replace"
    assert result["verified"] is True
    assert [r["destination"] for r in cpanel.records] == ["https://www.example.org/"]
    assert cpanel.names() == [
        "list_redirects",
        "list_redirects",
        "delete_redirect",
        "add_redirect",
        "list_redirects",
    ]


@pytest.mark.asyncio
async def test_replace_restores_the_old_redirect_when_the_add_fails() -> None:
    old = {**REAL_RECORD, "domain": "example.com", "urldomain": "example.com"}
    cpanel = RedirectCPanel([old])
    cpanel.fail_add_after_delete = True
    workflows = _workflows(cpanel)
    arguments = {**ARGS, "replace_existing": True}
    before = await workflows.prepare_ensure("acct", arguments)
    preparation = Preparation.model_construct(
        account="acct", arguments=arguments, before_state=before
    )

    with pytest.raises(CPanelError) as error:
        await workflows.execute_ensure(preparation)

    assert error.value.code == "REDIRECT_REPLACE_FAILED"
    assert error.value.details == {
        "old_redirect_restored": True,
        "cause": "UPSTREAM_OPERATION_FAILED",
    }
    assert [r["destination"] for r in cpanel.records] == [old["destination"]]


@pytest.mark.asyncio
async def test_lost_response_after_the_write_is_reconciled() -> None:
    cpanel = RedirectCPanel()
    cpanel.lose_add_response = True
    _, result = await _ensure(cpanel, ARGS)

    assert result["verified"] is True
    assert result["data"]["reconciled_after_transport_error"] is True
    assert cpanel.names().count("add_redirect") == 1


@pytest.mark.asyncio
async def test_lost_response_without_a_write_reports_unknown_state() -> None:
    cpanel = RedirectCPanel()
    cpanel.lose_add_and_drop = True
    with pytest.raises(CPanelError) as error:
        await _ensure(cpanel, ARGS)
    assert error.value.code == "REDIRECT_WRITE_STATE_UNKNOWN"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {"destination": "ftp://example.org/"},
        {"destination": "javascript:alert(1)"},
        {"destination": "https://user:pass@example.org/"},
        {"destination": "https://example.org/a b"},
        {"destination": "/relative"},
        {"destination": "https://example.com/"},
        {"destination": "https://www.example.com/"},
        {"src": "/old", "destination": "https://example.com/old"},
        {"src": "/old", "destination": "https://example.com/old/x", "wildcard": True},
        {"src": "old"},
        {"src": "/a/../b"},
        {"src": "/a?b=1"},
        {"type": "gone"},
        {"www": "sometimes"},
        {"domain": "localhost"},
        {"domain": "bad domain.com"},
    ],
)
async def test_invalid_or_looping_requests_are_rejected(overrides: dict[str, Any]) -> None:
    cpanel = RedirectCPanel()
    with pytest.raises(CPanelError) as error:
        await _workflows(cpanel).prepare_ensure("acct", {**ARGS, **overrides})
    assert error.value.code == "REDIRECT_INVALID_VALUE"
    assert cpanel.calls == []


@pytest.mark.asyncio
async def test_same_host_with_a_different_path_is_not_a_loop() -> None:
    cpanel = RedirectCPanel()
    _, result = await _ensure(
        cpanel, {**ARGS, "src": "/old", "destination": "https://example.com/new"}
    )
    assert result["verified"] is True


@pytest.mark.asyncio
async def test_remove_needs_the_exact_destination_and_verifies() -> None:
    record = {**REAL_RECORD, "domain": "example.com", "urldomain": "example.com"}
    cpanel = RedirectCPanel([record, {**record, "sourceurl": "/keep", "source": "/keep"}])
    workflows = _workflows(cpanel)

    with pytest.raises(CPanelError) as error:
        await workflows.prepare_remove(
            "acct", {"domain": "example.com", "destination": "https://other.example/"}
        )
    assert error.value.code == "REDIRECT_NOT_FOUND"

    arguments = {"domain": "example.com", "destination": record["destination"]}
    before = await workflows.prepare_remove("acct", arguments)
    preparation = Preparation.model_construct(
        account="acct", arguments=arguments, before_state=before
    )
    result = await workflows.execute_remove(preparation)

    assert result["verified"] is True
    assert [r["sourceurl"] for r in cpanel.records] == ["/keep"]
    delete_call = next(args for name, args in cpanel.calls if name == "delete_redirect")
    assert delete_call["docroot"] == record["docroot"]


def test_redirect_and_subdomain_capabilities_are_curated_with_the_right_risk(tmp_path) -> None:
    capabilities = {item.id: item for item in Catalog(tmp_path / "missing.json").load()}

    ensure = capabilities["workflow.redirect_ensure"]
    assert (ensure.risk, ensure.required_role) == (Risk.REVERSIBLE_WRITE, Role.OPERATOR)
    assert ensure.input_schema["required"] == ["domain", "destination"]
    assert ensure.input_schema["additionalProperties"] is False

    remove = capabilities["workflow.redirect_remove"]
    assert remove.risk == Risk.DESTRUCTIVE
    assert remove.input_schema["required"] == ["domain", "destination"]

    subdomain = capabilities["uapi.SubDomain.addsubdomain"]
    assert subdomain.curated is True
    assert subdomain.risk == Risk.REVERSIBLE_WRITE
    assert subdomain.input_schema["required"] == ["domain", "rootdomain"]


@pytest.mark.asyncio
async def test_redirect_workflows_run_through_the_harness(harness, admin) -> None:
    harness.cpanel = RedirectCPanel()
    prepared = await harness.prepare_action(admin, "workflow.redirect_ensure", "acctalpha", ARGS)
    assert prepared["risk"] == "reversible_write"
    assert prepared["requires_confirmation"] is False
    assert prepared["before_state"]["plan"]["operation"] == "add"
    result = await harness.execute_action(admin, prepared["preparation_id"])
    assert (result.ok, result.verified) == (True, True)

    removal = await harness.prepare_action(admin, "workflow.redirect_remove", "acctalpha", ARGS)
    assert removal["risk"] == "destructive"
    assert removal["confirmation_phrase"] == "CONFIRM redirect_remove acctalpha"
    with pytest.raises(HarnessError) as error:
        await harness.execute_action(admin, removal["preparation_id"], "wrong")
    assert error.value.code == "CONFIRMATION_REQUIRED"
    result = await harness.execute_action(
        admin, removal["preparation_id"], removal["confirmation_phrase"]
    )
    assert (result.ok, result.verified) == (True, True)
    assert harness.cpanel.records == []


class SubdomainCPanel:
    def __init__(self) -> None:
        self.subdomains: list[str] = []
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call(self, capability, account, arguments, *, retry_safe=False):
        name = capability.id.rsplit(".", 1)[-1]
        self.calls.append((name, dict(arguments)))
        if name == "domains_data":
            return {
                "status": 1,
                "data": {
                    "main_domain": {"domain": "example.com"},
                    "sub_domains": [{"domain": item} for item in self.subdomains],
                },
            }
        if name == "addsubdomain":
            self.subdomains.append(f"{arguments['domain']}.{arguments['rootdomain']}")
            return {"status": 1, "data": None}
        raise AssertionError(f"unexpected call: {name}")


@pytest.mark.asyncio
async def test_subdomain_is_created_and_verified_from_the_domain_listing(harness, admin) -> None:
    harness.cpanel = SubdomainCPanel()
    prepared = await harness.prepare_action(
        admin,
        "uapi.SubDomain.addsubdomain",
        "acctalpha",
        {"domain": "app", "rootdomain": "example.com", "dir": "public_html/app"},
    )
    assert prepared["risk"] == "reversible_write"
    assert prepared["requires_confirmation"] is False

    result = await harness.execute_action(admin, prepared["preparation_id"])

    assert (result.ok, result.verified) == (True, True)
    assert harness.cpanel.subdomains == ["app.example.com"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "directory",
    ["../etc", "public_html/../.ssh", "/etc/passwd", ".ssh", "mail", "public_html_evil/x", "/"],
)
async def test_subdomain_document_root_is_confined_to_public_html(
    harness, admin, directory: str
) -> None:
    harness.cpanel = SubdomainCPanel()
    with pytest.raises(HarnessError) as error:
        await harness.prepare_action(
            admin,
            "uapi.SubDomain.addsubdomain",
            "acctalpha",
            {"domain": "app", "rootdomain": "example.com", "dir": directory},
        )
    assert error.value.code == "PATH_OUTSIDE_ALLOWED_ROOT"
    assert harness.cpanel.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("label", ["a.b", "-app", "app-", "a b", "app_x", ""])
async def test_subdomain_label_must_be_a_single_hostname_label(harness, admin, label: str) -> None:
    harness.cpanel = SubdomainCPanel()
    with pytest.raises(HarnessError) as error:
        await harness.prepare_action(
            admin,
            "uapi.SubDomain.addsubdomain",
            "acctalpha",
            {"domain": label, "rootdomain": "example.com"},
        )
    assert error.value.code == "INVALID_ARGUMENTS"


@pytest.mark.asyncio
async def test_a_different_www_mode_is_not_a_noop() -> None:
    existing = {**REAL_RECORD, "domain": "example.com", "urldomain": "example.com"}
    same = {**ARGS, "destination": existing["destination"]}

    both, _ = await _ensure(RedirectCPanel([existing]), same)
    with_www, _ = await _ensure(RedirectCPanel([existing]), {**same, "www": "with_www"})
    assert both["plan"]["operation"] == "noop"
    # both and with_www read back identically, so they cannot be told apart.
    assert with_www["plan"]["operation"] == "noop"

    with pytest.raises(CPanelError) as error:
        await _workflows(RedirectCPanel([existing])).prepare_ensure(
            "acct", {**same, "www": "without_www"}
        )
    assert error.value.code == "REDIRECT_CONFLICT"


@pytest.mark.asyncio
async def test_without_www_is_created_verified_and_restored_as_without_www() -> None:
    existing = {**REAL_RECORD, "domain": "example.com", "urldomain": "example.com", "matchwww": 0}
    cpanel = RedirectCPanel([existing])
    cpanel.fail_add_after_delete = True
    workflows = _workflows(cpanel)
    arguments = {**ARGS, "replace_existing": True}
    before = await workflows.prepare_ensure("acct", arguments)
    preparation = Preparation.model_construct(
        account="acct", arguments=arguments, before_state=before
    )

    with pytest.raises(CPanelError):
        await workflows.execute_ensure(preparation)

    restored = [args for name, args in cpanel.calls if name == "add_redirect"][-1]
    assert restored["redirect_www"] == 1

    created, result = await _ensure(RedirectCPanel(), {**ARGS, "www": "without_www"})
    assert created["plan"]["operation"] == "add"
    assert result["verified"] is True
