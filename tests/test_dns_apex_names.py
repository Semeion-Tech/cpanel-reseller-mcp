from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from reseller_mcp.cpanel import CPanelError
from reseller_mcp.dns_workflows import DNSWorkflows
from reseller_mcp.models import Preparation

ZONE = "example.com"


def _b64(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


class RealShapeCPanel:
    """Zone that returns parse_zone in the shape cPanel really uses.

    The apex is reported as the absolute zone name in dname_raw, other names are relative to
    the zone, and all values are base64 encoded. Comment and control lines are interleaved.
    """

    def __init__(self, records: list[tuple[str, str, list[str]]]) -> None:
        self.serial = 2026082701
        self.lines: list[dict[str, Any]] = [
            {"type": "comment", "text_b64": _b64("; zone file"), "line_index": 0},
            {"type": "control", "text_b64": _b64("$TTL 14400"), "line_index": 1},
            {
                "type": "record",
                "record_type": "SOA",
                "dname_raw": f"{ZONE}.",
                "ttl": 86400,
                "line_index": 2,
                "data_b64": [
                    _b64("ns1.example.net."),
                    _b64("hostmaster.example.net."),
                    _b64(str(self.serial)),
                    _b64("86400"),
                    _b64("7200"),
                    _b64("3600000"),
                    _b64("86400"),
                ],
            },
        ]
        self.next_index = 3
        for name, record_type, data in records:
            self._append(name, record_type, data, 14400)
        self.writes: list[dict[str, Any]] = []

    def _append(self, name: str, record_type: str, data: list[str], ttl: int) -> None:
        self.lines.append(self._line(name, record_type, data, ttl, self.next_index))
        self.next_index += 1

    @staticmethod
    def _line(name: str, record_type: str, data: list[str], ttl: int, index: int) -> dict[str, Any]:
        return {
            "type": "record",
            "record_type": record_type,
            "dname_raw": name,
            "ttl": ttl,
            "line_index": index,
            "data_b64": [_b64(item) for item in data],
        }

    def names(self) -> list[tuple[str, str, list[str]]]:
        return [
            (
                line["dname_raw"],
                line["record_type"],
                [base64.b64decode(item).decode() for item in line["data_b64"]],
            )
            for line in self.lines
            if line["type"] == "record" and line["record_type"] != "SOA"
        ]

    async def call(self, capability, account, arguments, *, retry_safe=False):
        if capability.id == "uapi.DNS.parse_zone":
            return {"status": 1, "data": [dict(line) for line in self.lines]}
        assert capability.id == "uapi.DNS.mass_edit_zone"
        assert arguments["serial"] == self.serial, "stale serial"
        self.writes.append(dict(arguments))
        if "add" in arguments:
            record = json.loads(arguments["add"])
            self._append(record["dname"], record["record_type"], record["data"], record["ttl"])
        elif "edit" in arguments:
            record = json.loads(arguments["edit"])
            index = record["line_index"]
            self.lines = [
                self._line(
                    record["dname"], record["record_type"], record["data"], record["ttl"], index
                )
                if line["line_index"] == index
                else line
                for line in self.lines
            ]
        elif "remove" in arguments:
            self.lines = [line for line in self.lines if line["line_index"] != arguments["remove"]]
        self.serial += 1
        return {"status": 1}


class WorkflowHarness:
    def __init__(self, cpanel: RealShapeCPanel) -> None:
        self.cpanel = cpanel

    def _get_capability(self, capability_id: str) -> Any:
        return type("CapabilityRef", (), {"id": capability_id})()


async def _ensure(
    cpanel: RealShapeCPanel, record_type: str, arguments: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    workflows = DNSWorkflows(WorkflowHarness(cpanel))
    before = await workflows.prepare_hook(record_type)("acct", arguments)
    preparation = Preparation.model_construct(
        account="acct", arguments=arguments, before_state=before
    )
    return before, await workflows.execute_hook(record_type)(preparation)


@pytest.mark.asyncio
async def test_apex_a_record_is_matched_and_edited_in_place() -> None:
    cpanel = RealShapeCPanel([(f"{ZONE}.", "A", ["203.0.113.5"])])
    arguments = {
        "zone": ZONE,
        "name": "@",
        "address": "203.0.113.9",
        "ttl": 3600,
        "replace_existing": True,
    }
    before, result = await _ensure(cpanel, "A", arguments)

    assert before["plan"]["operation"] == "edit"
    assert result["verified"] is True
    assert json.loads(cpanel.writes[0]["edit"])["dname"] == f"{ZONE}."
    assert cpanel.names() == [(f"{ZONE}.", "A", ["203.0.113.9"])]


@pytest.mark.asyncio
async def test_apex_a_record_without_a_choice_is_a_conflict() -> None:
    cpanel = RealShapeCPanel([(f"{ZONE}.", "A", ["203.0.113.5"])])
    workflows = DNSWorkflows(WorkflowHarness(cpanel))
    with pytest.raises(CPanelError) as error:
        await workflows.prepare_typed(
            "A", "acct", {"zone": ZONE, "name": "@", "address": "203.0.113.9", "ttl": 3600}
        )
    assert error.value.code == "DNS_RECORD_CONFLICT"


@pytest.mark.asyncio
async def test_apex_mx_is_replaced_and_sent_with_the_absolute_zone_name() -> None:
    cpanel = RealShapeCPanel([(f"{ZONE}.", "MX", ["0", f"mail.{ZONE}."])])
    arguments = {
        "zone": ZONE,
        "name": "@",
        "priority": 0,
        "exchange": "example-com.mail.protection.outlook.com",
        "ttl": 3600,
        "replace_existing": True,
    }
    before, result = await _ensure(cpanel, "MX", arguments)

    assert before["plan"]["operation"] == "edit"
    assert result["verified"] is True
    assert cpanel.names() == [(f"{ZONE}.", "MX", ["0", "example-com.mail.protection.outlook.com."])]


@pytest.mark.asyncio
async def test_a_cname_at_the_apex_blocks_other_records() -> None:
    cpanel = RealShapeCPanel([(f"{ZONE}.", "CNAME", ["target.example.net."])])
    workflows = DNSWorkflows(WorkflowHarness(cpanel))
    with pytest.raises(CPanelError) as error:
        await workflows.prepare_typed(
            "A", "acct", {"zone": ZONE, "name": "@", "address": "203.0.113.9", "ttl": 3600}
        )
    assert error.value.code == "DNS_RECORD_CONFLICT"


@pytest.mark.asyncio
async def test_txt_spf_at_the_apex_is_replaced_by_prefix_instead_of_duplicated() -> None:
    cpanel = RealShapeCPanel([(f"{ZONE}.", "TXT", ["v=spf1 a mx ~all"])])
    workflows = DNSWorkflows(WorkflowHarness(cpanel))
    arguments = {
        "zone": ZONE,
        "name": "@",
        "value": "v=spf1 include:spf.protection.outlook.com -all",
        "match_prefix": "v=spf1",
        "replace_existing": True,
        "ttl": 3600,
    }
    before = await workflows.prepare_txt("acct", arguments)
    preparation = Preparation.model_construct(
        account="acct", arguments=arguments, before_state=before
    )
    result = await workflows.execute_txt(preparation)

    assert before["plan"]["operation"] == "edit"
    assert result["verified"] is True
    assert cpanel.names() == [
        (f"{ZONE}.", "TXT", ["v=spf1 include:spf.protection.outlook.com -all"])
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["app", "app.example.com", "app.example.com.", "APP"])
async def test_relative_and_qualified_spellings_of_a_name_are_the_same_record(name: str) -> None:
    cpanel = RealShapeCPanel([("app", "A", ["203.0.113.10"])])
    before, _ = await _ensure(
        cpanel, "A", {"zone": ZONE, "name": name, "address": "203.0.113.10", "ttl": 3600}
    )
    assert before["plan"]["operation"] == "noop"


@pytest.mark.asyncio
async def test_non_apex_names_are_still_sent_relative() -> None:
    cpanel = RealShapeCPanel([])
    await _ensure(
        cpanel,
        "A",
        {"zone": ZONE, "name": "app.example.com.", "address": "203.0.113.10", "ttl": 3600},
    )
    assert json.loads(cpanel.writes[0]["add"])["dname"] == "app"


@pytest.mark.asyncio
async def test_name_outside_the_zone_is_rejected() -> None:
    workflows = DNSWorkflows(WorkflowHarness(RealShapeCPanel([])))
    with pytest.raises(CPanelError) as error:
        await workflows.prepare_typed(
            "A",
            "acct",
            {"zone": ZONE, "name": "app.other.org.", "address": "203.0.113.10", "ttl": 3600},
        )
    assert error.value.code == "DNS_INVALID_VALUE"


@pytest.mark.asyncio
async def test_apex_record_can_be_removed_by_at_sign() -> None:
    cpanel = RealShapeCPanel(
        [(f"{ZONE}.", "TXT", ["_mcptest"]), (f"{ZONE}.", "A", ["203.0.113.5"])]
    )
    workflows = DNSWorkflows(WorkflowHarness(cpanel))
    arguments = {"zone": ZONE, "name": "@", "record_type": "TXT", "value": "_mcptest"}
    before = await workflows.prepare_remove("acct", arguments)
    preparation = Preparation.model_construct(
        account="acct", arguments=arguments, before_state=before
    )
    result = await workflows.execute_remove(preparation)

    assert result["verified"] is True
    assert cpanel.names() == [(f"{ZONE}.", "A", ["203.0.113.5"])]


def test_absolute_and_wire_names() -> None:
    assert DNSWorkflows._absolute(ZONE, "@") == ZONE
    assert DNSWorkflows._absolute(ZONE, "example.com.") == ZONE
    assert DNSWorkflows._absolute(ZONE, "WWW") == "www.example.com"
    assert DNSWorkflows._absolute(ZONE, "www.example.com") == "www.example.com"
    assert DNSWorkflows._wire_name(ZONE, "@") == "example.com."
    assert DNSWorkflows._wire_name(ZONE, "www.example.com.") == "www"
    assert DNSWorkflows._wire_name(ZONE, "selector1._domainkey") == "selector1._domainkey"


TXT_SPF = (f"{ZONE}.", "TXT", ["v=spf1 a mx ~all"])
TXT_ARGS = {"zone": ZONE, "name": "@", "value": "google-site-verification=abc", "ttl": 300}


async def _txt(
    cpanel: RealShapeCPanel, arguments: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    workflows = DNSWorkflows(WorkflowHarness(cpanel))
    before = await workflows.prepare_txt("acct", arguments)
    preparation = Preparation.model_construct(
        account="acct", arguments=arguments, before_state=before
    )
    return before, await workflows.execute_txt(preparation)


@pytest.mark.asyncio
async def test_txt_never_overwrites_the_existing_spf_without_an_explicit_choice() -> None:
    cpanel = RealShapeCPanel([TXT_SPF])
    workflows = DNSWorkflows(WorkflowHarness(cpanel))
    with pytest.raises(CPanelError) as error:
        await workflows.prepare_txt("acct", TXT_ARGS)
    assert error.value.code == "DNS_RECORD_CONFLICT"
    assert cpanel.writes == []


@pytest.mark.asyncio
async def test_txt_allow_multiple_adds_a_token_next_to_the_spf() -> None:
    cpanel = RealShapeCPanel([TXT_SPF])
    before, result = await _txt(cpanel, {**TXT_ARGS, "allow_multiple": True})

    assert before["plan"]["operation"] == "add"
    assert result["verified"] is True
    assert cpanel.names() == [
        TXT_SPF,
        (f"{ZONE}.", "TXT", ["google-site-verification=abc"]),
    ]


@pytest.mark.asyncio
async def test_txt_replace_existing_edits_the_single_existing_record() -> None:
    cpanel = RealShapeCPanel([TXT_SPF])
    before, result = await _txt(cpanel, {**TXT_ARGS, "replace_existing": True})

    assert before["plan"]["operation"] == "edit"
    assert result["verified"] is True
    assert cpanel.names() == [(f"{ZONE}.", "TXT", ["google-site-verification=abc"])]


@pytest.mark.asyncio
async def test_txt_match_prefix_is_an_explicit_selection() -> None:
    cpanel = RealShapeCPanel([TXT_SPF, (f"{ZONE}.", "TXT", ["other-token"])])
    arguments = {**TXT_ARGS, "value": "v=spf1 -all", "match_prefix": "v=spf1"}
    before, result = await _txt(cpanel, arguments)

    assert before["plan"]["operation"] == "edit"
    assert result["verified"] is True
    assert cpanel.names() == [
        (f"{ZONE}.", "TXT", ["v=spf1 -all"]),
        (f"{ZONE}.", "TXT", ["other-token"]),
    ]


@pytest.mark.asyncio
async def test_txt_is_added_when_nothing_exists_at_the_name() -> None:
    cpanel = RealShapeCPanel([TXT_SPF])
    before, result = await _txt(cpanel, {**TXT_ARGS, "name": "_dmarc"})

    assert before["plan"]["operation"] == "add"
    assert result["verified"] is True
    assert len(cpanel.names()) == 2


@pytest.mark.asyncio
async def test_txt_with_several_records_and_no_choice_is_ambiguous() -> None:
    cpanel = RealShapeCPanel([TXT_SPF, (f"{ZONE}.", "TXT", ["other-token"])])
    workflows = DNSWorkflows(WorkflowHarness(cpanel))
    with pytest.raises(CPanelError) as error:
        await workflows.prepare_txt("acct", TXT_ARGS)
    assert error.value.code == "DNS_TXT_RECORD_AMBIGUOUS"


@pytest.mark.asyncio
async def test_txt_replace_and_allow_multiple_are_mutually_exclusive() -> None:
    workflows = DNSWorkflows(WorkflowHarness(RealShapeCPanel([])))
    with pytest.raises(CPanelError) as error:
        await workflows.prepare_txt(
            "acct", {**TXT_ARGS, "replace_existing": True, "allow_multiple": True}
        )
    assert error.value.code == "DNS_INVALID_VALUE"
