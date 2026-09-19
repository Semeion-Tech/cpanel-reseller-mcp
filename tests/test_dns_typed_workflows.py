from __future__ import annotations

import json
from typing import Any

import pytest

from reseller_mcp.catalog import Catalog
from reseller_mcp.cpanel import CPanelError
from reseller_mcp.dns_workflows import DNSWorkflows
from reseller_mcp.models import Preparation, Risk, Role


class ZoneCPanel:
    """In-memory zone that mimics parse_zone/mass_edit_zone for several records."""

    def __init__(self, records: list[dict[str, Any]] | None = None) -> None:
        self.serial = 10
        self.next_index = 100
        self.records: list[dict[str, Any]] = []
        for record in records or []:
            self._store(record)
        self.writes: list[dict[str, Any]] = []

    def _store(self, record: dict[str, Any]) -> None:
        self.records.append({**record, "line_index": self.next_index})
        self.next_index += 1

    async def call(self, capability, account, arguments, *, retry_safe=False):
        if capability.id == "uapi.DNS.parse_zone":
            return {"data": {"serial": self.serial, "records": [dict(r) for r in self.records]}}
        assert capability.id == "uapi.DNS.mass_edit_zone"
        assert arguments["serial"] == self.serial, "stale serial"
        self.writes.append(dict(arguments))
        if "add" in arguments:
            record = json.loads(arguments["add"])
            record["name"] = record.pop("dname")
            self._store(record)
        elif "edit" in arguments:
            record = json.loads(arguments["edit"])
            index = record.pop("line_index")
            record["name"] = record.pop("dname")
            self.records = [
                {**record, "line_index": index} if r["line_index"] == index else r
                for r in self.records
            ]
        elif "remove" in arguments:
            self.records = [r for r in self.records if r["line_index"] != arguments["remove"]]
        self.serial += 1
        return {"status": 1, "data": {"new_serial": self.serial}}


class WorkflowHarness:
    def __init__(self, cpanel: ZoneCPanel) -> None:
        self.cpanel = cpanel

    def _get_capability(self, capability_id: str) -> Any:
        return type("CapabilityRef", (), {"id": capability_id})()


def _record(name: str, record_type: str, data: list[str], ttl: int = 3600) -> dict[str, Any]:
    return {"name": name, "record_type": record_type, "data": data, "ttl": ttl}


async def _run(
    cpanel: ZoneCPanel, record_type: str, arguments: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    workflows = DNSWorkflows(WorkflowHarness(cpanel))
    before = await workflows.prepare_hook(record_type)("acctalpha", arguments)
    preparation = Preparation.model_construct(
        account="acctalpha", arguments=arguments, before_state=before
    )
    result = await workflows.execute_hook(record_type)(preparation)
    return before, result


A_ARGS = {"zone": "example.com", "name": "app", "address": "203.0.113.10", "ttl": 3600}


@pytest.mark.asyncio
async def test_a_record_is_added_and_verified() -> None:
    cpanel = ZoneCPanel()
    before, result = await _run(cpanel, "A", A_ARGS)

    assert before["plan"]["operation"] == "add"
    assert result["verified"] is True
    assert json.loads(cpanel.writes[0]["add"]) == {
        "dname": "app",
        "ttl": 3600,
        "record_type": "A",
        "data": ["203.0.113.10"],
    }


@pytest.mark.asyncio
async def test_a_record_is_a_noop_when_value_already_exists() -> None:
    cpanel = ZoneCPanel([_record("app", "A", ["203.0.113.10"])])
    before, result = await _run(cpanel, "A", A_ARGS)

    assert before["plan"]["operation"] == "noop"
    assert result["verified"] is True
    assert result["data"]["changed"] is False
    assert cpanel.writes == []


@pytest.mark.asyncio
async def test_a_record_with_different_value_requires_an_explicit_choice() -> None:
    cpanel = ZoneCPanel([_record("app", "A", ["198.51.100.7"])])
    workflows = DNSWorkflows(WorkflowHarness(cpanel))

    with pytest.raises(CPanelError) as error:
        await workflows.prepare_typed("A", "acctalpha", A_ARGS)
    assert error.value.code == "DNS_RECORD_CONFLICT"

    before, result = await _run(cpanel, "A", {**A_ARGS, "replace_existing": True})
    assert before["plan"]["operation"] == "edit"
    assert result["verified"] is True
    assert [r["data"] for r in cpanel.records] == [["203.0.113.10"]]


@pytest.mark.asyncio
async def test_a_record_allow_multiple_adds_a_second_value() -> None:
    cpanel = ZoneCPanel([_record("app", "A", ["198.51.100.7"])])
    before, result = await _run(cpanel, "A", {**A_ARGS, "allow_multiple": True})

    assert before["plan"]["operation"] == "add"
    assert result["verified"] is True
    assert len(cpanel.records) == 2


@pytest.mark.asyncio
async def test_replace_existing_refuses_to_pick_between_several_records() -> None:
    cpanel = ZoneCPanel(
        [_record("app", "A", ["198.51.100.7"]), _record("app", "A", ["198.51.100.8"])]
    )
    workflows = DNSWorkflows(WorkflowHarness(cpanel))

    with pytest.raises(CPanelError) as error:
        await workflows.prepare_typed("A", "acctalpha", {**A_ARGS, "replace_existing": True})
    assert error.value.code == "DNS_RECORD_NOT_EDITABLE"


@pytest.mark.asyncio
async def test_replace_and_allow_multiple_are_mutually_exclusive() -> None:
    workflows = DNSWorkflows(WorkflowHarness(ZoneCPanel()))
    with pytest.raises(CPanelError) as error:
        await workflows.prepare_typed(
            "A", "acctalpha", {**A_ARGS, "replace_existing": True, "allow_multiple": True}
        )
    assert error.value.code == "DNS_INVALID_VALUE"


@pytest.mark.asyncio
async def test_records_are_refused_next_to_a_cname() -> None:
    cpanel = ZoneCPanel([_record("app", "CNAME", ["target.example.net."])])
    workflows = DNSWorkflows(WorkflowHarness(cpanel))

    with pytest.raises(CPanelError) as error:
        await workflows.prepare_typed("A", "acctalpha", A_ARGS)
    assert error.value.code == "DNS_RECORD_CONFLICT"
    assert cpanel.writes == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("record_type", "address"),
    [
        ("A", "999.1.1.1"),
        ("A", "2001:db8::1"),
        ("A", "not-an-ip"),
        ("AAAA", "203.0.113.10"),
        ("AAAA", "2001:db8::zz"),
    ],
)
async def test_invalid_addresses_are_rejected(record_type: str, address: str) -> None:
    workflows = DNSWorkflows(WorkflowHarness(ZoneCPanel()))
    arguments = {**A_ARGS, "address": address}
    with pytest.raises(CPanelError) as error:
        await workflows.prepare_typed(record_type, "acctalpha", arguments)
    assert error.value.code == "DNS_INVALID_VALUE"


@pytest.mark.asyncio
async def test_aaaa_matches_equivalent_ipv6_spellings() -> None:
    cpanel = ZoneCPanel([_record("app", "AAAA", ["2001:0db8:0:0:0:0:0:10"])])
    before, _ = await _run(cpanel, "AAAA", {**A_ARGS, "address": "2001:db8::10"})
    assert before["plan"]["operation"] == "noop"


@pytest.mark.asyncio
async def test_mx_is_added_with_an_absolute_exchange_and_noop_ignores_trailing_dot() -> None:
    arguments = {
        "zone": "example.com",
        "name": "@",
        "priority": 0,
        "exchange": "Example-com.mail.protection.outlook.com",
        "ttl": 3600,
    }
    cpanel = ZoneCPanel()
    before, result = await _run(cpanel, "MX", arguments)
    assert before["plan"]["operation"] == "add"
    assert result["verified"] is True
    assert json.loads(cpanel.writes[0]["add"])["data"] == [
        "0",
        "example-com.mail.protection.outlook.com.",
    ]

    again, _ = await _run(cpanel, "MX", arguments)
    assert again["plan"]["operation"] == "noop"


@pytest.mark.asyncio
async def test_mx_replace_swaps_the_single_existing_exchange() -> None:
    cpanel = ZoneCPanel([_record("@", "MX", ["10", "mail.example.com."])])
    before, result = await _run(
        cpanel,
        "MX",
        {
            "zone": "example.com",
            "name": "@",
            "priority": 0,
            "exchange": "example-com.mail.protection.outlook.com",
            "ttl": 3600,
            "replace_existing": True,
        },
    )
    assert before["plan"]["operation"] == "edit"
    assert result["verified"] is True
    assert cpanel.records[0]["data"] == ["0", "example-com.mail.protection.outlook.com."]


@pytest.mark.asyncio
@pytest.mark.parametrize("exchange", ["203.0.113.5", "bad host", "-bad.example.com", ""])
async def test_mx_exchange_must_be_a_hostname(exchange: str) -> None:
    workflows = DNSWorkflows(WorkflowHarness(ZoneCPanel()))
    with pytest.raises(CPanelError) as error:
        await workflows.prepare_typed(
            "MX",
            "acctalpha",
            {"zone": "example.com", "name": "@", "priority": 0, "exchange": exchange, "ttl": 300},
        )
    assert error.value.code == "DNS_INVALID_VALUE"


@pytest.mark.asyncio
async def test_srv_record_is_added_and_verified() -> None:
    cpanel = ZoneCPanel()
    before, result = await _run(
        cpanel,
        "SRV",
        {
            "zone": "example.com",
            "name": "_sip._tcp",
            "priority": 10,
            "weight": 5,
            "port": 5060,
            "target": "sip.example.com",
            "ttl": 3600,
        },
    )
    assert before["plan"]["operation"] == "add"
    assert result["verified"] is True
    assert json.loads(cpanel.writes[0]["add"])["data"] == ["10", "5", "5060", "sip.example.com."]


@pytest.mark.asyncio
async def test_srv_port_zero_is_rejected() -> None:
    workflows = DNSWorkflows(WorkflowHarness(ZoneCPanel()))
    with pytest.raises(CPanelError) as error:
        await workflows.prepare_typed(
            "SRV",
            "acctalpha",
            {
                "zone": "example.com",
                "name": "_sip._tcp",
                "priority": 10,
                "weight": 5,
                "port": 0,
                "target": "sip.example.com",
                "ttl": 3600,
            },
        )
    assert error.value.code == "DNS_INVALID_VALUE"


CAA_ARGS = {
    "zone": "example.com",
    "name": "@",
    "tag": "issue",
    "value": "letsencrypt.org",
    "ttl": 3600,
}


@pytest.mark.asyncio
async def test_caa_different_tags_coexist_and_same_tag_conflicts() -> None:
    cpanel = ZoneCPanel([_record("@", "CAA", ["0", "issuewild", ";"])])
    before, result = await _run(cpanel, "CAA", CAA_ARGS)
    assert before["plan"]["operation"] == "add"
    assert result["verified"] is True
    assert len(cpanel.records) == 2

    workflows = DNSWorkflows(WorkflowHarness(cpanel))
    with pytest.raises(CPanelError) as error:
        await workflows.prepare_typed("CAA", "acctalpha", {**CAA_ARGS, "value": "digicert.com"})
    assert error.value.code == "DNS_RECORD_CONFLICT"

    same, _ = await _run(cpanel, "CAA", CAA_ARGS)
    assert same["plan"]["operation"] == "noop"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [{"tag": "bogus"}, {"flags": 1}, {"value": '""'}],
)
async def test_caa_validation(overrides: dict[str, Any]) -> None:
    workflows = DNSWorkflows(WorkflowHarness(ZoneCPanel()))
    with pytest.raises(CPanelError) as error:
        await workflows.prepare_typed("CAA", "acctalpha", {**CAA_ARGS, **overrides})
    assert error.value.code == "DNS_INVALID_VALUE"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("record", "record_type", "value"),
    [
        (_record("@", "MX", ["10", "mail.example.com."]), "MX", "10 mail.example.com"),
        (_record("app", "A", ["203.0.113.10"]), "A", "203.0.113.10"),
        (
            _record("@", "CAA", ["0", "issue", "letsencrypt.org"]),
            "CAA",
            '0 issue "letsencrypt.org"',
        ),
        (
            _record("_sip._tcp", "SRV", ["10", "5", "5060", "sip.example.com."]),
            "SRV",
            "10 5 5060 sip.example.com",
        ),
    ],
)
async def test_remove_matches_multi_field_records_by_value(
    record: dict[str, Any], record_type: str, value: str
) -> None:
    cpanel = ZoneCPanel([record])
    workflows = DNSWorkflows(WorkflowHarness(cpanel))
    arguments = {
        "zone": "example.com",
        "name": record["name"],
        "record_type": record_type,
        "value": value,
    }
    before = await workflows.prepare_remove("acctalpha", arguments)
    preparation = Preparation.model_construct(
        account="acctalpha", arguments=arguments, before_state=before
    )
    result = await workflows.execute_remove(preparation)

    assert result["verified"] is True
    assert cpanel.records == []


@pytest.mark.asyncio
async def test_remove_rejects_malformed_multi_field_value() -> None:
    cpanel = ZoneCPanel([_record("@", "MX", ["10", "mail.example.com."])])
    workflows = DNSWorkflows(WorkflowHarness(cpanel))
    with pytest.raises(CPanelError) as error:
        await workflows.prepare_remove(
            "acctalpha",
            {"zone": "example.com", "name": "@", "record_type": "MX", "value": "mail.example.com"},
        )
    assert error.value.code == "DNS_INVALID_VALUE"


def test_typed_dns_capabilities_are_curated_reversible_writes(tmp_path) -> None:
    capabilities = {item.id: item for item in Catalog(tmp_path / "missing.json").load()}
    for record_type in DNSWorkflows.ENSURE_TYPES:
        capability = capabilities[f"workflow.dns_{record_type.lower()}_ensure"]
        assert capability.curated is True
        assert capability.available is True
        assert capability.risk == Risk.REVERSIBLE_WRITE
        assert capability.required_role == Role.OPERATOR
        assert capability.input_schema["additionalProperties"] is False
        assert {"zone", "name", "ttl"} <= set(capability.input_schema["required"])
    assert capabilities["workflow.dns_srv_ensure"].input_schema["required"] == [
        "zone",
        "name",
        "priority",
        "weight",
        "port",
        "target",
        "ttl",
    ]


TYPED_ARGUMENTS: dict[str, dict[str, Any]] = {
    "A": {"zone": "example.com", "name": "app", "address": "203.0.113.10", "ttl": 3600},
    "AAAA": {"zone": "example.com", "name": "app", "address": "2001:db8::10", "ttl": 3600},
    "MX": {
        "zone": "example.com",
        "name": "@",
        "priority": 10,
        "exchange": "mail.example.com",
        "ttl": 3600,
    },
    "SRV": {
        "zone": "example.com",
        "name": "_sip._tcp",
        "priority": 10,
        "weight": 5,
        "port": 5060,
        "target": "sip.example.com",
        "ttl": 3600,
    },
    "CAA": CAA_ARGS,
}


@pytest.mark.asyncio
@pytest.mark.parametrize("record_type", DNSWorkflows.ENSURE_TYPES)
async def test_typed_dns_workflows_run_through_the_harness_without_a_phrase(
    harness, admin, record_type: str
) -> None:
    harness.cpanel = ZoneCPanel()
    prepared = await harness.prepare_action(
        admin,
        f"workflow.dns_{record_type.lower()}_ensure",
        "acctalpha",
        TYPED_ARGUMENTS[record_type],
    )

    assert prepared["risk"] == "reversible_write"
    assert prepared["requires_confirmation"] is False
    assert prepared["before_state"]["plan"]["operation"] == "add"
    result = await harness.execute_action(admin, prepared["preparation_id"])

    assert result.ok is True
    assert result.verified is True


@pytest.mark.asyncio
async def test_typed_dns_workflow_rejects_unknown_arguments(harness, admin) -> None:
    from reseller_mcp.harness import HarnessError

    harness.cpanel = ZoneCPanel()
    with pytest.raises(HarnessError) as error:
        await harness.prepare_action(
            admin,
            "workflow.dns_a_ensure",
            "acctalpha",
            {**TYPED_ARGUMENTS["A"], "proxied": True},
        )
    assert error.value.code == "INVALID_ARGUMENTS"


@pytest.mark.asyncio
async def test_typed_dns_workflow_rejects_out_of_range_ttl(harness, admin) -> None:
    from reseller_mcp.harness import HarnessError

    harness.cpanel = ZoneCPanel()
    with pytest.raises(HarnessError) as error:
        await harness.prepare_action(
            admin, "workflow.dns_a_ensure", "acctalpha", {**TYPED_ARGUMENTS["A"], "ttl": 5}
        )
    assert error.value.code == "INVALID_ARGUMENTS"


@pytest.mark.asyncio
@pytest.mark.parametrize("record_type", ["A", "AAAA"])
@pytest.mark.parametrize("name", ["_mcptest", "a_b", "-x", "x-", "app._sub", "a.*", "bad name"])
async def test_a_and_aaaa_owner_names_that_bind_rejects_never_reach_cpanel(
    record_type: str, name: str
) -> None:
    cpanel = ZoneCPanel()
    workflows = DNSWorkflows(WorkflowHarness(cpanel))
    address = "203.0.113.10" if record_type == "A" else "2001:db8::10"

    with pytest.raises(CPanelError) as error:
        await workflows.prepare_typed(
            record_type,
            "acctalpha",
            {"zone": "example.com", "name": name, "address": address, "ttl": 300},
        )

    assert error.value.code == "DNS_INVALID_VALUE"
    assert cpanel.writes == []


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["app", "a-b", "app.sub", "*", "*.sub", "x1", "@"])
async def test_valid_host_owner_names_are_accepted(name: str) -> None:
    workflows = DNSWorkflows(WorkflowHarness(ZoneCPanel()))
    before = await workflows.prepare_typed(
        "A",
        "acctalpha",
        {"zone": "example.com", "name": name, "address": "203.0.113.10", "ttl": 300},
    )
    assert before["plan"]["operation"] == "add"


@pytest.mark.asyncio
async def test_underscores_stay_valid_for_owner_names_of_other_record_types() -> None:
    workflows = DNSWorkflows(WorkflowHarness(ZoneCPanel()))
    srv = await workflows.prepare_typed(
        "SRV",
        "acctalpha",
        {
            "zone": "example.com",
            "name": "_sip._tcp",
            "priority": 10,
            "weight": 5,
            "port": 5060,
            "target": "sip.example.com",
            "ttl": 300,
        },
    )
    txt = await workflows.prepare_txt(
        "acctalpha", {"zone": "example.com", "name": "_dmarc", "value": "v=DMARC1", "ttl": 300}
    )
    assert srv["plan"]["operation"] == "add"
    assert txt["plan"]["operation"] == "add"


@pytest.mark.asyncio
@pytest.mark.parametrize("exchange", ["mail_server.example.com", "mx.-bad.example.com"])
async def test_an_mx_target_with_an_underscore_is_rejected(exchange: str) -> None:
    workflows = DNSWorkflows(WorkflowHarness(ZoneCPanel()))
    with pytest.raises(CPanelError) as error:
        await workflows.prepare_typed(
            "MX",
            "acctalpha",
            {"zone": "example.com", "name": "@", "priority": 0, "exchange": exchange, "ttl": 300},
        )
    assert error.value.code == "DNS_INVALID_VALUE"
