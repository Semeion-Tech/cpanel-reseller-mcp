from __future__ import annotations

from typing import Any

import pytest

from reseller_mcp.cpanel import CPanelError
from reseller_mcp.dns_workflows import DNSWorkflows
from reseller_mcp.models import Preparation


class WorkflowHarness:
    def __init__(self, cpanel: MutationCPanel) -> None:
        self.cpanel = cpanel

    def _get_capability(self, capability_id: str) -> Any:
        return type("CapabilityRef", (), {"id": capability_id})()


class MutationCPanel:
    def __init__(self, behavior: str) -> None:
        self.behavior = behavior
        self.serial = 1
        self.record: dict[str, Any] | None = None
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.reads_after_write = 0

    async def call(self, capability, account, arguments, *, retry_safe=False):
        self.calls.append((capability.id, dict(arguments)))
        if capability.id == "uapi.DNS.parse_zone":
            if self.behavior == "read_fails_after_write" and self.reads_after_write:
                raise CPanelError(
                    "read failed",
                    code="UPSTREAM_NETWORK_ERROR",
                    retryable=True,
                )
            records = [] if self.record is None else [self.record]
            return {"data": {"serial": self.serial, "records": records}}

        if capability.id != "uapi.DNS.mass_edit_zone":
            raise AssertionError(f"unexpected capability: {capability.id}")

        encoded = arguments.get("add") or arguments.get("edit")
        if "remove" in arguments:
            self.record = None
            self.serial += 1
            self.reads_after_write += 1
            if self.behavior == "remove_apply_then_error":
                raise CPanelError(
                    "connection closed after removal",
                    code="UPSTREAM_NETWORK_ERROR",
                    retryable=True,
                )
            return {"status": 1, "data": {"new_serial": self.serial}}

        if encoded:
            import json

            record = json.loads(str(encoded))
            record["name"] = record.pop("dname")
            record["data"] = [f"{record['data'][0]}."]
            self.record = record
        self.serial += 1
        self.reads_after_write += 1

        if (
            self.behavior == "apply_then_error"
            and len([call for call in self.calls if call[0] == "uapi.DNS.mass_edit_zone"]) == 1
        ):
            raise CPanelError(
                "connection closed after write",
                code="UPSTREAM_NETWORK_ERROR",
                retryable=True,
            )
        if (
            self.behavior == "serial_drift"
            and len([call for call in self.calls if call[0] == "uapi.DNS.mass_edit_zone"]) == 1
        ):
            self.record = None
            raise CPanelError(
                "connection closed before write",
                code="UPSTREAM_NETWORK_ERROR",
                retryable=True,
            )
        return {"status": 1, "data": {"new_serial": self.serial}}


def _preparation(before: dict[str, Any], arguments: dict[str, Any]) -> Preparation:
    return Preparation.model_construct(
        account="acctalpha",
        arguments=arguments,
        before_state=before,
    )


@pytest.mark.asyncio
async def test_cname_reconciles_when_write_response_is_lost_after_change() -> None:
    cpanel = MutationCPanel("apply_then_error")
    workflows = DNSWorkflows(WorkflowHarness(cpanel))
    arguments = {
        "zone": "example.com",
        "name": "_mcp-canary",
        "target": "target.example.net",
        "ttl": 300,
    }
    before = await workflows.prepare_cname("acctalpha", arguments)

    result = await workflows.execute_cname(_preparation(before, arguments))

    assert result["verified"] is True
    assert result["data"]["reconciled_after_transport_error"] is True
    assert len([call for call in cpanel.calls if call[0] == "uapi.DNS.mass_edit_zone"]) == 1


@pytest.mark.asyncio
async def test_cname_replans_with_new_serial_after_ambiguous_failure() -> None:
    cpanel = MutationCPanel("serial_drift")
    workflows = DNSWorkflows(WorkflowHarness(cpanel))
    arguments = {
        "zone": "example.com",
        "name": "_mcp-canary",
        "target": "target.example.net",
        "ttl": 300,
    }
    before = await workflows.prepare_cname("acctalpha", arguments)

    result = await workflows.execute_cname(_preparation(before, arguments))

    writes = [args for capability, args in cpanel.calls if capability == "uapi.DNS.mass_edit_zone"]
    assert result["verified"] is True
    assert [write["serial"] for write in writes] == [1, 2]


@pytest.mark.asyncio
async def test_cname_reports_unknown_state_when_post_write_read_fails() -> None:
    cpanel = MutationCPanel("read_fails_after_write")
    workflows = DNSWorkflows(WorkflowHarness(cpanel))
    arguments = {
        "zone": "example.com",
        "name": "_mcp-canary",
        "target": "target.example.net",
        "ttl": 300,
    }
    before = await workflows.prepare_cname("acctalpha", arguments)

    with pytest.raises(CPanelError) as error:
        await workflows.execute_cname(_preparation(before, arguments))

    assert error.value.code == "DNS_WRITE_STATE_UNKNOWN"
    assert error.value.details == {"state_unknown": True, "write_attempts": 1}


@pytest.mark.asyncio
async def test_remove_reconciles_when_response_is_lost_after_removal() -> None:
    cpanel = MutationCPanel("remove_apply_then_error")
    cpanel.record = {
        "name": "_mcp-canary",
        "ttl": 300,
        "record_type": "CNAME",
        "data": ["target.example.net"],
        "line_index": 4,
    }
    workflows = DNSWorkflows(WorkflowHarness(cpanel))
    arguments = {
        "zone": "example.com",
        "name": "_mcp-canary",
        "record_type": "CNAME",
        "value": "target.example.net",
    }
    before = await workflows.prepare_remove("acctalpha", arguments)

    result = await workflows.execute_remove(_preparation(before, arguments))

    assert result["verified"] is True
    assert result["data"]["reconciled_after_transport_error"] is True
