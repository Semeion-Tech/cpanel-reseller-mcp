from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from .cpanel import CPanelError
from .models import ApiFamily, Capability, Preparation, Risk, Role

if TYPE_CHECKING:
    from .harness import Harness


class DNSWorkflows:
    """Typed, account-scoped DNS mutations backed by cPanel UAPI."""

    def __init__(self, harness: Harness):
        self.harness = harness

    async def prepare_cname(self, account: str | None, arguments: dict[str, Any]) -> dict[str, Any]:
        if not account:
            raise CPanelError("DNS workflows require an account", code="ACCOUNT_REQUIRED")
        zone = str(arguments["zone"])
        name = self._canonical_name(str(arguments["name"]))
        target = self._canonical_name(str(arguments["target"]))
        current = await self._read_zone(account, zone)
        records = self._records(current)
        matching = [record for record in records if self._canonical_name(record["name"]) == name]
        same_target = [
            record
            for record in matching
            if record["record_type"].upper() == "CNAME"
            and self._canonical_name(record["data"][0]) == target
        ]
        plan: dict[str, Any]
        if same_target:
            plan = {"operation": "noop", "reason": "CNAME already points to target"}
        elif matching and not arguments.get("replace_existing", False):
            raise CPanelError(
                "a record already exists at this name; set replace_existing to edit it",
                code="DNS_RECORD_CONFLICT",
                category="validation",
            )
        elif matching:
            if len(matching) != 1 or "line_index" not in matching[0]:
                raise CPanelError(
                    "the existing DNS record has no unique line index",
                    code="DNS_RECORD_NOT_EDITABLE",
                    category="validation",
                )
            plan = {
                "operation": "edit",
                "line_index": matching[0]["line_index"],
                "record": self._record(name, int(arguments["ttl"]), target),
            }
        else:
            plan = {
                "operation": "add",
                "record": self._record(name, int(arguments["ttl"]), target),
            }
        return {"zone": zone, "serial": self._serial(current), "records": records, "plan": plan}

    async def execute_cname(self, preparation: Preparation) -> dict[str, Any]:
        account = preparation.account
        before = preparation.before_state or {}
        plan = before.get("plan", {})
        if plan.get("operation") == "noop":
            after = await self._read_zone(account, str(before["zone"]))
            return {
                "data": {"changed": False, "reason": plan["reason"]},
                "after_state": after,
                "verified": True,
                "warnings": [],
            }

        operation = self._mass_edit_capability()
        payload: dict[str, Any] = {
            "zone": before["zone"],
            "serial": before["serial"],
        }
        if plan["operation"] == "add":
            payload["add"] = json.dumps(plan["record"], separators=(",", ":"))
        else:
            record = {"line_index": plan["line_index"], **plan["record"]}
            payload["edit"] = json.dumps(record, separators=(",", ":"))
        result = await self.harness.cpanel.call(operation, account, payload, retry_safe=False)
        after = await self._read_zone(account, str(before["zone"]))
        requested = plan["record"]
        verified = any(
            self._canonical_name(record["name"]) == self._canonical_name(requested["dname"])
            and record["record_type"].upper() == "CNAME"
            and self._canonical_name(record["data"][0])
            == self._canonical_name(requested["data"][0])
            and record["ttl"] == requested["ttl"]
            for record in self._records(after)
        )
        return {
            "data": result,
            "after_state": after,
            "verified": verified,
            "warnings": [] if verified else ["CNAME postcondition did not match requested state"],
        }

    async def _read_zone(self, account: str | None, zone: str) -> Any:
        capability = self.harness._get_capability("uapi.DNS.parse_zone")
        return await self.harness.cpanel.call(capability, account, {"zone": zone}, retry_safe=True)

    @staticmethod
    def _mass_edit_capability() -> Capability:
        return Capability(
            id="uapi.DNS.mass_edit_zone",
            api=ApiFamily.UAPI,
            module="DNS",
            function="mass_edit_zone",
            title="Atualizar zona DNS",
            description="Internal typed workflow operation.",
            risk=Risk.REVERSIBLE_WRITE,
            required_role=Role.OPERATOR,
            upstream_profile="operator",
            input_schema={"type": "object", "additionalProperties": True},
            schema_source="official_cpanel_docs",
            curated=True,
        )

    @staticmethod
    def _record(name: str, ttl: int, target: str) -> dict[str, Any]:
        return {"dname": name, "ttl": ttl, "record_type": "CNAME", "data": [target]}

    @staticmethod
    def _canonical_name(value: str) -> str:
        return value.rstrip(".").casefold()

    @staticmethod
    def _serial(value: Any) -> int:
        found = DNSWorkflows._find_key(value, "serial")
        if found is None:
            raise CPanelError(
                "the parsed DNS zone did not include its current serial",
                code="DNS_SERIAL_UNAVAILABLE",
                category="validation",
            )
        try:
            return int(found)
        except (TypeError, ValueError) as exc:
            raise CPanelError(
                "the parsed DNS zone serial is invalid",
                code="DNS_SERIAL_INVALID",
                category="validation",
            ) from exc

    @staticmethod
    def _records(value: Any) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for item in DNSWorkflows._walk(value):
            name = item.get("dname", item.get("name"))
            record_type = item.get("record_type", item.get("type"))
            data = item.get("data")
            if not isinstance(name, str) or not isinstance(record_type, str):
                continue
            if isinstance(data, str):
                data = [data]
            if not isinstance(data, list) or not data or not isinstance(data[0], str):
                continue
            ttl_value = item.get("ttl")
            if not isinstance(ttl_value, (int, str)):
                continue
            try:
                ttl = int(ttl_value)
            except ValueError:
                continue
            record = {"name": name, "record_type": record_type, "data": data, "ttl": ttl}
            if "line_index" in item:
                record["line_index"] = item["line_index"]
            records.append(record)
        return records

    @staticmethod
    def _walk(value: Any) -> list[dict[str, Any]]:
        if isinstance(value, dict):
            found = [value]
            for item in value.values():
                found.extend(DNSWorkflows._walk(item))
            return found
        if isinstance(value, list):
            return [item for child in value for item in DNSWorkflows._walk(child)]
        return []

    @staticmethod
    def _find_key(value: Any, wanted: str) -> Any:
        if isinstance(value, dict):
            for key, item in value.items():
                if str(key).casefold() == wanted:
                    return item
                found = DNSWorkflows._find_key(item, wanted)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for item in value:
                found = DNSWorkflows._find_key(item, wanted)
                if found is not None:
                    return found
        return None
