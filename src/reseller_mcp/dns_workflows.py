from __future__ import annotations

import base64
import binascii
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
                "record": self._record(name, int(arguments["ttl"]), "CNAME", [target]),
            }
        else:
            plan = {
                "operation": "add",
                "record": self._record(name, int(arguments["ttl"]), "CNAME", [target]),
            }
        return {"zone": zone, "serial": self._serial(current), "records": records, "plan": plan}

    async def execute_cname(self, preparation: Preparation) -> dict[str, Any]:
        return await self._execute_record(preparation, "CNAME")

    async def prepare_txt(self, account: str | None, arguments: dict[str, Any]) -> dict[str, Any]:
        if not account:
            raise CPanelError("DNS workflows require an account", code="ACCOUNT_REQUIRED")
        zone = str(arguments["zone"])
        name = self._canonical_name(str(arguments["name"]))
        value = str(arguments["value"])
        current = await self._read_zone(account, zone)
        records = self._records(current)
        matching = [
            record
            for record in records
            if self._canonical_name(record["name"]) == name
            and record["record_type"].upper() == "TXT"
        ]
        same_value = [record for record in matching if record["data"] == [value]]
        plan: dict[str, Any]
        if same_value:
            plan = {"operation": "noop", "reason": "TXT already has the requested value"}
        else:
            prefix = arguments.get("match_prefix")
            candidates = (
                [record for record in matching if record["data"][0].startswith(str(prefix))]
                if prefix
                else matching
            )
            if len(candidates) > 1 or (matching and not candidates):
                raise CPanelError(
                    "the TXT record is ambiguous; provide match_prefix",
                    code="DNS_TXT_RECORD_AMBIGUOUS",
                    category="validation",
                )
            if candidates:
                line_index = candidates[0].get("line_index")
                if line_index is None:
                    raise CPanelError(
                        "the existing TXT record has no line index",
                        code="DNS_RECORD_NOT_EDITABLE",
                        category="validation",
                    )
                plan = {
                    "operation": "edit",
                    "line_index": line_index,
                    "record": self._record(name, int(arguments["ttl"]), "TXT", [value]),
                }
            elif matching and not arguments.get("replace_existing", False):
                raise CPanelError(
                    "a TXT record already exists; set replace_existing and match_prefix",
                    code="DNS_RECORD_CONFLICT",
                    category="validation",
                )
            else:
                plan = {
                    "operation": "add",
                    "record": self._record(name, int(arguments["ttl"]), "TXT", [value]),
                }
        return {"zone": zone, "serial": self._serial(current), "records": records, "plan": plan}

    async def execute_txt(self, preparation: Preparation) -> dict[str, Any]:
        return await self._execute_record(preparation, "TXT")

    async def prepare_remove(
        self, account: str | None, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        if not account:
            raise CPanelError("DNS workflows require an account", code="ACCOUNT_REQUIRED")
        zone = str(arguments["zone"])
        name = self._canonical_name(str(arguments["name"]))
        record_type = str(arguments["record_type"]).upper()
        value = str(arguments["value"])
        current = await self._read_zone(account, zone)
        matches = [
            record
            for record in self._records(current)
            if self._canonical_name(record["name"]) == name
            and record["record_type"].upper() == record_type
            and record["data"] == [value]
        ]
        if len(matches) != 1 or matches[0].get("line_index") is None:
            raise CPanelError(
                "the DNS record is not uniquely removable",
                code="DNS_RECORD_NOT_UNIQUE",
                category="validation",
            )
        return {
            "zone": zone,
            "serial": self._serial(current),
            "records": self._records(current),
            "plan": {"line_index": matches[0]["line_index"], "record": matches[0]},
        }

    async def execute_remove(self, preparation: Preparation) -> dict[str, Any]:
        account = preparation.account
        before = preparation.before_state or {}
        operation = self._mass_edit_capability()
        payload = {
            "zone": before["zone"],
            "serial": before["serial"],
            "remove": before["plan"]["line_index"],
        }
        result = await self.harness.cpanel.call(operation, account, payload, retry_safe=False)
        after = await self._read_zone(account, str(before["zone"]))
        removed = before["plan"]["record"]
        verified = not any(
            self._canonical_name(record["name"]) == self._canonical_name(removed["name"])
            and record["record_type"].upper() == removed["record_type"].upper()
            and record["data"] == removed["data"]
            for record in self._records(after)
        )
        return {
            "data": result,
            "after_state": after,
            "verified": verified,
            "warnings": [] if verified else ["DNS record removal was not verified"],
        }

    async def _execute_record(self, preparation: Preparation, record_type: str) -> dict[str, Any]:
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
        try:
            result = await self.harness.cpanel.call(operation, account, payload, retry_safe=False)
        except CPanelError as exc:
            if exc.code != "UPSTREAM_NETWORK_ERROR":
                raise
            reconciled = await self._read_zone(account, str(before["zone"]))
            if self._has_requested_record(reconciled, plan["record"], record_type):
                return {
                    "data": {"changed": True, "reconciled_after_transport_error": True},
                    "after_state": reconciled,
                    "verified": True,
                    "warnings": ["DNS write response was lost; state was reconciled from cPanel"],
                }
            result = await self.harness.cpanel.call(operation, account, payload, retry_safe=False)
        after = await self._read_zone(account, str(before["zone"]))
        requested = plan["record"]
        verified = self._has_requested_record(after, requested, record_type)
        return {
            "data": result,
            "after_state": after,
            "verified": verified,
            "warnings": (
                [] if verified else [f"{record_type} postcondition did not match requested state"]
            ),
        }

    def _has_requested_record(self, zone: Any, requested: dict[str, Any], record_type: str) -> bool:
        return any(
            self._canonical_name(record["name"]) == self._canonical_name(requested["dname"])
            and record["record_type"].upper() == record_type
            and record["data"] == requested["data"]
            and record["ttl"] == requested["ttl"]
            for record in self._records(zone)
        )

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
    def _record(name: str, ttl: int, record_type: str, data: list[str]) -> dict[str, Any]:
        return {"dname": name, "ttl": ttl, "record_type": record_type, "data": data}

    @staticmethod
    def _canonical_name(value: str) -> str:
        return value.rstrip(".").casefold()

    @staticmethod
    def _serial(value: Any) -> int:
        found = DNSWorkflows._find_key(value, "serial")
        if found is None:
            found = DNSWorkflows._find_key(value, "serial_b64")
            if found is not None:
                found = DNSWorkflows._decode_b64(found)
        if found is None:
            for item in DNSWorkflows._walk(value):
                if str(item.get("record_type", "")).upper() != "SOA":
                    continue
                data = DNSWorkflows._decoded_data(item)
                if len(data) >= 3:
                    found = data[2]
                    break
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
            name = item.get("dname", item.get("name", item.get("dname_raw")))
            record_type = item.get("record_type", item.get("type"))
            data = DNSWorkflows._decoded_data(item)
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
    def _decoded_data(item: dict[str, Any]) -> Any:
        data = item.get("data")
        if data is not None:
            return data
        encoded = item.get("data_b64")
        if not isinstance(encoded, list):
            return None
        return [DNSWorkflows._decode_b64(value) for value in encoded]

    @staticmethod
    def _decode_b64(value: Any) -> Any:
        if not isinstance(value, str):
            return value
        try:
            return base64.b64decode(value, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError, binascii.Error):
            return value

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
