from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from .cpanel import CPanelError
from .models import ApiFamily, Capability, Preparation, Risk, Role

if TYPE_CHECKING:
    from .harness import Harness


_HOSTNAME = re.compile(
    r"^(?=.{1,253}\.?$)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?"
    r"(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*\.?$",
    re.IGNORECASE,
)
_CAA_TAGS = ("issue", "issuewild", "iodef")


class DNSWorkflows:
    """Typed, account-scoped DNS mutations backed by cPanel UAPI."""

    # Record types handled by the generic ensure workflow (CNAME and TXT keep their own).
    ENSURE_TYPES = ("A", "AAAA", "CAA", "SRV", "MX")
    # Number of whitespace-separated fields in the human-readable value of a record.
    _VALUE_FIELDS = {"MX": 2, "SRV": 4, "CAA": 3}

    def __init__(self, harness: Harness):
        self.harness = harness

    def prepare_hook(
        self, record_type: str
    ) -> Callable[[str | None, dict[str, Any]], Awaitable[dict[str, Any]]]:
        async def prepare(account: str | None, arguments: dict[str, Any]) -> dict[str, Any]:
            return await self.prepare_typed(record_type, account, arguments)

        return prepare

    def execute_hook(self, record_type: str) -> Callable[[Preparation], Awaitable[dict[str, Any]]]:
        async def execute(preparation: Preparation) -> dict[str, Any]:
            return await self._execute_record(preparation, record_type)

        return execute

    async def prepare_typed(
        self, record_type: str, account: str | None, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Plan an idempotent add/edit of an A, AAAA, CAA, SRV or MX record."""
        if not account:
            raise CPanelError("DNS workflows require an account", code="ACCOUNT_REQUIRED")
        replace = bool(arguments.get("replace_existing", False))
        multiple = bool(arguments.get("allow_multiple", False))
        if replace and multiple:
            raise self._invalid("replace_existing and allow_multiple are mutually exclusive")
        zone = str(arguments["zone"])
        name = self._absolute(zone, str(arguments["name"]))
        wire_name = self._wire_name(zone, str(arguments["name"]))
        data = self._typed_data(record_type, arguments)
        wanted = self._normalize_data(record_type, data)
        current = await self._read_zone(account, zone)
        records = self._records(current)
        at_name = [record for record in records if self._absolute(zone, record["name"]) == name]
        if any(record["record_type"].upper() == "CNAME" for record in at_name):
            raise CPanelError(
                "a CNAME exists at this name and cannot coexist with other records",
                code="DNS_RECORD_CONFLICT",
                category="validation",
            )
        related = [record for record in at_name if record["record_type"].upper() == record_type]
        if record_type == "CAA":
            # Different CAA tags are independent policies and may coexist.
            related = [
                record
                for record in related
                if self._normalize_data("CAA", record["data"])[1] == wanted[1]
            ]
        new_record = self._record(wire_name, int(arguments["ttl"]), record_type, data)
        plan: dict[str, Any]
        if any(self._normalize_data(record_type, record["data"]) == wanted for record in related):
            plan = {"operation": "noop", "reason": f"{record_type} already has the requested value"}
        elif not related or multiple:
            plan = {"operation": "add", "record": new_record}
        elif replace:
            if len(related) != 1 or related[0].get("line_index") is None:
                raise CPanelError(
                    f"the existing {record_type} record is not uniquely editable; "
                    "remove the extra records with workflow.dns_record_remove first",
                    code="DNS_RECORD_NOT_EDITABLE",
                    category="validation",
                )
            plan = {
                "operation": "edit",
                "line_index": related[0]["line_index"],
                "record": new_record,
            }
        else:
            raise CPanelError(
                f"a {record_type} record already exists at this name; set replace_existing "
                "to change it or allow_multiple to add another value",
                code="DNS_RECORD_CONFLICT",
                category="validation",
            )
        return {"zone": zone, "serial": self._serial(current), "records": records, "plan": plan}

    @staticmethod
    def _invalid(message: str) -> CPanelError:
        return CPanelError(message, code="DNS_INVALID_VALUE", category="validation")

    @staticmethod
    def _typed_data(record_type: str, arguments: dict[str, Any]) -> list[str]:
        invalid = DNSWorkflows._invalid
        if record_type in {"A", "AAAA"}:
            try:
                address = ipaddress.ip_address(str(arguments["address"]).strip())
            except ValueError as exc:
                raise invalid(f"{arguments['address']!r} is not a valid IP address") from exc
            expected_version = 4 if record_type == "A" else 6
            if address.version != expected_version:
                raise invalid(f"a {record_type} record requires an IPv{expected_version} address")
            return [str(address)]
        if record_type == "MX":
            return [
                str(DNSWorkflows._bounded(arguments["priority"], "priority", 0, 65535)),
                DNSWorkflows._fqdn(str(arguments["exchange"])),
            ]
        if record_type == "SRV":
            return [
                str(DNSWorkflows._bounded(arguments["priority"], "priority", 0, 65535)),
                str(DNSWorkflows._bounded(arguments["weight"], "weight", 0, 65535)),
                str(DNSWorkflows._bounded(arguments["port"], "port", 1, 65535)),
                DNSWorkflows._fqdn(str(arguments["target"])),
            ]
        if record_type == "CAA":
            tag = str(arguments["tag"]).strip().lower()
            if tag not in _CAA_TAGS:
                raise invalid(f"the CAA tag must be one of {', '.join(_CAA_TAGS)}")
            flags = DNSWorkflows._bounded(arguments.get("flags", 0), "flags", 0, 255)
            if flags not in {0, 128}:
                raise invalid("the CAA flags must be 0 or 128")
            value = str(arguments["value"]).strip().strip('"')
            if not value:
                raise invalid("the CAA value must not be empty")
            return [str(flags), tag, value]
        raise invalid(f"unsupported record type {record_type}")

    @staticmethod
    def _bounded(value: Any, field: str, low: int, high: int) -> int:
        try:
            number = int(value)
        except (TypeError, ValueError) as exc:
            raise DNSWorkflows._invalid(f"{field} must be an integer") from exc
        if not low <= number <= high:
            raise DNSWorkflows._invalid(f"{field} must be between {low} and {high}")
        return number

    @staticmethod
    def _fqdn(value: str) -> str:
        host = value.strip()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise DNSWorkflows._invalid("a hostname is required, not an IP address")
        if not _HOSTNAME.match(host):
            raise DNSWorkflows._invalid(f"{value!r} is not a valid hostname")
        return host.rstrip(".").casefold() + "."

    @classmethod
    def _normalize_data(cls, record_type: str, data: list[str]) -> tuple[str, ...]:
        """Comparable form of a record's data, tolerant of cPanel formatting."""
        rtype = record_type.upper()
        try:
            if rtype in {"A", "AAAA"}:
                return (str(ipaddress.ip_address(data[0].strip())),)
            if rtype == "CNAME":
                return (cls._canonical_name(data[0]),)
            if rtype == "MX":
                return (str(int(data[0])), cls._canonical_name(data[1]))
            if rtype == "SRV":
                return (
                    str(int(data[0])),
                    str(int(data[1])),
                    str(int(data[2])),
                    cls._canonical_name(data[3]),
                )
            if rtype == "CAA":
                return (str(int(data[0])), data[1].strip().lower(), data[2].strip().strip('"'))
        except (ValueError, IndexError, AttributeError):
            pass
        return tuple(str(item) for item in data)

    def _parse_value(self, record_type: str, value: str) -> list[str]:
        """Split a human-readable record value ("10 mail.example.com") into data fields."""
        fields = self._VALUE_FIELDS.get(record_type)
        if fields is None:
            return [value]
        parts = value.split(None, fields - 1)
        if len(parts) != fields:
            raise self._invalid(f"a {record_type} value needs {fields} space-separated fields")
        return parts

    async def prepare_cname(self, account: str | None, arguments: dict[str, Any]) -> dict[str, Any]:
        if not account:
            raise CPanelError("DNS workflows require an account", code="ACCOUNT_REQUIRED")
        zone = str(arguments["zone"])
        name = self._absolute(zone, str(arguments["name"]))
        wire_name = self._wire_name(zone, str(arguments["name"]))
        target = self._canonical_name(str(arguments["target"]))
        current = await self._read_zone(account, zone)
        records = self._records(current)
        matching = [record for record in records if self._absolute(zone, record["name"]) == name]
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
                "record": self._record(wire_name, int(arguments["ttl"]), "CNAME", [target]),
            }
        else:
            plan = {
                "operation": "add",
                "record": self._record(wire_name, int(arguments["ttl"]), "CNAME", [target]),
            }
        return {"zone": zone, "serial": self._serial(current), "records": records, "plan": plan}

    async def execute_cname(self, preparation: Preparation) -> dict[str, Any]:
        return await self._execute_record(preparation, "CNAME")

    async def prepare_txt(self, account: str | None, arguments: dict[str, Any]) -> dict[str, Any]:
        if not account:
            raise CPanelError("DNS workflows require an account", code="ACCOUNT_REQUIRED")
        zone = str(arguments["zone"])
        name = self._absolute(zone, str(arguments["name"]))
        wire_name = self._wire_name(zone, str(arguments["name"]))
        value = str(arguments["value"])
        current = await self._read_zone(account, zone)
        records = self._records(current)
        matching = [
            record
            for record in records
            if self._absolute(zone, record["name"]) == name
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
                    "record": self._record(wire_name, int(arguments["ttl"]), "TXT", [value]),
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
                    "record": self._record(wire_name, int(arguments["ttl"]), "TXT", [value]),
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
        name = self._absolute(zone, str(arguments["name"]))
        record_type = str(arguments["record_type"]).upper()
        wanted = self._normalize_data(
            record_type, self._parse_value(record_type, str(arguments["value"]))
        )
        current = await self._read_zone(account, zone)
        matches = [
            record
            for record in self._records(current)
            if self._absolute(zone, record["name"]) == name
            and record["record_type"].upper() == record_type
            and self._normalize_data(record_type, record["data"]) == wanted
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
        operation = self._mass_edit_capability()
        before = preparation.before_state or {}
        current = before
        for attempt in range(2):
            removed = current["plan"]["record"]
            payload = {
                "zone": current["zone"],
                "serial": current["serial"],
                "remove": current["plan"]["line_index"],
            }
            try:
                result = await self.harness.cpanel.call(
                    operation, account, payload, retry_safe=False
                )
            except CPanelError as exc:
                if exc.code != "UPSTREAM_NETWORK_ERROR":
                    raise
                after = await self._read_after_ambiguous_write(account, str(current["zone"]))
                if not self._has_record(str(current["zone"]), after, removed):
                    return {
                        "data": {"changed": True, "reconciled_after_transport_error": True},
                        "after_state": after,
                        "verified": True,
                        "warnings": [
                            "DNS removal response was lost; state was reconciled from cPanel"
                        ],
                    }
                if attempt == 1:
                    raise self._unknown_write_error(attempt + 1) from exc
                current = await self._refresh_remove_plan(preparation)
                continue

            try:
                after = await self._read_zone(account, str(current["zone"]))
            except CPanelError as exc:
                if exc.code != "UPSTREAM_NETWORK_ERROR":
                    raise
                raise self._unknown_write_error(attempt + 1) from exc
            verified = not self._has_record(str(current["zone"]), after, removed)
            return {
                "data": result,
                "after_state": after,
                "verified": verified,
                "warnings": [] if verified else ["DNS record removal was not verified"],
            }
        raise self._unknown_write_error(2)

    async def _execute_record(self, preparation: Preparation, record_type: str) -> dict[str, Any]:
        account = preparation.account
        current = preparation.before_state or {}
        plan = current.get("plan", {})
        if plan.get("operation") == "noop":
            after = await self._read_zone(account, str(current["zone"]))
            return {
                "data": {"changed": False, "reason": plan["reason"]},
                "after_state": after,
                "verified": True,
                "warnings": [],
            }

        operation = self._mass_edit_capability()
        for attempt in range(2):
            plan = current["plan"]
            if plan.get("operation") == "noop":
                after = await self._read_zone(account, str(current["zone"]))
                return {
                    "data": {"changed": False, "reason": plan["reason"]},
                    "after_state": after,
                    "verified": True,
                    "warnings": [],
                }
            payload = self._record_payload(current)
            requested = plan["record"]
            try:
                result = await self.harness.cpanel.call(
                    operation, account, payload, retry_safe=False
                )
            except CPanelError as exc:
                if exc.code != "UPSTREAM_NETWORK_ERROR":
                    raise
                reconciled = await self._read_after_ambiguous_write(account, str(current["zone"]))
                if self._has_requested_record(
                    str(current["zone"]), reconciled, requested, record_type
                ):
                    return {
                        "data": {"changed": True, "reconciled_after_transport_error": True},
                        "after_state": reconciled,
                        "verified": True,
                        "warnings": [
                            "DNS write response was lost; state was reconciled from cPanel"
                        ],
                    }
                if attempt == 1:
                    raise self._unknown_write_error(attempt + 1) from exc
                current = await self._refresh_record_plan(preparation, record_type)
                continue

            try:
                after = await self._read_zone(account, str(current["zone"]))
            except CPanelError as exc:
                if exc.code != "UPSTREAM_NETWORK_ERROR":
                    raise
                raise self._unknown_write_error(attempt + 1) from exc
            verified = self._has_requested_record(
                str(current["zone"]), after, requested, record_type
            )
            return {
                "data": result,
                "after_state": after,
                "verified": verified,
                "warnings": (
                    []
                    if verified
                    else [f"{record_type} postcondition did not match requested state"]
                ),
            }
        raise self._unknown_write_error(2)

    @staticmethod
    def _record_payload(state: dict[str, Any]) -> dict[str, Any]:
        plan = state["plan"]
        payload: dict[str, Any] = {"zone": state["zone"], "serial": state["serial"]}
        if plan["operation"] == "add":
            payload["add"] = json.dumps(plan["record"], separators=(",", ":"))
        else:
            record = {"line_index": plan["line_index"], **plan["record"]}
            payload["edit"] = json.dumps(record, separators=(",", ":"))
        return payload

    async def _refresh_record_plan(
        self, preparation: Preparation, record_type: str
    ) -> dict[str, Any]:
        if record_type == "CNAME":
            return await self.prepare_cname(preparation.account, preparation.arguments)
        if record_type == "TXT":
            return await self.prepare_txt(preparation.account, preparation.arguments)
        return await self.prepare_typed(record_type, preparation.account, preparation.arguments)

    async def _refresh_remove_plan(self, preparation: Preparation) -> dict[str, Any]:
        return await self.prepare_remove(preparation.account, preparation.arguments)

    async def _read_after_ambiguous_write(self, account: str | None, zone: str) -> Any:
        try:
            return await self._read_zone(account, zone)
        except CPanelError as exc:
            if exc.code != "UPSTREAM_NETWORK_ERROR":
                raise
            raise self._unknown_write_error(1) from exc

    @staticmethod
    def _unknown_write_error(attempts: int) -> CPanelError:
        return CPanelError(
            "DNS write outcome could not be reconciled",
            code="DNS_WRITE_STATE_UNKNOWN",
            details={"state_unknown": True, "write_attempts": attempts},
            retryable=False,
            hint="Read the authoritative DNS zone before retrying the write.",
        )

    def _has_record(self, zone_name: str, zone: Any, removed: dict[str, Any]) -> bool:
        return any(
            self._absolute(zone_name, record["name"]) == self._absolute(zone_name, removed["name"])
            and record["record_type"].upper() == removed["record_type"].upper()
            and self._normalize_data(record["record_type"], record["data"])
            == self._normalize_data(removed["record_type"], removed["data"])
            for record in self._records(zone)
        )

    def _has_requested_record(
        self, zone_name: str, zone: Any, requested: dict[str, Any], record_type: str
    ) -> bool:
        return any(
            self._absolute(zone_name, record["name"])
            == self._absolute(zone_name, requested["dname"])
            and record["record_type"].upper() == record_type
            and self._normalize_data(record_type, record["data"])
            == self._normalize_data(record_type, requested["data"])
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

    @classmethod
    def _absolute(cls, zone: str, name: str) -> str:
        """Absolute, comparable form of a record name.

        cPanel reports the apex as the absolute zone name ("example.com.") and other names
        relative to the zone ("www"), while callers usually say "@". A name that already ends
        with the zone name is taken as qualified.
        """
        zone_name = cls._canonical_name(zone)
        text = name.strip()
        if text in {"", "@"}:
            return zone_name
        if text.endswith("."):
            return cls._canonical_name(text)
        canonical = cls._canonical_name(text)
        if canonical == zone_name or canonical.endswith(f".{zone_name}"):
            return canonical
        return f"{canonical}.{zone_name}"

    @classmethod
    def _wire_name(cls, zone: str, name: str) -> str:
        """Name to send to cPanel: the absolute zone name for the apex, else relative."""
        zone_name = cls._canonical_name(zone)
        absolute = cls._absolute(zone, name)
        if absolute == zone_name:
            return f"{zone_name}."
        if not absolute.endswith(f".{zone_name}"):
            raise cls._invalid(f"the record name {name!r} is outside the zone {zone}")
        return absolute[: -len(zone_name) - 1]

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
