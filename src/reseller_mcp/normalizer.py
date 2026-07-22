from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def _payload_data(value: Any) -> Any:
    if (
        isinstance(value, dict)
        and "data" in value
        and any(key in value for key in ("status", "metadata", "errors", "messages", "warnings"))
    ):
        return value.get("data")
    return value


def _integer(value: Any) -> int | None:
    if value in (None, "", "unlimited"):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _boolean(value: Any) -> bool:
    return str(value).lower() in {"1", "true", "yes", "on"}


def _bytes_from_cpanel_size(value: Any) -> int | None:
    if value in (None, "", "unlimited"):
        return None
    text = str(value).strip().upper()
    multipliers = {"B": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    suffix = text[-1] if text[-1:] in multipliers else "B"
    number = text[:-1] if suffix != "B" or text.endswith("B") else text
    if text.endswith("B") and len(text) > 1 and text[-2:-1] in multipliers:
        suffix = text[-2]
        number = text[:-2]
    try:
        return int(float(number) * multipliers[suffix])
    except ValueError:
        return None


def _human_bytes(value: int | None) -> str | None:
    if value is None:
        return None
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.2f} {unit}"
        amount /= 1024
    return None


def _percentage(used: int | None, limit: int | None) -> float | None:
    if used is None or not limit:
        return None
    return round((used / limit) * 100, 2)


def _iso_timestamp(value: Any) -> str | None:
    timestamp = _integer(value)
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, UTC).isoformat()


def _account(item: dict[str, Any]) -> dict[str, Any]:
    disk_used = _bytes_from_cpanel_size(item.get("diskused"))
    disk_limit = _bytes_from_cpanel_size(item.get("disklimit"))
    return {
        "username": item.get("user"),
        "uid": str(item.get("uid")) if item.get("uid") is not None else None,
        "domain": item.get("domain") or item.get("maindomain"),
        "owner": item.get("owner"),
        "contact_email": item.get("email"),
        "ip": item.get("ip"),
        "ipv6": item.get("ipv6") or [],
        "plan": item.get("plan"),
        "theme": item.get("theme"),
        "partition": item.get("partition"),
        "shell": item.get("shell"),
        "created_at": _iso_timestamp(item.get("unix_startdate")),
        "status": {
            "suspended": _boolean(item.get("suspended")),
            "locked": _boolean(item.get("is_locked")),
            "temporary": _boolean(item.get("temporary")),
            "reason": item.get("suspendreason"),
        },
        "disk": {
            "used_bytes": disk_used,
            "used_human": _human_bytes(disk_used),
            "limit_bytes": disk_limit,
            "limit_human": _human_bytes(disk_limit),
            "unlimited": str(item.get("disklimit")).lower() == "unlimited",
            "used_percent": _percentage(disk_used, disk_limit),
        },
        "inodes": {
            "used": _integer(item.get("inodesused")),
            "limit": _integer(item.get("inodeslimit")),
            "unlimited": str(item.get("inodeslimit")).lower() == "unlimited",
        },
        "mail": {
            "outgoing_suspended": _boolean(item.get("outgoing_mail_suspended")),
            "outgoing_hold": _boolean(item.get("outgoing_mail_hold")),
            "max_per_hour": item.get("max_email_per_hour"),
            "mailbox_format": item.get("mailbox_format"),
        },
        "backup": {
            "enabled": _boolean(item.get("backup")),
            "legacy_enabled": _boolean(item.get("legacy_backup")),
            "has_backup": _boolean(item.get("has_backup")),
        },
        "limits": {
            "ftp": item.get("maxftp"),
            "databases": item.get("maxsql"),
            "mailboxes": item.get("maxpop"),
            "subdomains": item.get("maxsub"),
            "addon_domains": item.get("maxaddons"),
            "parked_domains": item.get("maxparked"),
            "mailing_lists": item.get("maxlst"),
            "mailbox_quota": item.get("max_emailacct_quota"),
        },
    }


def _records(value: Any) -> list[dict[str, Any]]:
    payload = _payload_data(value)
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        return [payload]
    return []


def normalize_result(capability_id: str, value: Any, account: str | None = None) -> Any:
    if capability_id in {"whm.accountsummary", "whm.listaccts"}:
        items = value.get("acct", []) if isinstance(value, dict) else []
        normalized = [_account(item) for item in items if isinstance(item, dict)]
        return normalized[0] if capability_id == "whm.accountsummary" and normalized else normalized

    if capability_id == "uapi.DomainInfo.list_domains":
        payload = _payload_data(value)
        payload = payload if isinstance(payload, dict) else {}
        return {
            "main": payload.get("main_domain"),
            "addon": payload.get("addon_domains") or [],
            "aliases": payload.get("parked_domains") or [],
            "subdomains": payload.get("sub_domains") or [],
        }

    if capability_id == "uapi.Mysql.list_databases":
        databases = []
        for item in _records(value):
            usage = _integer(item.get("disk_usage")) or 0
            databases.append(
                {
                    "name": item.get("database"),
                    "users": item.get("users") or [],
                    "disk_usage_bytes": usage,
                    "disk_usage_human": _human_bytes(usage),
                }
            )
        return {"items": databases, "count": len(databases)}

    if capability_id == "uapi.Email.list_pops":
        mailboxes = [
            {
                "email": item.get("email"),
                "login": item.get("login"),
                "incoming_suspended": _boolean(item.get("suspended_incoming")),
                "login_suspended": _boolean(item.get("suspended_login")),
            }
            for item in _records(value)
        ]
        return {"items": mailboxes, "count": len(mailboxes)}

    if capability_id in {"uapi.Ftp.list_ftp", "uapi.Ftp.list_ftp_with_disk"}:
        items = [
            {
                "username": item.get("user"),
                "type": item.get("type"),
                "home": item.get("homedir"),
                "disk_usage_bytes": _integer(item.get("diskused")),
            }
            for item in _records(value)
        ]
        return {"items": items, "count": len(items)}

    if capability_id == "uapi.Ftp.allows_anonymous_ftp":
        payload = _payload_data(value)
        allows = payload.get("allows") if isinstance(payload, dict) else payload
        return {"enabled": _boolean(allows)}

    if capability_id == "uapi.Backup.list_backups":
        items = _payload_data(value)
        items = items if isinstance(items, list) else []
        return {"items": items, "count": len(items)}

    if capability_id == "uapi.LangPHP.php_get_vhost_versions":
        items = [
            {
                "vhost": item.get("vhost"),
                "version": item.get("version"),
                "php_fpm": _boolean(item.get("php_fpm")),
                "document_root": item.get("documentroot"),
                "home": item.get("homedir"),
                "main_domain": _boolean(item.get("main_domain")),
            }
            for item in _records(value)
        ]
        return {"items": items, "count": len(items)}

    if capability_id == "uapi.Email.list_mxs":
        return {"items": _records(value), "count": len(_records(value))}

    if capability_id in {
        "uapi.Email.list_forwarders",
        "uapi.Email.list_auto_responders",
        "uapi.Fileman.list_files",
        "uapi.SSL.list_ssl_items",
    }:
        items = _records(value)
        return {"items": items, "count": len(items)}

    if capability_id in {
        "uapi.EmailAuth.validate_current_spfs",
        "uapi.EmailAuth.validate_current_dkims",
    }:
        records = _records(value)
        states = [str(item.get("state", "UNKNOWN")).upper() for item in records]
        valid = bool(states) and all(state in {"VALID", "PASS"} for state in states)
        return {"valid": valid, "states": states, "items": records}

    if capability_id == "uapi.Bandwidth.query":
        payload = _payload_data(value)
        return {"account": account, "usage": payload}

    if capability_id == "whm.showbw" and isinstance(value, dict):
        accounts = []
        for item in value.get("acct", []):
            if not isinstance(item, dict):
                continue
            used = _integer(item.get("totalbytes")) or 0
            limit = _integer(item.get("limit"))
            accounts.append(
                {
                    "username": item.get("user"),
                    "domain": item.get("maindomain"),
                    "used_bytes": used,
                    "used_human": _human_bytes(used),
                    "limit_bytes": limit,
                    "limit_human": _human_bytes(limit),
                    "used_percent": _percentage(used, limit),
                    "limited": _boolean(item.get("bwlimited")),
                    "domains": item.get("bwusage") or [],
                }
            )
        return {"month": value.get("month"), "year": value.get("year"), "items": accounts}

    return _payload_data(value)
