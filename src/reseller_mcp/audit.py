from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from .db import Database
from .models import Principal

SENSITIVE_KEY = re.compile(
    r"pass(word)?|secret|token|access.?hash|authorization|api.?key|private.?key|content"
    r"|^(key|cert|crt|cab|cabundle|csr)$|_key$",
    re.IGNORECASE,
)
PRIVATE_KEY_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.IGNORECASE)
# A user or token embedded in a URL: any user info on http(s), and user:password on ssh or git.
_HTTP_USERINFO = re.compile(r"\b(https?)://[^/\s@]+@", re.IGNORECASE)
_SSH_USERINFO = re.compile(r"\b(ssh|git)://[^/\s@:]+:[^/\s@]*@", re.IGNORECASE)


def scrub_url_userinfo(text: str) -> str:
    """Mask a user, password or token embedded in a URL; a plain ssh user such as git stays."""
    text = _HTTP_USERINFO.sub(r"\1://[REDACTED]@", text)
    return _SSH_USERINFO.sub(r"\1://[REDACTED]@", text)


def scrub_urls(value: Any) -> Any:
    """scrub_url_userinfo over every string of a nested result."""
    if isinstance(value, dict):
        return {key: scrub_urls(item) for key, item in value.items()}
    if isinstance(value, list):
        return [scrub_urls(item) for item in value]
    if isinstance(value, str):
        return scrub_url_userinfo(value)
    return value


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if SENSITIVE_KEY.search(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str) and PRIVATE_KEY_PEM.search(value):
        # A private key must never reach the audit log, whatever the field is called.
        return "[REDACTED]"
    if isinstance(value, str):
        value = scrub_url_userinfo(value)
        if len(value) > 4096:
            return value[:4096] + "...[TRUNCATED]"
    return value


class AuditLog:
    def __init__(self, db: Database):
        self.db = db

    def append(
        self,
        *,
        principal: Principal | None,
        capability_id: str,
        account: str | None,
        correlation_id: str | None = None,
        phase: str,
        outcome: str,
        parameters: dict[str, Any] | None = None,
        details: dict[str, Any] | None = None,
    ) -> str:
        event_id = str(uuid.uuid4())
        occurred_at = datetime.now(UTC).isoformat()
        parameters_json = json.dumps(redact(parameters or {}), ensure_ascii=False, sort_keys=True)
        details_json = json.dumps(redact(details or {}), ensure_ascii=False, sort_keys=True)
        with self.db._lock, self.db.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT event_hash FROM audit_events ORDER BY occurred_at DESC,id DESC LIMIT 1"
            ).fetchone()
            previous_hash = row["event_hash"] if row else None
            canonical = "|".join(
                [
                    previous_hash or "",
                    event_id,
                    occurred_at,
                    principal.user_id if principal else "",
                    principal.client_id if principal else "",
                    capability_id,
                    account or "",
                    correlation_id or "",
                    phase,
                    outcome,
                    parameters_json,
                    details_json,
                ]
            )
            event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            conn.execute(
                """INSERT INTO audit_events
                   (id,occurred_at,user_id,client_id,capability_id,account,correlation_id,
                    phase,outcome,parameters,details,previous_hash,event_hash)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    event_id,
                    occurred_at,
                    principal.user_id if principal else None,
                    principal.client_id if principal else None,
                    capability_id,
                    account,
                    correlation_id,
                    phase,
                    outcome,
                    parameters_json,
                    details_json,
                    previous_hash,
                    event_hash,
                ),
            )
            conn.execute("COMMIT")
        return event_id
