from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .models import Capability, Preparation, PreparationState, Risk, Role

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK(role IN ('viewer','operator','admin')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS client_tokens (
  key_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  client_id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT
);
CREATE TABLE IF NOT EXISTS account_scopes (
  user_id TEXT NOT NULL REFERENCES users(id),
  account TEXT NOT NULL,
  PRIMARY KEY(user_id, account)
);
CREATE TABLE IF NOT EXISTS capabilities (
  id TEXT PRIMARY KEY,
  payload TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  api TEXT NOT NULL,
  risk TEXT NOT NULL,
  available INTEGER NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS capabilities_fts USING fts5(
  capability_id UNINDEXED, title, description, function_name, aliases,
  tokenize='unicode61 remove_diacritics 2'
);
CREATE TABLE IF NOT EXISTS preparations (
  id TEXT PRIMARY KEY,
  principal_user_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  capability_id TEXT NOT NULL,
  account TEXT,
  arguments TEXT NOT NULL,
  state TEXT NOT NULL,
  risk TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  confirmation_phrase TEXT,
  before_state TEXT,
  result TEXT,
  error TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(principal_user_id, client_id, idempotency_key)
);
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  preparation_id TEXT NOT NULL REFERENCES preparations(id),
  state TEXT NOT NULL,
  progress INTEGER NOT NULL DEFAULT 0,
  result TEXT,
  error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS preparation_approvals (
  preparation_id TEXT NOT NULL REFERENCES preparations(id),
  approver_user_id TEXT NOT NULL REFERENCES users(id),
  approved_at TEXT NOT NULL,
  PRIMARY KEY(preparation_id, approver_user_id)
);
CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  occurred_at TEXT NOT NULL,
  user_id TEXT,
  client_id TEXT,
  capability_id TEXT NOT NULL,
  account TEXT,
  correlation_id TEXT,
  phase TEXT NOT NULL,
  outcome TEXT NOT NULL,
  parameters TEXT NOT NULL,
  details TEXT NOT NULL,
  previous_hash TEXT,
  event_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_events_time_idx ON audit_events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_user_idx ON audit_events(user_id, occurred_at DESC);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(audit_events)").fetchall()
            }
            if "correlation_id" not in columns:
                conn.execute("ALTER TABLE audit_events ADD COLUMN correlation_id TEXT")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS audit_events_correlation_idx "
                "ON audit_events(correlation_id, occurred_at DESC)"
            )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def create_user(self, username: str, role: Role, scopes: list[str]) -> str:
        user_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        with self._lock, self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO users(id,username,role,created_at) VALUES(?,?,?,?)",
                (user_id, username, role.value, now),
            )
            conn.executemany(
                "INSERT INTO account_scopes(user_id,account) VALUES(?,?)",
                [(user_id, scope) for scope in scopes],
            )
            conn.execute("COMMIT")
        return user_id

    def get_user(self, username: str) -> sqlite3.Row | None:
        with self.connect() as conn:
            row: sqlite3.Row | None = conn.execute(
                "SELECT * FROM users WHERE username=? AND active=1", (username,)
            ).fetchone()
            return row

    def list_users(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """SELECT u.id,u.username,u.role,u.active,u.created_at,
                   COALESCE(group_concat(s.account), '') AS scopes
                   FROM users u LEFT JOIN account_scopes s ON s.user_id=u.id
                   GROUP BY u.id ORDER BY u.username"""
            ).fetchall()
        return [
            {
                **{key: row[key] for key in ("id", "username", "role", "created_at")},
                "active": bool(row["active"]),
                "scopes": sorted(filter(None, str(row["scopes"]).split(","))),
            }
            for row in rows
        ]

    def set_user_active(self, username: str, active: bool) -> bool:
        with self.connect() as conn:
            result = conn.execute(
                "UPDATE users SET active=? WHERE username=?", (int(active), username)
            )
            return result.rowcount > 0

    def replace_user_scopes(self, username: str, scopes: list[str]) -> bool:
        with self._lock, self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            if not row:
                conn.execute("ROLLBACK")
                return False
            conn.execute("DELETE FROM account_scopes WHERE user_id=?", (row["id"],))
            conn.executemany(
                "INSERT INTO account_scopes(user_id,account) VALUES(?,?)",
                [(row["id"], scope) for scope in sorted(set(scopes))],
            )
            conn.execute("COMMIT")
            return True

    def list_tokens(self, username: str | None = None) -> list[dict[str, Any]]:
        query = """SELECT t.key_id,u.username,t.client_id,t.active,t.expires_at,
                   t.created_at,t.last_used_at FROM client_tokens t
                   JOIN users u ON u.id=t.user_id"""
        params: tuple[Any, ...] = ()
        if username:
            query += " WHERE u.username=?"
            params = (username,)
        query += " ORDER BY t.created_at DESC"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [{**dict(row), "active": bool(row["active"])} for row in rows]

    def get_principal_by_key(self, key_id: str) -> tuple[sqlite3.Row, frozenset[str]] | None:
        now = datetime.now(UTC).isoformat()
        with self.connect() as conn:
            row = conn.execute(
                """SELECT t.*,u.username,u.role,u.active AS user_active
                   FROM client_tokens t JOIN users u ON u.id=t.user_id
                   WHERE t.key_id=? AND t.active=1 AND u.active=1
                   AND (t.expires_at IS NULL OR t.expires_at>?)""",
                (key_id, now),
            ).fetchone()
            if not row:
                return None
            scopes = frozenset(
                r["account"]
                for r in conn.execute(
                    "SELECT account FROM account_scopes WHERE user_id=?", (row["user_id"],)
                )
            )
            return row, scopes

    def insert_token(
        self,
        key_id: str,
        user_id: str,
        client_id: str,
        token_hash: str,
        expires_at: datetime | None,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO client_tokens
                   (key_id,user_id,client_id,token_hash,expires_at,created_at)
                   VALUES(?,?,?,?,?,?)""",
                (
                    key_id,
                    user_id,
                    client_id,
                    token_hash,
                    expires_at.isoformat() if expires_at else None,
                    datetime.now(UTC).isoformat(),
                ),
            )

    def touch_token(self, key_id: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE client_tokens SET last_used_at=? WHERE key_id=?",
                (datetime.now(UTC).isoformat(), key_id),
            )

    def revoke_token(self, key_id: str) -> bool:
        with self.connect() as conn:
            result = conn.execute("UPDATE client_tokens SET active=0 WHERE key_id=?", (key_id,))
            return result.rowcount > 0

    def sync_capabilities(self, capabilities: list[Capability], aliases: dict[str, str]) -> None:
        with self._lock, self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM capabilities")
            conn.execute("DELETE FROM capabilities_fts")
            for capability in capabilities:
                payload = capability.model_dump_json()
                conn.execute(
                    "INSERT INTO capabilities VALUES(?,?,?,?,?,?,?)",
                    (
                        capability.id,
                        payload,
                        capability.title,
                        capability.description,
                        capability.api.value,
                        capability.risk.value,
                        int(capability.available),
                    ),
                )
                conn.execute(
                    "INSERT INTO capabilities_fts VALUES(?,?,?,?,?)",
                    (
                        capability.id,
                        capability.title,
                        capability.description,
                        capability.function,
                        aliases.get(capability.id, ""),
                    ),
                )
            conn.execute("COMMIT")

    def search_capabilities(self, query: str, limit: int) -> list[Capability]:
        normalized = " ".join(
            "".join(character for character in part if character.isalnum() or character == "_")
            for part in query.replace("-", " ").split()
        ).strip()
        with self.connect() as conn:
            if not normalized:
                rows = conn.execute(
                    "SELECT payload FROM capabilities ORDER BY id LIMIT ?", (limit,)
                ).fetchall()
            else:
                terms = " OR ".join(f'"{part}"*' for part in normalized.split())
                rows = conn.execute(
                    """SELECT c.payload FROM capabilities_fts f
                       JOIN capabilities c ON c.id=f.capability_id
                       WHERE capabilities_fts MATCH ?
                       ORDER BY bm25(capabilities_fts) LIMIT ?""",
                    (terms, limit),
                ).fetchall()
        return [Capability.model_validate_json(row["payload"]) for row in rows]

    def approve_preparation(self, preparation_id: str, approver_user_id: str) -> bool:
        with self.connect() as conn:
            result = conn.execute(
                """INSERT OR IGNORE INTO preparation_approvals
                   (preparation_id,approver_user_id,approved_at) VALUES(?,?,?)""",
                (preparation_id, approver_user_id, datetime.now(UTC).isoformat()),
            )
            return result.rowcount > 0

    def preparation_approvers(self, preparation_id: str) -> frozenset[str]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT approver_user_id FROM preparation_approvals WHERE preparation_id=?",
                (preparation_id,),
            ).fetchall()
        return frozenset(row["approver_user_id"] for row in rows)

    def get_capability(self, capability_id: str) -> Capability | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload FROM capabilities WHERE id=?", (capability_id,)
            ).fetchone()
        return Capability.model_validate_json(row["payload"]) if row else None

    def insert_preparation(self, preparation: Preparation) -> Preparation:
        now = datetime.now(UTC).isoformat()
        with self.connect() as conn:
            try:
                conn.execute(
                    """INSERT INTO preparations
                       (id,principal_user_id,client_id,capability_id,account,arguments,state,risk,
                        idempotency_key,confirmation_phrase,before_state,created_at,expires_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        preparation.id,
                        preparation.principal_user_id,
                        preparation.client_id,
                        preparation.capability_id,
                        preparation.account,
                        json.dumps(preparation.arguments, ensure_ascii=False, sort_keys=True),
                        preparation.state.value,
                        preparation.risk.value,
                        preparation.idempotency_key,
                        preparation.confirmation_phrase,
                        json.dumps(preparation.before_state, ensure_ascii=False)
                        if preparation.before_state is not None
                        else None,
                        preparation.created_at.isoformat(),
                        preparation.expires_at.isoformat(),
                        now,
                    ),
                )
            except sqlite3.IntegrityError:
                existing = conn.execute(
                    """SELECT id FROM preparations
                       WHERE principal_user_id=? AND client_id=? AND idempotency_key=?""",
                    (
                        preparation.principal_user_id,
                        preparation.client_id,
                        preparation.idempotency_key,
                    ),
                ).fetchone()
                if not existing:
                    raise
                existing_preparation = self.get_preparation(existing["id"])
                if (
                    existing_preparation.capability_id != preparation.capability_id
                    or existing_preparation.account != preparation.account
                    or existing_preparation.arguments != preparation.arguments
                ):
                    raise ValueError(
                        "idempotency key already belongs to a different action"
                    ) from None
                return existing_preparation
        return preparation

    def get_preparation(self, preparation_id: str) -> Preparation:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM preparations WHERE id=?", (preparation_id,)
            ).fetchone()
        if not row:
            raise KeyError("preparation not found")
        return Preparation(
            id=row["id"],
            principal_user_id=row["principal_user_id"],
            client_id=row["client_id"],
            capability_id=row["capability_id"],
            account=row["account"],
            arguments=json.loads(row["arguments"]),
            state=PreparationState(row["state"]),
            risk=Risk(row["risk"]),
            idempotency_key=row["idempotency_key"],
            confirmation_phrase=row["confirmation_phrase"],
            before_state=json.loads(row["before_state"]) if row["before_state"] else None,
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
        )

    def set_preparation_state(
        self,
        preparation_id: str,
        state: PreparationState,
        *,
        result: dict[str, Any] | None = None,
        error: dict[str, Any] | None = None,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """UPDATE preparations SET state=?,result=?,error=?,updated_at=? WHERE id=?""",
                (
                    state.value,
                    json.dumps(result, ensure_ascii=False) if result is not None else None,
                    json.dumps(error, ensure_ascii=False) if error is not None else None,
                    datetime.now(UTC).isoformat(),
                    preparation_id,
                ),
            )

    def audit_rows(
        self, user_id: str | None, limit: int, correlation_id: str | None = None
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM audit_events"
        params: list[Any] = []
        filters: list[str] = []
        if user_id:
            filters.append("user_id=?")
            params.append(user_id)
        if correlation_id:
            filters.append("correlation_id=?")
            params.append(correlation_id)
        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY occurred_at DESC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            return [dict(row) for row in conn.execute(query, params).fetchall()]

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """SELECT j.*,p.principal_user_id FROM jobs j
                   JOIN preparations p ON p.id=j.preparation_id WHERE j.id=?""",
                (job_id,),
            ).fetchone()
        if not row:
            return None
        value = dict(row)
        value["result"] = json.loads(value["result"]) if value["result"] else None
        value["error"] = json.loads(value["error"]) if value["error"] else None
        return value

    def create_job(self, preparation_id: str) -> str:
        job_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO jobs(id,preparation_id,state,progress,created_at,updated_at)
                   VALUES(?,?,?,0,?,?)""",
                (job_id, preparation_id, "queued", now, now),
            )
        return job_id

    def update_job(
        self,
        job_id: str,
        state: str,
        progress: int,
        *,
        result: dict[str, Any] | None = None,
        error: dict[str, Any] | None = None,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """UPDATE jobs SET state=?,progress=?,result=?,error=?,updated_at=? WHERE id=?""",
                (
                    state,
                    min(max(progress, 0), 100),
                    json.dumps(result, ensure_ascii=False) if result is not None else None,
                    json.dumps(error, ensure_ascii=False) if error is not None else None,
                    datetime.now(UTC).isoformat(),
                    job_id,
                ),
            )

    def purge_old_audit(self, retention_days: int) -> int:
        cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat()
        with self.connect() as conn:
            result = conn.execute("DELETE FROM audit_events WHERE occurred_at<?", (cutoff,))
            return result.rowcount
