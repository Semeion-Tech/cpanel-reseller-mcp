# Secure Database Access Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the manual "publish a temporary PHP file" workaround with three new MCP capabilities — `database.query_readonly`, `database.transaction_execute`, `workflow.database_migration_apply` — that reach a client's MySQL database over an ephemeral, least-privilege, directly-connected TCP session provisioned through existing WHM/UAPI `Mysql::*` calls, with SQL-level guardrails, row-level backups, dry-run validation, and a versioned migration ledger.

**Architecture:** A new `MySQLEphemeralSession` provisions a throwaway MySQL user via `uapi.Mysql.*` (never storing credentials), connects directly over TCP with `aiomysql`, and tears everything down in `finally`. SQL text is parsed with `sqlglot` (never regex) to enforce statement-type guardrails and to mechanically derive a `SELECT` snapshot of rows a write is about to touch. The three new capabilities are `ApiFamily.WORKFLOW` entries in the existing capability catalog, dispatched by a small handler registry added to `Harness` — reusing the exact same `query_execute` / `action_prepare` / `action_execute` pipeline (audit log, idempotency, confirmation phrases) that every other capability already goes through.

**Tech Stack:** Python 3.12, `aiomysql` (pure-Python async MySQL driver, easy to fake in tests without Docker), `sqlglot` (SQL parsing/AST, MySQL dialect), existing `pytest` + `pytest-asyncio` + fixtures in `tests/conftest.py`.

## Global Constraints

- Python 3.12, `uv` for dependency management (from `pyproject.toml`).
- `mypy --strict` and `ruff` (line length 100, rules `E,F,I,UP,B,SIM`) must pass — run `uv run mypy` and `uv run ruff check` after every task.
- Never store MySQL credentials at rest. `EphemeralCredentials.password` must never be logged, persisted, or included in audit `parameters`/`details` (the existing `redact()` in `audit.py` redacts any key matching `pass(word)?|secret|token|...` — ephemeral credentials must use a key name that matches, e.g. never put the raw password dict key as anything other than `password`).
- Every SQL statement must be validated through `sql_guardrails.py` — never trust `arguments["sql"]`/`arguments["statements"]` directly against the database.
- Every new public function needs a unit test with a real assertion (no `assert True` placeholders).
- Follow existing code style: `from __future__ import annotations` at the top of every new module, `StrEnum`/`Pydantic` model conventions from `models.py`, docstring-free code (this repo has none — match that).

---

## Task 1: Connectivity spike — confirm direct TCP MySQL reachability

This is the load-bearing assumption for the whole plan (see `docs/superpowers/specs/2026-07-22-database-access-design.md`, "Risco em aberto"). It is *not* unit-testable — it is a manual/scripted check against the real demo cPanel account. Do this first; if it fails, stop and go back to brainstorming for the fallback design instead of continuing to Task 2.

**Files:**
- Create: `scripts/spike_mysql_connectivity.py`

- [ ] **Step 1: Write the spike script**

```python
#!/usr/bin/env python3
"""One-shot manual check: can we reach a cPanel account's MySQL server by direct TCP
after granting our egress IP via uapi.Mysql.add_host? Run this by hand against the demo
account before building on top of MySQLEphemeralSession. Not part of the automated suite.
"""
from __future__ import annotations

import asyncio
import os
import secrets
import sys

import aiomysql
import httpx


async def main() -> None:
    base_url = os.environ["RESELLER_MCP_CPANEL_BASE_URL"]
    reseller = os.environ["RESELLER_MCP_CPANEL_RESELLER"]
    token = os.environ["RESELLER_MCP_CPANEL_ADMIN_TOKEN"]
    account = os.environ["SPIKE_ACCOUNT"]
    database = os.environ["SPIKE_DATABASE"]
    egress_ip = os.environ["SPIKE_EGRESS_IP"]

    headers = {"Authorization": f"whm {reseller}:{token}"}
    async with httpx.AsyncClient(base_url=base_url, verify=True, timeout=30) as client:

        async def uapi(function: str, **params: str) -> dict:
            response = await client.get(
                "/json-api/uapi_cpanel",
                headers=headers,
                params={
                    "api.version": 1,
                    "cpanel.user": account,
                    "cpanel.module": "Mysql",
                    "cpanel.function": function,
                    **params,
                },
            )
            response.raise_for_status()
            return response.json()["data"]["uapi"]["result"]

        server_info = await uapi("get_server_information")
        print("server_information:", server_info)
        host = server_info.get("data", {}).get("host") or httpx.URL(base_url).host
        port = int(server_info.get("data", {}).get("port") or 3306)

        add_host = await uapi("add_host", host=egress_ip)
        print("add_host:", add_host)

        username = f"spike_{secrets.token_hex(4)}"
        password = secrets.token_urlsafe(24)
        create_user = await uapi("create_user", name=username, password=password)
        print("create_user:", create_user)
        full_username = create_user.get("data", {}).get("user", username)

        try:
            await uapi(
                "set_privileges_on_database",
                user=full_username,
                database=database,
                privileges="SELECT",
            )
            print(f"Attempting TCP connect to {host}:{port} as {full_username} ...")
            conn = await asyncio.wait_for(
                aiomysql.connect(
                    host=host,
                    port=port,
                    user=full_username,
                    password=password,
                    db=database,
                    connect_timeout=10,
                ),
                timeout=15,
            )
            async with conn.cursor() as cursor:
                await cursor.execute("SELECT 1")
                print("SELECT 1 ->", await cursor.fetchone())
            conn.close()
            print("SPIKE RESULT: direct TCP connection WORKS.")
        finally:
            await uapi("delete_user", name=full_username)
            await uapi("delete_host", host=egress_ip)


if __name__ == "__main__":
    asyncio.run(main())
```

- [ ] **Step 2: Add `aiomysql` as a temporary dev dependency and run the spike**

Run:
```bash
uv add aiomysql
RESELLER_MCP_CPANEL_BASE_URL=https://<demo-host>:2087 \
RESELLER_MCP_CPANEL_RESELLER=demo-reseller \
RESELLER_MCP_CPANEL_ADMIN_TOKEN=<real admin token from .env> \
SPIKE_ACCOUNT=<a real test account username> \
SPIKE_DATABASE=<a real database name on that account> \
SPIKE_EGRESS_IP=<the VPS Semeion public egress IP> \
uv run python scripts/spike_mysql_connectivity.py
```

Expected: either `SPIKE RESULT: direct TCP connection WORKS.` printed, or a clear connection
timeout/refused error.

- [ ] **Step 3: Record the outcome and decide**

If it printed `WORKS`: continue to Task 2 exactly as written below.

If it timed out or was refused: **stop**. Do not proceed with Tasks 2–11 as written — they
assume direct TCP reachability. Go back to `superpowers:brainstorming` to design the documented
fallback (mediated execution via cPanel) from the spec's "Fallback documentado" section instead.

- [ ] **Step 4: Commit the spike script (keep it — it's a useful diagnostic for future accounts)**

```bash
git add scripts/spike_mysql_connectivity.py
git commit -m "chore(spike): add MySQL direct-TCP connectivity check script"
```

---

## Task 2: Add dependencies and configuration settings

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/reseller_mcp/config.py`
- Test: `tests/test_config.py` (new)

**Interfaces:**
- Produces: `Settings.mysql_egress_ip: str`, `Settings.database_ephemeral_ttl_seconds: int`,
  `Settings.database_connect_timeout_seconds: float`, `Settings.database_query_timeout_seconds: float`,
  `Settings.database_max_rows: int`.

- [ ] **Step 1: Add real dependencies to `pyproject.toml`**

Edit the `dependencies` array in `pyproject.toml`:

```toml
dependencies = [
  "aiomysql>=0.2,<1",
  "httpx>=0.28,<1",
  "jsonschema>=4.23,<5",
  "mcp[cli]==1.28.1",
  "pydantic>=2.10,<3",
  "pydantic-settings>=2.7,<3",
  "sqlglot>=25,<26",
  "typer>=0.15,<1",
  "uvicorn>=0.34,<1",
]
```

Run: `uv sync --extra dev`
Expected: lockfile updates, no errors.

- [ ] **Step 2: Write a failing test for the new settings**

Create `tests/test_config.py`:

```python
from __future__ import annotations

from reseller_mcp.config import Settings


def test_database_settings_have_safe_defaults() -> None:
    settings = Settings(
        token_pepper="p" * 64,
        confirmation_secret="c" * 64,
        cpanel_reader_token="reader",
        cpanel_operator_token="operator",
        cpanel_admin_token="admin",
    )
    assert settings.mysql_egress_ip == ""
    assert settings.database_ephemeral_ttl_seconds == 300
    assert settings.database_connect_timeout_seconds == 10.0
    assert settings.database_query_timeout_seconds == 15.0
    assert settings.database_max_rows == 1000
```

- [ ] **Step 2b: Run test to verify it fails**

Run: `uv run pytest tests/test_config.py -v`
Expected: FAIL with `AttributeError: 'Settings' object has no attribute 'mysql_egress_ip'`.

- [ ] **Step 3: Add the settings fields**

In `src/reseller_mcp/config.py`, add after `health_min_php_version: str = "8.2"` (still inside
the `Settings` class body):

```python
    mysql_egress_ip: str = ""
    database_ephemeral_ttl_seconds: int = Field(default=300, ge=60, le=1800)
    database_connect_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    database_query_timeout_seconds: float = Field(default=15.0, gt=0, le=120)
    database_max_rows: int = Field(default=1000, ge=1, le=100000)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_config.py -v`
Expected: PASS.

- [ ] **Step 5: Update `.env.example` and commit**

Add to `.env.example` (append near the other `RESELLER_MCP_` entries):

```
RESELLER_MCP_MYSQL_EGRESS_IP=
```

```bash
git add pyproject.toml uv.lock src/reseller_mcp/config.py tests/test_config.py .env.example
git commit -m "feat(config): add MySQL ephemeral access settings and drivers"
```

---

## Task 3: SQL guardrails (pure functions, no I/O)

**Files:**
- Create: `src/reseller_mcp/sql_guardrails.py`
- Test: `tests/test_sql_guardrails.py`

**Interfaces:**
- Produces:
  - `class SQLGuardrailError(ValueError)` with `.code: str`
  - `require_single_select(sql: str) -> None`
  - `require_safe_write_statements(statements: list[str]) -> list[sqlglot.exp.Expression]`
  - `derive_backup_select(statement: sqlglot.exp.Expression) -> str | None`

- [ ] **Step 1: Write failing tests**

Create `tests/test_sql_guardrails.py`:

```python
from __future__ import annotations

import pytest

from reseller_mcp.sql_guardrails import (
    SQLGuardrailError,
    derive_backup_select,
    require_safe_write_statements,
    require_single_select,
)


def test_require_single_select_accepts_plain_select() -> None:
    require_single_select("SELECT id, email FROM users WHERE id = %s")


def test_require_single_select_rejects_non_select() -> None:
    with pytest.raises(SQLGuardrailError) as exc:
        require_single_select("DELETE FROM users WHERE id = 1")
    assert exc.value.code == "SQL_NOT_SELECT"


def test_require_single_select_rejects_multiple_statements() -> None:
    with pytest.raises(SQLGuardrailError) as exc:
        require_single_select("SELECT 1; SELECT 2")
    assert exc.value.code == "SQL_MULTIPLE_STATEMENTS"


def test_require_single_select_rejects_unparseable_sql() -> None:
    with pytest.raises(SQLGuardrailError) as exc:
        require_single_select("SELEKT this is not sql (")
    assert exc.value.code == "SQL_PARSE_ERROR"


def test_require_safe_write_statements_accepts_update_delete_insert() -> None:
    parsed = require_safe_write_statements(
        [
            "UPDATE users SET active = 0 WHERE id = %s",
            "DELETE FROM sessions WHERE user_id = %s",
            "INSERT INTO audit_log (event) VALUES (%s)",
        ]
    )
    assert len(parsed) == 3


def test_require_safe_write_statements_rejects_ddl() -> None:
    with pytest.raises(SQLGuardrailError) as exc:
        require_safe_write_statements(["DROP TABLE users"])
    assert exc.value.code == "SQL_FORBIDDEN_STATEMENT"


def test_require_safe_write_statements_rejects_grant() -> None:
    with pytest.raises(SQLGuardrailError) as exc:
        require_safe_write_statements(["GRANT ALL ON *.* TO 'x'@'%'"])
    assert exc.value.code in {"SQL_FORBIDDEN_STATEMENT", "SQL_PARSE_ERROR"}


def test_require_safe_write_statements_rejects_empty_list() -> None:
    with pytest.raises(SQLGuardrailError) as exc:
        require_safe_write_statements([])
    assert exc.value.code == "SQL_EMPTY_TRANSACTION"


def test_derive_backup_select_for_update() -> None:
    [statement] = require_safe_write_statements(["UPDATE users SET active = 0 WHERE id = 42"])
    backup_sql = derive_backup_select(statement)
    assert backup_sql is not None
    assert "SELECT" in backup_sql.upper()
    assert "USERS" in backup_sql.upper()
    assert "42" in backup_sql


def test_derive_backup_select_for_delete() -> None:
    [statement] = require_safe_write_statements(["DELETE FROM sessions WHERE user_id = 7"])
    backup_sql = derive_backup_select(statement)
    assert backup_sql is not None
    assert "SESSIONS" in backup_sql.upper()


def test_derive_backup_select_for_insert_is_none() -> None:
    [statement] = require_safe_write_statements(["INSERT INTO audit_log (event) VALUES ('x')"])
    assert derive_backup_select(statement) is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_sql_guardrails.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'reseller_mcp.sql_guardrails'`.

- [ ] **Step 3: Implement `sql_guardrails.py`**

Create `src/reseller_mcp/sql_guardrails.py`:

```python
from __future__ import annotations

import sqlglot
from sqlglot import exp

ALLOWED_WRITE_TYPES: tuple[type[exp.Expression], ...] = (exp.Update, exp.Delete, exp.Insert)


class SQLGuardrailError(ValueError):
    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


def _parse_one(sql: str) -> exp.Expression:
    try:
        statements = sqlglot.parse(sql, dialect="mysql")
    except sqlglot.errors.ParseError as exc:
        raise SQLGuardrailError(f"sql could not be parsed: {exc}", "SQL_PARSE_ERROR") from exc
    non_empty = [statement for statement in statements if statement is not None]
    if len(non_empty) != 1:
        raise SQLGuardrailError(
            "exactly one SQL statement is required per entry", "SQL_MULTIPLE_STATEMENTS"
        )
    return non_empty[0]


def require_single_select(sql: str) -> None:
    statement = _parse_one(sql)
    if not isinstance(statement, exp.Select):
        raise SQLGuardrailError("only SELECT statements are allowed here", "SQL_NOT_SELECT")


def require_safe_write_statements(statements: list[str]) -> list[exp.Expression]:
    if not statements:
        raise SQLGuardrailError("at least one statement is required", "SQL_EMPTY_TRANSACTION")
    parsed: list[exp.Expression] = []
    for sql in statements:
        statement = _parse_one(sql)
        if not isinstance(statement, ALLOWED_WRITE_TYPES):
            raise SQLGuardrailError(
                f"statement type {type(statement).__name__} is not allowed here; "
                "only UPDATE, DELETE, and INSERT are permitted",
                "SQL_FORBIDDEN_STATEMENT",
            )
        parsed.append(statement)
    return parsed


def derive_backup_select(statement: exp.Expression) -> str | None:
    if isinstance(statement, exp.Insert):
        return None
    table = statement.this
    if isinstance(table, exp.Table) is False and hasattr(table, "this"):
        table = table.this
    where = statement.args.get("where")
    select = exp.select("*").from_(table.copy())
    if where is not None:
        condition = where.this if hasattr(where, "this") else where
        select = select.where(condition.copy())
    return select.sql(dialect="mysql")
```

- [ ] **Step 4: Run tests to verify they pass, fixing sqlglot AST access as needed**

Run: `uv run pytest tests/test_sql_guardrails.py -v`
Expected: PASS. If `derive_backup_select` raises an `AttributeError` on `statement.this` for
`exp.Delete`/`exp.Update`, inspect the actual parsed tree with
`uv run python -c "import sqlglot; print(repr(sqlglot.parse_one('DELETE FROM t WHERE id=1')))"`
and adjust the attribute access to match — this is expected exploratory work, not a plan defect.

- [ ] **Step 5: Run lint and type checks**

Run: `uv run ruff check src/reseller_mcp/sql_guardrails.py tests/test_sql_guardrails.py`
Run: `uv run mypy src/reseller_mcp/sql_guardrails.py`
Expected: no errors (add `# type: ignore[...]` with a reason comment only if sqlglot's stubs
are incomplete — check first).

- [ ] **Step 6: Commit**

```bash
git add src/reseller_mcp/sql_guardrails.py tests/test_sql_guardrails.py
git commit -m "feat(db): add SQL guardrails using sqlglot AST validation"
```

---

## Task 4: Database ledger schema and methods

**Files:**
- Modify: `src/reseller_mcp/db.py`
- Test: `tests/test_db.py` (new)

**Interfaces:**
- Consumes: `Database.connect()`, `Database._lock` (existing, from `db.py`).
- Produces:
  - `Database.insert_ephemeral_grant(*, grant_id: str, account: str, database_name: str, mysql_username: str, host_entry_created: bool, ttl_seconds: int) -> None`
  - `Database.delete_ephemeral_grant(grant_id: str) -> None`
  - `Database.list_expired_ephemeral_grants() -> list[dict[str, Any]]`
  - `Database.save_backup(account: str, database_name: str, rows: list[dict[str, Any]]) -> str` (returns backup id)
  - `Database.get_backup(backup_id: str) -> dict[str, Any] | None`
  - `Database.get_migration(account: str, database_name: str, migration_id: str) -> dict[str, Any] | None`
  - `Database.record_migration(*, account: str, database_name: str, migration_id: str, checksum: str, backup_ref: str | None, rows_affected: int | None, status: str) -> None`

- [ ] **Step 1: Write failing tests**

Create `tests/test_db.py`:

```python
from __future__ import annotations

from pathlib import Path

from reseller_mcp.db import Database


def test_ephemeral_grant_roundtrip(tmp_path: Path) -> None:
    database = Database(tmp_path / "test.db")
    database.insert_ephemeral_grant(
        grant_id="grant-1",
        account="acctalpha",
        database_name="acctalpha_app",
        mysql_username="eph_abc123",
        host_entry_created=True,
        ttl_seconds=60,
    )
    expired = database.list_expired_ephemeral_grants()
    assert expired == []  # not expired yet, ttl is 60s in the future

    database.delete_ephemeral_grant("grant-1")
    assert database.list_expired_ephemeral_grants() == []


def test_expired_ephemeral_grant_is_listed(tmp_path: Path) -> None:
    database = Database(tmp_path / "test.db")
    database.insert_ephemeral_grant(
        grant_id="grant-2",
        account="acctalpha",
        database_name="acctalpha_app",
        mysql_username="eph_def456",
        host_entry_created=False,
        ttl_seconds=-1,  # already expired
    )
    expired = database.list_expired_ephemeral_grants()
    assert len(expired) == 1
    assert expired[0]["id"] == "grant-2"
    assert expired[0]["mysql_username"] == "eph_def456"
    assert bool(expired[0]["host_entry_created"]) is False


def test_backup_roundtrip(tmp_path: Path) -> None:
    database = Database(tmp_path / "test.db")
    rows = [{"statement_index": 0, "sql": "SELECT * FROM users WHERE id = 1", "rows": [{"id": 1}]}]
    backup_id = database.save_backup("acctalpha", "acctalpha_app", rows)
    stored = database.get_backup(backup_id)
    assert stored is not None
    assert stored["account"] == "acctalpha"
    assert stored["payload"] == rows


def test_get_backup_missing_returns_none(tmp_path: Path) -> None:
    database = Database(tmp_path / "test.db")
    assert database.get_backup("does-not-exist") is None


def test_migration_ledger_roundtrip(tmp_path: Path) -> None:
    database = Database(tmp_path / "test.db")
    assert database.get_migration("acctalpha", "acctalpha_app", "2026_01_add_index") is None

    database.record_migration(
        account="acctalpha",
        database_name="acctalpha_app",
        migration_id="2026_01_add_index",
        checksum="abc123",
        backup_ref="backup-1",
        rows_affected=5,
        status="applied",
    )
    record = database.get_migration("acctalpha", "acctalpha_app", "2026_01_add_index")
    assert record is not None
    assert record["checksum"] == "abc123"
    assert record["rows_affected"] == 5
    assert record["status"] == "applied"

    # Re-recording the same migration_id updates the row instead of failing.
    database.record_migration(
        account="acctalpha",
        database_name="acctalpha_app",
        migration_id="2026_01_add_index",
        checksum="abc123",
        backup_ref="backup-1",
        rows_affected=5,
        status="applied",
    )
    assert database.get_migration("acctalpha", "acctalpha_app", "2026_01_add_index") is not None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_db.py -v`
Expected: FAIL with `AttributeError: 'Database' object has no attribute 'insert_ephemeral_grant'`.

- [ ] **Step 3: Add tables to `SCHEMA` in `src/reseller_mcp/db.py`**

Insert before the closing `"""` of the `SCHEMA` string (after the existing
`audit_events_correlation_idx` line is fine since that's added via `ALTER`/separate `execute`,
not part of `SCHEMA` — append these right after `audit_events_user_idx`):

```python
CREATE TABLE IF NOT EXISTS mysql_ephemeral_grants (
  id TEXT PRIMARY KEY,
  account TEXT NOT NULL,
  database_name TEXT NOT NULL,
  mysql_username TEXT NOT NULL,
  host_entry_created INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS mysql_ephemeral_grants_expiry_idx
  ON mysql_ephemeral_grants(expires_at);
CREATE TABLE IF NOT EXISTS db_backups (
  id TEXT PRIMARY KEY,
  account TEXT NOT NULL,
  database_name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS db_migrations (
  account TEXT NOT NULL,
  database_name TEXT NOT NULL,
  migration_id TEXT NOT NULL,
  checksum TEXT NOT NULL,
  applied_at TEXT NOT NULL,
  backup_ref TEXT,
  rows_affected INTEGER,
  status TEXT NOT NULL,
  PRIMARY KEY(account, database_name, migration_id)
);
```

(Add this block right before the final `CREATE INDEX IF NOT EXISTS audit_events_correlation_idx`
line's containing string ends — i.e. just keep it inside the same `SCHEMA = """ ... """` triple
string, anywhere after the existing `CREATE INDEX ... audit_events_user_idx` line.)

- [ ] **Step 4: Add the methods to the `Database` class**

Add these methods to `src/reseller_mcp/db.py`, e.g. right after `purge_old_audit` (the last
method in the class):

```python
    def insert_ephemeral_grant(
        self,
        *,
        grant_id: str,
        account: str,
        database_name: str,
        mysql_username: str,
        host_entry_created: bool,
        ttl_seconds: int,
    ) -> None:
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=ttl_seconds)
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO mysql_ephemeral_grants
                   (id,account,database_name,mysql_username,host_entry_created,
                    created_at,expires_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (
                    grant_id,
                    account,
                    database_name,
                    mysql_username,
                    int(host_entry_created),
                    now.isoformat(),
                    expires_at.isoformat(),
                ),
            )

    def delete_ephemeral_grant(self, grant_id: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM mysql_ephemeral_grants WHERE id=?", (grant_id,))

    def list_expired_ephemeral_grants(self) -> list[dict[str, Any]]:
        now = datetime.now(UTC).isoformat()
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM mysql_ephemeral_grants WHERE expires_at<?", (now,)
            ).fetchall()
        return [dict(row) for row in rows]

    def save_backup(
        self, account: str, database_name: str, rows: list[dict[str, Any]]
    ) -> str:
        backup_id = str(uuid.uuid4())
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO db_backups(id,account,database_name,created_at,payload) "
                "VALUES(?,?,?,?,?)",
                (
                    backup_id,
                    account,
                    database_name,
                    datetime.now(UTC).isoformat(),
                    json.dumps(rows, ensure_ascii=False, default=str),
                ),
            )
        return backup_id

    def get_backup(self, backup_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM db_backups WHERE id=?", (backup_id,)).fetchone()
        if not row:
            return None
        value = dict(row)
        value["payload"] = json.loads(value["payload"])
        return value

    def get_migration(
        self, account: str, database_name: str, migration_id: str
    ) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """SELECT * FROM db_migrations
                   WHERE account=? AND database_name=? AND migration_id=?""",
                (account, database_name, migration_id),
            ).fetchone()
        return dict(row) if row else None

    def record_migration(
        self,
        *,
        account: str,
        database_name: str,
        migration_id: str,
        checksum: str,
        backup_ref: str | None,
        rows_affected: int | None,
        status: str,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO db_migrations
                   (account,database_name,migration_id,checksum,applied_at,backup_ref,
                    rows_affected,status)
                   VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(account,database_name,migration_id) DO UPDATE SET
                     checksum=excluded.checksum,
                     applied_at=excluded.applied_at,
                     backup_ref=excluded.backup_ref,
                     rows_affected=excluded.rows_affected,
                     status=excluded.status""",
                (
                    account,
                    database_name,
                    migration_id,
                    checksum,
                    datetime.now(UTC).isoformat(),
                    backup_ref,
                    rows_affected,
                    status,
                ),
            )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_db.py -v`
Expected: PASS.

- [ ] **Step 6: Run the full existing test suite to check for regressions**

Run: `uv run pytest -v`
Expected: all existing tests still PASS (schema change is additive only).

- [ ] **Step 7: Lint, type-check, commit**

```bash
uv run ruff check src/reseller_mcp/db.py tests/test_db.py
uv run mypy src/reseller_mcp/db.py
git add src/reseller_mcp/db.py tests/test_db.py
git commit -m "feat(db): add ephemeral grant, backup, and migration ledger tables"
```

---

## Task 5: Ephemeral MySQL session

**Files:**
- Create: `src/reseller_mcp/mysql_client.py`
- Test: `tests/test_mysql_client.py`

**Interfaces:**
- Consumes: `CPanelClient.call(capability, account, arguments, *, retry_safe=False)` (from `cpanel.py`,
  returns the UAPI `result` dict — for `Mysql::*` UAPI calls that's the inner `data` payload per
  `cpanel.py:191-197`), `Database.insert_ephemeral_grant`/`delete_ephemeral_grant` (Task 4),
  `Settings.mysql_egress_ip`/`database_ephemeral_ttl_seconds`/`database_connect_timeout_seconds` (Task 2).
- Produces:
  - `class MySQLProvisionError(RuntimeError)` with `.code: str`
  - `class MySQLEphemeralSession` — async context manager, constructor
    `(*, cpanel: CPanelClient, db: Database, settings: Settings, account: str, database: str, mode: Literal["read", "write"], connect_fn: ConnectFn = _default_connect)`
  - `MySQLEphemeralSession.fetch_all(sql: str, params: Sequence[Any] | None = None, *, max_rows: int | None = None) -> list[dict[str, Any]]`
  - `MySQLEphemeralSession.run_transaction(statements: list[tuple[str, Sequence[Any]]], *, commit: bool) -> int` (returns total rows affected)

- [ ] **Step 1: Write failing tests using a fake connection (no real MySQL, no Docker)**

Create `tests/test_mysql_client.py`:

```python
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from reseller_mcp.config import Settings
from reseller_mcp.cpanel import CPanelError
from reseller_mcp.db import Database
from reseller_mcp.mysql_client import MySQLEphemeralSession, MySQLProvisionError


class FakeCursor:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows
        self.rowcount = len(rows)
        self.executed: list[tuple[str, Any]] = []

    async def execute(self, sql: str, params: Any = None) -> None:
        self.executed.append((sql, params))

    async def fetchall(self) -> list[dict[str, Any]]:
        return self._rows

    async def fetchmany(self, size: int) -> list[dict[str, Any]]:
        return self._rows[:size]

    async def __aenter__(self) -> "FakeCursor":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None


class FakeConnection:
    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        self.rows = rows or []
        self.closed = False
        self.began = False
        self.committed = False
        self.rolled_back = False

    def cursor(self, *_: Any, **__: Any) -> FakeCursor:
        return FakeCursor(self.rows)

    async def begin(self) -> None:
        self.began = True

    async def commit(self) -> None:
        self.committed = True

    async def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        self.closed = True


class FakeCPanel:
    def __init__(self, *, uapi_results: dict[str, dict[str, Any]] | None = None) -> None:
        self.calls: list[tuple[str, str | None, dict[str, Any]]] = []
        self.uapi_results = uapi_results or {}

    async def call(self, capability: Any, account: str | None, arguments: dict[str, Any], *, retry_safe: bool = False) -> Any:
        self.calls.append((capability.function, account, arguments))
        if capability.function == "get_server_information":
            return {"host": "db.example.com", "port": 3306}
        if capability.function == "create_user":
            return {"user": f"cpaneluser_{arguments['name']}"}
        return {}


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        db_path=tmp_path / "mcp.db",
        catalog_path=tmp_path / "missing.json",
        token_pepper="p" * 64,
        confirmation_secret="c" * 64,
        cpanel_reader_token="reader",
        cpanel_operator_token="operator",
        cpanel_admin_token="admin",
        mysql_egress_ip="203.0.113.10",
    )


@pytest.fixture
def db(settings: Settings) -> Database:
    return Database(settings.db_path)


async def test_session_provisions_and_cleans_up(settings: Settings, db: Database) -> None:
    cpanel = FakeCPanel()
    fake_connection = FakeConnection(rows=[{"id": 1}])

    async def fake_connect(**kwargs: Any) -> FakeConnection:
        assert kwargs["host"] == "db.example.com"
        assert kwargs["port"] == 3306
        assert kwargs["user"] == "cpaneluser_eph_test"
        return fake_connection

    async with MySQLEphemeralSession(
        cpanel=cpanel,  # type: ignore[arg-type]
        db=db,
        settings=settings,
        account="acctalpha",
        database="acctalpha_app",
        mode="read",
        connect_fn=fake_connect,
        username_factory=lambda: "eph_test",
    ) as session:
        rows = await session.fetch_all("SELECT 1")
        assert rows == [{"id": 1}]

    assert fake_connection.closed is True
    function_calls = [call[0] for call in cpanel.calls]
    assert "create_user" in function_calls
    assert "delete_user" in function_calls
    assert "add_host" in function_calls
    assert "delete_host" in function_calls
    # No ledger row should remain after a clean exit.
    assert db.list_expired_ephemeral_grants() == []


async def test_session_records_ledger_row_during_use(settings: Settings, db: Database) -> None:
    cpanel = FakeCPanel()
    fake_connection = FakeConnection()

    async def fake_connect(**kwargs: Any) -> FakeConnection:
        return fake_connection

    captured: dict[str, Any] = {}

    async with MySQLEphemeralSession(
        cpanel=cpanel,  # type: ignore[arg-type]
        db=db,
        settings=settings,
        account="acctalpha",
        database="acctalpha_app",
        mode="write",
        connect_fn=fake_connect,
    ) as session:
        captured["grant_id"] = session._grant_id
        assert captured["grant_id"] is not None

    assert db.list_expired_ephemeral_grants() == []


async def test_run_transaction_rolls_back_when_commit_false(settings: Settings, db: Database) -> None:
    cpanel = FakeCPanel()
    fake_connection = FakeConnection()

    async def fake_connect(**kwargs: Any) -> FakeConnection:
        return fake_connection

    async with MySQLEphemeralSession(
        cpanel=cpanel,  # type: ignore[arg-type]
        db=db,
        settings=settings,
        account="acctalpha",
        database="acctalpha_app",
        mode="write",
        connect_fn=fake_connect,
    ) as session:
        await session.run_transaction([("UPDATE t SET x=1 WHERE id=1", [])], commit=False)

    assert fake_connection.began is True
    assert fake_connection.rolled_back is True
    assert fake_connection.committed is False


async def test_cleanup_failure_leaves_ledger_row_for_reaper(settings: Settings, db: Database) -> None:
    class FailingCPanel(FakeCPanel):
        async def call(self, capability: Any, account: str | None, arguments: dict[str, Any], *, retry_safe: bool = False) -> Any:
            if capability.function == "delete_user":
                raise CPanelError("upstream unavailable", code="UPSTREAM_NETWORK_ERROR")
            return await super().call(capability, account, arguments, retry_safe=retry_safe)

    cpanel = FailingCPanel()
    fake_connection = FakeConnection()

    async def fake_connect(**kwargs: Any) -> FakeConnection:
        return fake_connection

    async with MySQLEphemeralSession(
        cpanel=cpanel,  # type: ignore[arg-type]
        db=db,
        settings=settings,
        account="acctalpha",
        database="acctalpha_app",
        mode="read",
        connect_fn=fake_connect,
    ):
        pass

    # Cleanup partially failed, so the ledger row must survive for the reaper (Task 10).
    remaining = db.list_expired_ephemeral_grants()
    assert remaining == []  # not expired yet (ttl_seconds default is minutes away)
```

Note the last test only proves the row is *not deleted prematurely*; it can't assert the row's
mere existence via `list_expired_ephemeral_grants()` since that only returns *expired* rows. Add
one more direct check using SQLite:

```python
async def test_cleanup_failure_row_exists_directly(settings: Settings, db: Database) -> None:
    class FailingCPanel(FakeCPanel):
        async def call(self, capability: Any, account: str | None, arguments: dict[str, Any], *, retry_safe: bool = False) -> Any:
            if capability.function == "delete_user":
                raise CPanelError("upstream unavailable", code="UPSTREAM_NETWORK_ERROR")
            return await super().call(capability, account, arguments, retry_safe=retry_safe)

    cpanel = FailingCPanel()
    fake_connection = FakeConnection()

    async def fake_connect(**kwargs: Any) -> FakeConnection:
        return fake_connection

    async with MySQLEphemeralSession(
        cpanel=cpanel,  # type: ignore[arg-type]
        db=db,
        settings=settings,
        account="acctalpha",
        database="acctalpha_app",
        mode="read",
        connect_fn=fake_connect,
    ):
        pass

    with db.connect() as conn:
        rows = conn.execute("SELECT * FROM mysql_ephemeral_grants").fetchall()
    assert len(rows) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_mysql_client.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'reseller_mcp.mysql_client'`.

- [ ] **Step 3: Implement `mysql_client.py`**

Create `src/reseller_mcp/mysql_client.py`:

```python
from __future__ import annotations

import secrets
import uuid
from collections.abc import Awaitable, Callable, Sequence
from typing import TYPE_CHECKING, Any, Literal

import aiomysql

from .cpanel import CPanelError
from .models import ApiFamily, Capability, Risk, Role

if TYPE_CHECKING:
    from .config import Settings
    from .cpanel import CPanelClient
    from .db import Database

ConnectFn = Callable[..., Awaitable[Any]]


class MySQLProvisionError(RuntimeError):
    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


async def _default_connect(**kwargs: Any) -> Any:
    return await aiomysql.connect(**kwargs)


def _internal_capability(function: str) -> Capability:
    return Capability(
        id=f"uapi.Mysql.{function}",
        api=ApiFamily.UAPI,
        module="Mysql",
        function=function,
        title=function,
        description="Internal MySQL provisioning call used by MySQLEphemeralSession.",
        risk=Risk.PRIVILEGED,
        required_role=Role.ADMIN,
        upstream_profile="admin",
        curated=False,
        schema_source="internal",
    )


class MySQLEphemeralSession:
    def __init__(
        self,
        *,
        cpanel: CPanelClient,
        db: Database,
        settings: Settings,
        account: str,
        database: str,
        mode: Literal["read", "write"],
        connect_fn: ConnectFn = _default_connect,
        username_factory: Callable[[], str] = lambda: f"eph_{secrets.token_hex(4)}",
    ) -> None:
        self.cpanel = cpanel
        self.db = db
        self.settings = settings
        self.account = account
        self.database = database
        self.mode = mode
        self.connect_fn = connect_fn
        self.username_factory = username_factory
        self._grant_id: str | None = None
        self._username: str | None = None
        self._host_created = False
        self._connection: Any = None

    async def __aenter__(self) -> MySQLEphemeralSession:
        if not self.settings.mysql_egress_ip:
            raise MySQLProvisionError(
                "RESELLER_MCP_MYSQL_EGRESS_IP is not configured", "EGRESS_IP_NOT_CONFIGURED"
            )
        server_info = await self.cpanel.call(
            _internal_capability("get_server_information"), self.account, {}
        )
        host = (server_info or {}).get("host") or "127.0.0.1"
        port = int((server_info or {}).get("port") or 3306)

        try:
            await self.cpanel.call(
                _internal_capability("add_host"),
                self.account,
                {"host": self.settings.mysql_egress_ip},
            )
            self._host_created = True
        except CPanelError as exc:
            if "already" not in str(exc).lower():
                raise MySQLProvisionError(f"add_host failed: {exc}", "PROVISION_FAILED") from exc

        candidate_username = self.username_factory()
        password = secrets.token_urlsafe(24)
        create_result = await self.cpanel.call(
            _internal_capability("create_user"),
            self.account,
            {"name": candidate_username, "password": password},
        )
        self._username = (create_result or {}).get("user") or candidate_username

        privileges = "SELECT" if self.mode == "read" else "ALL PRIVILEGES"
        await self.cpanel.call(
            _internal_capability("set_privileges_on_database"),
            self.account,
            {"user": self._username, "database": self.database, "privileges": privileges},
        )

        self._grant_id = str(uuid.uuid4())
        self.db.insert_ephemeral_grant(
            grant_id=self._grant_id,
            account=self.account,
            database_name=self.database,
            mysql_username=self._username,
            host_entry_created=self._host_created,
            ttl_seconds=self.settings.database_ephemeral_ttl_seconds,
        )

        self._connection = await self.connect_fn(
            host=host,
            port=port,
            user=self._username,
            password=password,
            db=self.database,
            connect_timeout=self.settings.database_connect_timeout_seconds,
            autocommit=False,
        )
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._connection is not None:
            self._connection.close()
        await self._cleanup()

    async def _cleanup(self) -> None:
        user_deleted = True
        host_deleted = not self._host_created
        if self._username is not None:
            try:
                await self.cpanel.call(
                    _internal_capability("delete_user"), self.account, {"name": self._username}
                )
            except CPanelError:
                user_deleted = False
        if self._host_created:
            try:
                await self.cpanel.call(
                    _internal_capability("delete_host"),
                    self.account,
                    {"host": self.settings.mysql_egress_ip},
                )
                host_deleted = True
            except CPanelError:
                host_deleted = False
        if user_deleted and host_deleted and self._grant_id is not None:
            self.db.delete_ephemeral_grant(self._grant_id)
        # If cleanup was incomplete, the ledger row survives on purpose so the
        # reaper (Task 10) can finish revoking access once upstream recovers.

    async def fetch_all(
        self, sql: str, params: Sequence[Any] | None = None, *, max_rows: int | None = None
    ) -> list[dict[str, Any]]:
        async with self._connection.cursor(aiomysql.DictCursor) as cursor:
            await cursor.execute(sql, params or ())
            if max_rows is not None:
                return list(await cursor.fetchmany(max_rows))
            return list(await cursor.fetchall())

    async def run_transaction(
        self, statements: list[tuple[str, Sequence[Any]]], *, commit: bool
    ) -> int:
        await self._connection.begin()
        total_rows = 0
        try:
            async with self._connection.cursor() as cursor:
                for sql, params in statements:
                    await cursor.execute(sql, params or ())
                    total_rows += cursor.rowcount
            if commit:
                await self._connection.commit()
            else:
                await self._connection.rollback()
        except Exception:
            await self._connection.rollback()
            raise
        return total_rows
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_mysql_client.py -v`
Expected: PASS.

- [ ] **Step 5: Lint, type-check, commit**

```bash
uv run ruff check src/reseller_mcp/mysql_client.py tests/test_mysql_client.py
uv run mypy src/reseller_mcp/mysql_client.py
git add src/reseller_mcp/mysql_client.py tests/test_mysql_client.py
git commit -m "feat(db): add ephemeral MySQL session with provisioning and cleanup"
```

---

## Task 6: Harness WORKFLOW dispatch plumbing

**Files:**
- Modify: `src/reseller_mcp/harness.py`
- Modify: `src/reseller_mcp/policy.py`
- Test: `tests/test_harness.py` (add cases)

**Interfaces:**
- Produces on `Harness`:
  - `Harness._workflow_query_hooks: dict[str, Callable[[str | None, dict[str, Any]], Awaitable[Any]]]`
  - `Harness._workflow_prepare_hooks: dict[str, Callable[[str | None, dict[str, Any]], Awaitable[dict[str, Any] | None]]]`
  - `Harness._workflow_execute_hooks: dict[str, Callable[[Preparation], Awaitable[dict[str, Any]]]]`

This task proves the dispatch mechanism works with a **trivial in-test handler**, before Task 7
wires in the real database workflows. Keep `DatabaseWorkflows` out of this task entirely.

- [ ] **Step 1: Write a failing test for query-path dispatch**

Add to `tests/test_harness.py` (check the file's existing imports first and match them; the
snippet below assumes `harness`, `admin`, and `settings` fixtures from `conftest.py` are already
imported/available in that file, as they are for the other tests there):

```python
from reseller_mcp.models import ApiFamily, Capability, Risk, Role


async def test_workflow_query_capability_dispatches_to_registered_hook(harness, admin) -> None:
    workflow_capability = Capability(
        id="workflow.test_echo",
        api=ApiFamily.WORKFLOW,
        function="test_echo",
        title="Test echo",
        description="Test-only workflow capability.",
        risk=Risk.READ,
        required_role=Role.VIEWER,
        upstream_profile="reader",
        input_schema={"type": "object", "additionalProperties": True},
        curated=True,
    )
    harness.db.sync_capabilities([workflow_capability], {})

    async def echo_hook(account, arguments):
        return {"echoed": arguments}

    harness._workflow_query_hooks["workflow.test_echo"] = echo_hook

    result = await harness.query_execute(admin, "workflow.test_echo", "acctalpha", {"x": 1})
    assert result.ok is True
    assert result.data == {"echoed": {"x": 1}}


async def test_workflow_query_capability_without_registered_hook_fails(harness, admin) -> None:
    workflow_capability = Capability(
        id="workflow.test_missing",
        api=ApiFamily.WORKFLOW,
        function="test_missing",
        title="Test missing",
        description="Test-only workflow capability with no handler.",
        risk=Risk.READ,
        required_role=Role.VIEWER,
        upstream_profile="reader",
        input_schema={"type": "object", "additionalProperties": True},
        curated=True,
    )
    harness.db.sync_capabilities([workflow_capability], {})

    from reseller_mcp.harness import HarnessError

    with pytest.raises(HarnessError) as exc:
        await harness.query_execute(admin, "workflow.test_missing", "acctalpha", {})
    assert exc.value.code == "WORKFLOW_HANDLER_MISSING"
```

(Add `import pytest` at the top of `tests/test_harness.py` if it is not already imported — check
first.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_harness.py -k workflow -v`
Expected: FAIL — `harness.query_execute` currently always calls `self.cpanel.call(...)`, so the
fake echo hook is never invoked and `result.data` will be `{"ok": True}` (from `FakeCPanel`'s
default branch) or the call will error because `capability.api == ApiFamily.WORKFLOW` has no
UAPI/WHM dispatch path in `cpanel.py`.

- [ ] **Step 3: Add the dispatch registries and wire them into `Harness`**

In `src/reseller_mcp/harness.py`, add to the imports:

```python
from collections.abc import Awaitable, Callable
```

In `Harness.__init__`, after `self.accounts = AccountWorkflows(self)`, add:

```python
        self._workflow_query_hooks: dict[
            str, Callable[[str | None, dict[str, Any]], Awaitable[Any]]
        ] = {}
        self._workflow_prepare_hooks: dict[
            str, Callable[[str | None, dict[str, Any]], Awaitable[dict[str, Any] | None]]
        ] = {}
        self._workflow_execute_hooks: dict[
            str, Callable[[Preparation], Awaitable[dict[str, Any]]]
        ] = {}
```

In `query_execute`, replace:

```python
            data = await self.cpanel.call(capability, account, arguments, retry_safe=True)
```

with:

```python
            if capability.api == ApiFamily.WORKFLOW:
                hook = self._workflow_query_hooks.get(capability.id)
                if hook is None:
                    raise HarnessError(
                        "no workflow handler registered for this capability",
                        "WORKFLOW_HANDLER_MISSING",
                    )
                data = await hook(account, arguments)
            else:
                data = await self.cpanel.call(capability, account, arguments, retry_safe=True)
```

Note: this `raise HarnessError(...)` inside the `try` block will be caught by the existing
`except CPanelError` clause? No — `HarnessError` is not a `CPanelError`, so it will propagate
out of `query_execute` uncaught by the existing `try/except CPanelError` — check the surrounding
code in `query_execute` (the `try:` starts right after the policy checks) and confirm this is
the desired behavior: an unregistered workflow handler is a server bug, not an upstream failure,
so it should propagate as an unhandled `HarnessError` up to `_tool_error` in `server.py`, which
already handles `HarnessError` specially. This is correct — no extra try/except needed.

In `_snapshot`, replace the body with:

```python
    async def _snapshot(
        self, capability: Capability, account: str | None, arguments: dict[str, Any]
    ) -> dict[str, Any] | None:
        if capability.api == ApiFamily.WORKFLOW:
            hook = self._workflow_prepare_hooks.get(capability.id)
            if hook is None:
                return None
            return await hook(account, arguments)
        snapshot = self._snapshot_capability(capability, arguments)
        if not snapshot:
            return None
        snapshot_capability, snapshot_account, snapshot_args = snapshot
        try:
            result = await self.cpanel.call(
                snapshot_capability,
                snapshot_account or account,
                snapshot_args,
                retry_safe=True,
            )
            return result if isinstance(result, dict) else {"data": result}
        except CPanelError:
            return None
```

In `execute_action`, inside the `async with self._locks[lock_key]:` block, replace:

```python
                data = await self.cpanel.call(
                    capability, preparation.account, preparation.arguments, retry_safe=False
                )
                after_state, verified, warnings = await self._verify(
                    capability, preparation.account, preparation.arguments, data
                )
```

with:

```python
                if capability.api == ApiFamily.WORKFLOW:
                    hook = self._workflow_execute_hooks.get(capability.id)
                    if hook is None:
                        raise HarnessError(
                            "no workflow handler registered for this capability",
                            "WORKFLOW_HANDLER_MISSING",
                        )
                    data = await hook(preparation)
                    after_state = data.get("after_state")
                    verified = data.get("verified")
                    warnings = list(data.get("warnings") or [])
                else:
                    data = await self.cpanel.call(
                        capability, preparation.account, preparation.arguments, retry_safe=False
                    )
                    after_state, verified, warnings = await self._verify(
                        capability, preparation.account, preparation.arguments, data
                    )
```

Note this `raise HarnessError(...)` is inside the existing `try: ... except CPanelError as exc:`
block in `execute_action` — a `HarnessError` here is **not** a `CPanelError`, so it will
propagate uncaught, skipping the `except CPanelError` handler and leaving the preparation stuck
in `EXECUTING` state. That is only reachable if a capability is registered in the catalog with
`api=WORKFLOW` but nobody called `register` for it — a deployment bug we want to be loud about
rather than silently marking the preparation `FAILED`. Leave as-is; Task 7–9 always register
both prepare and execute hooks together for every WORKFLOW capability that gets added.

- [ ] **Step 4: Extend `policy.py` to require an account for WORKFLOW capabilities too**

In `src/reseller_mcp/policy.py`, change:

```python
        if capability.api.value == "uapi" and not account:
            raise PolicyError("UAPI capability requires an account", "ACCOUNT_REQUIRED")
```

to:

```python
        if capability.api.value in {"uapi", "workflow"} and not account:
            raise PolicyError("this capability requires an account", "ACCOUNT_REQUIRED")
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_harness.py -v`
Expected: PASS (including the two new tests and all pre-existing ones).

- [ ] **Step 6: Run the full suite**

Run: `uv run pytest -v`
Expected: all PASS.

- [ ] **Step 7: Lint, type-check, commit**

```bash
uv run ruff check src/reseller_mcp/harness.py src/reseller_mcp/policy.py tests/test_harness.py
uv run mypy src/reseller_mcp/harness.py src/reseller_mcp/policy.py
git add src/reseller_mcp/harness.py src/reseller_mcp/policy.py tests/test_harness.py
git commit -m "feat(harness): add WORKFLOW capability dispatch registry"
```

---

## Task 7: `database.query_readonly`

**Files:**
- Create: `src/reseller_mcp/database_workflows.py`
- Modify: `src/reseller_mcp/catalog.py`
- Modify: `src/reseller_mcp/harness.py`
- Test: `tests/test_database_workflows.py`

**Interfaces:**
- Consumes: `sql_guardrails.require_single_select` (Task 3), `MySQLEphemeralSession` (Task 5),
  `Harness._workflow_query_hooks` (Task 6).
- Produces: `class DatabaseWorkflows` with
  `async def query_readonly(self, account: str | None, arguments: dict[str, Any]) -> dict[str, Any]`.

- [ ] **Step 1: Register the capability in the catalog**

In `src/reseller_mcp/catalog.py`, fix the id-parsing branch inside `curated_capabilities()` to
recognize the new `database.*`/`workflow.*` prefixes as `ApiFamily.WORKFLOW` (currently anything
that isn't `uapi.*` falls through to `ApiFamily.WHM`, which is wrong for these). Replace:

```python
    for definition in definitions:
        capability_id = definition["id"]
        api_name, *rest = capability_id.split(".")
        if api_name == "uapi":
            module, function = rest
            api = ApiFamily.UAPI
        else:
            module, function = None, rest[0]
            api = ApiFamily.WHM
```

with:

```python
    for definition in definitions:
        capability_id = definition["id"]
        api_name, *rest = capability_id.split(".")
        if api_name == "uapi":
            module, function = rest
            api = ApiFamily.UAPI
        elif api_name in {"workflow", "database"}:
            module, function = None, rest[0]
            api = ApiFamily.WORKFLOW
        else:
            module, function = None, rest[0]
            api = ApiFamily.WHM
```

Add to `EXPLICIT_RISKS`:

```python
    "database.query_readonly": (Risk.SENSITIVE_READ, Role.OPERATOR, "operator"),
```

Add to `ALIASES`:

```python
    "database.query_readonly": "banco dados mysql consulta select leitura",
```

Add to the `definitions` list inside `curated_capabilities()` (anywhere after the
`uapi.Mysql.list_databases` entry reads well):

```python
        {
            "id": "database.query_readonly",
            "title": "Consultar banco de dados (somente leitura)",
            "description": (
                "Executa um único SELECT parametrizado contra um banco MySQL da conta, usando "
                "credenciais efêmeras de privilégio mínimo provisionadas sob demanda."
            ),
            "schema": _schema(
                {"database": string, "sql": string, "params": {"type": "array"}},
                ["database", "sql"],
            ),
            "examples": [
                {
                    "database": "acctalpha_app",
                    "sql": "SELECT id, email FROM users WHERE id = %s",
                    "params": [42],
                }
            ],
        },
```

- [ ] **Step 2: Write failing tests**

Create `tests/test_database_workflows.py`:

```python
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from reseller_mcp.config import Settings
from reseller_mcp.database_workflows import DatabaseWorkflows
from reseller_mcp.db import Database
from reseller_mcp.harness import Harness, HarnessError
from reseller_mcp.sql_guardrails import SQLGuardrailError


class RecordingFakeCPanel:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def call(self, capability: Any, account: str | None, arguments: dict[str, Any], *, retry_safe: bool = False) -> Any:
        self.calls.append(capability.function)
        if capability.function == "get_server_information":
            return {"host": "db.example.com", "port": 3306}
        if capability.function == "create_user":
            return {"user": f"cpaneluser_{arguments['name']}"}
        return {}


class FakeCursor:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows
        self.rowcount = len(rows)

    async def execute(self, sql: str, params: Any = None) -> None:
        pass

    async def fetchall(self) -> list[dict[str, Any]]:
        return self._rows

    async def fetchmany(self, size: int) -> list[dict[str, Any]]:
        return self._rows[:size]

    async def __aenter__(self) -> "FakeCursor":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None


class FakeConnection:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.closed = False

    def cursor(self, *_: Any, **__: Any) -> FakeCursor:
        return FakeCursor(self.rows)

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        db_path=tmp_path / "mcp.db",
        catalog_path=tmp_path / "missing.json",
        token_pepper="p" * 64,
        confirmation_secret="c" * 64,
        cpanel_reader_token="reader",
        cpanel_operator_token="operator",
        cpanel_admin_token="admin",
        mysql_egress_ip="203.0.113.10",
    )


@pytest.fixture
def db(settings: Settings) -> Database:
    return Database(settings.db_path)


async def test_query_readonly_returns_rows(settings: Settings, db: Database) -> None:
    cpanel = RecordingFakeCPanel()
    harness = Harness(settings, db, cpanel)  # type: ignore[arg-type]
    workflows = DatabaseWorkflows(harness)

    fake_connection = FakeConnection(rows=[{"id": 1, "email": "a@example.com"}])

    async def fake_connect(**kwargs: Any) -> FakeConnection:
        return fake_connection

    result = await workflows.query_readonly(
        "acctalpha",
        {"database": "acctalpha_app", "sql": "SELECT id, email FROM users", "params": []},
        connect_fn=fake_connect,
    )
    assert result == {"rows": [{"id": 1, "email": "a@example.com"}], "row_count": 1}
    assert fake_connection.closed is True


async def test_query_readonly_rejects_non_select(settings: Settings, db: Database) -> None:
    cpanel = RecordingFakeCPanel()
    harness = Harness(settings, db, cpanel)  # type: ignore[arg-type]
    workflows = DatabaseWorkflows(harness)

    with pytest.raises(HarnessError) as exc:
        await workflows.query_readonly(
            "acctalpha", {"database": "acctalpha_app", "sql": "DELETE FROM users"}
        )
    assert exc.value.code == "SQL_NOT_SELECT"


async def test_query_readonly_requires_account(settings: Settings, db: Database) -> None:
    cpanel = RecordingFakeCPanel()
    harness = Harness(settings, db, cpanel)  # type: ignore[arg-type]
    workflows = DatabaseWorkflows(harness)

    with pytest.raises(HarnessError) as exc:
        await workflows.query_readonly(None, {"database": "acctalpha_app", "sql": "SELECT 1"})
    assert exc.value.code == "ACCOUNT_REQUIRED"
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_database_workflows.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'reseller_mcp.database_workflows'`.

- [ ] **Step 4: Implement `database_workflows.py` (query_readonly only for now)**

Create `src/reseller_mcp/database_workflows.py`:

```python
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .harness import HarnessError
from .mysql_client import ConnectFn, MySQLEphemeralSession, _default_connect
from .sql_guardrails import SQLGuardrailError, require_single_select

if TYPE_CHECKING:
    from .harness import Harness


class DatabaseWorkflows:
    def __init__(self, harness: Harness) -> None:
        self.harness = harness

    async def query_readonly(
        self,
        account: str | None,
        arguments: dict[str, Any],
        *,
        connect_fn: ConnectFn = _default_connect,
    ) -> dict[str, Any]:
        if account is None:
            raise HarnessError("database workflows require an account", "ACCOUNT_REQUIRED")
        database_name = arguments["database"]
        sql = arguments["sql"]
        try:
            require_single_select(sql)
        except SQLGuardrailError as exc:
            raise HarnessError(str(exc), exc.code) from exc

        async with MySQLEphemeralSession(
            cpanel=self.harness.cpanel,
            db=self.harness.db,
            settings=self.harness.settings,
            account=account,
            database=database_name,
            mode="read",
            connect_fn=connect_fn,
        ) as session:
            rows = await session.fetch_all(
                sql,
                arguments.get("params") or [],
                max_rows=self.harness.settings.database_max_rows,
            )
        return {"rows": rows, "row_count": len(rows)}
```

- [ ] **Step 5: Wire the query hook into `Harness.__init__`**

In `src/reseller_mcp/harness.py`, add the import:

```python
from .database_workflows import DatabaseWorkflows
```

In `Harness.__init__`, after the `self._workflow_execute_hooks: ... = {}` block added in Task 6,
add:

```python
        self.database = DatabaseWorkflows(self)
        self._workflow_query_hooks["database.query_readonly"] = self.database.query_readonly
```

Watch for a circular import: `database_workflows.py` imports `HarnessError` from `.harness`
under `if TYPE_CHECKING` only for the `Harness` type but imports `HarnessError` directly (used
at runtime) — `harness.py` importing `DatabaseWorkflows` from `.database_workflows` at module
level, while `database_workflows.py` imports `HarnessError` from `.harness` at module level, is
a real circular import. Fix it by importing `HarnessError` lazily inside
`database_workflows.py`, or — simpler and consistent with `account_workflows.py` (which never
imports anything from `harness.py` at module level, only under `TYPE_CHECKING`) — define a local
`class DatabaseWorkflowError(HarnessError)` is unnecessary; instead move the `HarnessError`
import in `database_workflows.py` to also be deferred: change
`from .harness import HarnessError` to importing it inside each function body
(`from .harness import HarnessError`) instead of at module scope. Apply that fix now.

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_database_workflows.py -v`
Expected: PASS.

- [ ] **Step 7: Run the full suite (catches the catalog id-parsing change and circular import)**

Run: `uv run pytest -v`
Expected: all PASS. Pay special attention to `tests/test_catalog.py` — the `curated_capabilities()`
change must not alter the `api`/`module`/`function` of any existing `uapi.*`/`whm.*` capability.

- [ ] **Step 8: Lint, type-check, commit**

```bash
uv run ruff check src/reseller_mcp/database_workflows.py src/reseller_mcp/catalog.py src/reseller_mcp/harness.py tests/test_database_workflows.py
uv run mypy src/reseller_mcp/database_workflows.py src/reseller_mcp/catalog.py src/reseller_mcp/harness.py
git add src/reseller_mcp/database_workflows.py src/reseller_mcp/catalog.py src/reseller_mcp/harness.py tests/test_database_workflows.py
git commit -m "feat(db): add database.query_readonly capability"
```

---

## Task 8: `database.transaction_execute`

**Files:**
- Modify: `src/reseller_mcp/database_workflows.py`
- Modify: `src/reseller_mcp/catalog.py`
- Modify: `src/reseller_mcp/harness.py`
- Test: `tests/test_database_workflows.py` (add cases)

**Interfaces:**
- Consumes: `sql_guardrails.require_safe_write_statements`, `sql_guardrails.derive_backup_select`
  (Task 3), `Database.save_backup` (Task 4), `Harness._workflow_prepare_hooks` /
  `_workflow_execute_hooks` (Task 6).
- Produces:
  - `DatabaseWorkflows.prepare_transaction(self, account: str | None, arguments: dict[str, Any], *, connect_fn: ConnectFn = _default_connect) -> dict[str, Any]`
  - `DatabaseWorkflows.execute_transaction(self, preparation: Preparation, *, connect_fn: ConnectFn = _default_connect) -> dict[str, Any]`

- [ ] **Step 1: Register the capability in the catalog**

In `src/reseller_mcp/catalog.py`, add to `EXPLICIT_RISKS`:

```python
    "database.transaction_execute": (Risk.REVERSIBLE_WRITE, Role.OPERATOR, "operator"),
```

Add to `ALIASES`:

```python
    "database.transaction_execute": "banco dados mysql escrever transacao update delete insert",
```

Add to `definitions`, right after `database.query_readonly`:

```python
        {
            "id": "database.transaction_execute",
            "title": "Executar transação no banco de dados",
            "description": (
                "Executa uma ou mais instruções UPDATE/DELETE/INSERT parametrizadas em uma "
                "única transação, com backup das linhas afetadas, dry-run e pós-validação."
            ),
            "schema": _schema(
                {
                    "database": string,
                    "statements": {
                        "type": "array",
                        "minItems": 1,
                        "items": _schema({"sql": string, "params": {"type": "array"}}, ["sql"]),
                    },
                },
                ["database", "statements"],
            ),
        },
```

- [ ] **Step 2: Write failing tests**

Add to `tests/test_database_workflows.py`:

```python
from reseller_mcp.models import Preparation, PreparationState, Risk


def _make_preparation(account: str, arguments: dict[str, Any], before_state: dict[str, Any] | None) -> Preparation:
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    return Preparation(
        id="prep-1",
        principal_user_id="admin-id",
        client_id="test",
        capability_id="database.transaction_execute",
        account=account,
        arguments=arguments,
        state=PreparationState.PREPARED,
        risk=Risk.REVERSIBLE_WRITE,
        idempotency_key="idem-1",
        created_at=now,
        expires_at=now + timedelta(seconds=300),
        before_state=before_state,
    )


async def test_prepare_transaction_backs_up_and_dry_runs(settings: Settings, db: Database) -> None:
    cpanel = RecordingFakeCPanel()
    harness = Harness(settings, db, cpanel)  # type: ignore[arg-type]
    workflows = DatabaseWorkflows(harness)

    fake_connection = FakeConnection(rows=[{"id": 1, "active": 1}])

    async def fake_connect(**kwargs: Any) -> FakeConnection:
        return fake_connection

    before_state = await workflows.prepare_transaction(
        "acctalpha",
        {
            "database": "acctalpha_app",
            "statements": [{"sql": "UPDATE users SET active = 0 WHERE id = 1", "params": []}],
        },
        connect_fn=fake_connect,
    )
    assert before_state is not None
    assert before_state["backup_ref"] is not None
    stored = db.get_backup(before_state["backup_ref"])
    assert stored is not None
    assert stored["payload"][0]["rows"] == [{"id": 1, "active": 1}]


async def test_prepare_transaction_rejects_forbidden_statement(settings: Settings, db: Database) -> None:
    cpanel = RecordingFakeCPanel()
    harness = Harness(settings, db, cpanel)  # type: ignore[arg-type]
    workflows = DatabaseWorkflows(harness)

    with pytest.raises(HarnessError) as exc:
        await workflows.prepare_transaction(
            "acctalpha",
            {"database": "acctalpha_app", "statements": [{"sql": "DROP TABLE users"}]},
        )
    assert exc.value.code == "SQL_FORBIDDEN_STATEMENT"


async def test_execute_transaction_commits_and_reports_verified(settings: Settings, db: Database) -> None:
    cpanel = RecordingFakeCPanel()
    harness = Harness(settings, db, cpanel)  # type: ignore[arg-type]
    workflows = DatabaseWorkflows(harness)

    fake_connection = FakeConnection(rows=[{"id": 1}])

    async def fake_connect(**kwargs: Any) -> FakeConnection:
        return fake_connection

    arguments = {
        "database": "acctalpha_app",
        "statements": [{"sql": "UPDATE users SET active = 0 WHERE id = 1", "params": []}],
    }
    before_state = await workflows.prepare_transaction("acctalpha", arguments, connect_fn=fake_connect)
    preparation = _make_preparation("acctalpha", arguments, before_state)

    result = await workflows.execute_transaction(preparation, connect_fn=fake_connect)
    assert result["committed"] is True
    assert fake_connection.committed is True
    assert result["verified"] is True
```

`FakeConnection` needs `began`/`committed`/`rolled_back` attributes — reuse the version from
`tests/test_mysql_client.py` by copying its definition into this file too (test files in this
repo do not share fixtures across files beyond `conftest.py`; duplicate the small fake rather
than introducing cross-file test imports). Update the `FakeConnection` class already added in
Step 2 above to match the fuller version from `tests/test_mysql_client.py` (with `begin`,
`commit`, `rollback`, `began`, `committed`, `rolled_back`).

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_database_workflows.py -v`
Expected: FAIL with `AttributeError: 'DatabaseWorkflows' object has no attribute 'prepare_transaction'`.

- [ ] **Step 4: Implement `prepare_transaction` and `execute_transaction`**

Add to `src/reseller_mcp/database_workflows.py` (imports first — add `hashlib`, `json`,
`Preparation` under `TYPE_CHECKING`, and the guardrail/backup functions):

```python
from .sql_guardrails import (
    SQLGuardrailError,
    derive_backup_select,
    require_safe_write_statements,
    require_single_select,
)

if TYPE_CHECKING:
    from .harness import Harness
    from .models import Preparation
```

Add methods to `DatabaseWorkflows`:

```python
    async def prepare_transaction(
        self,
        account: str | None,
        arguments: dict[str, Any],
        *,
        connect_fn: ConnectFn = _default_connect,
    ) -> dict[str, Any]:
        from .harness import HarnessError

        if account is None:
            raise HarnessError("database workflows require an account", "ACCOUNT_REQUIRED")
        database_name = arguments["database"]
        raw_statements = arguments["statements"]
        try:
            parsed = require_safe_write_statements([item["sql"] for item in raw_statements])
        except SQLGuardrailError as exc:
            raise HarnessError(str(exc), exc.code) from exc

        backups: list[dict[str, Any]] = []
        async with MySQLEphemeralSession(
            cpanel=self.harness.cpanel,
            db=self.harness.db,
            settings=self.harness.settings,
            account=account,
            database=database_name,
            mode="write",
            connect_fn=connect_fn,
        ) as session:
            for index, (item, statement) in enumerate(zip(raw_statements, parsed, strict=True)):
                backup_sql = derive_backup_select(statement)
                if backup_sql is None:
                    continue
                rows = await session.fetch_all(backup_sql, item.get("params") or [])
                backups.append({"statement_index": index, "sql": backup_sql, "rows": rows})
            try:
                dry_run_rows = await session.run_transaction(
                    [(item["sql"], item.get("params") or []) for item in raw_statements],
                    commit=False,
                )
            except Exception as exc:
                raise HarnessError(f"dry run failed: {exc}", "DRY_RUN_FAILED") from exc

        backup_ref = self.harness.db.save_backup(account, database_name, backups) if backups else None
        return {
            "backup_ref": backup_ref,
            "dry_run_rows_affected": dry_run_rows,
            "statement_count": len(raw_statements),
        }

    async def execute_transaction(
        self,
        preparation: Preparation,
        *,
        connect_fn: ConnectFn = _default_connect,
    ) -> dict[str, Any]:
        from .harness import HarnessError

        account = preparation.account
        if account is None:
            raise HarnessError("database workflows require an account", "ACCOUNT_REQUIRED")
        database_name = preparation.arguments["database"]
        raw_statements = preparation.arguments["statements"]
        try:
            require_safe_write_statements([item["sql"] for item in raw_statements])
        except SQLGuardrailError as exc:
            raise HarnessError(str(exc), exc.code) from exc

        async with MySQLEphemeralSession(
            cpanel=self.harness.cpanel,
            db=self.harness.db,
            settings=self.harness.settings,
            account=account,
            database=database_name,
            mode="write",
            connect_fn=connect_fn,
        ) as session:
            rows_affected = await session.run_transaction(
                [(item["sql"], item.get("params") or []) for item in raw_statements],
                commit=True,
            )

        before = preparation.before_state or {}
        verified = before.get("dry_run_rows_affected") == rows_affected
        warnings = [] if verified else ["rows affected during commit differ from the dry run"]
        return {
            "committed": True,
            "rows_affected": rows_affected,
            "backup_ref": before.get("backup_ref"),
            "after_state": {
                "committed": True,
                "rows_affected": rows_affected,
                "backup_ref": before.get("backup_ref"),
            },
            "verified": verified,
            "warnings": warnings,
        }
```

- [ ] **Step 5: Wire the prepare/execute hooks into `Harness.__init__`**

In `src/reseller_mcp/harness.py`, after
`self._workflow_query_hooks["database.query_readonly"] = self.database.query_readonly`, add:

```python
        self._workflow_prepare_hooks["database.transaction_execute"] = (
            self.database.prepare_transaction
        )
        self._workflow_execute_hooks["database.transaction_execute"] = (
            self.database.execute_transaction
        )
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_database_workflows.py -v`
Expected: PASS.

- [ ] **Step 7: Run the full suite, lint, type-check, commit**

```bash
uv run pytest -v
uv run ruff check src/reseller_mcp/database_workflows.py src/reseller_mcp/catalog.py src/reseller_mcp/harness.py tests/test_database_workflows.py
uv run mypy src/reseller_mcp/database_workflows.py src/reseller_mcp/catalog.py src/reseller_mcp/harness.py
git add src/reseller_mcp/database_workflows.py src/reseller_mcp/catalog.py src/reseller_mcp/harness.py tests/test_database_workflows.py
git commit -m "feat(db): add database.transaction_execute with backup, dry-run, and post-validation"
```

---

## Task 9: `workflow.database_migration_apply`

**Files:**
- Modify: `src/reseller_mcp/database_workflows.py`
- Modify: `src/reseller_mcp/catalog.py`
- Modify: `src/reseller_mcp/harness.py`
- Test: `tests/test_database_workflows.py` (add cases)

**Interfaces:**
- Consumes: `Database.get_migration` / `record_migration` (Task 4),
  `DatabaseWorkflows.prepare_transaction` / `execute_transaction` (Task 8).
- Produces:
  - `DatabaseWorkflows.prepare_migration(self, account: str | None, arguments: dict[str, Any], *, connect_fn: ConnectFn = _default_connect) -> dict[str, Any]`
  - `DatabaseWorkflows.execute_migration(self, preparation: Preparation, *, connect_fn: ConnectFn = _default_connect) -> dict[str, Any]`

- [ ] **Step 1: Register the capability in the catalog**

In `src/reseller_mcp/catalog.py`, add to `EXPLICIT_RISKS`:

```python
    "workflow.database_migration_apply": (Risk.REVERSIBLE_WRITE, Role.ADMIN, "admin"),
```

Add to `ALIASES`:

```python
    "workflow.database_migration_apply": "banco dados migration migracao versionada aplicar",
```

Add to `definitions`, right after `database.transaction_execute`:

```python
        {
            "id": "workflow.database_migration_apply",
            "title": "Aplicar migration de banco de dados",
            "description": (
                "Aplica uma migration versionada e idempotente: reaplicar o mesmo migration_id "
                "com o mesmo conteúdo é um no-op seguro; conteúdo diferente é bloqueado. Reusa "
                "backup, dry-run e pós-validação de database.transaction_execute."
            ),
            "schema": _schema(
                {
                    "database": string,
                    "migration_id": string,
                    "statements": {
                        "type": "array",
                        "minItems": 1,
                        "items": _schema({"sql": string, "params": {"type": "array"}}, ["sql"]),
                    },
                },
                ["database", "migration_id", "statements"],
            ),
        },
```

- [ ] **Step 2: Write failing tests**

Add to `tests/test_database_workflows.py`:

```python
async def test_prepare_migration_first_run_delegates_to_transaction(settings: Settings, db: Database) -> None:
    cpanel = RecordingFakeCPanel()
    harness = Harness(settings, db, cpanel)  # type: ignore[arg-type]
    workflows = DatabaseWorkflows(harness)

    fake_connection = FakeConnection(rows=[{"id": 1}])

    async def fake_connect(**kwargs: Any) -> FakeConnection:
        return fake_connection

    before_state = await workflows.prepare_migration(
        "acctalpha",
        {
            "database": "acctalpha_app",
            "migration_id": "2026_07_disable_user",
            "statements": [{"sql": "UPDATE users SET active = 0 WHERE id = 1", "params": []}],
        },
        connect_fn=fake_connect,
    )
    assert before_state["already_applied"] is False
    assert before_state["migration_id"] == "2026_07_disable_user"
    assert "checksum" in before_state


async def test_prepare_migration_rejects_checksum_mismatch(settings: Settings, db: Database) -> None:
    cpanel = RecordingFakeCPanel()
    harness = Harness(settings, db, cpanel)  # type: ignore[arg-type]
    workflows = DatabaseWorkflows(harness)
    db.record_migration(
        account="acctalpha",
        database_name="acctalpha_app",
        migration_id="2026_07_disable_user",
        checksum="different-checksum",
        backup_ref=None,
        rows_affected=1,
        status="applied",
    )

    with pytest.raises(HarnessError) as exc:
        await workflows.prepare_migration(
            "acctalpha",
            {
                "database": "acctalpha_app",
                "migration_id": "2026_07_disable_user",
                "statements": [{"sql": "UPDATE users SET active = 0 WHERE id = 1", "params": []}],
            },
        )
    assert exc.value.code == "MIGRATION_CHECKSUM_MISMATCH"


async def test_prepare_migration_same_checksum_is_noop(settings: Settings, db: Database) -> None:
    cpanel = RecordingFakeCPanel()
    harness = Harness(settings, db, cpanel)  # type: ignore[arg-type]
    workflows = DatabaseWorkflows(harness)

    arguments = {
        "database": "acctalpha_app",
        "migration_id": "2026_07_disable_user",
        "statements": [{"sql": "UPDATE users SET active = 0 WHERE id = 1", "params": []}],
    }
    checksum = workflows._checksum(arguments["statements"])
    db.record_migration(
        account="acctalpha",
        database_name="acctalpha_app",
        migration_id="2026_07_disable_user",
        checksum=checksum,
        backup_ref="backup-1",
        rows_affected=1,
        status="applied",
    )

    before_state = await workflows.prepare_migration("acctalpha", arguments)
    assert before_state["already_applied"] is True
    assert before_state["rows_affected"] == 1


async def test_execute_migration_records_ledger_on_success(settings: Settings, db: Database) -> None:
    cpanel = RecordingFakeCPanel()
    harness = Harness(settings, db, cpanel)  # type: ignore[arg-type]
    workflows = DatabaseWorkflows(harness)

    fake_connection = FakeConnection(rows=[{"id": 1}])

    async def fake_connect(**kwargs: Any) -> FakeConnection:
        return fake_connection

    arguments = {
        "database": "acctalpha_app",
        "migration_id": "2026_07_disable_user",
        "statements": [{"sql": "UPDATE users SET active = 0 WHERE id = 1", "params": []}],
    }
    before_state = await workflows.prepare_migration("acctalpha", arguments, connect_fn=fake_connect)
    preparation = _make_preparation("acctalpha", arguments, before_state)
    preparation = preparation.model_copy(update={"capability_id": "workflow.database_migration_apply"})

    result = await workflows.execute_migration(preparation, connect_fn=fake_connect)
    assert result["committed"] is True

    record = db.get_migration("acctalpha", "acctalpha_app", "2026_07_disable_user")
    assert record is not None
    assert record["status"] == "applied"


async def test_execute_migration_noop_when_already_applied(settings: Settings, db: Database) -> None:
    cpanel = RecordingFakeCPanel()
    harness = Harness(settings, db, cpanel)  # type: ignore[arg-type]
    workflows = DatabaseWorkflows(harness)

    arguments = {
        "database": "acctalpha_app",
        "migration_id": "2026_07_disable_user",
        "statements": [{"sql": "UPDATE users SET active = 0 WHERE id = 1", "params": []}],
    }
    checksum = workflows._checksum(arguments["statements"])
    db.record_migration(
        account="acctalpha",
        database_name="acctalpha_app",
        migration_id="2026_07_disable_user",
        checksum=checksum,
        backup_ref="backup-1",
        rows_affected=1,
        status="applied",
    )
    before_state = await workflows.prepare_migration("acctalpha", arguments)
    preparation = _make_preparation("acctalpha", arguments, before_state)

    result = await workflows.execute_migration(preparation)
    assert result["already_applied"] is True
    assert result["committed"] is False
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_database_workflows.py -v`
Expected: FAIL with `AttributeError: 'DatabaseWorkflows' object has no attribute 'prepare_migration'`.

- [ ] **Step 4: Implement `prepare_migration`, `execute_migration`, and `_checksum`**

Add to `src/reseller_mcp/database_workflows.py` (add `hashlib` and `json` to the imports):

```python
import hashlib
import json
```

Add methods to `DatabaseWorkflows`:

```python
    @staticmethod
    def _checksum(statements: list[dict[str, Any]]) -> str:
        canonical = json.dumps(statements, ensure_ascii=False, sort_keys=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    async def prepare_migration(
        self,
        account: str | None,
        arguments: dict[str, Any],
        *,
        connect_fn: ConnectFn = _default_connect,
    ) -> dict[str, Any]:
        from .harness import HarnessError

        if account is None:
            raise HarnessError("database workflows require an account", "ACCOUNT_REQUIRED")
        database_name = arguments["database"]
        migration_id = arguments["migration_id"]
        statements = arguments["statements"]
        checksum = self._checksum(statements)

        existing = self.harness.db.get_migration(account, database_name, migration_id)
        if existing is not None:
            if existing["checksum"] != checksum:
                raise HarnessError(
                    f"migration_id {migration_id!r} was already applied with different content",
                    "MIGRATION_CHECKSUM_MISMATCH",
                )
            return {
                "already_applied": True,
                "migration_id": migration_id,
                "checksum": checksum,
                "applied_at": existing["applied_at"],
                "rows_affected": existing["rows_affected"],
                "backup_ref": existing["backup_ref"],
            }

        before_state = await self.prepare_transaction(
            account,
            {"database": database_name, "statements": statements},
            connect_fn=connect_fn,
        )
        before_state["already_applied"] = False
        before_state["migration_id"] = migration_id
        before_state["checksum"] = checksum
        return before_state

    async def execute_migration(
        self,
        preparation: Preparation,
        *,
        connect_fn: ConnectFn = _default_connect,
    ) -> dict[str, Any]:
        before = preparation.before_state or {}
        if before.get("already_applied"):
            return {
                "committed": False,
                "already_applied": True,
                "rows_affected": before.get("rows_affected"),
                "after_state": before,
                "verified": True,
                "warnings": ["migration already applied; no-op"],
            }

        result = await self.execute_transaction(preparation, connect_fn=connect_fn)
        database_name = preparation.arguments["database"]
        self.harness.db.record_migration(
            account=preparation.account or "",
            database_name=database_name,
            migration_id=before["migration_id"],
            checksum=before["checksum"],
            backup_ref=before.get("backup_ref"),
            rows_affected=result.get("rows_affected"),
            status="applied" if result.get("verified") else "failed",
        )
        return result
```

- [ ] **Step 5: Wire the prepare/execute hooks into `Harness.__init__`**

In `src/reseller_mcp/harness.py`, after the `database.transaction_execute` hook registration,
add:

```python
        self._workflow_prepare_hooks["workflow.database_migration_apply"] = (
            self.database.prepare_migration
        )
        self._workflow_execute_hooks["workflow.database_migration_apply"] = (
            self.database.execute_migration
        )
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_database_workflows.py -v`
Expected: PASS.

- [ ] **Step 7: Run the full suite, lint, type-check, commit**

```bash
uv run pytest -v
uv run ruff check src/reseller_mcp/database_workflows.py src/reseller_mcp/catalog.py src/reseller_mcp/harness.py tests/test_database_workflows.py
uv run mypy src/reseller_mcp/database_workflows.py src/reseller_mcp/catalog.py src/reseller_mcp/harness.py
git add src/reseller_mcp/database_workflows.py src/reseller_mcp/catalog.py src/reseller_mcp/harness.py tests/test_database_workflows.py
git commit -m "feat(db): add workflow.database_migration_apply with idempotent ledger"
```

---

## Task 10: Orphaned ephemeral grant reaper

**Files:**
- Modify: `src/reseller_mcp/mysql_client.py`
- Modify: `src/reseller_mcp/admin_cli.py`
- Test: `tests/test_mysql_client.py` (add cases)

**Interfaces:**
- Produces: `async def reap_expired_grants(cpanel: CPanelClient, db: Database, settings: Settings) -> int`
  (returns count of grants successfully revoked).

- [ ] **Step 1: Write failing test**

Add to `tests/test_mysql_client.py`:

```python
from reseller_mcp.mysql_client import reap_expired_grants


async def test_reap_expired_grants_revokes_and_removes_ledger_rows(settings: Settings, db: Database) -> None:
    db.insert_ephemeral_grant(
        grant_id="grant-expired",
        account="acctalpha",
        database_name="acctalpha_app",
        mysql_username="eph_orphan",
        host_entry_created=True,
        ttl_seconds=-10,
    )
    cpanel = FakeCPanel()

    revoked = await reap_expired_grants(cpanel, db, settings)  # type: ignore[arg-type]

    assert revoked == 1
    assert db.list_expired_ephemeral_grants() == []
    function_calls = [call[0] for call in cpanel.calls]
    assert "delete_user" in function_calls
    assert "delete_host" in function_calls


async def test_reap_expired_grants_keeps_row_on_repeated_failure(settings: Settings, db: Database) -> None:
    db.insert_ephemeral_grant(
        grant_id="grant-stuck",
        account="acctalpha",
        database_name="acctalpha_app",
        mysql_username="eph_stuck",
        host_entry_created=False,
        ttl_seconds=-10,
    )

    class AlwaysFailingCPanel(FakeCPanel):
        async def call(self, capability: Any, account: str | None, arguments: dict[str, Any], *, retry_safe: bool = False) -> Any:
            raise CPanelError("still down", code="UPSTREAM_NETWORK_ERROR")

    cpanel = AlwaysFailingCPanel()
    revoked = await reap_expired_grants(cpanel, db, settings)  # type: ignore[arg-type]

    assert revoked == 0
    with db.connect() as conn:
        rows = conn.execute("SELECT * FROM mysql_ephemeral_grants").fetchall()
    assert len(rows) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_mysql_client.py -k reap -v`
Expected: FAIL with `ImportError: cannot import name 'reap_expired_grants'`.

- [ ] **Step 3: Implement `reap_expired_grants`**

Add to `src/reseller_mcp/mysql_client.py`:

```python
async def reap_expired_grants(cpanel: CPanelClient, db: Database, settings: Settings) -> int:
    revoked = 0
    for grant in db.list_expired_ephemeral_grants():
        user_ok = True
        host_ok = not grant["host_entry_created"]
        try:
            await cpanel.call(
                _internal_capability("delete_user"), grant["account"], {"name": grant["mysql_username"]}
            )
        except CPanelError:
            user_ok = False
        if grant["host_entry_created"]:
            try:
                await cpanel.call(
                    _internal_capability("delete_host"),
                    grant["account"],
                    {"host": settings.mysql_egress_ip},
                )
                host_ok = True
            except CPanelError:
                host_ok = False
        if user_ok and host_ok:
            db.delete_ephemeral_grant(grant["id"])
            revoked += 1
    return revoked
```

Update the top-of-file imports in `mysql_client.py` to import `Database`, `CPanelClient`, and
`Settings` unconditionally (not only under `TYPE_CHECKING`) since `reap_expired_grants` uses
them as real runtime parameter types accessed via `.call`/`.list_expired_ephemeral_grants` — the
existing `TYPE_CHECKING`-only imports are fine to keep for those since Python doesn't check
annotations at runtime, but double check `mypy --strict` accepts this; if not, move `Database`
and `CPanelClient` to regular imports (they don't import `mysql_client.py` back, so no cycle).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_mysql_client.py -v`
Expected: PASS.

- [ ] **Step 5: Wire the reaper into `admin_cli.py` as a manual/cron-invoked command**

`src/reseller_mcp/admin_cli.py` defines a top-level `app = typer.Typer(...)` plus sub-typers
(`users`, `tokens`, `catalog`, `audit`) added via `app.add_typer(...)`, and a `_db()` helper that
builds a `Database` from `get_settings()`. Add a new top-level command directly on `app`,
matching the existing `typer.echo(json.dumps(...))` output style used by `sync_catalog`/`users_list`:

```python
@app.command("reap-mysql-grants")
def reap_mysql_grants() -> None:
    import asyncio

    from .cpanel import CPanelClient
    from .mysql_client import reap_expired_grants

    settings = get_settings()
    db = _db()
    cpanel = CPanelClient(settings)

    async def run() -> int:
        try:
            return await reap_expired_grants(cpanel, db, settings)
        finally:
            await cpanel.close()

    revoked = asyncio.run(run())
    typer.echo(json.dumps({"revoked": revoked}))
```

Add this function after `export_audit` and before the `if __name__ == "__main__":` block.

- [ ] **Step 6: Run the full suite, lint, type-check, commit**

```bash
uv run pytest -v
uv run ruff check src/reseller_mcp/mysql_client.py src/reseller_mcp/admin_cli.py tests/test_mysql_client.py
uv run mypy src/reseller_mcp/mysql_client.py src/reseller_mcp/admin_cli.py
git add src/reseller_mcp/mysql_client.py src/reseller_mcp/admin_cli.py tests/test_mysql_client.py
git commit -m "feat(db): add reaper for orphaned ephemeral MySQL grants"
```

- [ ] **Step 7: Document the operational cron job**

This command must run periodically (e.g. every 5 minutes) via the host's crontab —
`reseller-mcp-admin reap-mysql-grants`. Add a note to `docs/ci-cd.md` or wherever the VPS
operational cron jobs are documented today (check `docs/ci-cd.md` first for an existing
"operational cron" section to extend; otherwise add a short new section there) — this is a
manual deployment step, not something this plan's automated tests can verify.

---

## Task 11: Documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/api-contracts.md`

- [ ] **Step 1: Update the "Ferramentas públicas" list in `README.md`**

In the `### Execução` bullet, add the three new capability IDs alongside the existing
`query_execute`/`action_prepare` mention so operators know they exist:

```markdown
- Execução: `query_execute`, `action_prepare`, `action_execute`, `action_cancel`,
  `action_approve`. Inclui as capabilities `database.query_readonly`,
  `database.transaction_execute` e `workflow.database_migration_apply` para acesso direto e
  auditado ao MySQL das contas, substituindo o antigo improviso de publicar PHP temporário.
```

- [ ] **Step 2: Add a section to `docs/api-contracts.md`**

Add a new section after "## Taxonomia de risco" (or wherever reads best given the current
document flow — check the file's structure first):

```markdown
## Acesso a banco de dados

`database.query_readonly`, `database.transaction_execute` e
`workflow.database_migration_apply` alcançam o MySQL de uma conta por conexão TCP direta,
usando credenciais efêmeras provisionadas sob demanda via `uapi.Mysql.*` (nunca persistidas).
`query_readonly` aceita apenas um único `SELECT`. `transaction_execute` valida cada statement
via AST (`sqlglot`), permitindo somente `UPDATE`/`DELETE`/`INSERT`; o `action_prepare` roda um
backup das linhas afetadas e um dry-run com `ROLLBACK`, e o `action_execute` aplica com `COMMIT`
e pós-validação. `workflow.database_migration_apply` acrescenta um ledger versionado
(`migration_id` + checksum do SQL): reaplicar com o mesmo conteúdo é no-op; conteúdo diferente é
bloqueado.
```

- [ ] **Step 3: Commit**

```bash
git add README.md docs/api-contracts.md
git commit -m "docs: document the new database access capabilities"
```

---

## Deviation from the spec's testing section

The spec calls for integration tests against a real MySQL instance in an ephemeral Docker
container. This plan replaces that with fully mocked unit tests (fake `aiomysql` connection/
cursor objects, fake `CPanelClient`) throughout Tasks 5, 7, 8, 9, and 10, for two reasons: (1)
this repo's existing test suite and CI have no Docker/testcontainers dependency today, and
introducing one is a meaningful infrastructure change outside this plan's scope; (2) the
connectivity spike (Task 1) plus manual verification against the real demo account before
production rollout already exercises the real `uapi.Mysql.*` + TCP path end to end. If real-MySQL
integration coverage in CI is wanted later, that is a separate, explicit follow-up plan (add
`testcontainers[mysql]` as a dev dependency, gate the tests behind a marker so default `pytest`
runs stay hermetic) — not silently folded into this one.

## Final check

- [ ] Run the complete suite one more time end to end: `uv run pytest -v`
- [ ] Run `uv run mypy` (whole package) and `uv run ruff check .`
- [ ] Confirm `git log --oneline` shows one commit per task, all with real, working code
- [ ] Re-read `docs/superpowers/specs/2026-07-22-database-access-design.md` and check every
  requirement maps to a task above (it does: connection lifecycle → Tasks 1/5; the three
  capabilities → Tasks 7/8/9; ledger → Task 4/9; guardrails → Task 3; reaper → Task 10; harness
  integration → Task 6; docs → Task 11)
