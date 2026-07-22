from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from reseller_mcp.config import Settings
from reseller_mcp.database_workflows import DatabaseWorkflows
from reseller_mcp.db import Database
from reseller_mcp.harness import Harness, HarnessError


class RecordingFakeCPanel:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def call(
        self,
        capability: Any,
        account: str | None,
        arguments: dict[str, Any],
        *,
        retry_safe: bool = False,
    ) -> Any:
        self.calls.append(capability.function)
        if capability.function == "get_server_information":
            return {"host": "db.example.com", "port": 3306}
        if capability.function == "get_restrictions":
            return {"prefix": "acctalph_", "max_username_length": 32}
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

    async def __aenter__(self) -> FakeCursor:
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
