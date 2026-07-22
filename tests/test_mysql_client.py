from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from reseller_mcp.config import Settings
from reseller_mcp.cpanel import CPanelError
from reseller_mcp.db import Database
from reseller_mcp.mysql_client import MySQLEphemeralSession


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

    async def __aenter__(self) -> FakeCursor:
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

    async def call(
        self,
        capability: Any,
        account: str | None,
        arguments: dict[str, Any],
        *,
        retry_safe: bool = False,
    ) -> Any:
        self.calls.append((capability.function, account, arguments))
        if capability.function == "get_server_information":
            return {"host": "db.example.com", "port": 3306}
        if capability.function == "get_restrictions":
            return {"prefix": "acctalph_", "max_username_length": 32}
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


async def test_session_provisions_and_cleans_up(
    settings: Settings, db: Database
) -> None:
    cpanel = FakeCPanel()
    fake_connection = FakeConnection(rows=[{"id": 1}])

    async def fake_connect(**kwargs: Any) -> FakeConnection:
        assert kwargs["host"] == "db.example.com"
        assert kwargs["port"] == 3306
        assert kwargs["user"] == "acctalph_eph_test"
        return fake_connection

    async with MySQLEphemeralSession(
        cpanel=cpanel,  # type: ignore[arg-type]
        db=db,
        settings=settings,
        account="acctalpha",
        database="acctalpha_app",
        mode="read",
        connect_fn=fake_connect,
        username_suffix_factory=lambda: "eph_test",
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


async def test_session_records_ledger_row_during_use(
    settings: Settings, db: Database
) -> None:
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


async def test_run_transaction_rolls_back_when_commit_false(
    settings: Settings, db: Database
) -> None:
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
        await session.run_transaction(
            [("UPDATE t SET x=1 WHERE id=1", [])], commit=False
        )

    assert fake_connection.began is True
    assert fake_connection.rolled_back is True
    assert fake_connection.committed is False


async def test_cleanup_failure_leaves_ledger_row_for_reaper(
    settings: Settings, db: Database
) -> None:
    class FailingCPanel(FakeCPanel):
        async def call(
            self,
            capability: Any,
            account: str | None,
            arguments: dict[str, Any],
            *,
            retry_safe: bool = False,
        ) -> Any:
            if capability.function == "delete_user":
                raise CPanelError("upstream unavailable", code="UPSTREAM_NETWORK_ERROR")
            return await super().call(
                capability, account, arguments, retry_safe=retry_safe
            )

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


async def test_cleanup_failure_row_exists_directly(
    settings: Settings, db: Database
) -> None:
    class FailingCPanel(FakeCPanel):
        async def call(
            self,
            capability: Any,
            account: str | None,
            arguments: dict[str, Any],
            *,
            retry_safe: bool = False,
        ) -> Any:
            if capability.function == "delete_user":
                raise CPanelError("upstream unavailable", code="UPSTREAM_NETWORK_ERROR")
            return await super().call(
                capability, account, arguments, retry_safe=retry_safe
            )

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
