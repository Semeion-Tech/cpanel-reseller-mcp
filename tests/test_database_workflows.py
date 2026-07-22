from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from reseller_mcp.config import Settings
from reseller_mcp.database_workflows import DatabaseWorkflows
from reseller_mcp.db import Database
from reseller_mcp.harness import Harness, HarnessError
from reseller_mcp.models import Preparation, PreparationState, Risk


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
        placeholder_count = sql.count("%s")
        param_list = params or []
        if len(param_list) != placeholder_count:
            raise TypeError(
                f"not all arguments converted during string formatting "
                f"(expected {placeholder_count}, got {len(param_list)})"
            )

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


def _make_preparation(
    account: str, arguments: dict[str, Any], before_state: dict[str, Any] | None
) -> Preparation:
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
            "statements": [{"sql": "UPDATE users SET active = %s WHERE id = %s", "params": [0, 1]}],
        },
        connect_fn=fake_connect,
    )
    assert before_state is not None
    assert before_state["backup_ref"] is not None
    stored = db.get_backup(before_state["backup_ref"])
    assert stored is not None
    assert stored["payload"][0]["rows"] == [{"id": 1, "active": 1}]


async def test_prepare_transaction_rejects_forbidden_statement(
    settings: Settings, db: Database
) -> None:
    cpanel = RecordingFakeCPanel()
    harness = Harness(settings, db, cpanel)  # type: ignore[arg-type]
    workflows = DatabaseWorkflows(harness)

    with pytest.raises(HarnessError) as exc:
        await workflows.prepare_transaction(
            "acctalpha",
            {"database": "acctalpha_app", "statements": [{"sql": "DROP TABLE users"}]},
        )
    assert exc.value.code == "SQL_FORBIDDEN_STATEMENT"


async def test_execute_transaction_commits_and_reports_verified(
    settings: Settings, db: Database
) -> None:
    cpanel = RecordingFakeCPanel()
    harness = Harness(settings, db, cpanel)  # type: ignore[arg-type]
    workflows = DatabaseWorkflows(harness)

    fake_connection = FakeConnection(rows=[{"id": 1}])

    async def fake_connect(**kwargs: Any) -> FakeConnection:
        return fake_connection

    arguments = {
        "database": "acctalpha_app",
        "statements": [{"sql": "UPDATE users SET active = %s WHERE id = %s", "params": [0, 1]}],
    }
    before_state = await workflows.prepare_transaction(
        "acctalpha", arguments, connect_fn=fake_connect
    )
    preparation = _make_preparation("acctalpha", arguments, before_state)

    result = await workflows.execute_transaction(preparation, connect_fn=fake_connect)
    assert result["committed"] is True
    assert fake_connection.committed is True
    assert result["verified"] is True


async def test_prepare_transaction_with_multiple_placeholders_uses_where_params_only(
    settings: Settings, db: Database
) -> None:
    cpanel = RecordingFakeCPanel()
    harness = Harness(settings, db, cpanel)  # type: ignore[arg-type]
    workflows = DatabaseWorkflows(harness)

    fake_connection = FakeConnection(rows=[{"id": 5, "active": 0}])

    async def fake_connect(**kwargs: Any) -> FakeConnection:
        return fake_connection

    before_state = await workflows.prepare_transaction(
        "acctalpha",
        {
            "database": "acctalpha_app",
            "statements": [
                {
                    "sql": "UPDATE users SET active = %s, role = %s WHERE id = %s",
                    "params": [1, "admin", 5],
                }
            ],
        },
        connect_fn=fake_connect,
    )
    assert before_state is not None
    assert before_state["backup_ref"] is not None
    stored = db.get_backup(before_state["backup_ref"])
    assert stored is not None
    assert stored["payload"][0]["sql"] == "SELECT * FROM users WHERE id = %s"
    assert stored["payload"][0]["rows"] == [{"id": 5, "active": 0}]


async def test_prepare_migration_first_run_delegates_to_transaction(
    settings: Settings, db: Database
) -> None:
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


async def test_prepare_migration_rejects_checksum_mismatch(
    settings: Settings, db: Database
) -> None:
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


async def test_execute_migration_records_ledger_on_success(
    settings: Settings, db: Database
) -> None:
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
    before_state = await workflows.prepare_migration(
        "acctalpha", arguments, connect_fn=fake_connect
    )
    preparation = _make_preparation("acctalpha", arguments, before_state)
    preparation = preparation.model_copy(
        update={"capability_id": "workflow.database_migration_apply"}
    )

    result = await workflows.execute_migration(preparation, connect_fn=fake_connect)
    assert result["committed"] is True

    record = db.get_migration("acctalpha", "acctalpha_app", "2026_07_disable_user")
    assert record is not None
    assert record["status"] == "applied"


async def test_execute_migration_noop_when_already_applied(
    settings: Settings, db: Database
) -> None:
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


async def test_execute_migration_toctou_race_already_applied_by_another(
    settings: Settings, db: Database
) -> None:
    cpanel = RecordingFakeCPanel()
    harness = Harness(settings, db, cpanel)  # type: ignore[arg-type]
    workflows = DatabaseWorkflows(harness)

    arguments = {
        "database": "acctalpha_app",
        "migration_id": "2026_07_disable_user",
        "statements": [{"sql": "UPDATE users SET active = 0 WHERE id = 1", "params": []}],
    }
    checksum = workflows._checksum(arguments["statements"])

    # Simulate prepare_migration running when nothing is recorded yet
    before_state = {
        "already_applied": False,
        "migration_id": "2026_07_disable_user",
        "checksum": checksum,
        "backup_ref": None,
        "dry_run_rows_affected": 1,
        "statement_count": 1,
    }

    # Simulate another execute_migration winning the race and committing first
    db.record_migration(
        account="acctalpha",
        database_name="acctalpha_app",
        migration_id="2026_07_disable_user",
        checksum=checksum,
        backup_ref=None,
        rows_affected=1,
        status="applied",
    )

    preparation = _make_preparation("acctalpha", arguments, before_state)

    # Verify that connect_fn is never called (proving execute_transaction wasn't invoked)
    connect_called = False

    async def failing_connect(**kwargs: Any) -> FakeConnection:
        nonlocal connect_called
        connect_called = True
        raise AssertionError("connect_fn should not be called in TOCTOU race scenario")

    result = await workflows.execute_migration(preparation, connect_fn=failing_connect)
    assert result["already_applied"] is True
    assert result["committed"] is False
    assert connect_called is False


async def test_execute_migration_toctou_race_checksum_mismatch(
    settings: Settings, db: Database
) -> None:
    cpanel = RecordingFakeCPanel()
    harness = Harness(settings, db, cpanel)  # type: ignore[arg-type]
    workflows = DatabaseWorkflows(harness)

    arguments = {
        "database": "acctalpha_app",
        "migration_id": "2026_07_disable_user",
        "statements": [{"sql": "UPDATE users SET active = 0 WHERE id = 1", "params": []}],
    }
    checksum = workflows._checksum(arguments["statements"])
    different_checksum = "different-checksum-value"

    # Simulate prepare_migration running when nothing is recorded yet
    before_state = {
        "already_applied": False,
        "migration_id": "2026_07_disable_user",
        "checksum": checksum,
        "backup_ref": None,
        "dry_run_rows_affected": 1,
        "statement_count": 1,
    }

    # Simulate another execute_migration recording a different checksum for same migration_id
    db.record_migration(
        account="acctalpha",
        database_name="acctalpha_app",
        migration_id="2026_07_disable_user",
        checksum=different_checksum,
        backup_ref=None,
        rows_affected=5,
        status="applied",
    )

    preparation = _make_preparation("acctalpha", arguments, before_state)

    with pytest.raises(HarnessError) as exc:
        await workflows.execute_migration(preparation)
    assert exc.value.code == "MIGRATION_CHECKSUM_MISMATCH"
