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
