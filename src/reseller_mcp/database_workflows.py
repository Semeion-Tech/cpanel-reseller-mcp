from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

from .mysql_client import ConnectFn, MySQLEphemeralSession, _default_connect
from .sql_guardrails import (
    SQLGuardrailError,
    derive_backup_select,
    require_safe_write_statements,
    require_single_select,
)

if TYPE_CHECKING:
    from .harness import Harness
    from .models import Preparation


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
        from .harness import HarnessError

        if account is None:
            raise HarnessError(
                "database workflows require an account", "ACCOUNT_REQUIRED"
            )
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
                placeholder_count = backup_sql.count("%s")
                all_params = item.get("params") or []
                backup_params = all_params[-placeholder_count:] if placeholder_count > 0 else []
                rows = await session.fetch_all(backup_sql, backup_params)
                backups.append({"statement_index": index, "sql": backup_sql, "rows": rows})
            try:
                dry_run_rows = await session.run_transaction(
                    [(item["sql"], item.get("params") or []) for item in raw_statements],
                    commit=False,
                )
            except Exception as exc:
                raise HarnessError(f"dry run failed: {exc}", "DRY_RUN_FAILED") from exc

        backup_ref = (
            self.harness.db.save_backup(account, database_name, backups) if backups else None
        )
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

        # Re-check ledger inside the lock to close TOCTOU race
        database_name = preparation.arguments["database"]
        migration_id = before["migration_id"]
        checksum = before["checksum"]
        existing = self.harness.db.get_migration(
            preparation.account or "", database_name, migration_id
        )
        if existing is not None:
            if existing["checksum"] != checksum:
                from .harness import HarnessError

                raise HarnessError(
                    f"migration_id {migration_id!r} was already applied with different content",
                    "MIGRATION_CHECKSUM_MISMATCH",
                )
            # Another execute won the race; return no-op result
            return {
                "committed": False,
                "already_applied": True,
                "rows_affected": existing.get("rows_affected"),
                "after_state": existing,
                "verified": True,
                "warnings": ["migration already applied; no-op"],
            }

        result = await self.execute_transaction(preparation, connect_fn=connect_fn)
        self.harness.db.record_migration(
            account=preparation.account or "",
            database_name=database_name,
            migration_id=migration_id,
            checksum=checksum,
            backup_ref=before.get("backup_ref"),
            rows_affected=result.get("rows_affected"),
            status="applied" if result.get("verified") else "failed",
        )
        return result
