from __future__ import annotations

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
                rows = await session.fetch_all(backup_sql, item.get("params") or [])
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
