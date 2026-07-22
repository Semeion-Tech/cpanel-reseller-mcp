from __future__ import annotations

from typing import TYPE_CHECKING, Any

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
