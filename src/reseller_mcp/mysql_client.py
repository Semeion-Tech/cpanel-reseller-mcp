from __future__ import annotations

import secrets
import uuid
from collections.abc import Awaitable, Callable, Sequence
from typing import TYPE_CHECKING, Any, Literal

import aiomysql  # type: ignore[import-untyped]

from .config import Settings
from .cpanel import CPanelClient, CPanelError
from .db import Database
from .models import ApiFamily, Capability, Risk, Role

if TYPE_CHECKING:
    pass

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


async def reap_expired_grants(cpanel: CPanelClient, db: Database, settings: Settings) -> int:
    revoked = 0
    for grant in db.list_expired_ephemeral_grants():
        user_ok = True
        host_ok = not grant["host_entry_created"]
        try:
            await cpanel.call(
                _internal_capability("delete_user"),
                grant["account"],
                {"name": grant["mysql_username"]},
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
        username_suffix_factory: Callable[[], str] = lambda: f"eph{secrets.token_hex(4)}",
    ) -> None:
        self.cpanel = cpanel
        self.db = db
        self.settings = settings
        self.account = account
        self.database = database
        self.mode = mode
        self.connect_fn = connect_fn
        self.username_suffix_factory = username_suffix_factory
        self._grant_id: str | None = None
        self._username: str | None = None
        self._host_created = False
        self._connection: Any = None

    async def __aenter__(self) -> MySQLEphemeralSession:
        if not self.settings.mysql_egress_ip:
            raise MySQLProvisionError(
                "RESELLER_MCP_MYSQL_EGRESS_IP is not configured",
                "EGRESS_IP_NOT_CONFIGURED",
            )
        server_info = await self.cpanel.call(
            _internal_capability("get_server_information"), self.account, {}
        )
        raw_host = (server_info or {}).get("host")
        # cPanel reports "localhost" when MySQL is co-located with cPanel (the common case) —
        # that literal string is not connectable externally. Verified against a real account
        # on 2026-07-22: fall back to the cPanel hostname itself in that case.
        host = raw_host if raw_host and raw_host != "localhost" else self._cpanel_hostname()
        port = int((server_info or {}).get("port") or 3306)

        try:
            try:
                await self.cpanel.call(
                    _internal_capability("add_host"),
                    self.account,
                    {"host": self.settings.mysql_egress_ip},
                )
                self._host_created = True
            except CPanelError as exc:
                if "already exists" not in str(exc).lower():
                    raise MySQLProvisionError(
                        f"add_host failed: {exc}", "PROVISION_FAILED"
                    ) from exc

            # cPanel rejects any username that doesn't already carry the account's required
            # prefix — it does not auto-prefix a short name. Verified against a real account on
            # 2026-07-22 (create_user rejected "spike_xxxx", accepted "drumagco_spikexxxx" after
            # reading the required prefix from get_restrictions).
            restrictions = await self.cpanel.call(
                _internal_capability("get_restrictions"), self.account, {}
            )
            prefix = (restrictions or {}).get("prefix") or f"{self.account}_"
            max_len = int((restrictions or {}).get("max_username_length") or 32)
            self._username = (prefix + self.username_suffix_factory())[:max_len]

            password = secrets.token_urlsafe(24)
            await self.cpanel.call(
                _internal_capability("create_user"),
                self.account,
                {"name": self._username, "password": password},
            )

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
        except Exception:
            await self._cleanup()
            raise
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._connection is not None:
            self._connection.close()
        await self._cleanup()

    def _cpanel_hostname(self) -> str:
        import httpx

        return httpx.URL(self.settings.cpanel_base_url).host

    async def _cleanup(self) -> None:
        user_deleted = True
        host_deleted = not self._host_created
        if self._username is not None:
            try:
                await self.cpanel.call(
                    _internal_capability("delete_user"),
                    self.account,
                    {"name": self._username},
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
        # Last-resort registration: if immediate cleanup failed but we provisioned a user,
        # create the ledger row so the reaper can find it later (e.g., on __aenter__ failure
        # before the normal db.insert_ephemeral_grant call).
        elif (
            (not user_deleted or not host_deleted)
            and self._grant_id is None
            and self._username is not None
        ):
            self.db.insert_ephemeral_grant(
                grant_id=str(uuid.uuid4()),
                account=self.account,
                database_name=self.database,
                mysql_username=self._username,
                host_entry_created=self._host_created,
                ttl_seconds=self.settings.database_ephemeral_ttl_seconds,
            )

    async def fetch_all(
        self,
        sql: str,
        params: Sequence[Any] | None = None,
        *,
        max_rows: int | None = None,
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
