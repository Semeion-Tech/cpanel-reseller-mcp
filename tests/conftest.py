from __future__ import annotations

from pathlib import Path

import pytest

from reseller_mcp.catalog import Catalog
from reseller_mcp.config import Settings
from reseller_mcp.db import Database
from reseller_mcp.harness import Harness
from reseller_mcp.models import Principal, Role


class FakeCPanel:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None, dict[str, object]]] = []

    async def call(self, capability, account, arguments, *, retry_safe=False):
        self.calls.append((capability.id, account, arguments))
        if capability.function == "accountsummary":
            return {
                "acct": [
                    {
                        "user": arguments.get("user"),
                        "uid": "1001",
                        "domain": "alpha.example",
                        "owner": "demo-reseller",
                        "diskused": "100M",
                        "disklimit": "1000M",
                        "suspended": 1,
                        "backup": 1,
                    }
                ]
            }
        if capability.function == "listaccts":
            return {
                "acct": [
                    {
                        "user": "acctalpha",
                        "uid": "1001",
                        "domain": "alpha.example",
                        "owner": "demo-reseller",
                        "email": "operator@example.com",
                        "ip": "192.0.2.10",
                        "diskused": "100M",
                        "disklimit": "1000M",
                        "backup": 1,
                    },
                    {
                        "user": "acctbeta",
                        "uid": "1002",
                        "domain": "example.com",
                        "owner": "demo-reseller",
                    },
                ]
            }
        if capability.function == "showbw":
            return {
                "acct": [
                    {"user": "acctalpha", "totalbytes": 10, "limit": 100},
                    {"user": "acctbeta", "totalbytes": 20, "limit": 100},
                ]
            }
        if capability.function == "verify_user_has_feature":
            return {"has_feature": 1}
        if capability.id == "uapi.DomainInfo.list_domains":
            return {
                "status": 1,
                "data": {
                    "main_domain": "alpha.example",
                    "addon_domains": [],
                    "parked_domains": [],
                    "sub_domains": [],
                },
            }
        if capability.id == "uapi.Backup.list_backups":
            return {"status": 1, "data": []}
        if capability.id == "uapi.EmailAuth.validate_current_spfs":
            return {"status": 1, "data": [{"state": "INVALID", "domain": "alpha.example"}]}
        if capability.id == "uapi.EmailAuth.validate_current_dkims":
            return {"status": 1, "data": [{"state": "MISMATCH", "domain": "alpha.example"}]}
        if capability.id == "uapi.Ftp.allows_anonymous_ftp":
            return {"status": 1, "data": {"allows": 0}}
        if capability.id == "uapi.LangPHP.php_get_vhost_versions":
            return {
                "status": 1,
                "data": [
                    {
                        "vhost": "alpha.example",
                        "version": "ea-php82",
                        "php_fpm": 1,
                        "documentroot": "/home/acctalpha/public_html",
                    }
                ],
            }
        return {"ok": True}


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
    )


@pytest.fixture
def db(settings: Settings) -> Database:
    database = Database(settings.db_path)
    database.sync_capabilities(Catalog(settings.catalog_path).load(), {})
    return database


@pytest.fixture
def viewer() -> Principal:
    return Principal(
        user_id="viewer-id",
        username="viewer",
        role=Role.VIEWER,
        client_id="test",
        account_scopes=frozenset({"acctalpha"}),
    )


@pytest.fixture
def admin() -> Principal:
    return Principal(
        user_id="admin-id",
        username="admin",
        role=Role.ADMIN,
        client_id="test",
        account_scopes=frozenset({"*"}),
    )


@pytest.fixture
def harness(settings: Settings, db: Database) -> Harness:
    return Harness(settings, db, FakeCPanel())
