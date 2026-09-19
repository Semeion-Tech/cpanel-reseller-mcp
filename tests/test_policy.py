from __future__ import annotations

import pytest

from reseller_mcp.models import Principal, Role
from reseller_mcp.policy import PolicyEngine, PolicyError


def test_viewer_cannot_write(db, viewer) -> None:
    capability = db.get_capability("uapi.Email.add_pop")
    with pytest.raises(PolicyError, match="requires role operator"):
        PolicyEngine().authorize(
            viewer,
            capability,
            "acctalpha",
            {"email": "test", "domain": "example.com", "password": "secret"},
        )


def test_account_argument_confusion_is_rejected(db, admin) -> None:
    capability = db.get_capability("whm.suspendacct")
    with pytest.raises(PolicyError) as error:
        PolicyEngine().authorize(admin, capability, "acctalpha", {"user": "acctbeta"})
    assert error.value.code == "ACCOUNT_ARGUMENT_MISMATCH"


def test_scoped_reader_cannot_escape_account(db, viewer) -> None:
    capability = db.get_capability("whm.accountsummary")
    with pytest.raises(PolicyError) as error:
        PolicyEngine().authorize(viewer, capability, None, {"user": "acctbeta"})
    assert error.value.code == "ACCOUNT_OUT_OF_SCOPE"


def test_sensitive_file_targets_are_blocked_by_default(db, admin) -> None:
    capability = db.get_capability("uapi.Fileman.get_file_content")
    with pytest.raises(PolicyError) as error:
        PolicyEngine().authorize(
            admin,
            capability,
            "acctalpha",
            {"dir": "public_html", "file": ".env"},
        )
    assert error.value.code == "SENSITIVE_TARGET_BLOCKED"


def test_untyped_advanced_capabilities_are_blocked_by_default(tmp_path, admin) -> None:
    path = tmp_path / "catalog.json"
    path.write_text('{"whm": ["custom_read"], "uapi": []}')
    from reseller_mcp.catalog import Catalog

    capability = next(item for item in Catalog(path).load() if item.id == "whm.custom_read")
    with pytest.raises(PolicyError) as error:
        PolicyEngine().authorize(admin, capability, None, {})
    assert error.value.code == "UNTYPED_CAPABILITY_BLOCKED"


def test_database_writes_require_confirmation(db) -> None:
    policy = PolicyEngine()
    transaction_capability = db.get_capability("database.transaction_execute")
    assert policy.requires_confirmation(transaction_capability) is True
    migration_capability = db.get_capability("workflow.database_migration_apply")
    assert policy.requires_confirmation(migration_capability) is True


def _listfiles(engine_module):
    from reseller_mcp.catalog import curated_capabilities

    return next(item for item in curated_capabilities() if item.id == "api2.Fileman.listfiles")


@pytest.mark.parametrize("directory", ["public_html", "public_html/app", ".", "a/b/c"])
def test_api2_listfiles_accepts_paths_inside_the_home(directory: str) -> None:
    principal = Principal(
        user_id="u", username="u", role=Role.ADMIN, client_id="c", account_scopes=frozenset({"*"})
    )
    PolicyEngine().authorize(principal, _listfiles(None), "acct", {"dir": directory})


@pytest.mark.parametrize(
    "directory",
    ["../etc", "/etc", "/home/other", "public_html/../.ssh", ".ssh", "mail/x", "ssl/keys", "a\\b"],
)
def test_api2_listfiles_rejects_traversal_absolute_and_protected_paths(directory: str) -> None:
    principal = Principal(
        user_id="u", username="u", role=Role.ADMIN, client_id="c", account_scopes=frozenset({"*"})
    )
    with pytest.raises(PolicyError) as error:
        PolicyEngine().authorize(principal, _listfiles(None), "acct", {"dir": directory})
    assert error.value.code == "PATH_OUTSIDE_ALLOWED_ROOT"


def test_api2_capabilities_require_an_account() -> None:
    principal = Principal(
        user_id="u", username="u", role=Role.ADMIN, client_id="c", account_scopes=frozenset({"*"})
    )
    with pytest.raises(PolicyError) as error:
        PolicyEngine().authorize(principal, _listfiles(None), None, {"dir": "public_html"})
    assert error.value.code == "ACCOUNT_REQUIRED"
