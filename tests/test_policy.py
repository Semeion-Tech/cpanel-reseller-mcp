from __future__ import annotations

import pytest

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
