from __future__ import annotations

import asyncio

import pytest

from reseller_mcp.harness import HarnessError
from reseller_mcp.models import (
    ApiFamily,
    Capability,
    PreparationState,
    Principal,
    Risk,
    Role,
)
from reseller_mcp.mysql_client import MySQLProvisionError


@pytest.mark.asyncio
async def test_list_accounts_is_filtered_to_scope(harness, viewer) -> None:
    result = await harness.query_execute(
        viewer,
        "whm.listaccts",
        None,
        {"search": "demo-reseller", "searchtype": "owner"},
    )
    assert [account["user"] for account in result.data["acct"]] == ["acctalpha"]


@pytest.mark.asyncio
async def test_destructive_action_requires_exact_phrase(harness, admin) -> None:
    prepared = await harness.prepare_action(
        admin,
        "uapi.Email.delete_pop",
        "acctalpha",
        {"email": "old", "domain": "example.com"},
    )
    with pytest.raises(HarnessError) as error:
        await harness.execute_action(admin, prepared["preparation_id"], "wrong")
    assert error.value.code == "CONFIRMATION_REQUIRED"

    result = await harness.execute_action(
        admin, prepared["preparation_id"], prepared["confirmation_phrase"]
    )
    assert result.ok
    assert result.verified is True


@pytest.mark.asyncio
async def test_idempotent_prepare_returns_same_record(harness, admin) -> None:
    first = await harness.prepare_action(
        admin,
        "whm.suspendacct",
        "acctalpha",
        {"user": "acctalpha"},
        "stable-key",
    )
    second = await harness.prepare_action(
        admin,
        "whm.suspendacct",
        "acctalpha",
        {"user": "acctalpha"},
        "stable-key",
    )
    assert second["preparation_id"] == first["preparation_id"]

    with pytest.raises(HarnessError) as error:
        await harness.prepare_action(
            admin,
            "whm.suspendacct",
            "acctbeta",
            {"user": "acctbeta"},
            "stable-key",
        )
    assert error.value.code == "IDEMPOTENCY_CONFLICT"


@pytest.mark.asyncio
async def test_optional_second_admin_approval(harness, settings, db) -> None:
    settings.require_second_approver = True
    author_id = db.create_user("author", Role.ADMIN, ["*"])
    approver_id = db.create_user("approver", Role.ADMIN, ["*"])
    author = Principal(
        user_id=author_id,
        username="author",
        role=Role.ADMIN,
        client_id="test",
        account_scopes=frozenset({"*"}),
    )
    approver = Principal(
        user_id=approver_id,
        username="approver",
        role=Role.ADMIN,
        client_id="review",
        account_scopes=frozenset({"*"}),
    )
    prepared = await harness.prepare_action(
        author,
        "uapi.Email.delete_pop",
        "acctalpha",
        {"email": "old", "domain": "example.com"},
    )
    with pytest.raises(HarnessError) as error:
        await harness.execute_action(
            author, prepared["preparation_id"], prepared["confirmation_phrase"]
        )
    assert error.value.code == "SECOND_APPROVAL_REQUIRED"

    harness.approve_action(approver, prepared["preparation_id"])
    result = await harness.execute_action(
        author, prepared["preparation_id"], prepared["confirmation_phrase"]
    )
    assert result.ok


@pytest.mark.asyncio
async def test_action_can_run_as_persistent_job(harness, admin) -> None:
    prepared = await harness.prepare_action(
        admin, "whm.suspendacct", "acctalpha", {"user": "acctalpha"}
    )
    accepted = harness.start_action_job(admin, prepared["preparation_id"])
    for _ in range(10):
        job = harness.get_job(admin, accepted["job_id"])
        if job["state"] in {"completed", "failed"}:
            break
        await asyncio.sleep(0)
    assert job["state"] == "completed"
    assert job["progress"] == 100


def test_read_intent_search_excludes_destructive_results(harness, admin) -> None:
    results = harness.search_capabilities(admin, "listar bancos mysql", intent="read", limit=20)
    assert results
    assert all(item["risk"] in {"read", "sensitive_read"} for item in results)
    mysql = next(item for item in results if item["id"] == "uapi.Mysql.list_databases")
    assert mysql["input_schema"]["additionalProperties"] is False


@pytest.mark.asyncio
async def test_workflow_query_capability_dispatches_to_registered_hook(harness, admin) -> None:
    workflow_capability = Capability(
        id="workflow.test_echo",
        api=ApiFamily.WORKFLOW,
        function="test_echo",
        title="Test echo",
        description="Test-only workflow capability.",
        risk=Risk.READ,
        required_role=Role.VIEWER,
        upstream_profile="reader",
        input_schema={"type": "object", "additionalProperties": True},
        curated=True,
    )
    harness.db.sync_capabilities([workflow_capability], {})

    async def echo_hook(account, arguments):
        return {"echoed": arguments}

    harness._workflow_query_hooks["workflow.test_echo"] = echo_hook

    result = await harness.query_execute(admin, "workflow.test_echo", "acctalpha", {"x": 1})
    assert result.ok is True
    assert result.data == {"echoed": {"x": 1}}


@pytest.mark.asyncio
async def test_workflow_query_capability_without_registered_hook_fails(harness, admin) -> None:
    workflow_capability = Capability(
        id="workflow.test_missing",
        api=ApiFamily.WORKFLOW,
        function="test_missing",
        title="Test missing",
        description="Test-only workflow capability with no handler.",
        risk=Risk.READ,
        required_role=Role.VIEWER,
        upstream_profile="reader",
        input_schema={"type": "object", "additionalProperties": True},
        curated=True,
    )
    harness.db.sync_capabilities([workflow_capability], {})

    result = await harness.query_execute(admin, "workflow.test_missing", "acctalpha", {})
    assert result.ok is False
    assert result.error["code"] == "WORKFLOW_HANDLER_MISSING"


@pytest.mark.asyncio
async def test_workflow_query_hook_mysql_provision_error_recorded(harness, admin) -> None:
    workflow_capability = Capability(
        id="workflow.test_mysql_error",
        api=ApiFamily.WORKFLOW,
        function="test_mysql_error",
        title="Test MySQL error",
        description="Test-only workflow that raises MySQLProvisionError.",
        risk=Risk.READ,
        required_role=Role.VIEWER,
        upstream_profile="reader",
        input_schema={"type": "object", "additionalProperties": True},
        curated=True,
    )
    harness.db.sync_capabilities([workflow_capability], {})

    async def failing_hook(account, arguments):
        raise MySQLProvisionError("Connection failed", "TEST_CONNECTION_FAILED")

    harness._workflow_query_hooks["workflow.test_mysql_error"] = failing_hook

    result = await harness.query_execute(admin, "workflow.test_mysql_error", "acctalpha", {})
    assert result.ok is False
    assert result.error["code"] == "TEST_CONNECTION_FAILED"
    assert "Connection failed" in result.error["message"]


@pytest.mark.asyncio
async def test_workflow_execute_hook_mysql_provision_error_marks_failed(harness, admin) -> None:
    workflow_capability = Capability(
        id="workflow.test_mysql_execute_error",
        api=ApiFamily.WORKFLOW,
        function="test_mysql_execute_error",
        title="Test MySQL execute error",
        description="Test-only workflow that raises MySQLProvisionError on execute.",
        risk=Risk.DESTRUCTIVE,
        required_role=Role.ADMIN,
        upstream_profile="admin",
        input_schema={"type": "object", "additionalProperties": True},
        curated=True,
    )
    harness.db.sync_capabilities([workflow_capability], {})

    async def failing_execute_hook(preparation):
        raise MySQLProvisionError("Execution failed", "TEST_EXECUTE_FAILED")

    harness._workflow_execute_hooks["workflow.test_mysql_execute_error"] = failing_execute_hook

    prepared = await harness.prepare_action(
        admin, "workflow.test_mysql_execute_error", "acctalpha", {}
    )
    result = await harness.execute_action(
        admin, prepared["preparation_id"], prepared["confirmation_phrase"]
    )
    assert result.ok is False
    assert result.error["code"] == "TEST_EXECUTE_FAILED"

    prep = harness.db.get_preparation(prepared["preparation_id"])
    assert prep.state == PreparationState.FAILED


@pytest.mark.asyncio
async def test_workflow_execute_hook_unexpected_error_marks_failed(harness, admin) -> None:
    workflow_capability = Capability(
        id="workflow.test_unexpected_execute_error",
        api=ApiFamily.WORKFLOW,
        function="test_unexpected_execute_error",
        title="Test unexpected error",
        description="Test-only workflow that raises an unexpected driver error.",
        risk=Risk.DESTRUCTIVE,
        required_role=Role.ADMIN,
        upstream_profile="admin",
        input_schema={"type": "object", "additionalProperties": True},
        curated=True,
    )
    harness.db.sync_capabilities([workflow_capability], {})

    async def failing_execute_hook(preparation):
        raise RuntimeError("driver connection details must not leak")

    harness._workflow_execute_hooks[workflow_capability.id] = failing_execute_hook
    prepared = await harness.prepare_action(admin, workflow_capability.id, "acctalpha", {})

    result = await harness.execute_action(
        admin, prepared["preparation_id"], prepared["confirmation_phrase"]
    )

    assert result.ok is False
    assert result.error == {
        "code": "WORKFLOW_EXECUTION_FAILED",
        "message": "workflow execution failed",
        "details": {"exception_type": "RuntimeError"},
    }
    prep = harness.db.get_preparation(prepared["preparation_id"])
    assert prep.state == PreparationState.FAILED
