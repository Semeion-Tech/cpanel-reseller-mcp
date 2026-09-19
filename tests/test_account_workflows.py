from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_resolve_account_accepts_uid_domain_and_username(harness, viewer) -> None:
    by_uid = await harness.accounts.resolve(viewer, "1001")
    by_domain = await harness.accounts.resolve(viewer, "alpha.example")
    by_username = await harness.accounts.resolve(viewer, "acctalpha")

    assert by_uid["canonical_username"] == "acctalpha"
    assert by_uid["matched_by"] == "uid"
    assert by_domain["canonical_username"] == "acctalpha"
    assert by_username["canonical_username"] == "acctalpha"


@pytest.mark.asyncio
async def test_showbw_explicit_target_is_filtered_even_for_global_admin(harness, admin) -> None:
    result = await harness.query_execute(admin, "whm.showbw", None, {"search": "acctalpha"})
    assert [item["user"] for item in result.data["acct"]] == ["acctalpha"]


@pytest.mark.asyncio
async def test_dossier_is_correlated_normalized_and_health_checked(harness, viewer) -> None:
    dossier = await harness.accounts.dossier(viewer, "1001")

    assert dossier["resolved"]["canonical_username"] == "acctalpha"
    assert dossier["correlation_id"]
    assert dossier["read_only"] is True
    codes = {item["code"] for item in dossier["health"]["findings"]}
    assert {"SPF_INVALID", "DKIM_INVALID", "NO_RESTORABLE_BACKUP"} <= codes
    audit = harness.audit_search(viewer, correlation_id=dossier["correlation_id"])
    assert len(audit) > 5
    assert all(item["correlation_id"] == dossier["correlation_id"] for item in audit)


@pytest.mark.asyncio
async def test_capability_check_reports_account_features(harness, viewer) -> None:
    calls_before = len(harness.cpanel.calls)
    check = await harness.accounts.capability_check(viewer, "uapi.SSL.list_ssl_items", "acctalpha")
    if check["server_available"]:
        assert check["features"]["sslmanager"] is True
    else:
        assert check["features"]["sslmanager"] is None
        feature_calls = [
            call
            for call in harness.cpanel.calls[calls_before:]
            if call[0] == "whm.verify_user_has_feature"
        ]
        assert feature_calls == []


class DeniedFeatureCPanel:
    """cPanel double whose feature lookup is refused, like the reseller token on the server."""

    def __init__(self, inner, mode: str) -> None:
        self.inner = inner
        self.mode = mode

    async def call(self, capability, account, arguments, *, retry_safe=False):
        if capability.function == "verify_user_has_feature":
            if self.mode == "denied":
                from reseller_mcp.cpanel import CPanelError

                raise CPanelError(
                    "Permission denied: You do not have the required privileges",
                    code="UPSTREAM_OPERATION_FAILED",
                )
            return {"has_feature": 0}
        return await self.inner.call(capability, account, arguments, retry_safe=retry_safe)


@pytest.mark.asyncio
async def test_a_feature_lookup_the_token_cannot_make_is_unknown_not_missing(
    harness, viewer
) -> None:
    harness.cpanel = DeniedFeatureCPanel(harness.cpanel, "denied")

    check = await harness.accounts.capability_check(viewer, "uapi.SSL.list_ssl_items", "acctalpha")

    assert check["features"] == {"sslmanager": None}
    assert check["executable"] is True
    assert "could not be verified" in check["reason"]
    assert "sslmanager" in check["feature_errors"]


@pytest.mark.asyncio
async def test_a_confirmed_missing_feature_still_blocks_execution(harness, viewer) -> None:
    harness.cpanel = DeniedFeatureCPanel(harness.cpanel, "missing")

    check = await harness.accounts.capability_check(viewer, "uapi.SSL.list_ssl_items", "acctalpha")

    assert check["features"] == {"sslmanager": False}
    assert check["executable"] is False
    assert check["reason"] == "account does not have every required feature"
