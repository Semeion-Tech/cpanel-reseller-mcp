from __future__ import annotations

import json

from reseller_mcp.catalog import Catalog, classify
from reseller_mcp.models import Risk, Role


def test_live_catalog_blocks_sensitive_operations(tmp_path) -> None:
    path = tmp_path / "catalog.json"
    path.write_text(
        json.dumps(
            {
                "whm": ["version", "api_token_create"],
                "uapi": ["Email::list_pops", "Tokens::create_full_access"],
            }
        )
    )
    capabilities = {item.id: item for item in Catalog(path).load()}
    assert capabilities["whm.api_token_create"].available is False
    assert capabilities["uapi.Tokens.create_full_access"].available is False
    assert capabilities["whm.version"].available is True
    assert capabilities["whm.listaccts"].available is False


def test_known_side_effects_and_sensitive_reads_are_not_plain_reads() -> None:
    assert classify("uapi.Backup.fullbackup_to_ftp") == (
        Risk.EXTERNAL_SIDE_EFFECT,
        Role.ADMIN,
        "admin",
    )
    assert classify("uapi.SiteQuality.send_activation_email")[0] == Risk.EXTERNAL_SIDE_EFFECT
    assert classify("uapi.Email.unset_manual_mx_redirects")[0] == Risk.REVERSIBLE_WRITE
    assert classify("uapi.Fileman.get_file_content")[0] == Risk.SENSITIVE_READ
    assert classify("uapi.EmailAuth.fetch_dkim_private_keys")[0] == Risk.PRIVILEGED


def test_curated_email_auth_schema_declares_domain(tmp_path) -> None:
    capabilities = {item.id: item for item in Catalog(tmp_path / "missing.json").load()}
    schema = capabilities["uapi.EmailAuth.validate_current_dkims"].input_schema
    assert schema["required"] == ["domain"]
    assert schema["additionalProperties"] is False
