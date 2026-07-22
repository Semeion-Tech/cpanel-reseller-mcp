from __future__ import annotations

from reseller_mcp.config import Settings


def test_database_settings_have_safe_defaults() -> None:
    settings = Settings(
        token_pepper="p" * 64,
        confirmation_secret="c" * 64,
        cpanel_reader_token="reader",
        cpanel_operator_token="operator",
        cpanel_admin_token="admin",
    )
    assert settings.mysql_egress_ip == ""
    assert settings.database_ephemeral_ttl_seconds == 300
    assert settings.database_connect_timeout_seconds == 10.0
    assert settings.database_query_timeout_seconds == 15.0
    assert settings.database_max_rows == 1000
