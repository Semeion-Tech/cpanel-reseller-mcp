from __future__ import annotations

import pytest

from reseller_mcp.auth import AuthenticationError, TokenService
from reseller_mcp.models import Role


def test_tokens_are_per_client_and_revocable(db, settings) -> None:
    db.create_user("ana", Role.OPERATOR, ["acctalpha"])
    service = TokenService(db, settings.token_pepper.get_secret_value())
    token = service.issue("ana", "claude", expires_days=30)

    principal = service.authenticate(token)
    assert principal.username == "ana"
    assert principal.client_id == "claude"
    assert principal.account_scopes == frozenset({"acctalpha"})

    key_id = token.split("_", 2)[1]
    assert db.revoke_token(key_id)
    with pytest.raises(AuthenticationError):
        service.authenticate(token)
