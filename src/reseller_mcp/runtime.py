from __future__ import annotations

from dataclasses import dataclass

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken

from .auth import AuthenticationError, TokenService
from .catalog import Catalog
from .config import Settings
from .cpanel import CPanelClient
from .db import Database
from .harness import Harness, HarnessError
from .models import Principal, Role


class ResellerTokenVerifier:
    def __init__(self, tokens: TokenService):
        self.tokens = tokens

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            principal = self.tokens.authenticate(token)
        except AuthenticationError:
            return None
        return AccessToken(
            token=token,
            client_id=principal.client_id,
            subject=principal.user_id,
            scopes=["mcp", f"role:{principal.role.value}"],
            claims={
                "username": principal.username,
                "role": principal.role.value,
                "account_scopes": sorted(principal.account_scopes),
            },
        )


@dataclass
class Runtime:
    settings: Settings
    db: Database
    tokens: TokenService
    cpanel: CPanelClient
    harness: Harness

    @classmethod
    def build(cls, settings: Settings) -> Runtime:
        db = Database(settings.db_path)
        tokens = TokenService(db, settings.token_pepper.get_secret_value())
        cpanel = CPanelClient(settings)
        harness = Harness(settings, db, cpanel)
        harness.sync_catalog(Catalog(settings.catalog_path).load())
        return cls(settings=settings, db=db, tokens=tokens, cpanel=cpanel, harness=harness)


def current_principal() -> Principal:
    access_token = get_access_token()
    if access_token is None or not access_token.subject:
        raise HarnessError("authenticated principal is unavailable", "UNAUTHENTICATED")
    claims = access_token.claims or {}
    return Principal(
        user_id=access_token.subject,
        username=str(claims.get("username", "unknown")),
        role=Role(str(claims.get("role", "viewer"))),
        client_id=access_token.client_id,
        account_scopes=frozenset(str(item) for item in claims.get("account_scopes", [])),
    )
