from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from .db import Database
from .models import Principal, Role


class AuthenticationError(ValueError):
    pass


class TokenService:
    def __init__(self, db: Database, pepper: str):
        self.db = db
        self.pepper = pepper.encode("utf-8")

    def _digest(self, token: str) -> str:
        return hmac.new(self.pepper, token.encode("utf-8"), hashlib.sha256).hexdigest()

    def issue(self, username: str, client_id: str, expires_days: int = 90) -> str:
        user = self.db.get_user(username)
        if not user:
            raise KeyError(f"unknown active user: {username}")
        key_id = secrets.token_hex(8)
        secret = secrets.token_urlsafe(32)
        token = f"rmcp_{key_id}_{secret}"
        expires_at = datetime.now(UTC) + timedelta(days=expires_days) if expires_days else None
        self.db.insert_token(
            key_id,
            user["id"],
            client_id,
            self._digest(token),
            expires_at,
        )
        return token

    def authenticate(self, token: str) -> Principal:
        parts = token.split("_", 2)
        if len(parts) != 3 or parts[0] != "rmcp":
            raise AuthenticationError("invalid bearer token format")
        key_id = parts[1]
        record = self.db.get_principal_by_key(key_id)
        if not record:
            raise AuthenticationError("unknown, expired, or revoked bearer token")
        row, scopes = record
        if not hmac.compare_digest(row["token_hash"], self._digest(token)):
            raise AuthenticationError("invalid bearer token")
        self.db.touch_token(key_id)
        return Principal(
            user_id=row["user_id"],
            username=row["username"],
            role=Role(row["role"]),
            client_id=row["client_id"],
            account_scopes=scopes,
        )
