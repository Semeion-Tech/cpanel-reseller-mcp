from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Role(StrEnum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"

    @property
    def rank(self) -> int:
        return {Role.VIEWER: 10, Role.OPERATOR: 20, Role.ADMIN: 30}[self]


class Risk(StrEnum):
    READ = "read"
    SENSITIVE_READ = "sensitive_read"
    EXTERNAL_SIDE_EFFECT = "external_side_effect"
    REVERSIBLE_WRITE = "reversible_write"
    DESTRUCTIVE = "destructive"
    PRIVILEGED = "privileged"


class ApiFamily(StrEnum):
    WHM = "whm"
    UAPI = "uapi"
    WORKFLOW = "workflow"


class Capability(BaseModel):
    id: str
    api: ApiFamily
    module: str | None = None
    function: str
    title: str
    description: str
    risk: Risk
    required_role: Role
    upstream_profile: str
    input_schema: dict[str, Any] = Field(default_factory=dict)
    examples: list[dict[str, Any]] = Field(default_factory=list)
    available: bool = True
    availability_reason: str | None = None
    required_features: list[str] = Field(default_factory=list)
    sensitive_output: bool = False
    documentation_url: str | None = None
    schema_source: str = "catalog"
    curated: bool = False


class Principal(BaseModel):
    user_id: str
    username: str
    role: Role
    client_id: str
    account_scopes: frozenset[str]

    def can_access_account(self, account: str | None) -> bool:
        return account is None or "*" in self.account_scopes or account in self.account_scopes


class PreparationState(StrEnum):
    PREPARED = "prepared"
    CONFIRMED = "confirmed"
    EXECUTING = "executing"
    VERIFIED = "verified"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class Preparation(BaseModel):
    id: str
    principal_user_id: str
    client_id: str
    capability_id: str
    account: str | None
    arguments: dict[str, Any]
    state: PreparationState
    risk: Risk
    idempotency_key: str
    confirmation_phrase: str | None = None
    created_at: datetime
    expires_at: datetime
    before_state: dict[str, Any] | None = None

    @property
    def expired(self) -> bool:
        return datetime.now(UTC) >= self.expires_at


class OperationResult(BaseModel):
    ok: bool
    capability_id: str
    account: str | None = None
    data: Any = None
    normalized_data: Any = None
    correlation_id: str | None = None
    before_state: Any = None
    after_state: Any = None
    verified: bool | None = None
    warnings: list[str] = Field(default_factory=list)
    error: dict[str, Any] | None = None
    audit_id: str | None = None
