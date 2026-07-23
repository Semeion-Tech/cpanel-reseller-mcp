from __future__ import annotations

import re
from typing import Any

from jsonschema import Draft202012Validator

from .models import Capability, Principal, Risk, Role


class PolicyError(PermissionError):
    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


class PolicyEngine:
    def __init__(
        self,
        *,
        allow_untyped_advanced: bool = False,
        allow_sensitive_file_reads: bool = False,
    ) -> None:
        self.allow_untyped_advanced = allow_untyped_advanced
        self.allow_sensitive_file_reads = allow_sensitive_file_reads

    def authorize(
        self,
        principal: Principal,
        capability: Capability,
        account: str | None,
        arguments: dict[str, Any],
    ) -> None:
        if not capability.available:
            raise PolicyError(
                capability.availability_reason or "capability is unavailable",
                "CAPABILITY_UNAVAILABLE",
            )
        if principal.role.rank < capability.required_role.rank:
            raise PolicyError(
                f"{capability.id} requires role {capability.required_role.value}",
                "INSUFFICIENT_ROLE",
            )
        if capability.api.value in {"uapi", "workflow"} and not account:
            raise PolicyError("this capability requires an account", "ACCOUNT_REQUIRED")
        inferred_account = account
        if inferred_account is None and capability.function != "createacct":
            inferred_account = arguments.get("user") or arguments.get("username")
        if not principal.can_access_account(inferred_account):
            raise PolicyError("account is outside the principal scope", "ACCOUNT_OUT_OF_SCOPE")
        argument_account = arguments.get("user") or arguments.get("username")
        if account and argument_account and account != argument_account:
            raise PolicyError(
                "account and operation arguments refer to different cPanel accounts",
                "ACCOUNT_ARGUMENT_MISMATCH",
            )
        if not capability.curated and principal.role != Role.ADMIN:
            raise PolicyError(
                "advanced capabilities are restricted to administrators",
                "ADVANCED_ADMIN_ONLY",
            )
        if (
            not capability.curated
            and capability.schema_source == "live_discovery_untyped"
            and not self.allow_untyped_advanced
        ):
            raise PolicyError(
                "advanced capability has no validated parameter contract",
                "UNTYPED_CAPABILITY_BLOCKED",
            )
        errors = sorted(
            Draft202012Validator(capability.input_schema).iter_errors(arguments),
            key=lambda error: list(error.path),
        )
        if errors:
            summary = "; ".join(error.message for error in errors[:5])
            raise PolicyError(f"invalid arguments: {summary}", "INVALID_ARGUMENTS")

        if capability.id == "uapi.Fileman.get_file_content":
            target = f"{arguments.get('dir', '')}/{arguments.get('file', '')}"
            sensitive = re.search(
                r"(^|/)(\.env|\.my\.cnf|wp-config\.php|configuration\.php|id_rsa|id_ed25519)($|/)"
                r"|secret|token|private.?key",
                target,
                re.IGNORECASE,
            )
            if sensitive and not self.allow_sensitive_file_reads:
                raise PolicyError(
                    "reading known secret-bearing files is disabled by policy",
                    "SENSITIVE_TARGET_BLOCKED",
                )

        # A scoped administrator cannot create a new account outside a global reseller scope.
        if capability.function == "createacct" and "*" not in principal.account_scopes:
            raise PolicyError(
                "creating accounts requires global reseller scope", "GLOBAL_SCOPE_REQUIRED"
            )

    @staticmethod
    def requires_confirmation(capability: Capability) -> bool:
        return capability.risk in {
            Risk.EXTERNAL_SIDE_EFFECT,
            Risk.DESTRUCTIVE,
            Risk.PRIVILEGED,
        }

    @staticmethod
    def assert_read(capability: Capability) -> None:
        if capability.risk not in {Risk.READ, Risk.SENSITIVE_READ}:
            raise PolicyError(
                "query_execute only accepts read-only capabilities; use action_prepare",
                "WRITE_REQUIRES_PREPARATION",
            )
