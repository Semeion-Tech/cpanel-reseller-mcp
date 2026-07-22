from __future__ import annotations

import asyncio
import hmac
import json
import secrets
import time
import uuid
from collections import defaultdict
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from .account_workflows import AccountWorkflows
from .audit import AuditLog
from .catalog import ALIASES
from .config import Settings
from .cpanel import CPanelClient, CPanelError
from .db import Database
from .models import (
    ApiFamily,
    Capability,
    OperationResult,
    Preparation,
    PreparationState,
    Principal,
    Risk,
    Role,
)
from .normalizer import normalize_result
from .observability import OperationMetrics
from .policy import PolicyEngine, PolicyError


class HarnessError(RuntimeError):
    def __init__(self, message: str, code: str, *, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": str(self), "details": self.details}


class Harness:
    def __init__(
        self,
        settings: Settings,
        db: Database,
        cpanel: CPanelClient,
        policy: PolicyEngine | None = None,
    ):
        self.settings = settings
        self.db = db
        self.cpanel = cpanel
        self.policy = policy or PolicyEngine(
            allow_untyped_advanced=settings.allow_untyped_advanced,
            allow_sensitive_file_reads=settings.allow_sensitive_file_reads,
        )
        self.audit = AuditLog(db)
        self.accounts = AccountWorkflows(self)
        self._workflow_query_hooks: dict[
            str, Callable[[str | None, dict[str, Any]], Awaitable[Any]]
        ] = {}
        self._workflow_prepare_hooks: dict[
            str, Callable[[str | None, dict[str, Any]], Awaitable[dict[str, Any] | None]]
        ] = {}
        self._workflow_execute_hooks: dict[
            str, Callable[[Preparation], Awaitable[dict[str, Any]]]
        ] = {}
        self.metrics = OperationMetrics()
        self._locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._background_tasks: set[asyncio.Task[None]] = set()

    def sync_catalog(self, capabilities: list[Capability]) -> None:
        self.db.sync_capabilities(capabilities, ALIASES)

    def search_capabilities(
        self,
        principal: Principal,
        query: str,
        *,
        limit: int = 10,
        risk: Risk | None = None,
        api: ApiFamily | None = None,
        intent: str | None = None,
    ) -> list[dict[str, Any]]:
        result_limit = min(max(limit, 1), 50)
        results = self.db.search_capabilities(query, 50)
        normalized_query = query.casefold()
        if intent not in {None, "read", "write", "any"}:
            raise HarnessError("intent must be read, write, or any", "INVALID_INTENT")
        if intent is None:
            read_terms = {
                "list",
                "listar",
                "consulta",
                "consultar",
                "buscar",
                "mostrar",
                "inventário",
                "inventario",
                "detalhes",
                "verificar",
                "validar",
            }
            write_terms = {"criar", "adicionar", "alterar", "editar", "excluir", "remover"}
            words = set(normalized_query.replace("-", " ").split())
            if words & write_terms:
                intent = "write"
            elif words & read_terms:
                intent = "read"

        visible = [
            item
            for item in results
            if item.required_role.rank <= principal.role.rank
            and (risk is None or item.risk == risk)
            and (api is None or item.api == api)
            and (
                intent in {None, "any"}
                or (intent == "read" and item.risk in {Risk.READ, Risk.SENSITIVE_READ})
                or (intent == "write" and item.risk not in {Risk.READ, Risk.SENSITIVE_READ})
            )
        ]

        def relevance(item: Capability) -> tuple[int, str]:
            score = 100 if item.curated else 0
            searchable = f"{item.id} {item.title} {item.function}".casefold()
            if normalized_query in searchable:
                score += 100
            score += sum(10 for word in normalized_query.split() if word in searchable)
            if item.available:
                score += 10
            return (-score, item.id)

        visible.sort(key=relevance)
        return [self._capability_summary(item) for item in visible[:result_limit]]

    def describe_capability(self, principal: Principal, capability_id: str) -> dict[str, Any]:
        capability = self._get_capability(capability_id)
        if capability.required_role.rank > principal.role.rank:
            raise HarnessError("capability is not visible for this role", "INSUFFICIENT_ROLE")
        return capability.model_dump(mode="json")

    async def query_execute(
        self,
        principal: Principal,
        capability_id: str,
        account: str | None,
        arguments: dict[str, Any],
        *,
        correlation_id: str | None = None,
    ) -> OperationResult:
        started = time.perf_counter()
        capability = self._get_capability(capability_id)
        try:
            self.policy.authorize(principal, capability, account, arguments)
            self.policy.assert_read(capability)
        except PolicyError as exc:
            self._audit_denied(
                principal, capability_id, account, arguments, exc, correlation_id=correlation_id
            )
            self.metrics.record(capability_id, "denied", (time.perf_counter() - started) * 1000)
            raise HarnessError(str(exc), exc.code) from exc
        try:
            if capability.api == ApiFamily.WORKFLOW:
                hook = self._workflow_query_hooks.get(capability.id)
                if hook is None:
                    raise HarnessError(
                        "no workflow handler registered for this capability",
                        "WORKFLOW_HANDLER_MISSING",
                    )
                data = await hook(account, arguments)
            else:
                data = await self.cpanel.call(capability, account, arguments, retry_safe=True)
            data = self._filter_scoped_result(
                principal, capability, data, account=account, arguments=arguments
            )
            normalized_data = normalize_result(capability.id, data, account)
            audit_id = self.audit.append(
                principal=principal,
                capability_id=capability.id,
                account=account,
                correlation_id=correlation_id,
                phase="query",
                outcome="success",
                parameters=arguments,
                details={"result": data},
            )
            self.metrics.record(capability.id, "success", (time.perf_counter() - started) * 1000)
            return OperationResult(
                ok=True,
                capability_id=capability.id,
                account=account,
                data=data,
                normalized_data=normalized_data,
                correlation_id=correlation_id,
                audit_id=audit_id,
            )
        except CPanelError as exc:
            error = exc.as_dict()
            audit_id = self.audit.append(
                principal=principal,
                capability_id=capability.id,
                account=account,
                correlation_id=correlation_id,
                phase="query",
                outcome="failed",
                parameters=arguments,
                details=error,
            )
            self.metrics.record(capability.id, "failed", (time.perf_counter() - started) * 1000)
            return OperationResult(
                ok=False,
                capability_id=capability.id,
                account=account,
                correlation_id=correlation_id,
                error=error,
                audit_id=audit_id,
            )

    async def prepare_action(
        self,
        principal: Principal,
        capability_id: str,
        account: str | None,
        arguments: dict[str, Any],
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        capability = self._get_capability(capability_id)
        if capability.risk in {Risk.READ, Risk.SENSITIVE_READ}:
            raise HarnessError(
                "read-only capability must use query_execute", "READ_USE_QUERY_EXECUTE"
            )
        try:
            self.policy.authorize(principal, capability, account, arguments)
        except PolicyError as exc:
            self._audit_denied(principal, capability_id, account, arguments, exc)
            raise HarnessError(str(exc), exc.code) from exc

        before_state = await self._snapshot(capability, account, arguments)
        preparation_id = str(uuid.uuid4())
        idempotency_key = idempotency_key or secrets.token_urlsafe(18)
        phrase = None
        if self.policy.requires_confirmation(capability):
            target = account or arguments.get("user") or arguments.get("domain") or "reseller"
            phrase = f"CONFIRM {capability.function} {target}"
        now = datetime.now(UTC)
        preparation = Preparation(
            id=preparation_id,
            principal_user_id=principal.user_id,
            client_id=principal.client_id,
            capability_id=capability.id,
            account=account,
            arguments=arguments,
            state=PreparationState.PREPARED,
            risk=capability.risk,
            idempotency_key=idempotency_key,
            confirmation_phrase=phrase,
            created_at=now,
            expires_at=now + timedelta(seconds=self.settings.preparation_ttl_seconds),
            before_state=before_state,
        )
        try:
            preparation = self.db.insert_preparation(preparation)
        except ValueError as exc:
            raise HarnessError(str(exc), "IDEMPOTENCY_CONFLICT") from exc
        self.audit.append(
            principal=principal,
            capability_id=capability.id,
            account=account,
            phase="prepare",
            outcome="prepared",
            parameters=arguments,
            details={"preparation_id": preparation.id, "risk": capability.risk.value},
        )
        return {
            "preparation_id": preparation.id,
            "capability_id": capability.id,
            "risk": capability.risk.value,
            "account": account,
            "arguments": arguments,
            "before_state": before_state,
            "requires_confirmation": phrase is not None,
            "confirmation_phrase": phrase,
            "expires_at": preparation.expires_at.isoformat(),
            "next_step": (
                "Ask the human to approve the exact phrase, then call action_execute."
                if phrase
                else "Call action_execute with this preparation_id."
            ),
        }

    async def execute_action(
        self,
        principal: Principal,
        preparation_id: str,
        confirmation_phrase: str | None = None,
    ) -> OperationResult:
        preparation, capability = self._validate_execution(
            principal, preparation_id, confirmation_phrase
        )

        lock_key = preparation.account or str(preparation.arguments.get("user", "reseller"))
        async with self._locks[lock_key]:
            self.db.set_preparation_state(preparation.id, PreparationState.EXECUTING)
            try:
                if capability.api == ApiFamily.WORKFLOW:
                    hook = self._workflow_execute_hooks.get(capability.id)
                    if hook is None:
                        raise HarnessError(
                            "no workflow handler registered for this capability",
                            "WORKFLOW_HANDLER_MISSING",
                        )
                    data = await hook(preparation)
                    after_state = data.get("after_state")
                    verified = data.get("verified")
                    warnings = list(data.get("warnings") or [])
                else:
                    data = await self.cpanel.call(
                        capability, preparation.account, preparation.arguments, retry_safe=False
                    )
                    after_state, verified, warnings = await self._verify(
                        capability, preparation.account, preparation.arguments, data
                    )
                payload = {
                    "data": data,
                    "before_state": preparation.before_state,
                    "after_state": after_state,
                    "verified": verified,
                    "warnings": warnings,
                }
                final_state = (
                    PreparationState.VERIFIED if verified is not False else PreparationState.FAILED
                )
                self.db.set_preparation_state(preparation.id, final_state, result=payload)
                audit_id = self.audit.append(
                    principal=principal,
                    capability_id=capability.id,
                    account=preparation.account,
                    phase="execute",
                    outcome="verified" if verified else "unverified",
                    parameters=preparation.arguments,
                    details=payload,
                )
                return OperationResult(
                    ok=verified is not False,
                    capability_id=capability.id,
                    account=preparation.account,
                    data=data,
                    before_state=preparation.before_state,
                    after_state=after_state,
                    verified=verified,
                    warnings=warnings,
                    audit_id=audit_id,
                )
            except CPanelError as exc:
                error = {"code": exc.code, "message": str(exc)}
                self.db.set_preparation_state(preparation.id, PreparationState.FAILED, error=error)
                audit_id = self.audit.append(
                    principal=principal,
                    capability_id=capability.id,
                    account=preparation.account,
                    phase="execute",
                    outcome="failed",
                    parameters=preparation.arguments,
                    details=error,
                )
                return OperationResult(
                    ok=False,
                    capability_id=capability.id,
                    account=preparation.account,
                    error=error,
                    audit_id=audit_id,
                )

    def start_action_job(
        self,
        principal: Principal,
        preparation_id: str,
        confirmation_phrase: str | None = None,
    ) -> dict[str, Any]:
        # Validate ownership and approval synchronously before accepting the job. The worker calls
        # execute_action again so expiry and state are checked immediately before the write.
        self._validate_execution(principal, preparation_id, confirmation_phrase)
        job_id = self.db.create_job(preparation_id)

        async def run() -> None:
            self.db.update_job(job_id, "running", 10)
            try:
                result = await self.execute_action(principal, preparation_id, confirmation_phrase)
                payload = result.model_dump(mode="json")
                if result.ok:
                    self.db.update_job(job_id, "completed", 100, result=payload)
                else:
                    self.db.update_job(
                        job_id,
                        "failed",
                        100,
                        result=payload,
                        error=result.error or {"code": "ACTION_FAILED"},
                    )
            except Exception as exc:
                error = {
                    "code": getattr(exc, "code", "INTERNAL_ERROR"),
                    "message": str(exc),
                }
                self.db.update_job(job_id, "failed", 100, error=error)

        task = asyncio.create_task(run(), name=f"reseller-job-{job_id}")
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        return {"job_id": job_id, "state": "queued", "preparation_id": preparation_id}

    def get_job(self, principal: Principal, job_id: str) -> dict[str, Any]:
        job = self.db.get_job(job_id)
        if not job:
            raise HarnessError("job does not exist", "JOB_NOT_FOUND")
        if principal.role != Role.ADMIN and job["principal_user_id"] != principal.user_id:
            raise HarnessError("job belongs to another user", "OWNER_MISMATCH")
        job.pop("principal_user_id", None)
        return job

    def _validate_execution(
        self,
        principal: Principal,
        preparation_id: str,
        confirmation_phrase: str | None,
    ) -> tuple[Preparation, Capability]:
        try:
            preparation = self.db.get_preparation(preparation_id)
        except KeyError as exc:
            raise HarnessError("preparation not found", "PREPARATION_NOT_FOUND") from exc
        capability = self._get_capability(preparation.capability_id)
        if (
            preparation.principal_user_id != principal.user_id
            or preparation.client_id != principal.client_id
        ):
            raise HarnessError(
                "preparation belongs to a different principal or client", "OWNER_MISMATCH"
            )
        if preparation.state == PreparationState.VERIFIED:
            raise HarnessError("preparation has already been executed", "ALREADY_EXECUTED")
        if preparation.state != PreparationState.PREPARED:
            raise HarnessError(
                f"preparation cannot execute from state {preparation.state.value}", "INVALID_STATE"
            )
        if preparation.expired:
            self.db.set_preparation_state(preparation.id, PreparationState.EXPIRED)
            raise HarnessError("preparation expired", "PREPARATION_EXPIRED")
        if preparation.confirmation_phrase and not hmac.compare_digest(
            preparation.confirmation_phrase, confirmation_phrase or ""
        ):
            raise HarnessError("exact confirmation phrase is required", "CONFIRMATION_REQUIRED")
        if self.settings.require_second_approver and capability.risk in {
            Risk.DESTRUCTIVE,
            Risk.PRIVILEGED,
        }:
            approvers = self.db.preparation_approvers(preparation.id)
            if not any(user_id != preparation.principal_user_id for user_id in approvers):
                raise HarnessError(
                    "a second administrator must approve this action",
                    "SECOND_APPROVAL_REQUIRED",
                )
        return preparation, capability

    def cancel_action(self, principal: Principal, preparation_id: str) -> dict[str, Any]:
        preparation = self.db.get_preparation(preparation_id)
        if preparation.principal_user_id != principal.user_id:
            raise HarnessError("preparation belongs to another user", "OWNER_MISMATCH")
        if preparation.state != PreparationState.PREPARED:
            raise HarnessError("only prepared actions can be cancelled", "INVALID_STATE")
        self.db.set_preparation_state(preparation.id, PreparationState.CANCELLED)
        self.audit.append(
            principal=principal,
            capability_id=preparation.capability_id,
            account=preparation.account,
            phase="cancel",
            outcome="cancelled",
            parameters={},
            details={"preparation_id": preparation.id},
        )
        return {"preparation_id": preparation.id, "state": "cancelled"}

    def approve_action(self, principal: Principal, preparation_id: str) -> dict[str, Any]:
        if principal.role != Role.ADMIN:
            raise HarnessError("only administrators may approve actions", "INSUFFICIENT_ROLE")
        try:
            preparation = self.db.get_preparation(preparation_id)
        except KeyError as exc:
            raise HarnessError("preparation not found", "PREPARATION_NOT_FOUND") from exc
        if preparation.state != PreparationState.PREPARED or preparation.expired:
            raise HarnessError("only active prepared actions may be approved", "INVALID_STATE")
        if preparation.principal_user_id == principal.user_id:
            raise HarnessError("the action author cannot be the second approver", "SELF_APPROVAL")
        self.db.approve_preparation(preparation.id, principal.user_id)
        self.audit.append(
            principal=principal,
            capability_id=preparation.capability_id,
            account=preparation.account,
            phase="approve",
            outcome="approved",
            parameters={},
            details={"preparation_id": preparation.id},
        )
        return {"preparation_id": preparation.id, "approved": True}

    def audit_search(
        self, principal: Principal, limit: int = 50, correlation_id: str | None = None
    ) -> list[dict[str, Any]]:
        user_id = None if principal.role == Role.ADMIN else principal.user_id
        rows = self.db.audit_rows(user_id, min(max(limit, 1), 200), correlation_id)
        for row in rows:
            row["parameters"] = json.loads(row["parameters"])
            row["details"] = json.loads(row["details"])
        return rows

    def observability_snapshot(self, principal: Principal) -> dict[str, Any]:
        if principal.role != Role.ADMIN:
            raise HarnessError("observability requires administrator role", "INSUFFICIENT_ROLE")
        return self.metrics.snapshot()

    async def reseller_overview(self, principal: Principal) -> dict[str, Any]:
        version = await self.query_execute(principal, "whm.version", None, {})
        privileges = await self.query_execute(principal, "whm.myprivs", None, {})
        accounts = await self.query_execute(
            principal,
            "whm.listaccts",
            None,
            {"search": self.settings.cpanel_reseller, "searchtype": "owner"},
        )
        return {
            "version": version.model_dump(mode="json"),
            "privileges": privileges.model_dump(mode="json"),
            "accounts": accounts.model_dump(mode="json"),
        }

    def _get_capability(self, capability_id: str) -> Capability:
        capability = self.db.get_capability(capability_id)
        if not capability:
            raise HarnessError("unknown capability", "CAPABILITY_NOT_FOUND")
        return capability

    @staticmethod
    def _capability_summary(capability: Capability) -> dict[str, Any]:
        return {
            "id": capability.id,
            "title": capability.title,
            "description": capability.description,
            "risk": capability.risk.value,
            "required_role": capability.required_role.value,
            "available": capability.available,
            "curated": capability.curated,
            "schema_source": capability.schema_source,
            "input_schema": capability.input_schema if capability.curated else None,
            "examples": capability.examples if capability.curated else [],
        }

    def _audit_denied(
        self,
        principal: Principal,
        capability_id: str,
        account: str | None,
        arguments: dict[str, Any],
        error: PolicyError,
        *,
        correlation_id: str | None = None,
    ) -> None:
        self.audit.append(
            principal=principal,
            capability_id=capability_id,
            account=account,
            correlation_id=correlation_id,
            phase="authorize",
            outcome="denied",
            parameters=arguments,
            details={"code": error.code, "message": str(error)},
        )

    @staticmethod
    def _filter_scoped_result(
        principal: Principal,
        capability: Capability,
        data: Any,
        *,
        account: str | None,
        arguments: dict[str, Any],
    ) -> Any:
        if capability.function == "listaccts" and isinstance(data, dict):
            copied = dict(data)
            accounts = data.get("acct", [])
            if "*" not in principal.account_scopes:
                accounts = [
                    item for item in accounts if item.get("user") in principal.account_scopes
                ]
            copied["acct"] = accounts
            return copied
        if capability.function == "showbw" and isinstance(data, dict):
            copied = dict(data)
            requested = account or arguments.get("search")
            for key in ("acct", "accounts", "bandwidth"):
                if isinstance(copied.get(key), list):
                    copied[key] = [
                        item
                        for item in copied[key]
                        if (
                            (
                                "*" in principal.account_scopes
                                or item.get("user") in principal.account_scopes
                            )
                            and (not requested or item.get("user") == requested)
                        )
                    ]
            return copied
        if "*" in principal.account_scopes:
            return data
        return data

    async def _snapshot(
        self, capability: Capability, account: str | None, arguments: dict[str, Any]
    ) -> dict[str, Any] | None:
        if capability.api == ApiFamily.WORKFLOW:
            hook = self._workflow_prepare_hooks.get(capability.id)
            if hook is None:
                return None
            return await hook(account, arguments)
        snapshot = self._snapshot_capability(capability, arguments)
        if not snapshot:
            return None
        snapshot_capability, snapshot_account, snapshot_args = snapshot
        try:
            result = await self.cpanel.call(
                snapshot_capability,
                snapshot_account or account,
                snapshot_args,
                retry_safe=True,
            )
            return result if isinstance(result, dict) else {"data": result}
        except CPanelError:
            return None

    def _snapshot_capability(
        self, capability: Capability, arguments: dict[str, Any]
    ) -> tuple[Capability, str | None, dict[str, Any]] | None:
        if capability.function in {"suspendacct", "unsuspendacct", "removeacct"}:
            summary = self._get_capability("whm.accountsummary")
            return summary, None, {"user": arguments.get("user")}
        if capability.api == ApiFamily.UAPI and capability.module == "Email":
            listing = self._get_capability("uapi.Email.list_pops")
            return listing, None, {"domain": arguments.get("domain")}
        if capability.id == "uapi.Fileman.save_file_content":
            read = self._get_capability("uapi.Fileman.get_file_content")
            return read, None, {"dir": arguments.get("dir"), "file": arguments.get("file")}
        return None

    async def _verify(
        self,
        capability: Capability,
        account: str | None,
        arguments: dict[str, Any],
        data: Any,
    ) -> tuple[Any, bool | None, list[str]]:
        snapshot = self._snapshot_capability(capability, arguments)
        if not snapshot:
            return (
                data,
                None,
                ["No deterministic postcondition verifier is defined for this capability"],
            )
        verify_capability, verify_account, verify_args = snapshot
        try:
            after = await self.cpanel.call(
                verify_capability, verify_account or account, verify_args, retry_safe=True
            )
        except CPanelError as exc:
            return None, False, [f"Postcondition read failed: {exc.code}"]
        verified = self._evaluate_postcondition(capability, arguments, after)
        return after, verified, [] if verified else ["Postcondition did not match requested state"]

    @staticmethod
    def _evaluate_postcondition(
        capability: Capability, arguments: dict[str, Any], after: Any
    ) -> bool:
        serialized = json.dumps(after, ensure_ascii=False).lower()
        if capability.function == "removeacct":
            return not after or arguments.get("user", "").lower() not in serialized
        if capability.function in {"suspendacct", "unsuspendacct"}:
            expected = capability.function == "suspendacct"

            def suspended_values(value: Any) -> list[bool]:
                found: list[bool] = []
                if isinstance(value, dict):
                    for key, item in value.items():
                        if str(key).lower() == "suspended":
                            found.append(str(item).lower() in {"1", "true", "yes"})
                        else:
                            found.extend(suspended_values(item))
                elif isinstance(value, list):
                    for item in value:
                        found.extend(suspended_values(item))
                return found

            return expected in suspended_values(after)
        if capability.module == "Email" and capability.function == "add_pop":
            return str(arguments.get("email", "")).lower() in serialized
        if capability.module == "Email" and capability.function == "delete_pop":
            return str(arguments.get("email", "")).lower() not in serialized
        if capability.id == "uapi.Fileman.save_file_content":
            expected_content = str(arguments.get("content", "")).lower()
            return expected_content in serialized or expected_content == str(after).lower()
        return True
