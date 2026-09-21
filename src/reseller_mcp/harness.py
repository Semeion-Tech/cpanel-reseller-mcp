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
from .audit import AuditLog, scrub_urls
from .catalog import ALIASES
from .config import Settings
from .cpanel import CPanelClient, CPanelError
from .database_workflows import DatabaseWorkflows
from .db import Database
from .dns_workflows import DNSWorkflows
from .git_workflows import GitWorkflows
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
from .mysql_client import MySQLProvisionError
from .normalizer import normalize_result
from .observability import OperationMetrics
from .policy import PolicyEngine, PolicyError
from .redirect_workflows import RedirectWorkflows
from .subdomain_workflows import SubdomainWorkflows


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
        self.database = DatabaseWorkflows(self)
        self.dns = DNSWorkflows(self)
        self.redirects = RedirectWorkflows(self)
        self.subdomains = SubdomainWorkflows(self)
        self.git = GitWorkflows(self)
        self._workflow_query_hooks["database.query_readonly"] = self.database.query_readonly
        self._workflow_prepare_hooks["database.transaction_execute"] = (
            self.database.prepare_transaction
        )
        self._workflow_execute_hooks["database.transaction_execute"] = (
            self.database.execute_transaction
        )
        self._workflow_prepare_hooks["workflow.database_migration_apply"] = (
            self.database.prepare_migration
        )
        self._workflow_execute_hooks["workflow.database_migration_apply"] = (
            self.database.execute_migration
        )
        self._workflow_prepare_hooks["workflow.dns_cname_ensure"] = self.dns.prepare_cname
        self._workflow_execute_hooks["workflow.dns_cname_ensure"] = self.dns.execute_cname
        self._workflow_prepare_hooks["workflow.dns_txt_ensure"] = self.dns.prepare_txt
        self._workflow_execute_hooks["workflow.dns_txt_ensure"] = self.dns.execute_txt
        self._workflow_prepare_hooks["workflow.dns_record_remove"] = self.dns.prepare_remove
        self._workflow_execute_hooks["workflow.dns_record_remove"] = self.dns.execute_remove
        self._workflow_prepare_hooks["workflow.redirect_ensure"] = self.redirects.prepare_ensure
        self._workflow_execute_hooks["workflow.redirect_ensure"] = self.redirects.execute_ensure
        self._workflow_prepare_hooks["workflow.redirect_remove"] = self.redirects.prepare_remove
        self._workflow_execute_hooks["workflow.redirect_remove"] = self.redirects.execute_remove
        self._workflow_prepare_hooks["workflow.subdomain_remove"] = self.subdomains.prepare_remove
        self._workflow_execute_hooks["workflow.subdomain_remove"] = self.subdomains.execute_remove
        self._workflow_prepare_hooks["workflow.git_clone"] = self.git.prepare_clone
        self._workflow_execute_hooks["workflow.git_clone"] = self.git.execute_clone
        for record_type in DNSWorkflows.ENSURE_TYPES:
            capability_id = f"workflow.dns_{record_type.lower()}_ensure"
            self._workflow_prepare_hooks[capability_id] = self.dns.prepare_hook(record_type)
            self._workflow_execute_hooks[capability_id] = self.dns.execute_hook(record_type)
        self.metrics = OperationMetrics()
        self._locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._background_tasks: set[asyncio.Task[None]] = set()

    @staticmethod
    def _workflow_error(exc: Exception) -> dict[str, Any]:
        if isinstance(exc, CPanelError):
            return exc.as_dict()
        if isinstance(exc, (HarnessError, MySQLProvisionError)):
            return {"code": exc.code, "message": str(exc)}
        return {
            "code": "WORKFLOW_EXECUTION_FAILED",
            "message": "workflow execution failed",
            "details": {"exception_type": type(exc).__name__},
        }

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
                try:
                    hook = self._workflow_query_hooks.get(capability.id)
                    if hook is None:
                        raise HarnessError(
                            "no workflow handler registered for this capability",
                            "WORKFLOW_HANDLER_MISSING",
                        )
                    data = await hook(account, arguments)
                except Exception as exc:
                    error = self._workflow_error(exc)
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
                    self.metrics.record(
                        capability.id, "failed", (time.perf_counter() - started) * 1000
                    )
                    return OperationResult(
                        ok=False,
                        capability_id=capability.id,
                        account=account,
                        correlation_id=correlation_id,
                        error=error,
                        audit_id=audit_id,
                    )
            else:
                data = await self.cpanel.call(capability, account, arguments, retry_safe=True)
            data = self._filter_scoped_result(
                principal, capability, data, account=account, arguments=arguments
            )
            # A remote URL can carry a user or token; the model and the audit never see it.
            data = scrub_urls(data)
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
        if self.policy.requires_confirmation(capability, arguments):
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
                    try:
                        hook = self._workflow_execute_hooks.get(capability.id)
                        if hook is None:
                            raise HarnessError(
                                "no workflow handler registered for this capability",
                                "WORKFLOW_HANDLER_MISSING",
                            )
                        data = await hook(preparation)
                    except Exception as exc:
                        error = self._workflow_error(exc)
                        self.db.set_preparation_state(
                            preparation.id, PreparationState.FAILED, error=error
                        )
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
                    after_state = data.get("after_state")
                    verified = data.get("verified")
                    warnings = list(data.get("warnings") or [])
                else:
                    data = await self.cpanel.call(
                        capability,
                        preparation.account,
                        self._call_arguments(capability, preparation),
                        retry_safe=False,
                    )
                    after_state, verified, warnings = await self._verify(
                        capability,
                        preparation.account,
                        preparation.arguments,
                        data,
                        preparation.before_state,
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
        if capability.id == "api2.Fileman.fileop" and arguments.get("op") != "trash":
            return await self._fileop_before_state(account, arguments)
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
        if capability.id == "uapi.Email.change_mx":
            listing = self._get_capability("uapi.Email.list_mxs")
            return listing, None, {"domain": arguments.get("domain")}
        if capability.function in {"suspendacct", "unsuspendacct", "removeacct"}:
            summary = self._get_capability("whm.accountsummary")
            return summary, None, {"user": arguments.get("user")}
        if capability.api == ApiFamily.UAPI and capability.module == "Email":
            listing = self._get_capability("uapi.Email.list_pops")
            return listing, None, {"domain": arguments.get("domain")}
        if capability.id == "uapi.SubDomain.addsubdomain":
            listing = self._get_capability("uapi.DomainInfo.domains_data")
            return listing, None, {"format": "hash"}
        if capability.id == "api2.Fileman.mkdir":
            listing = self._get_capability("api2.Fileman.listfiles")
            return listing, None, {"dir": str(arguments["path"]).strip().strip("/")}
        if capability.id == "api2.Fileman.fileop":
            parent, _, _ = str(arguments["sourcefiles"]).strip().strip("/").rpartition("/")
            listing = self._get_capability("api2.Fileman.listfiles")
            return listing, None, {"dir": parent}
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
        before_state: dict[str, Any] | None = None,
    ) -> tuple[Any, bool | None, list[str]]:
        if capability.id == "api2.Fileman.fileop" and arguments.get("op") != "trash":
            return await self._verify_fileop(account, arguments, before_state or {})
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
    def _call_arguments(capability: Capability, preparation: Preparation) -> dict[str, Any]:
        """Arguments as cPanel needs them.

        cPanel reads a relative destfiles from public_html rather than from the home (a copy to
        "public_html/x" landed in "public_html/public_html/x"), so copy and move send both
        paths absolute, built from the account home read at preparation.
        """
        arguments = dict(preparation.arguments)
        home = (preparation.before_state or {}).get("home")
        if capability.id == "api2.Fileman.fileop" and arguments.get("op") != "trash" and home:
            for field in ("sourcefiles", "destfiles"):
                arguments[field] = f"{home}/{str(arguments[field]).strip().strip('/')}"
        return arguments

    async def _list_names(self, account: str | None, directory: str) -> list[dict[str, Any]] | None:
        listing = self._get_capability("api2.Fileman.listfiles")
        try:
            result = await self.cpanel.call(
                listing, account, {"dir": directory or "."}, retry_safe=True
            )
        except CPanelError:
            return None
        return [
            item for item in (result if isinstance(result, list) else []) if isinstance(item, dict)
        ]

    @staticmethod
    def _split(path: str) -> tuple[str, str]:
        parent, _, name = path.strip().strip("/").rpartition("/")
        return parent, name

    async def _fileop_before_state(
        self, account: str | None, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """State a copy or move starts from; refuses anything that would overwrite."""
        source_parent, source_name = self._split(str(arguments["sourcefiles"]))
        destination = str(arguments["destfiles"]).strip().strip("/")
        destination_parent, destination_name = self._split(destination)
        source_entries = await self._list_names(account, source_parent)
        destination_parent_entries = await self._list_names(account, destination_parent)
        destination_entries = await self._list_names(account, destination)
        if source_entries is None or source_name not in {e.get("file") for e in source_entries}:
            raise HarnessError(
                f"the source {arguments['sourcefiles']} does not exist", "SOURCE_NOT_FOUND"
            )
        if destination_parent_entries is None:
            raise HarnessError(
                "the destination's parent directory does not exist", "DESTINATION_PARENT_MISSING"
            )
        existing = next(
            (e for e in destination_parent_entries if e.get("file") == destination_name), None
        )
        if existing is not None and existing.get("type") != "dir":
            raise HarnessError(
                f"{destination} is an existing file and would be overwritten", "DESTINATION_EXISTS"
            )
        if existing is not None and source_name in {
            e.get("file") for e in destination_entries or []
        }:
            raise HarnessError(
                f"{destination} already holds an item named {source_name}", "DESTINATION_EXISTS"
            )
        source_relative = str(arguments["sourcefiles"]).strip().strip("/")
        source_entry = next(e for e in source_entries if e.get("file") == source_name)
        full = str(source_entry.get("fullpath") or "")
        home = full[: -len(source_relative)].rstrip("/") if full.endswith(source_relative) else None
        return {
            "home": home,
            "source_parent": [e.get("file") for e in source_entries],
            "destination_parent": [e.get("file") for e in destination_parent_entries],
            "destination": None
            if destination_entries is None
            else [e.get("file") for e in destination_entries],
        }

    async def _verify_fileop(
        self, account: str | None, arguments: dict[str, Any], before: dict[str, Any]
    ) -> tuple[Any, bool | None, list[str]]:
        """Confirm a copy or move by what is new, whichever way cPanel reads the destination.

        The destination is either the final path of the item (a new entry named like it appears
        in its parent) or an existing directory that receives the item (a new entry named like
        the source appears inside it). A move must also have left its source.
        """
        source_parent, source_name = self._split(str(arguments["sourcefiles"]))
        destination = str(arguments["destfiles"]).strip().strip("/")
        destination_parent, destination_name = self._split(destination)
        parent_after = await self._list_names(account, destination_parent)
        inside_after = await self._list_names(account, destination)
        names_parent = {e.get("file") for e in parent_after or []}
        names_inside = {e.get("file") for e in inside_after or []}
        as_final_path = destination_name in names_parent and destination_name not in (
            before.get("destination_parent") or []
        )
        as_directory = source_name in names_inside and source_name not in (
            before.get("destination") or []
        )
        placed = as_final_path or as_directory
        warnings: list[str] = []
        if arguments["op"] == "move":
            remaining = await self._list_names(account, source_parent)
            gone = remaining is not None and source_name not in {e.get("file") for e in remaining}
            if not gone:
                warnings.append("the source is still present after the move")
            placed = placed and gone
        if not placed:
            warnings.append("the destination does not hold the new item after the operation")
        after = {
            "placed_as": "final_path"
            if as_final_path
            else "inside_directory"
            if as_directory
            else None,
            "destination_entries": sorted(str(n) for n in names_inside),
            "destination_parent_entries": sorted(str(n) for n in names_parent),
        }
        return after, placed, warnings

    @staticmethod
    def _evaluate_postcondition(
        capability: Capability, arguments: dict[str, Any], after: Any
    ) -> bool:
        serialized = json.dumps(after, ensure_ascii=False).lower()
        if capability.id == "uapi.Email.change_mx":
            records = Harness._find_mx_records(after)
            target = str(arguments.get("exchanger", "")).rstrip(".").casefold()
            expected_priority = int(arguments["priority"])
            return any(
                str(item.get("exchanger", item.get("exchange", ""))).rstrip(".").casefold()
                == target
                and Harness._coerce_int(item.get("priority")) == expected_priority
                for item in records
            )
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
        if capability.id == "api2.Fileman.mkdir":
            return any(
                isinstance(item, dict)
                and item.get("file") == arguments["name"]
                and item.get("type") == "dir"
                for item in (after if isinstance(after, list) else [])
            )
        if capability.id == "api2.Fileman.fileop":
            base = str(arguments["sourcefiles"]).strip().strip("/").rsplit("/", 1)[-1]
            return not any(
                isinstance(item, dict) and item.get("file") == base
                for item in (after if isinstance(after, list) else [])
            )
        if capability.id == "uapi.SubDomain.addsubdomain":
            full_name = f"{arguments.get('domain', '')}.{arguments.get('rootdomain', '')}"
            return full_name.lower() in serialized
        if capability.id == "uapi.Fileman.save_file_content":
            actual = Harness._find_content(after)
            if actual is None:
                return False
            return Harness._normalize_text(actual) == Harness._normalize_text(
                str(arguments.get("content", ""))
            )
        return True

    @staticmethod
    def _normalize_text(value: str) -> str:
        return value.replace("\r\n", "\n").rstrip("\n")

    @staticmethod
    def _find_content(value: Any) -> str | None:
        """The file content wherever get_file_content nests it."""
        if isinstance(value, dict):
            content = value.get("content")
            if isinstance(content, str):
                return content
            for item in value.values():
                found = Harness._find_content(item)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for item in value:
                found = Harness._find_content(item)
                if found is not None:
                    return found
        return None

    @staticmethod
    def _coerce_int(value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _find_mx_records(value: Any) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        if isinstance(value, dict):
            keys = {str(key).casefold() for key in value}
            if ("exchanger" in keys or "exchange" in keys) and "priority" in keys:
                records.append(value)
            for item in value.values():
                records.extend(Harness._find_mx_records(item))
        elif isinstance(value, list):
            for item in value:
                records.extend(Harness._find_mx_records(item))
        return records
