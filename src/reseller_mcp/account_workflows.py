from __future__ import annotations

import asyncio
import uuid
from collections import defaultdict
from typing import TYPE_CHECKING, Any

from .models import Capability, Principal

if TYPE_CHECKING:
    from .harness import Harness


DOSSIER_SECTIONS = frozenset(
    {
        "account",
        "domains",
        "databases",
        "email",
        "ftp",
        "backups",
        "bandwidth",
        "php",
        "ssl",
        "files",
    }
)


class AccountWorkflows:
    def __init__(self, harness: Harness):
        self.harness = harness

    async def resolve(
        self, principal: Principal, identifier: str, *, correlation_id: str | None = None
    ) -> dict[str, Any]:
        identifier = identifier.strip()
        if not identifier:
            raise self._error("account identifier cannot be empty", "INVALID_IDENTIFIER")
        result = await self.harness.query_execute(
            principal,
            "whm.listaccts",
            None,
            {"search": self.harness.settings.cpanel_reseller, "searchtype": "owner"},
            correlation_id=correlation_id,
        )
        if not result.ok:
            raise self._error("could not load account inventory", "ACCOUNT_INVENTORY_FAILED")
        accounts = result.normalized_data if isinstance(result.normalized_data, list) else []
        needle = identifier.casefold()
        matches: list[tuple[str, dict[str, Any]]] = []
        for account in accounts:
            candidates = {
                "username": account.get("username"),
                "uid": account.get("uid"),
                "domain": account.get("domain"),
                "contact_email": account.get("contact_email"),
                "ip": account.get("ip"),
            }
            for kind, value in candidates.items():
                if value is not None and str(value).casefold() == needle:
                    matches.append((kind, account))
                    break
        if not matches:
            raise self._error("account identifier was not found in scope", "ACCOUNT_NOT_FOUND")
        unique = {str(item[1].get("username")): item for item in matches}
        if len(unique) != 1:
            raise self._error(
                "account identifier is ambiguous",
                "ACCOUNT_IDENTIFIER_AMBIGUOUS",
                {"matches": sorted(unique)},
            )
        match_type, account = next(iter(unique.values()))
        return {
            "identifier": identifier,
            "matched_by": match_type,
            "account": account,
            "canonical_username": account.get("username"),
            "correlation_id": correlation_id,
        }

    async def capability_check(
        self,
        principal: Principal,
        capability_id: str,
        identifier: str | None = None,
        *,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        capability = self.harness._get_capability(capability_id)
        username = None
        if identifier:
            resolved = await self.resolve(principal, identifier, correlation_id=correlation_id)
            username = str(resolved["canonical_username"])
        return await self._check_capability(
            principal, capability, username, correlation_id=correlation_id
        )

    async def dossier(
        self,
        principal: Principal,
        identifier: str,
        sections: list[str] | None = None,
    ) -> dict[str, Any]:
        correlation_id = str(uuid.uuid4())
        selected = set(sections or DOSSIER_SECTIONS)
        unknown = selected - DOSSIER_SECTIONS
        if unknown:
            raise self._error(
                "unknown dossier sections",
                "INVALID_SECTIONS",
                {"unknown": sorted(unknown), "allowed": sorted(DOSSIER_SECTIONS)},
            )
        resolved = await self.resolve(principal, identifier, correlation_id=correlation_id)
        username = str(resolved["canonical_username"])
        account = resolved["account"]
        domain = str(account.get("domain") or "")

        operations: list[tuple[str, str, dict[str, Any]]] = [
            ("account", "whm.accountsummary", {"user": username}),
            ("domains", "uapi.DomainInfo.list_domains", {}),
            ("databases", "uapi.Mysql.list_databases", {}),
            ("email", "uapi.Email.list_pops", {"domain": domain}),
            ("email", "uapi.Email.list_mxs", {}),
            ("email", "uapi.Email.list_forwarders", {"domain": domain}),
            ("email", "uapi.Email.list_auto_responders", {"domain": domain}),
            ("email", "uapi.EmailAuth.validate_current_spfs", {"domain": domain}),
            ("email", "uapi.EmailAuth.validate_current_dkims", {"domain": domain}),
            ("ftp", "uapi.Ftp.list_ftp_with_disk", {}),
            ("ftp", "uapi.Ftp.allows_anonymous_ftp", {}),
            ("backups", "uapi.Backup.list_backups", {}),
            (
                "bandwidth",
                "uapi.Bandwidth.query",
                {"grouping": "domain|year_month", "domains": domain, "interval": "daily"},
            ),
            ("php", "uapi.LangPHP.php_get_vhost_versions", {"vhost": domain}),
            ("ssl", "uapi.SSL.list_ssl_items", {"domains": domain, "item": "crt"}),
            ("ssl", "uapi.SSL.can_ssl_redirect", {}),
            (
                "files",
                "uapi.Fileman.list_files",
                {"dir": "public_html", "show_hidden": 0, "types": "file|dir"},
            ),
        ]
        selected_operations = [item for item in operations if item[0] in selected]
        results = await asyncio.gather(
            *(
                self._run_operation(
                    principal,
                    section,
                    capability_id,
                    username,
                    arguments,
                    correlation_id,
                )
                for section, capability_id, arguments in selected_operations
            )
        )

        grouped: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for result in results:
            grouped[str(result["section"])].append(result)
        dossier_sections = {
            section: self._combine_section(items) for section, items in sorted(grouped.items())
        }
        findings = self._health_findings(account, dossier_sections)
        summary = self._health_summary(findings)
        limitations = [
            {
                "section": section,
                "capability_id": item.get("capability_id"),
                "error": item.get("error"),
            }
            for section, value in dossier_sections.items()
            for item in value.get("operations", [])
            if item.get("status") != "ok"
        ]
        self.harness.audit.append(
            principal=principal,
            capability_id="workflow.account_dossier",
            account=username,
            correlation_id=correlation_id,
            phase="workflow",
            outcome="completed",
            parameters={"identifier": identifier, "sections": sorted(selected)},
            details={"health": summary, "limitations": limitations},
        )
        return {
            "correlation_id": correlation_id,
            "resolved": resolved,
            "sections": dossier_sections,
            "health": {"summary": summary, "findings": findings},
            "limitations": limitations,
            "read_only": True,
        }

    async def healthcheck(self, principal: Principal, identifier: str) -> dict[str, Any]:
        dossier = await self.dossier(principal, identifier)
        return {
            "correlation_id": dossier["correlation_id"],
            "account": dossier["resolved"]["account"],
            **dossier["health"],
            "limitations": dossier["limitations"],
            "read_only": True,
        }

    async def _run_operation(
        self,
        principal: Principal,
        section: str,
        capability_id: str,
        username: str,
        arguments: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, Any]:
        try:
            capability = self.harness._get_capability(capability_id)
            availability = await self._check_capability(
                principal, capability, username, correlation_id=correlation_id
            )
            if not availability["executable"]:
                return {
                    "section": section,
                    "capability_id": capability_id,
                    "status": "unavailable",
                    "error": availability,
                }
            result = await self.harness.query_execute(
                principal,
                capability_id,
                username,
                arguments,
                correlation_id=correlation_id,
            )
            return {
                "section": section,
                "capability_id": capability_id,
                "status": "ok" if result.ok else "failed",
                "data": result.normalized_data,
                "error": result.error,
                "audit_id": result.audit_id,
            }
        except Exception as exc:
            return {
                "section": section,
                "capability_id": capability_id,
                "status": "failed",
                "error": self._failure_error(exc),
            }

    async def _check_capability(
        self,
        principal: Principal,
        capability: Capability,
        username: str | None,
        *,
        correlation_id: str | None,
    ) -> dict[str, Any]:
        checks: dict[str, Any] = {
            "server_available": capability.available,
            "role_authorized": principal.role.rank >= capability.required_role.rank,
            "schema_validated": capability.curated
            or capability.schema_source != "live_discovery_untyped",
            "account": username,
            "required_features": capability.required_features,
            "features": {},
        }
        if capability.api.value == "uapi" and not username:
            checks["account_required"] = True
        base_ready = bool(
            checks["server_available"]
            and checks["role_authorized"]
            and checks["schema_validated"]
            and not checks.get("account_required")
        )
        if base_ready:
            for feature in capability.required_features:
                try:
                    result = await self.harness.query_execute(
                        principal,
                        "whm.verify_user_has_feature",
                        username,
                        {"user": username, "feature": feature},
                        correlation_id=correlation_id,
                    )
                    checks["features"][feature] = result.ok and self._feature_enabled(result.data)
                except Exception as exc:
                    checks["features"][feature] = False
                    checks.setdefault("feature_errors", {})[feature] = self._failure_error(exc)
        else:
            checks["features"] = {feature: None for feature in capability.required_features}
        checks["executable"] = bool(
            checks["server_available"]
            and checks["role_authorized"]
            and checks["schema_validated"]
            and not checks.get("account_required")
            and all(checks["features"].values())
        )
        if not checks["server_available"]:
            checks["reason"] = capability.availability_reason
        elif not checks["role_authorized"]:
            checks["reason"] = f"requires role {capability.required_role.value}"
        elif not checks["schema_validated"]:
            checks["reason"] = "capability has no validated schema"
        elif checks.get("account_required"):
            checks["reason"] = "account identifier is required"
        elif checks["features"] and not all(checks["features"].values()):
            checks["reason"] = "account does not have every required feature"
        return checks

    @staticmethod
    def _feature_enabled(value: Any) -> bool:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"has_feature", "hasfeature", "enabled", "result", "value"}:
                    return str(item).lower() in {"1", "true", "yes", "on"}
                if AccountWorkflows._feature_enabled(item):
                    return True
        if isinstance(value, list):
            return any(AccountWorkflows._feature_enabled(item) for item in value)
        return False

    @staticmethod
    def _combine_section(items: list[dict[str, Any]]) -> dict[str, Any]:
        operations = []
        data: dict[str, Any] = {}
        for item in items:
            key = str(item["capability_id"]).rsplit(".", 1)[-1]
            data[key] = item.get("data")
            operations.append({key: value for key, value in item.items() if key != "section"})
        statuses = {item["status"] for item in items}
        status = "ok" if statuses == {"ok"} else "failed" if "ok" not in statuses else "partial"
        return {"status": status, "data": data, "operations": operations}

    def _health_findings(
        self, account: dict[str, Any], sections: dict[str, dict[str, Any]]
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        def add(severity: str, code: str, title: str, evidence: Any, remediation: str) -> None:
            findings.append(
                {
                    "severity": severity,
                    "code": code,
                    "title": title,
                    "evidence": evidence,
                    "remediation": remediation,
                }
            )

        status = account.get("status", {})
        if status.get("suspended") or status.get("locked"):
            add(
                "critical",
                "ACCOUNT_RESTRICTED",
                "Conta suspensa ou bloqueada",
                status,
                "Revisar o motivo antes de reativar a conta.",
            )
        disk = account.get("disk", {})
        disk_percent = disk.get("used_percent")
        if isinstance(disk_percent, (int, float)) and disk_percent >= 80:
            add(
                "critical" if disk_percent >= 95 else "warning",
                "DISK_PRESSURE",
                "Uso de disco elevado",
                disk,
                "Liberar espaço ou ampliar a quota.",
            )

        backup_data = sections.get("backups", {}).get("data", {}).get("list_backups", {})
        if account.get("backup", {}).get("enabled") and backup_data.get("count") == 0:
            add(
                "warning",
                "NO_RESTORABLE_BACKUP",
                "Backup habilitado sem cópia restaurável",
                backup_data,
                "Verificar a política e a retenção de backups no servidor.",
            )

        email = sections.get("email", {}).get("data", {})
        spf = email.get("validate_current_spfs") or {}
        if spf and not spf.get("valid"):
            add(
                "warning",
                "SPF_INVALID",
                "SPF inválido ou incompleto",
                {"states": spf.get("states")},
                "Publicar o SPF esperado após revisão humana da infraestrutura de envio.",
            )
        dkim = email.get("validate_current_dkims") or {}
        if dkim and not dkim.get("valid"):
            add(
                "critical",
                "DKIM_INVALID",
                "DKIM ausente ou divergente",
                {"states": dkim.get("states")},
                "Publicar a chave pública DKIM esperada sem expor a chave privada.",
            )

        ftp = sections.get("ftp", {}).get("data", {}).get("allows_anonymous_ftp", {})
        if ftp.get("enabled"):
            add(
                "critical",
                "ANONYMOUS_FTP_ENABLED",
                "FTP anônimo habilitado",
                ftp,
                "Desabilitar FTP anônimo após aprovação explícita.",
            )

        php_items = (
            sections.get("php", {})
            .get("data", {})
            .get("php_get_vhost_versions", {})
            .get("items", [])
        )
        minimum = tuple(
            int(part) for part in self.harness.settings.health_min_php_version.split(".")
        )
        for item in php_items:
            version = str(item.get("version", "")).removeprefix("ea-php")
            if version.isdigit() and len(version) >= 2:
                parsed = (int(version[0]), int(version[1:]))
                if parsed < minimum:
                    add(
                        "warning",
                        "PHP_BELOW_BASELINE",
                        "PHP abaixo da versão mínima configurada",
                        item,
                        "Planejar atualização com teste de compatibilidade da aplicação.",
                    )

        for section, value in sections.items():
            if value.get("status") != "ok":
                add(
                    "info",
                    "SECTION_INCOMPLETE",
                    f"Seção {section} incompleta",
                    {"status": value.get("status")},
                    "Consultar as limitações do dossiê antes de concluir o diagnóstico.",
                )
        return findings

    @staticmethod
    def _health_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
        counts = {
            severity: sum(item["severity"] == severity for item in findings)
            for severity in ("critical", "warning", "info")
        }
        status = "critical" if counts["critical"] else "warning" if counts["warning"] else "ok"
        return {"status": status, "counts": counts, "healthy": status == "ok"}

    @staticmethod
    def _error(message: str, code: str, details: dict[str, Any] | None = None) -> Exception:
        from .harness import HarnessError

        return HarnessError(message, code, details=details)

    @staticmethod
    def _failure_error(exc: Exception) -> dict[str, Any]:
        from .cpanel import CPanelError
        from .harness import HarnessError

        if isinstance(exc, CPanelError):
            return exc.as_dict()
        if isinstance(exc, HarnessError):
            return {"code": exc.code, "message": str(exc), "details": exc.details}
        return {"code": "WORKFLOW_OPERATION_FAILED", "message": str(exc)}
