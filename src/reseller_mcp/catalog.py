from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import ApiFamily, Capability, Risk, Role

BLOCKED_FUNCTIONS = {
    "accesshash",
    "api_token_create",
    "api_token_get_details",
    "api_token_list",
    "api_token_revoke",
    "api_token_update",
    "create_user_session",
    "execute_remote_whmapi1_with_password",
    "cors_proxy_get",
    "batch",
    "cpanel",
    "uapi_cpanel",
    "fetch_dkim_private_keys",
    "list_keys",
}

EXPLICIT_RISKS: dict[str, tuple[Risk, Role, str]] = {
    "uapi.Backup.fullbackup_to_ftp": (Risk.EXTERNAL_SIDE_EFFECT, Role.ADMIN, "admin"),
    "uapi.Backup.fullbackup_to_homedir": (
        Risk.EXTERNAL_SIDE_EFFECT,
        Role.OPERATOR,
        "operator",
    ),
    "uapi.Market.request_ssl_certificates": (
        Risk.EXTERNAL_SIDE_EFFECT,
        Role.OPERATOR,
        "operator",
    ),
    "uapi.SiteQuality.send_activation_email": (
        Risk.EXTERNAL_SIDE_EFFECT,
        Role.OPERATOR,
        "operator",
    ),
    "uapi.Email.unset_manual_mx_redirects": (
        Risk.REVERSIBLE_WRITE,
        Role.OPERATOR,
        "operator",
    ),
    "uapi.ContactInformation.unset_email_addresses": (
        Risk.REVERSIBLE_WRITE,
        Role.OPERATOR,
        "operator",
    ),
    "uapi.Fileman.get_file_content": (Risk.SENSITIVE_READ, Role.ADMIN, "reader"),
}

DESTRUCTIVE = re.compile(
    r"(^|_)(delete|remove|kill|terminate|destroy|drop|erase|unlink|revoke|restore|reset)(_|$)"
    r"|remove_ip|deldb|deluser|delete_zone|killdns|removeacct|terminateacct",
    re.IGNORECASE,
)
WRITE = re.compile(
    r"(^|_)(add|create|set|unset|update|edit|change|enable|disable|ensure|install|upload|save|suspend|unsuspend|start|stop|generate|provision|assign|unassign|hold|release|rebuild|toggle)(_|$)"
    r"|addpop|passwd|mkdir|save_file_content|suspendacct|unsuspendacct|createacct",
    re.IGNORECASE,
)
PRIVILEGED = re.compile(
    r"password|passwd|token|ssh|shell|privilege|acl|session|sudo|root|remote_whm|accesshash|private.?key|mycnf",
    re.IGNORECASE,
)

EXTERNAL_SIDE_EFFECT = re.compile(
    r"send_|request_|fullbackup_to_|deliver_messages|disinfect_files", re.IGNORECASE
)

SENSITIVE_READ = re.compile(
    r"get_file_content|get_message|get_log|audit_log|fetch.*private", re.IGNORECASE
)


ALIASES = {
    "whm.listaccts": "contas usuários hospedagens listar clientes",
    "whm.accountsummary": "conta detalhes domínio plano quota resumo",
    "whm.createacct": "criar provisionar nova conta hospedagem cliente",
    "whm.suspendacct": "suspender bloquear conta",
    "whm.unsuspendacct": "reativar desbloquear conta",
    "whm.removeacct": "excluir apagar encerrar conta",
    "whm.parse_dns_zone": "dns zona registros consultar",
    "whm.mass_edit_dns_zone": "dns editar registros zona",
    "uapi.Email.list_pops": "email emails caixas postais listar",
    "uapi.Email.add_pop": "email criar caixa postal",
    "uapi.Email.delete_pop": "email excluir caixa postal",
    "uapi.Mysql.list_databases": "mysql banco bancos listar",
    "uapi.Ftp.list_ftp": "ftp usuários listar",
    "uapi.DomainInfo.list_domains": "domínios subdomínios listar",
    "uapi.Fileman.get_file_content": "arquivo ler conteúdo",
    "uapi.Fileman.save_file_content": "arquivo salvar escrever conteúdo",
    "uapi.Fileman.list_files": "arquivos diretórios inventário listar",
    "uapi.Email.list_mxs": "email mx roteamento servidor",
    "uapi.Email.list_forwarders": "email encaminhadores redirecionamentos",
    "uapi.Email.list_auto_responders": "email autoresponders respostas automáticas",
    "uapi.EmailAuth.validate_current_spfs": "spf validar autenticação email dns",
    "uapi.EmailAuth.validate_current_dkims": "dkim validar autenticação email dns",
    "uapi.Ftp.allows_anonymous_ftp": "ftp anônimo segurança verificar",
    "uapi.LangPHP.php_get_vhost_versions": "php versão virtual host document root",
    "uapi.SSL.list_ssl_items": "ssl certificados validade tls https",
    "uapi.SSL.can_ssl_redirect": "ssl https redirecionamento seguro",
    "uapi.Bandwidth.query": "banda tráfego consumo conta domínio",
}


def classify(operation: str) -> tuple[Risk, Role, str]:
    if operation in EXPLICIT_RISKS:
        return EXPLICIT_RISKS[operation]
    function = operation.rsplit(".", 1)[-1]
    if function in BLOCKED_FUNCTIONS or PRIVILEGED.search(operation):
        return Risk.PRIVILEGED, Role.ADMIN, "admin"
    if DESTRUCTIVE.search(function):
        return Risk.DESTRUCTIVE, Role.ADMIN, "admin"
    if EXTERNAL_SIDE_EFFECT.search(function):
        return Risk.EXTERNAL_SIDE_EFFECT, Role.OPERATOR, "operator"
    if WRITE.search(function):
        return Risk.REVERSIBLE_WRITE, Role.OPERATOR, "operator"
    if SENSITIVE_READ.search(function):
        return Risk.SENSITIVE_READ, Role.ADMIN, "reader"
    return Risk.READ, Role.VIEWER, "reader"


def _schema(
    properties: dict[str, dict[str, Any]] | None = None, required: list[str] | None = None
) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": properties or {},
        "required": required or [],
    }


def curated_capabilities() -> list[Capability]:
    string = {"type": "string", "minLength": 1}
    integer = {"type": "integer", "minimum": 0}
    boolean_integer = {"type": "integer", "enum": [0, 1]}
    definitions: list[dict[str, Any]] = [
        {
            "id": "whm.version",
            "title": "Versão do cPanel/WHM",
            "description": "Retorna a versão exata do servidor cPanel/WHM.",
            "schema": _schema(),
        },
        {
            "id": "whm.myprivs",
            "title": "Privilégios do reseller",
            "description": "Lista os privilégios efetivos do revendedor autenticado.",
            "schema": _schema(),
        },
        {
            "id": "whm.listaccts",
            "title": "Listar contas",
            "description": "Lista contas cPanel pertencentes ao reseller, com domínio e status.",
            "schema": _schema(
                {"search": string, "searchtype": {"type": "string", "default": "owner"}}
            ),
        },
        {
            "id": "whm.accountsummary",
            "title": "Inspecionar conta",
            "description": "Retorna o resumo de uma conta cPanel específica.",
            "schema": _schema({"user": string}, ["user"]),
        },
        {
            "id": "whm.createacct",
            "title": "Provisionar conta",
            "description": "Cria uma conta cPanel subordinada ao reseller.",
            "schema": _schema(
                {"username": string, "domain": string, "password": string, "pkgname": string},
                ["username", "domain", "password"],
            ),
        },
        {
            "id": "whm.suspendacct",
            "title": "Suspender conta",
            "description": "Suspende uma conta cPanel, preservando seus dados.",
            "schema": _schema({"user": string, "reason": string}, ["user"]),
        },
        {
            "id": "whm.unsuspendacct",
            "title": "Reativar conta",
            "description": "Remove a suspensão de uma conta cPanel.",
            "schema": _schema({"user": string}, ["user"]),
        },
        {
            "id": "whm.removeacct",
            "title": "Encerrar conta",
            "description": "Exclui definitivamente uma conta cPanel e seus dados.",
            "schema": _schema({"user": string, "keepdns": {"type": "boolean"}}, ["user"]),
        },
        {
            "id": "whm.showbw",
            "title": "Consultar banda",
            "description": "Retorna o consumo de largura de banda das contas.",
            "schema": _schema({"search": string}),
        },
        {
            "id": "whm.verify_user_has_feature",
            "title": "Verificar recurso da conta",
            "description": "Confirma se uma conta cPanel possui um recurso específico habilitado.",
            "schema": _schema({"user": string, "feature": string}, ["user", "feature"]),
            "examples": [{"user": "cliente", "feature": "sslmanager"}],
        },
        {
            "id": "uapi.DomainInfo.list_domains",
            "title": "Listar domínios da conta",
            "description": "Lista domínio principal, adicionais, aliases e subdomínios.",
            "schema": _schema(),
        },
        {
            "id": "uapi.Email.list_pops",
            "title": "Listar caixas de e-mail",
            "description": "Lista contas de e-mail da conta cPanel selecionada.",
            "schema": _schema({"domain": string}),
        },
        {
            "id": "uapi.Email.list_mxs",
            "title": "Listar roteamento MX",
            "description": "Lista os servidores MX e o modo de roteamento de e-mail da conta.",
            "schema": _schema(),
        },
        {
            "id": "uapi.Email.list_forwarders",
            "title": "Listar encaminhadores",
            "description": "Lista os encaminhadores de um domínio da conta.",
            "schema": _schema({"domain": string, "regex": string}, ["domain"]),
            "examples": [{"domain": "example.com"}],
        },
        {
            "id": "uapi.Email.list_auto_responders",
            "title": "Listar respostas automáticas",
            "description": "Lista os autoresponders de um domínio da conta.",
            "schema": _schema({"domain": string, "regex": string}, ["domain"]),
            "examples": [{"domain": "example.com"}],
        },
        {
            "id": "uapi.EmailAuth.validate_current_spfs",
            "title": "Validar SPF",
            "description": "Valida o registro SPF publicado para um domínio da conta.",
            "schema": _schema({"domain": string}, ["domain"]),
            "examples": [{"domain": "example.com"}],
        },
        {
            "id": "uapi.EmailAuth.validate_current_dkims",
            "title": "Validar DKIM",
            "description": "Valida o registro DKIM publicado para um domínio da conta.",
            "schema": _schema({"domain": string}, ["domain"]),
            "examples": [{"domain": "example.com"}],
        },
        {
            "id": "uapi.Email.add_pop",
            "title": "Criar caixa de e-mail",
            "description": "Cria uma conta de e-mail com quota opcional.",
            "schema": _schema(
                {"email": string, "password": string, "domain": string, "quota": integer},
                ["email", "password", "domain"],
            ),
        },
        {
            "id": "uapi.Email.delete_pop",
            "title": "Excluir caixa de e-mail",
            "description": "Exclui uma conta de e-mail e seus dados.",
            "schema": _schema({"email": string, "domain": string}, ["email", "domain"]),
        },
        {
            "id": "uapi.Ftp.list_ftp",
            "title": "Listar usuários FTP",
            "description": "Lista usuários FTP da conta cPanel.",
            "schema": _schema(),
        },
        {
            "id": "uapi.Ftp.list_ftp_with_disk",
            "title": "Listar usuários FTP com uso",
            "description": "Lista usuários FTP e seu consumo de disco.",
            "schema": _schema({"include_acct_types": string, "skip_acct_types": string}),
        },
        {
            "id": "uapi.Ftp.allows_anonymous_ftp",
            "title": "Verificar FTP anônimo",
            "description": "Informa se a conta aceita conexões FTP anônimas.",
            "schema": _schema(),
        },
        {
            "id": "uapi.Mysql.list_databases",
            "title": "Listar bancos MySQL",
            "description": "Lista bancos MySQL e uso da conta.",
            "schema": _schema(),
        },
        {
            "id": "uapi.Fileman.get_file_content",
            "title": "Ler arquivo",
            "description": "Lê um arquivo dentro da conta cPanel.",
            "schema": _schema({"dir": string, "file": string}, ["dir", "file"]),
            "risk": Risk.SENSITIVE_READ,
            "role": Role.ADMIN,
            "sensitive_output": True,
        },
        {
            "id": "uapi.Fileman.list_files",
            "title": "Listar arquivos e diretórios",
            "description": "Retorna um inventário de metadados, sem ler o conteúdo dos arquivos.",
            "schema": _schema(
                {
                    "dir": string,
                    "show_hidden": boolean_integer,
                    "types": {"type": "string", "pattern": "^(file|dir)(\\|(file|dir))*$"},
                    "only_these_files": string,
                },
                ["dir"],
            ),
            "examples": [{"dir": "public_html", "show_hidden": 0, "types": "file|dir"}],
        },
        {
            "id": "uapi.Fileman.save_file_content",
            "title": "Salvar arquivo",
            "description": "Grava conteúdo em um arquivo dentro da conta cPanel.",
            "schema": _schema(
                {"dir": string, "file": string, "content": string}, ["dir", "file", "content"]
            ),
        },
        {
            "id": "uapi.Backup.list_backups",
            "title": "Listar backups",
            "description": "Lista backups disponíveis para a conta cPanel.",
            "schema": _schema(),
        },
        {
            "id": "uapi.Bandwidth.query",
            "title": "Consultar banda da conta",
            "description": "Retorna consumo de banda limitado à conta cPanel selecionada.",
            "schema": _schema(
                {
                    "grouping": {
                        "type": "string",
                        "pattern": (
                            "^(domain|protocol|year|year_month|year_month_day)"
                            "(\\|(domain|protocol|year|year_month|year_month_day)){0,2}$"
                        ),
                    },
                    "domains": string,
                    "protocols": string,
                    "interval": {"type": "string", "enum": ["daily", "hourly", "5min"]},
                    "start": integer,
                    "end": integer,
                    "timezone": string,
                },
                ["grouping"],
            ),
            "examples": [{"grouping": "domain|year_month", "interval": "daily"}],
        },
        {
            "id": "uapi.LangPHP.php_get_vhost_versions",
            "title": "Consultar PHP dos domínios",
            "description": (
                "Retorna versão PHP, document root e estado do PHP-FPM por virtual host."
            ),
            "schema": _schema({"vhost": string}),
            "examples": [{"vhost": "example.com"}],
        },
        {
            "id": "uapi.SSL.list_ssl_items",
            "title": "Listar certificados SSL",
            "description": (
                "Lista apenas certificados públicos SSL de um domínio, sem chaves privadas."
            ),
            "schema": _schema(
                {"domains": string, "item": {"type": "string", "const": "crt"}},
                ["domains", "item"],
            ),
            "examples": [{"domains": "example.com", "item": "crt"}],
            "required_features": ["sslmanager"],
        },
        {
            "id": "uapi.SSL.can_ssl_redirect",
            "title": "Verificar redirecionamento HTTPS",
            "description": (
                "Informa se o cPanel consegue gerenciar redirecionamentos HTTPS da conta."
            ),
            "schema": _schema(),
        },
    ]
    capabilities: list[Capability] = []
    for definition in definitions:
        capability_id = definition["id"]
        api_name, *rest = capability_id.split(".")
        if api_name == "uapi":
            module, function = rest
            api = ApiFamily.UAPI
        else:
            module, function = None, rest[0]
            api = ApiFamily.WHM
        risk, role, profile = classify(capability_id)
        risk = definition.get("risk", risk)
        role = definition.get("role", role)
        profile = definition.get("profile", profile)
        capabilities.append(
            Capability(
                id=capability_id,
                api=api,
                module=module,
                function=function,
                title=definition["title"],
                description=definition["description"],
                risk=risk,
                required_role=role,
                upstream_profile=profile,
                input_schema=definition["schema"],
                examples=definition.get("examples", []),
                required_features=definition.get("required_features", []),
                sensitive_output=definition.get("sensitive_output", False),
                documentation_url=definition.get("documentation_url"),
                schema_source="official_cpanel_docs",
                curated=True,
            )
        )
    return capabilities


class Catalog:
    def __init__(self, live_path: Path):
        self.live_path = live_path

    def load(self) -> list[Capability]:
        by_id = {cap.id: cap for cap in curated_capabilities()}
        if not self.live_path.exists():
            return sorted(by_id.values(), key=lambda item: item.id)
        raw = json.loads(self.live_path.read_text(encoding="utf-8"))
        live_whm = set(raw.get("whm", []))
        live_uapi = set(raw.get("uapi", []))
        for capability in by_id.values():
            live_key = (
                capability.function
                if capability.api == ApiFamily.WHM
                else f"{capability.module}::{capability.function}"
            )
            live_set = live_whm if capability.api == ApiFamily.WHM else live_uapi
            if live_key not in live_set:
                capability.available = False
                capability.availability_reason = "Not advertised by the live cPanel server"
        for function in live_whm:
            capability_id = f"whm.{function}"
            if capability_id in by_id:
                continue
            by_id[capability_id] = self._advanced(ApiFamily.WHM, None, function)
        for operation in live_uapi:
            module, function = operation.split("::", 1)
            capability_id = f"uapi.{module}.{function}"
            if capability_id in by_id:
                continue
            by_id[capability_id] = self._advanced(ApiFamily.UAPI, module, function)
        return sorted(by_id.values(), key=lambda item: item.id)

    @staticmethod
    def _advanced(api: ApiFamily, module: str | None, function: str) -> Capability:
        capability_id = f"{api.value}.{module + '.' if module else ''}{function}"
        risk, role, profile = classify(capability_id)
        blocked = function in BLOCKED_FUNCTIONS or bool(PRIVILEGED.search(capability_id))
        return Capability(
            id=capability_id,
            api=api,
            module=module,
            function=function,
            title=function.replace("_", " "),
            description=(
                "Operação avançada descoberta no servidor. Parâmetros são validados pelo cPanel; "
                "consulte a documentação antes de executar."
            ),
            risk=risk,
            required_role=Role.ADMIN if not blocked else Role.ADMIN,
            upstream_profile=profile,
            input_schema={"type": "object", "additionalProperties": True},
            available=not blocked,
            availability_reason="Blocked by harness policy" if blocked else None,
            sensitive_output=risk in {Risk.SENSITIVE_READ, Risk.PRIVILEGED},
            schema_source="live_discovery_untyped",
            curated=False,
        )
