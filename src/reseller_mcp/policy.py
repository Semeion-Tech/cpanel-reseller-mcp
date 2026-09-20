from __future__ import annotations

import re
from typing import Any

from jsonschema import Draft202012Validator

from .models import Capability, Principal, Risk, Role


class PolicyError(PermissionError):
    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


# Files that hold secrets: never written through the MCP, so a secret cannot travel through it.
SECRET_FILE = re.compile(
    r"^(\.env(\..*)?|\.my\.cnf|wp-config\.php|configuration\.php|id_rsa|id_ed25519|\.htpasswd"
    r"|.*\.(pem|key|p12|pfx))$",
    re.IGNORECASE,
)
# Files the web server or a shell will execute or obey. Writing one needs the confirmation phrase.
EXECUTABLE_FILE = re.compile(
    r"^(.*\.(php\d?|phtml|phar|pl|py|cgi|sh|rb|asp|aspx|jsp)|\.htaccess|\.user\.ini|php\.ini)$",
    re.IGNORECASE,
)


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
        if capability.api.value in {"uapi", "api2", "workflow"} and not account:
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

        if capability.id == "uapi.Fileman.save_file_content":
            self._check_save_file(arguments)
        if capability.id == "api2.Fileman.listfiles":
            self._check_home_path(str(arguments["dir"]))
        if capability.id == "api2.Fileman.mkdir":
            self._check_write_path(str(arguments["path"]), allow_root=True)
        if capability.id == "api2.Fileman.fileop":
            self._check_fileop(arguments)
        if capability.id == "uapi.SubDomain.addsubdomain" and "dir" in arguments:
            self._check_subdomain_dir(str(arguments["dir"]))

        # A scoped administrator cannot create a new account outside a global reseller scope.
        if capability.function == "createacct" and "*" not in principal.account_scopes:
            raise PolicyError(
                "creating accounts requires global reseller scope", "GLOBAL_SCOPE_REQUIRED"
            )

    # Directories that hold keys, mail, or panel state and are never a target.
    _PROTECTED_SEGMENTS = frozenset(
        {".ssh", ".gnupg", ".cpanel", ".cagefs", "etc", "mail", "ssl", ".htpasswds"}
    )

    @classmethod
    def _check_home_path(cls, value: str) -> None:
        """A path relative to the account home, without traversal or protected directories."""
        text = value.strip()
        segments = [part for part in text.split("/") if part]
        invalid = (
            not text
            or text.startswith("/")
            or "\\" in text
            or "\x00" in text
            or any(part == ".." for part in segments)
            or any(part in cls._PROTECTED_SEGMENTS for part in segments)
        )
        if invalid:
            raise PolicyError(
                "the path must be relative to the account home and outside protected directories",
                "PATH_OUTSIDE_ALLOWED_ROOT",
            )

    @classmethod
    def _check_save_file(cls, arguments: dict[str, Any]) -> None:
        """A file write: inside public_html, one plain file name, never a secret-bearing file."""
        cls._check_write_path(str(arguments["dir"]), allow_root=True)
        name = str(arguments["file"]).strip()
        if (
            not name
            or name in {".", ".."}
            or "/" in name
            or "\\" in name
            or "\x00" in name
            or len(name) > 255
        ):
            raise PolicyError("file must be a plain file name", "PATH_OUTSIDE_ALLOWED_ROOT")
        if SECRET_FILE.match(name):
            raise PolicyError(
                "writing files that hold secrets is disabled by policy", "SENSITIVE_TARGET_BLOCKED"
            )

    @classmethod
    def _check_fileop(cls, arguments: dict[str, Any]) -> None:
        """trash takes one source; copy and move take a source and a destination."""
        source = str(arguments["sourcefiles"])
        cls._check_write_path(source, allow_root=False)
        destination = arguments.get("destfiles")
        if arguments["op"] == "trash":
            if destination is not None:
                raise PolicyError(
                    "destfiles is only accepted by copy and move", "INVALID_ARGUMENTS"
                )
            return
        if not destination:
            raise PolicyError(f"{arguments['op']} requires destfiles", "INVALID_ARGUMENTS")
        cls._check_write_path(str(destination), allow_root=True)
        src = "/".join(part for part in source.strip().split("/") if part)
        dest = "/".join(part for part in str(destination).strip().split("/") if part)
        if dest == src or dest.startswith(f"{src}/"):
            raise PolicyError(
                "the destination cannot be the source or inside it", "PATH_OUTSIDE_ALLOWED_ROOT"
            )

    @classmethod
    def _check_write_path(cls, value: str, *, allow_root: bool) -> None:
        """A write target: one path inside public_html (public_html itself only if allowed)."""
        cls._check_home_path(value)
        segments = [part for part in value.strip().split("/") if part]
        minimum = 1 if allow_root else 2
        if len(segments) < minimum or segments[0] != "public_html" or "," in value:
            raise PolicyError(
                "the path must be a single path inside public_html",
                "PATH_OUTSIDE_ALLOWED_ROOT",
            )

    @staticmethod
    def _check_subdomain_dir(value: str) -> None:
        """Keep a subdomain's document root inside public_html of the account."""
        segments = [part for part in value.strip().split("/") if part]
        invalid = (
            not segments
            or "\\" in value
            or "\x00" in value
            or any(part in {".", ".."} for part in segments)
            or segments[0] != "public_html"
        )
        if invalid:
            raise PolicyError(
                "the subdomain document root must be a path inside public_html",
                "PATH_OUTSIDE_ALLOWED_ROOT",
            )

    @staticmethod
    def requires_confirmation(
        capability: Capability, arguments: dict[str, Any] | None = None
    ) -> bool:
        if capability.risk in {Risk.EXTERNAL_SIDE_EFFECT, Risk.DESTRUCTIVE, Risk.PRIVILEGED}:
            return True
        # Writing a file the server executes or obeys is a code change, not a content edit.
        return bool(
            capability.id == "uapi.Fileman.save_file_content"
            and arguments
            and EXECUTABLE_FILE.match(str(arguments.get("file", "")).strip())
        )

    @staticmethod
    def assert_read(capability: Capability) -> None:
        if capability.risk not in {Risk.READ, Risk.SENSITIVE_READ}:
            raise PolicyError(
                "query_execute only accepts read-only capabilities; use action_prepare",
                "WRITE_REQUIRES_PREPARATION",
            )
