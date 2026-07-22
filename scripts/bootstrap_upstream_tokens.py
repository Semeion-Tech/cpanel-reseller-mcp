#!/usr/bin/env python3
"""Create least-privilege cPanel tokens and install the service .env on Semeion.

Token values stay in process memory and are sent directly to the VPS over SSH. They are never
printed or written to the local filesystem.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import subprocess
import urllib.parse

PROJECT_DIR = os.environ.get("RESELLER_MCP_PROJECT_DIR", "/home/semeion-tech/cpanel-reseller-mcp")
CPANEL_SSH_HOST = os.environ.get("RESELLER_MCP_CPANEL_SSH_HOST", "cpanel")
VPS_SSH_HOST = os.environ.get("RESELLER_MCP_VPS_SSH_HOST", "mcp-vps")
CPANEL_RESELLER = os.environ.get("RESELLER_MCP_CPANEL_RESELLER", "demo-reseller")
CPANEL_ACCESS_HASH = os.environ.get(
    "RESELLER_MCP_CPANEL_ACCESS_HASH", f"/home/{CPANEL_RESELLER}/.accesshash"
)
CPANEL_BASE_URL = os.environ.get("RESELLER_MCP_CPANEL_BASE_URL", "https://cpanel.example.com:2087")
PUBLIC_URL = os.environ.get("RESELLER_MCP_PUBLIC_URL", "https://mcp.example.com")
TOKEN_NAMES = {
    "reader": "reseller_mcp_reader",
    "operator": "reseller_mcp_operator",
    "admin": "reseller_mcp_admin",
}
READER_ACLS = {
    "acct-summary",
    "basic-system-info",
    "basic-whm-functions",
    "cpanel-api",
    "list-accts",
    "list-pkgs",
    "mailcheck",
    "mysql-info",
    "show-bandwidth",
    "ssl-info",
}
OPERATOR_ACLS = READER_ACLS | {
    "create-acct",
    "create-dns",
    "edit-dns",
    "edit-mx",
    "manage-dns-records",
    "ssl",
    "suspend-acct",
}
DENIED_ADMIN_ACLS = {"all", "create-user-session", "manage-api-tokens"}


def ssh(host: str, command: str, *, stdin: str | None = None) -> str:
    result = subprocess.run(
        ["ssh", host, command],
        input=stdin,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"SSH command failed on {host}: {result.stderr.strip()}")
    return result.stdout


def cpanel_call(function: str, params: list[tuple[str, str]]) -> dict[str, object]:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", CPANEL_RESELLER):
        raise RuntimeError("invalid cPanel reseller name")
    query = urllib.parse.urlencode([("api.version", "1"), *params])
    url = f"https://127.0.0.1:2087/json-api/{function}?{query}"
    command = (
        f"TOKEN=$(tr -d '\\n' < {shlex.quote(CPANEL_ACCESS_HASH)}); "
        f'curl -ksS --fail -H "Authorization: WHM {CPANEL_RESELLER}:$TOKEN" ' + shlex.quote(url)
    )
    payload = json.loads(ssh(CPANEL_SSH_HOST, command))
    metadata = payload.get("metadata", {})
    if metadata.get("result") != 1:
        raise RuntimeError(f"cPanel {function} failed: {metadata.get('reason', 'unknown')}")
    return payload


def create_token(name: str, acls: set[str], vps_ip: str) -> str:
    params = [("token_name", name), ("whitelist_ip", vps_ip)]
    params.extend((f"acl-{index}", acl) for index, acl in enumerate(sorted(acls)))
    payload = cpanel_call("api_token_create", params)
    token = payload.get("data", {}).get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError(f"cPanel did not return the newly created token {name}")
    return token


def main() -> None:
    vps_ip = ssh(VPS_SSH_HOST, "curl -4 -fsS https://api.ipify.org").strip()
    existing_payload = cpanel_call("api_token_list", [])
    existing = {
        item.get("name")
        for item in existing_payload.get("data", {}).get("tokens", [])
        if isinstance(item, dict)
    }
    collisions = existing.intersection(TOKEN_NAMES.values())
    if collisions:
        raise RuntimeError(f"refusing to replace existing token names: {sorted(collisions)}")

    privileges_payload = cpanel_call("myprivs", [])
    privileges = privileges_payload.get("data", {}).get("privileges", [{}])[0]
    admin_acls = {
        name
        for name, enabled in privileges.items()
        if enabled == 1 and name not in DENIED_ADMIN_ACLS
    }
    tokens = {
        "reader": create_token(TOKEN_NAMES["reader"], READER_ACLS, vps_ip),
        "operator": create_token(TOKEN_NAMES["operator"], OPERATOR_ACLS, vps_ip),
        "admin": create_token(TOKEN_NAMES["admin"], admin_acls, vps_ip),
    }
    environment = "\n".join(
        [
            f"RESELLER_MCP_PUBLIC_URL={PUBLIC_URL}",
            f"RESELLER_MCP_TOKEN_PEPPER={secrets.token_urlsafe(64)}",
            f"RESELLER_MCP_CONFIRMATION_SECRET={secrets.token_urlsafe(64)}",
            f"RESELLER_MCP_CPANEL_BASE_URL={CPANEL_BASE_URL}",
            f"RESELLER_MCP_CPANEL_RESELLER={CPANEL_RESELLER}",
            f"RESELLER_MCP_CPANEL_READER_TOKEN={tokens['reader']}",
            f"RESELLER_MCP_CPANEL_OPERATOR_TOKEN={tokens['operator']}",
            f"RESELLER_MCP_CPANEL_ADMIN_TOKEN={tokens['admin']}",
            "RESELLER_MCP_CPANEL_VERIFY_TLS=true",
            "RESELLER_MCP_AUDIT_RETENTION_DAYS=365",
            "RESELLER_MCP_REQUIRE_SECOND_APPROVER=false",
            "",
        ]
    )
    ssh(
        VPS_SSH_HOST,
        "umask 077; mkdir -p "
        f"{shlex.quote(PROJECT_DIR)}; tee {shlex.quote(f'{PROJECT_DIR}/.env')} >/dev/null",
        stdin=environment,
    )
    print(json.dumps({"status": "created", "profiles": sorted(tokens), "whitelist_ip": vps_ip}))


if __name__ == "__main__":
    main()
