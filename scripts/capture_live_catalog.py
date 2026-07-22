#!/usr/bin/env python3
"""Capture the operation names advertised by a cPanel server over SSH."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from datetime import UTC, datetime
from pathlib import Path

CALL_RE = re.compile(r"^\s{8}([A-Za-z][A-Za-z0-9_:]+)\s*$", re.MULTILINE)
CPANEL_SSH_HOST = os.environ.get("RESELLER_MCP_CPANEL_SSH_HOST", "cpanel")
CPANEL_RESELLER = os.environ.get("RESELLER_MCP_CPANEL_RESELLER", "demo-reseller")
CPANEL_ACCESS_HASH = os.environ.get(
    "RESELLER_MCP_CPANEL_ACCESS_HASH", f"/home/{CPANEL_RESELLER}/.accesshash"
)
CPANEL_CATALOG_SOURCE = os.environ.get("RESELLER_MCP_CATALOG_SOURCE", "redacted-cpanel")


def remote_help(command: str) -> str:
    result = subprocess.run(
        ["ssh", CPANEL_SSH_HOST, command],
        check=False,
        capture_output=True,
        text=True,
    )
    output = result.stdout + result.stderr
    if not output.strip():
        raise RuntimeError(f"SSH catalog capture failed with exit code {result.returncode}")
    return output


def main() -> None:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", CPANEL_RESELLER):
        raise RuntimeError("invalid cPanel reseller name")
    applist_command = (
        f"TOKEN=$(tr -d '\\n' < {shlex.quote(CPANEL_ACCESS_HASH)}); "
        f'curl -ksS -H "Authorization: WHM {CPANEL_RESELLER}:$TOKEN" '
        '"https://127.0.0.1:2087/json-api/applist?api.version=1"'
    )
    applist = json.loads(remote_help(applist_command))
    whm = sorted(set(applist["data"]["app"]))
    uapi = sorted({item for item in CALL_RE.findall(remote_help("uapi --help")) if "::" in item})
    payload = {
        "captured_at": datetime.now(UTC).isoformat(),
        "source": CPANEL_CATALOG_SOURCE,
        "whm": whm,
        "uapi": uapi,
    }
    output = Path(__file__).resolve().parents[1] / "data" / "live_operations.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "whm": len(whm), "uapi": len(uapi)}))


if __name__ == "__main__":
    main()
