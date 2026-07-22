from __future__ import annotations

import os


def main() -> None:
    url = os.environ.get("RESELLER_MCP_URL", "https://mcp-reseller.semeiontech.com/mcp")
    token = os.environ.get("RESELLER_MCP_ACCESS_TOKEN", "")
    if not token:
        raise SystemExit("RESELLER_MCP_ACCESS_TOKEN is required")
    # mcp-remote expands this variable itself; keep the bearer value out of argv.
    os.environ["RESELLER_MCP_AUTH_HEADER"] = f"Bearer {token}"
    os.execvp(
        "npx",
        [
            "npx",
            "-y",
            "mcp-remote@0.1.37",
            url,
            "--header",
            "Authorization:${RESELLER_MCP_AUTH_HEADER}",
        ],
    )


if __name__ == "__main__":
    main()
