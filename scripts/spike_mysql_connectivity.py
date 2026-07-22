#!/usr/bin/env python3
"""One-shot manual check: can we reach a cPanel account's MySQL server by direct TCP
after granting our egress IP via uapi.Mysql.add_host? Run this by hand against a real
account before building on top of MySQLEphemeralSession. Not part of the automated suite.

Verified working against a real account on 2026-07-22 (see docs/superpowers/plans/
2026-07-22-database-access-implementation.md, Task 1).
"""
from __future__ import annotations

import asyncio
import os
import secrets

import aiomysql
import httpx


async def main() -> None:
    base_url = os.environ["RESELLER_MCP_CPANEL_BASE_URL"]
    reseller = os.environ["RESELLER_MCP_CPANEL_RESELLER"]
    token = os.environ["RESELLER_MCP_CPANEL_ADMIN_TOKEN"]
    account = os.environ["SPIKE_ACCOUNT"]
    database = os.environ["SPIKE_DATABASE"]
    egress_ip = os.environ["SPIKE_EGRESS_IP"]

    headers = {"Authorization": f"whm {reseller}:{token}"}
    async with httpx.AsyncClient(base_url=base_url, verify=True, timeout=30) as client:

        async def uapi(function: str, **params: str) -> dict:
            response = await client.get(
                "/json-api/uapi_cpanel",
                headers=headers,
                params={
                    "api.version": 1,
                    "cpanel.user": account,
                    "cpanel.module": "Mysql",
                    "cpanel.function": function,
                    **params,
                },
            )
            response.raise_for_status()
            return response.json()["data"]["uapi"]["result"]

        server_info = await uapi("get_server_information")
        print("server_information:", server_info)
        raw_host = (server_info.get("data") or {}).get("host")
        # cPanel reports "localhost" when MySQL is co-located with cPanel itself (the common
        # case) -- that literal string is not connectable from outside, so fall back to the
        # cPanel hostname in that case.
        host = raw_host if raw_host and raw_host != "localhost" else httpx.URL(base_url).host
        port = int((server_info.get("data") or {}).get("port") or 3306)

        restrictions = await uapi("get_restrictions")
        print("get_restrictions:", restrictions)
        prefix = restrictions["data"]["prefix"]
        max_len = int(restrictions["data"]["max_username_length"])

        add_host = await uapi("add_host", host=egress_ip)
        print("add_host:", add_host)

        # cPanel rejects any username that doesn't already carry the account's required
        # prefix -- it does not auto-prefix a short name for you.
        suffix = f"spike{secrets.token_hex(3)}"
        username = (prefix + suffix)[:max_len]
        password = secrets.token_urlsafe(24)
        create_user = await uapi("create_user", name=username, password=password)
        print("create_user:", create_user)

        try:
            await uapi(
                "set_privileges_on_database",
                user=username,
                database=database,
                privileges="SELECT",
            )
            print(f"Attempting TCP connect to {host}:{port} as {username} ...")
            conn = await asyncio.wait_for(
                aiomysql.connect(
                    host=host,
                    port=port,
                    user=username,
                    password=password,
                    db=database,
                    connect_timeout=10,
                ),
                timeout=15,
            )
            async with conn.cursor() as cursor:
                await cursor.execute("SELECT 1")
                print("SELECT 1 ->", await cursor.fetchone())
            conn.close()
            print("SPIKE RESULT: direct TCP connection WORKS.")
        finally:
            await uapi("delete_user", name=username)
            await uapi("delete_host", host=egress_ip)


if __name__ == "__main__":
    asyncio.run(main())
