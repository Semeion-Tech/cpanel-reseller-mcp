#!/usr/bin/env python3
"""Verify the installed stdio bridge against the public MCP endpoint."""

from __future__ import annotations

import asyncio
import os

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def smoke() -> None:
    command = os.environ.get("RESELLER_MCP_BRIDGE_COMMAND", "reseller-mcp-bridge")
    parameters = StdioServerParameters(command=command)
    async with (
        stdio_client(parameters) as (reader, writer),
        ClientSession(reader, writer) as session,
    ):
        await session.initialize()
        tools = await session.list_tools()
        print(f"connected tools={len(tools.tools)} first={tools.tools[0].name}")


if __name__ == "__main__":
    asyncio.run(smoke())
