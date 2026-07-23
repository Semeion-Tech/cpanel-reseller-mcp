from __future__ import annotations

from pathlib import Path

import pytest

from reseller_mcp.models import Principal, Role
from reseller_mcp.server import create_server


def test_query_execute_is_registered_without_structured_output(settings) -> None:
    mcp, _ = create_server(settings)

    tool = mcp._tool_manager.get_tool("query_execute")

    assert tool is not None
    assert tool.output_schema is None
    assert tool.fn_metadata.output_schema is None


class _FakeCPanel:
    async def call(self, capability, account, arguments, *, retry_safe=False):
        if capability.id != "uapi.Fileman.get_file_content":
            raise AssertionError(f"unexpected capability {capability.id}")
        size = 2048 if arguments["file"] == "small.txt" else 12288
        return {
            "status": 1,
            "data": {
                "dir": arguments["dir"],
                "file": arguments["file"],
                "encoding": "utf-8",
                "content": "x" * size,
            },
        }


@pytest.mark.asyncio
async def test_query_execute_returns_single_text_block_with_smaller_envelope(
    settings, monkeypatch, tmp_path
) -> None:
    settings.db_path = tmp_path / "mcp.db"
    settings.catalog_path = Path("data/live_operations.json")
    principal = Principal(
        user_id="admin-id",
        username="admin",
        role=Role.ADMIN,
        client_id="test-client",
        account_scopes=frozenset({"*"}),
    )
    monkeypatch.setattr("reseller_mcp.server.current_principal", lambda: principal)

    mcp, runtime = create_server(settings)
    runtime.harness.cpanel = _FakeCPanel()

    baseline = await mcp.call_tool(
        "query_execute",
        {
            "capability_id": "uapi.Fileman.get_file_content",
            "account": "outpromo",
                "arguments": {
                    "dir": "/home2/outpromo/reservadesalas.outpromo.com.br",
                    "file": "small.txt",
                },
            },
        )
    large = await mcp.call_tool(
        "query_execute",
        {
            "capability_id": "uapi.Fileman.get_file_content",
            "account": "outpromo",
            "arguments": {
                "dir": "/home2/outpromo/reservadesalas.outpromo.com.br",
                "file": "error_log",
            },
        },
    )

    assert len(baseline) == 1
    assert len(large) == 1
    assert baseline[0].type == "text"
    assert large[0].type == "text"
    assert len(large[0].text) > len(baseline[0].text)
    assert "structuredContent" not in baseline[0].text
    assert "structuredContent" not in large[0].text
    assert "normalized_data" in baseline[0].text
    assert "content_length_chars" in baseline[0].text
    assert "content_length_chars" in large[0].text
