from __future__ import annotations

import json

import httpx
import respx
from typer.testing import CliRunner

from reseller_mcp.upload_cli import app, staging_url

runner = CliRunner()


def test_staging_url_is_derived_from_the_mcp_url() -> None:
    assert staging_url("https://mcp.example.com/mcp") == "https://mcp.example.com/staging/images"
    assert staging_url("https://mcp.example.com/mcp/") == "https://mcp.example.com/staging/images"


def test_token_is_required(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("RESELLER_MCP_ACCESS_TOKEN", raising=False)
    (tmp_path / "a.png").write_bytes(b"x")
    result = runner.invoke(app, [str(tmp_path / "a.png")])
    assert result.exit_code != 0


@respx.mock
def test_folder_sends_only_images_with_bearer_and_prints_ids(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("RESELLER_MCP_ACCESS_TOKEN", "rmcp_k_secret")
    monkeypatch.setenv("RESELLER_MCP_URL", "https://mcp.example.com/mcp")
    (tmp_path / "a.png").write_bytes(b"png-bytes")
    (tmp_path / "b.jpg").write_bytes(b"jpg-bytes")
    (tmp_path / "notes.txt").write_text("skip me")
    route = respx.post("https://mcp.example.com/staging/images").mock(
        return_value=httpx.Response(
            200, json={"items": [{"staging_id": "s1", "name": "a.png"}], "rejected": []}
        )
    )

    result = runner.invoke(app, [str(tmp_path)])

    assert result.exit_code == 0, result.output
    request = route.calls.last.request
    assert request.headers["authorization"] == "Bearer rmcp_k_secret"
    assert b'filename="a.png"' in request.content and b'filename="b.jpg"' in request.content
    assert b"notes.txt" not in request.content
    assert json.loads(result.output)["items"][0]["staging_id"] == "s1"
    assert "rmcp_k_secret" not in result.output


@respx.mock
def test_rejected_files_exit_with_error(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("RESELLER_MCP_ACCESS_TOKEN", "rmcp_k_secret")
    monkeypatch.setenv("RESELLER_MCP_URL", "https://mcp.example.com/mcp")
    (tmp_path / "a.png").write_bytes(b"x")
    respx.post("https://mcp.example.com/staging/images").mock(
        return_value=httpx.Response(
            200, json={"items": [], "rejected": [{"name": "a.png", "code": "X"}]}
        )
    )
    assert runner.invoke(app, [str(tmp_path / "a.png")]).exit_code == 1


def test_invalid_local_name_is_refused_before_sending(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("RESELLER_MCP_ACCESS_TOKEN", "rmcp_k_secret")
    (tmp_path / "Foto Final.PNG").write_bytes(b"x")
    result = runner.invoke(app, [str(tmp_path / "Foto Final.PNG")])
    assert result.exit_code != 0
