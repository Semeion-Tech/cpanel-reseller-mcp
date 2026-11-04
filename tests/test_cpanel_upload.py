from __future__ import annotations

from typing import Any

import httpx
import pytest

from reseller_mcp.cpanel import CPanelClient, CPanelError

SESSION_URL = "https://cpanel.example.com:2083/cpsess1234567890/login/?session=acct%3atoken"
# Real shapes captured on 2026-11-04 (promocaosaborque).
SESSION_DENIED = {
    "metadata": {
        "result": 0,
        "reason": (
            "Permission denied: You do not have the required privileges to run "
            "“create_user_session”."
        ),
        "command": "create_user_session",
    }
}
SESSION_OK = {
    "metadata": {"result": 1, "reason": "Created session", "command": "create_user_session"},
    "data": {"url": SESSION_URL, "session": "acct:token", "expires": 1793830462},
}


def upload_ok(names: list[str]) -> dict[str, Any]:
    return {
        "status": 1,
        "errors": None,
        "messages": None,
        "warnings": None,
        "metadata": {},
        "data": {
            "warned": 0,
            "succeeded": len(names),
            "failed": 0,
            "uploads": [
                {
                    "status": 1,
                    "reason": f"Êxito ao carregar “{name}”.",
                    "file": name,
                    "size": 78,
                    "warnings": [],
                }
                for name in names
            ],
        },
    }


class Server:
    def __init__(self, session: dict[str, Any], upload: dict[str, Any] | None = None):
        self.session = session
        self.upload = upload
        self.requests: list[httpx.Request] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/json-api/create_user_session":
            return httpx.Response(200, json=self.session)
        if path.startswith("/cpsess1234567890/login"):
            return httpx.Response(200, headers={"set-cookie": "cpsession=abc; path=/"}, text="ok")
        if path == "/cpsess1234567890/execute/Fileman/upload_files":
            assert self.upload is not None
            return httpx.Response(200, json=self.upload)
        return httpx.Response(404)


@pytest.mark.asyncio
async def test_upload_without_create_user_session_acl_is_denied(settings) -> None:
    server = Server(SESSION_DENIED)
    client = CPanelClient(settings, transport=httpx.MockTransport(server))

    with pytest.raises(CPanelError) as error:
        await client.upload_files("acctalpha", "public_html", [("a.png", b"x", "image/png")])

    assert error.value.code == "UPLOAD_SESSION_DENIED"
    assert "create_user_session" in error.value.details["reason"]
    assert [r.url.path for r in server.requests] == ["/json-api/create_user_session"]
    await client.close()


@pytest.mark.asyncio
async def test_upload_sends_batch_as_multipart_through_the_session(settings) -> None:
    server = Server(SESSION_OK, upload_ok(["a.png", "b.jpg"]))
    client = CPanelClient(settings, transport=httpx.MockTransport(server))

    result = await client.upload_files(
        "acctalpha",
        "public_html/mail/images",
        [("a.png", b"\x89PNG-a", "image/png"), ("b.jpg", b"\xff\xd8-b", "image/jpeg")],
    )

    assert result["succeeded"] == 2
    assert [item["file"] for item in result["uploads"]] == ["a.png", "b.jpg"]
    session_request = server.requests[0]
    assert session_request.url.params["user"] == "acctalpha"
    assert session_request.url.params["service"] == "cpaneld"
    assert session_request.headers["authorization"] == f"whm {settings.cpanel_reseller}:operator"
    login = server.requests[1]
    assert login.url.port == 2083
    assert login.url.params["session"] == "acct:token"
    upload = server.requests[2]
    assert upload.method == "POST"
    assert upload.headers["cookie"] == "cpsession=abc"
    body = upload.content
    assert b'name="dir"\r\n\r\npublic_html/mail/images' in body
    assert b'name="overwrite"\r\n\r\n0' in body
    assert b'name="file-1"; filename="a.png"' in body
    assert b'name="file-2"; filename="b.jpg"' in body
    assert b"\x89PNG-a" in body and b"\xff\xd8-b" in body
    await client.close()


@pytest.mark.asyncio
async def test_partial_upload_failure_reports_each_file(settings) -> None:
    payload = upload_ok(["a.png"])
    payload["status"] = 0
    payload["errors"] = ["“b.png” já existe."]
    payload["data"]["failed"] = 1
    payload["data"]["uploads"].append(
        {"status": 0, "reason": "“b.png” já existe.", "file": "b.png", "size": 0}
    )
    server = Server(SESSION_OK, payload)
    client = CPanelClient(settings, transport=httpx.MockTransport(server))

    with pytest.raises(CPanelError) as error:
        await client.upload_files(
            "acctalpha", "public_html", [("a.png", b"a", "image/png"), ("b.png", b"b", "image/png")]
        )

    assert error.value.code == "UPLOAD_FAILED"
    statuses = {item["file"]: item["status"] for item in error.value.details["uploads"]}
    assert statuses == {"a.png": 1, "b.png": 0}
    await client.close()


@pytest.mark.asyncio
async def test_session_url_never_leaks_into_errors(settings) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/json-api/create_user_session":
            return httpx.Response(200, json=SESSION_OK)
        raise httpx.ConnectError(f"cannot reach {request.url}")

    client = CPanelClient(settings, transport=httpx.MockTransport(handler))

    with pytest.raises(CPanelError) as error:
        await client.upload_files("acctalpha", "public_html", [("a.png", b"a", "image/png")])

    rendered = f"{error.value} {error.value.as_dict()} {error.value.__cause__!r}"
    assert error.value.code == "UPSTREAM_NETWORK_ERROR"
    assert "cpsess" not in rendered and "session=" not in rendered
    await client.close()
