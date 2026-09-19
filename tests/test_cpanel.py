from __future__ import annotations

import httpx
import pytest

from reseller_mcp.cpanel import CPanelClient, CPanelError
from reseller_mcp.models import ApiFamily, Capability, Risk, Role


@pytest.mark.asyncio
async def test_remote_protocol_error_is_normalized_as_retryable_upstream_error(settings) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.RemoteProtocolError("connection closed before response")

    client = CPanelClient(settings, transport=httpx.MockTransport(handler))
    capability = Capability(
        id="uapi.DNS.mass_edit_zone",
        api=ApiFamily.UAPI,
        module="DNS",
        function="mass_edit_zone",
        title="DNS mass edit",
        description="test",
        risk=Risk.REVERSIBLE_WRITE,
        required_role=Role.OPERATOR,
        upstream_profile="operator",
        input_schema={"type": "object"},
        schema_source="test",
        curated=True,
    )

    with pytest.raises(CPanelError) as error:
        await client.call(capability, "acctalpha", {"zone": "example.com"})

    assert error.value.code == "UPSTREAM_NETWORK_ERROR"
    assert error.value.retryable is True
    await client.close()


@pytest.mark.asyncio
async def test_uapi_mutations_use_isolated_post_query(settings) -> None:
    seen: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["url"] = request.url
        seen["connection"] = request.headers.get("connection")
        return httpx.Response(
            200,
            json={
                "metadata": {"result": 1},
                "data": {"uapi": {"result": {"status": 1}}},
            },
        )

    client = CPanelClient(settings, transport=httpx.MockTransport(handler))
    capability = Capability(
        id="uapi.DNS.mass_edit_zone",
        api=ApiFamily.UAPI,
        module="DNS",
        function="mass_edit_zone",
        title="DNS mass edit",
        description="test",
        risk=Risk.REVERSIBLE_WRITE,
        required_role=Role.OPERATOR,
        upstream_profile="operator",
        input_schema={"type": "object"},
        schema_source="test",
        curated=True,
    )

    await client.call(
        capability,
        "acctalpha",
        {"zone": "example.com", "add": '{"record_type":"TXT"}'},
    )

    assert seen["method"] == "POST"
    assert seen["connection"] == "close"
    assert b"cpanel.function=mass_edit_zone" in str(seen.get("url")).encode()
    assert b"add=%7B%22record_type%22%3A%22TXT%22%7D" in str(seen.get("url")).encode()
    await client.close()


@pytest.mark.parametrize(
    "message",
    [
        "You do not have the feature “sslinstall”.",
        "Você não tem o recurso “sslinstall”.",
        "Voce nao tem o recurso “sslinstall”.",
    ],
)
def test_missing_account_feature_is_recognized_in_english_and_portuguese(message: str) -> None:
    from reseller_mcp.cpanel import _operation_error

    error = _operation_error(message)

    assert error.code == "ACCOUNT_FEATURE_UNAVAILABLE"
    assert error.category == "account_configuration"


def _api2_capability(function: str = "listfiles", risk: Risk = Risk.READ) -> Capability:
    return Capability(
        id=f"api2.Fileman.{function}",
        api=ApiFamily.API2,
        module="Fileman",
        function=function,
        title=function,
        description="test",
        risk=risk,
        required_role=Role.VIEWER,
        upstream_profile="reader",
        input_schema={"type": "object"},
        schema_source="test",
        curated=True,
    )


@pytest.mark.asyncio
async def test_api2_is_sent_through_the_whm_cpanel_function(settings) -> None:
    seen: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["params"] = dict(request.url.params)
        return httpx.Response(
            200,
            json={
                "metadata": {"result": 1},
                "data": {
                    "cpanelresult": {
                        "apiversion": 2,
                        "event": {"result": 1},
                        "data": [{"file": "index.html", "type": "file"}],
                    }
                },
            },
        )

    client = CPanelClient(settings, transport=httpx.MockTransport(handler))
    result = await client.call(_api2_capability(), "acctalpha", {"dir": "public_html"})

    assert seen["method"] == "GET"
    assert seen["path"] == "/json-api/cpanel"
    assert seen["params"] == {
        "api.version": "1",
        "cpanel_jsonapi_user": "acctalpha",
        "cpanel_jsonapi_apiversion": "2",
        "cpanel_jsonapi_module": "Fileman",
        "cpanel_jsonapi_func": "listfiles",
        "dir": "public_html",
    }
    assert result == [{"file": "index.html", "type": "file"}]
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"metadata": {"result": 1}, "cpanelresult": {"event": {"result": 1}, "data": ["x"]}},
        {"metadata": {"result": 1}, "data": ["x"]},
    ],
)
async def test_api2_result_is_unwrapped_wherever_it_is_nested(settings, payload) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    client = CPanelClient(settings, transport=httpx.MockTransport(handler))
    assert await client.call(_api2_capability(), "acctalpha", {"dir": "x"}) == ["x"]
    await client.close()


@pytest.mark.asyncio
async def test_api2_failure_inside_the_result_is_an_error(settings) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "metadata": {"result": 1},
                "data": {
                    "cpanelresult": {"event": {"result": 0}, "error": "Directory does not exist"}
                },
            },
        )

    client = CPanelClient(settings, transport=httpx.MockTransport(handler))
    with pytest.raises(CPanelError) as error:
        await client.call(_api2_capability(), "acctalpha", {"dir": "missing"})
    assert error.value.code == "UPSTREAM_OPERATION_FAILED"
    assert "Directory does not exist" in str(error.value)
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("module", "function"),
    [("Email", "listpops"), ("Fileman", "getdir"), ("Cron", "add_line"), ("Fileman", "savefile")],
)
async def test_api2_functions_outside_the_allowlist_are_never_sent(
    settings, module: str, function: str
) -> None:
    calls: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"metadata": {"result": 1}, "data": {}})

    client = CPanelClient(settings, transport=httpx.MockTransport(handler))
    capability = _api2_capability().model_copy(update={"module": module, "function": function})

    with pytest.raises(CPanelError) as error:
        await client.call(capability, "acctalpha", {})

    assert error.value.code == "API2_FUNCTION_NOT_ALLOWED"
    assert calls == []
    await client.close()


@pytest.mark.asyncio
async def test_api2_requires_an_account(settings) -> None:
    client = CPanelClient(settings, transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    with pytest.raises(CPanelError) as error:
        await client.call(_api2_capability(), None, {})
    assert error.value.code == "ACCOUNT_REQUIRED"
    await client.close()


@pytest.mark.asyncio
async def test_api2_writes_are_posted_like_uapi_writes(settings) -> None:
    seen: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        return httpx.Response(
            200, json={"metadata": {"result": 1}, "data": {"cpanelresult": {"data": []}}}
        )

    client = CPanelClient(settings, transport=httpx.MockTransport(handler))
    await client.call(_api2_capability("mkdir", Risk.REVERSIBLE_WRITE), "acctalpha", {})

    assert seen["method"] == "POST"
    await client.close()


@pytest.mark.asyncio
async def test_api2_delsubdomain_is_on_the_allowlist(settings) -> None:
    seen: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["params"] = dict(request.url.params)
        seen["method"] = request.method
        return httpx.Response(
            200, json={"metadata": {"result": 1}, "data": {"cpanelresult": {"data": []}}}
        )

    client = CPanelClient(settings, transport=httpx.MockTransport(handler))
    capability = _api2_capability("delsubdomain", Risk.DESTRUCTIVE).model_copy(
        update={"module": "SubDomain"}
    )
    await client.call(capability, "acctalpha", {"domain": "app_example.com"})

    assert seen["method"] == "POST"
    assert seen["params"]["cpanel_jsonapi_module"] == "SubDomain"
    assert seen["params"]["cpanel_jsonapi_func"] == "delsubdomain"
    assert seen["params"]["domain"] == "app_example.com"
    await client.close()
