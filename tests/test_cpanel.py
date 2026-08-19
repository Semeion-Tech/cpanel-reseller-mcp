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
async def test_uapi_mutations_use_post_form_data(settings) -> None:
    seen: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["body"] = request.content
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
    assert b"cpanel.function=mass_edit_zone" in seen["body"]
    assert b"add=%7B%22record_type%22%3A%22TXT%22%7D" in seen["body"]
    await client.close()
