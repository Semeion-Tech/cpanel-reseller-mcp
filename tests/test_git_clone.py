from __future__ import annotations

import json
from typing import Any

import pytest

from reseller_mcp.catalog import Catalog
from reseller_mcp.cpanel import CPanelError
from reseller_mcp.git_workflows import GitWorkflows
from reseller_mcp.models import Preparation, Risk, Role

MAIN = {"domain": "example.com", "documentroot": "/home/acct/public_html", "type": "main_domain"}


@pytest.mark.parametrize(
    ("url", "owner", "repo"),
    [
        ("https://github.com/OMC-Media-DRUM-DEV/site.git", "OMC-Media-DRUM-DEV", "site"),
        ("https://github.com/Semeion-Tech/site", "Semeion-Tech", "site"),
        ("git@github.com:LucioRibeiro-IHC/my.repo.git", "LucioRibeiro-IHC", "my.repo"),
        ("ssh://git@github.com/omc-media-drum-dev/x.git", "omc-media-drum-dev", "x"),
    ],
)
def test_an_allowed_remote_is_accepted(url: str, owner: str, repo: str) -> None:
    assert GitWorkflows.parse_remote(url) == (owner, repo)


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("https://github.com/someone-else/site.git", "GIT_REMOTE_NOT_ALLOWED"),
        ("https://user:pass@github.com/Semeion-Tech/site.git", "GIT_REMOTE_INVALID"),
        ("https://ghp_token@github.com/Semeion-Tech/site.git", "GIT_REMOTE_INVALID"),
        ("https://gitlab.com/Semeion-Tech/site.git", "GIT_REMOTE_INVALID"),
        ("https://github.com.evil.com/Semeion-Tech/site.git", "GIT_REMOTE_INVALID"),
        ("https://github.com/Semeion-Tech/site.git?x=1", "GIT_REMOTE_INVALID"),
        ("https://github.com/Semeion-Tech", "GIT_REMOTE_INVALID"),
        ("file:///etc/passwd", "GIT_REMOTE_INVALID"),
        ("git@github.com:Semeion-Tech/../x.git", "GIT_REMOTE_INVALID"),
        ("http://github.com/Semeion-Tech/site.git", "GIT_REMOTE_INVALID"),
    ],
)
def test_any_other_remote_is_refused(url: str, code: str) -> None:
    with pytest.raises(CPanelError) as caught:
        GitWorkflows.parse_remote(url)
    assert caught.value.code == code


class GitCPanel:
    def __init__(self, repositories: list[dict[str, Any]] | None = None) -> None:
        self.repositories = list(repositories or [])
        self.created: list[dict[str, Any]] = []
        self.lose_response = False
        self.lose_and_drop = False

    async def call(self, capability, account, arguments, *, retry_safe=False):
        name = capability.id.rsplit(".", 1)[-1]
        if name == "domains_data":
            return {"status": 1, "data": {"main_domain": MAIN, "sub_domains": []}}
        if name == "retrieve":
            return {"status": 1, "data": list(self.repositories)}
        if name == "create":
            self.created.append(dict(arguments))
            if self.lose_and_drop:
                raise CPanelError("connection lost", code="UPSTREAM_NETWORK_ERROR")
            source = json.loads(arguments["source_repository"])
            self.repositories.append(
                {
                    "name": arguments["name"],
                    "repository_root": arguments["repository_root"],
                    "source_repository": source,
                }
            )
            if self.lose_response:
                raise CPanelError("connection lost", code="UPSTREAM_NETWORK_ERROR")
            return {"status": 1, "data": {}}
        raise AssertionError(f"unexpected call: {name}")


class WorkflowHarness:
    def __init__(self, cpanel: GitCPanel) -> None:
        self.cpanel = cpanel

    def _get_capability(self, capability_id: str) -> Any:
        return type("CapabilityRef", (), {"id": capability_id})()


async def _clone(cpanel: GitCPanel, **arguments: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    workflows = GitWorkflows(WorkflowHarness(cpanel))
    before = await workflows.prepare_clone("acct", arguments)
    preparation = Preparation.model_construct(
        account="acct", arguments=arguments, before_state=before
    )
    return before, await workflows.execute_clone(preparation)


URL = "https://github.com/OMC-Media-DRUM-DEV/site.git"


@pytest.mark.asyncio
async def test_a_clone_lands_in_the_repositories_directory_and_is_verified() -> None:
    cpanel = GitCPanel()

    before, result = await _clone(cpanel, url=URL, branch="main")

    assert before["repository_root"] == "/home/acct/repositories/site"
    assert cpanel.created == [
        {
            "type": "git",
            "name": "site",
            "repository_root": "/home/acct/repositories/site",
            "source_repository": json.dumps({"remote_name": "origin", "url": URL}),
            "checkout_branch": "main",
        }
    ]
    assert result["verified"] is True
    assert result["data"]["changed"] is True


@pytest.mark.asyncio
async def test_cloning_the_same_remote_again_is_a_noop() -> None:
    cpanel = GitCPanel()
    await _clone(cpanel, url=URL)

    before, result = await _clone(cpanel, url=URL)

    assert before["noop"] is True
    assert result["data"] == {
        "changed": False,
        "repository_root": "/home/acct/repositories/site",
        "noop": True,
    }
    assert len(cpanel.created) == 1


@pytest.mark.asyncio
async def test_a_different_remote_in_the_same_directory_is_refused() -> None:
    cpanel = GitCPanel()
    await _clone(cpanel, url=URL)

    with pytest.raises(CPanelError) as caught:
        await _clone(cpanel, url="https://github.com/Semeion-Tech/other.git", name="site")

    assert caught.value.code == "GIT_REPOSITORY_EXISTS"
    assert len(cpanel.created) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["../x", "a/b", ".hidden", "x" * 65])
async def test_a_directory_name_cannot_escape_repositories(name: str) -> None:
    cpanel = GitCPanel()
    with pytest.raises(CPanelError) as caught:
        await _clone(cpanel, url=URL, name=name)
    assert caught.value.code == "GIT_NAME_INVALID"
    assert cpanel.created == []


@pytest.mark.asyncio
@pytest.mark.parametrize("branch", ["--upload-pack=x", "a..b", "-x", "a b"])
async def test_a_branch_cannot_carry_options(branch: str) -> None:
    cpanel = GitCPanel()
    with pytest.raises(CPanelError) as caught:
        await _clone(cpanel, url=URL, branch=branch)
    assert caught.value.code == "GIT_BRANCH_INVALID"
    assert cpanel.created == []


@pytest.mark.asyncio
async def test_a_lost_response_is_reconciled_by_listing_the_repositories() -> None:
    cpanel = GitCPanel()
    cpanel.lose_response = True

    _, result = await _clone(cpanel, url=URL)

    assert result["verified"] is True
    assert result["data"]["reconciled_after_transport_error"] is True


@pytest.mark.asyncio
async def test_a_lost_request_that_left_nothing_is_reported_as_unknown() -> None:
    cpanel = GitCPanel()
    cpanel.lose_and_drop = True

    with pytest.raises(CPanelError) as caught:
        await _clone(cpanel, url=URL)

    assert caught.value.code == "GIT_WRITE_STATE_UNKNOWN"


def test_the_clone_is_an_external_side_effect_that_needs_the_phrase(tmp_path) -> None:
    capabilities = {item.id: item for item in Catalog(tmp_path / "missing.json").load()}
    capability = capabilities["workflow.git_clone"]

    assert capability.curated is True
    assert (capability.risk, capability.required_role) == (Risk.EXTERNAL_SIDE_EFFECT, Role.OPERATOR)
    assert capability.input_schema["additionalProperties"] is False
    assert capability.input_schema["required"] == ["url"]
