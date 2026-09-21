from __future__ import annotations

import pytest

from reseller_mcp.audit import redact, scrub_url_userinfo, scrub_urls
from reseller_mcp.catalog import Catalog
from reseller_mcp.models import Risk, Role


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("https://user:pass@github.com/org/repo.git", "https://[REDACTED]@github.com/org/repo.git"),
        (
            "https://ghp_abc123@github.com/org/repo.git",
            "https://[REDACTED]@github.com/org/repo.git",
        ),
        ("http://u:p@host/x", "http://[REDACTED]@host/x"),
        ("ssh://user:pass@host/repo.git", "ssh://[REDACTED]@host/repo.git"),
        ("git://user:pass@host/repo.git", "git://[REDACTED]@host/repo.git"),
        (
            "clone https://a:b@h1/x and https://tok@h2/y now",
            "clone https://[REDACTED]@h1/x and https://[REDACTED]@h2/y now",
        ),
    ],
)
def test_a_user_or_token_embedded_in_a_url_is_masked(text: str, expected: str) -> None:
    assert scrub_url_userinfo(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "https://github.com/org/repo.git",
        "ssh://git@github.com/org/repo.git",
        "git@github.com:org/repo.git",
        "mail me at someone@example.com",
        "https://example.com/path?email=a@b.com",
        "plain text",
    ],
)
def test_urls_without_embedded_user_info_are_left_alone(text: str) -> None:
    assert scrub_url_userinfo(text) == text


def test_scrubbing_walks_nested_results_and_keeps_other_values() -> None:
    value = {
        "data": [
            {"url": "https://u:p@github.com/o/r.git", "branch": "main", "count": 3},
            {"url": "ssh://git@github.com/o/r.git", "flags": [True, None]},
        ]
    }

    assert scrub_urls(value) == {
        "data": [
            {"url": "https://[REDACTED]@github.com/o/r.git", "branch": "main", "count": 3},
            {"url": "ssh://git@github.com/o/r.git", "flags": [True, None]},
        ]
    }


def test_the_audit_redactor_also_masks_urls_in_any_field() -> None:
    redacted = redact({"result": {"remote": "https://tok@github.com/o/r.git"}, "zone": "a.com"})

    assert redacted == {
        "result": {"remote": "https://[REDACTED]@github.com/o/r.git"},
        "zone": "a.com",
    }


def test_the_git_reads_are_typed_viewer_reads(tmp_path) -> None:
    capabilities = {item.id: item for item in Catalog(tmp_path / "missing.json").load()}

    for operation in ["uapi.VersionControl.retrieve", "uapi.VersionControlDeployment.retrieve"]:
        capability = capabilities[operation]
        assert capability.curated is True
        assert capability.available is True
        assert (capability.risk, capability.required_role) == (Risk.READ, Role.VIEWER)
        assert capability.input_schema["additionalProperties"] is False
        assert capability.input_schema["properties"] == {}


class GitCPanel:
    async def call(self, capability, account, arguments, *, retry_safe=False):
        assert capability.id == "uapi.VersionControl.retrieve"
        return {
            "status": 1,
            "data": [
                {
                    "type": "git",
                    "name": "site",
                    "repository_root": "/home/acct/repositories/site",
                    "url": "https://ghp_secrettoken@github.com/Semeion-Tech/site.git",
                    "branch": "main",
                }
            ],
        }


@pytest.mark.asyncio
async def test_a_git_read_never_returns_a_token_embedded_in_the_remote(harness, viewer) -> None:
    harness.cpanel = GitCPanel()

    result = await harness.query_execute(viewer, "uapi.VersionControl.retrieve", "acctalpha", {})

    assert result.ok is True
    remote = result.data["data"][0]["url"]
    assert remote == "https://[REDACTED]@github.com/Semeion-Tech/site.git"
    assert "ghp_secrettoken" not in str(result.data)
    assert "ghp_secrettoken" not in str(result.normalized_data)
    audit = harness.audit_search(viewer, limit=50)
    assert any(row["capability_id"] == "uapi.VersionControl.retrieve" for row in audit)
    assert "ghp_secrettoken" not in str(audit)
