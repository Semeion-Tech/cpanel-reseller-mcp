from __future__ import annotations

from typing import Any

import pytest

from reseller_mcp.harness import HarnessError


class FilesCPanel:
    """get_file_content and save_file_content over an in-memory home, like the live shapes."""

    def __init__(self, files: dict[str, str] | None = None) -> None:
        self.files = dict(files or {})
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.ignore_writes = False

    async def call(self, capability, account, arguments, *, retry_safe=False):
        name = capability.id.rsplit(".", 1)[-1]
        self.calls.append((name, dict(arguments)))
        key = f"{arguments['dir'].strip('/')}/{arguments['file']}"
        if name == "get_file_content":
            if key not in self.files:
                return {"status": 1, "data": {"content": "", "filename": arguments["file"]}}
            return {
                "status": 1,
                "data": {
                    "content": self.files[key],
                    "filename": arguments["file"],
                    "dir": f"/home/acct/{arguments['dir'].strip('/')}",
                },
            }
        if name == "save_file_content":
            if not self.ignore_writes:
                self.files[key] = arguments["content"]
            return {"status": 1, "data": {"path": f"/home/acct/{key}"}}
        raise AssertionError(f"unexpected call: {name}")

    def writes(self) -> list[dict[str, Any]]:
        return [args for name, args in self.calls if name == "save_file_content"]


async def _prepare(harness, admin, arguments: dict[str, Any]):
    return await harness.prepare_action(
        admin, "uapi.Fileman.save_file_content", "acctalpha", arguments
    )


@pytest.mark.asyncio
async def test_a_multiline_text_file_is_written_and_verified_by_its_content(harness, admin) -> None:
    harness.cpanel = FilesCPanel()
    content = 'User-agent: *\nDisallow: /private/\n\nSitemap: "https://example.com/s.xml"\n'
    prepared = await _prepare(
        harness, admin, {"dir": "public_html", "file": "robots.txt", "content": content}
    )

    assert prepared["risk"] == "reversible_write"
    assert prepared["requires_confirmation"] is False
    result = await harness.execute_action(admin, prepared["preparation_id"])

    assert (result.ok, result.verified) == (True, True)
    assert harness.cpanel.files["public_html/robots.txt"] == content


@pytest.mark.asyncio
async def test_a_write_that_changed_nothing_is_reported_as_unverified(harness, admin) -> None:
    cpanel = FilesCPanel()
    cpanel.ignore_writes = True
    harness.cpanel = cpanel
    prepared = await _prepare(
        harness, admin, {"dir": "public_html", "file": "a.txt", "content": "hello"}
    )

    result = await harness.execute_action(admin, prepared["preparation_id"])

    assert result.ok is False
    assert result.verified is False


@pytest.mark.asyncio
async def test_the_previous_content_is_kept_in_the_before_state(harness, admin) -> None:
    harness.cpanel = FilesCPanel({"public_html/a.txt": "old"})
    prepared = await _prepare(
        harness, admin, {"dir": "public_html", "file": "a.txt", "content": "new"}
    )

    assert prepared["before_state"]["data"]["content"] == "old"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "directory",
    ["../etc", "/etc", "etc", ".ssh", "mail", "public_html/../.ssh", "public_ftp", "tmp", ".", ""],
)
async def test_writes_are_confined_to_public_html(harness, admin, directory: str) -> None:
    harness.cpanel = FilesCPanel()
    with pytest.raises(HarnessError) as error:
        await _prepare(harness, admin, {"dir": directory, "file": "x.txt", "content": "x"})
    assert error.value.code in {"PATH_OUTSIDE_ALLOWED_ROOT", "INVALID_ARGUMENTS"}
    assert harness.cpanel.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["../x.txt", "a/b.txt", "..", ".", "a\\b", "x" * 256])
async def test_the_file_name_must_be_a_plain_name(harness, admin, name: str) -> None:
    harness.cpanel = FilesCPanel()
    with pytest.raises(HarnessError) as error:
        await _prepare(harness, admin, {"dir": "public_html", "file": name, "content": "x"})
    assert error.value.code in {"PATH_OUTSIDE_ALLOWED_ROOT", "INVALID_ARGUMENTS"}
    assert harness.cpanel.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name",
    [
        ".env",
        ".env.production",
        "wp-config.php",
        "configuration.php",
        "id_rsa",
        "server.pem",
        "private.key",
        ".htpasswd",
        ".my.cnf",
        "WP-CONFIG.PHP",
    ],
)
async def test_files_that_hold_secrets_are_never_written(harness, admin, name: str) -> None:
    harness.cpanel = FilesCPanel()
    with pytest.raises(HarnessError) as error:
        await _prepare(harness, admin, {"dir": "public_html", "file": name, "content": "x"})
    assert error.value.code == "SENSITIVE_TARGET_BLOCKED"
    assert harness.cpanel.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name",
    [
        "index.php",
        "page.phtml",
        "run.sh",
        "script.py",
        "cgi.cgi",
        ".htaccess",
        ".user.ini",
        "php.ini",
        "shell.PHP",
        "a.php8",
    ],
)
async def test_writing_a_file_the_server_executes_needs_the_confirmation_phrase(
    harness, admin, name: str
) -> None:
    harness.cpanel = FilesCPanel()
    prepared = await _prepare(harness, admin, {"dir": "public_html", "file": name, "content": "x"})

    assert prepared["requires_confirmation"] is True
    assert prepared["confirmation_phrase"] == "CONFIRM save_file_content acctalpha"
    with pytest.raises(HarnessError) as error:
        await harness.execute_action(admin, prepared["preparation_id"], "nope")
    assert error.value.code == "CONFIRMATION_REQUIRED"
    assert harness.cpanel.writes() == []

    result = await harness.execute_action(
        admin, prepared["preparation_id"], prepared["confirmation_phrase"]
    )
    assert (result.ok, result.verified) == (True, True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name",
    [
        "index.html",
        "style.css",
        "app.js",
        "data.json",
        "notes.md",
        "robots.txt",
        "feed.xml",
        "logo.svg",
        "readme",
    ],
)
async def test_static_and_text_files_need_no_phrase(harness, admin, name: str) -> None:
    harness.cpanel = FilesCPanel()
    prepared = await _prepare(
        harness, admin, {"dir": "public_html/site", "file": name, "content": "x"}
    )

    assert prepared["requires_confirmation"] is False


@pytest.mark.asyncio
async def test_content_over_the_limit_is_rejected(harness, admin) -> None:
    harness.cpanel = FilesCPanel()
    with pytest.raises(HarnessError) as error:
        await _prepare(
            harness, admin, {"dir": "public_html", "file": "big.txt", "content": "x" * 8193}
        )
    assert error.value.code == "INVALID_ARGUMENTS"
    assert harness.cpanel.calls == []

    prepared = await _prepare(
        harness, admin, {"dir": "public_html", "file": "ok.txt", "content": "x" * 8192}
    )
    assert prepared["preparation_id"]
