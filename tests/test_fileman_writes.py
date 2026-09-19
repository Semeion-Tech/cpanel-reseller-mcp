from __future__ import annotations

from typing import Any

import pytest

from reseller_mcp.catalog import Catalog
from reseller_mcp.harness import HarnessError
from reseller_mcp.models import Risk, Role


class FilesCPanel:
    """In-memory home with the listfiles response shape captured on the live server."""

    def __init__(self, entries: dict[str, list[tuple[str, str]]] | None = None) -> None:
        self.entries = {
            "public_html": [("cgi-bin", "dir")],
            **(entries or {}),
        }
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.silently_ignore_writes = False

    async def call(self, capability, account, arguments, *, retry_safe=False):
        name = capability.id.rsplit(".", 1)[-1]
        self.calls.append((name, dict(arguments)))
        if name == "listfiles":
            directory = arguments["dir"].strip("/")
            return [
                {
                    "file": file,
                    "type": kind,
                    "path": f"/home2/acct/{directory}",
                    "absdir": f"/home2/acct/{directory}",
                    "fullpath": f"/home2/acct/{directory}/{file}",
                    "nicemode": "0755",
                }
                for file, kind in self.entries.get(directory, [])
            ]
        if self.silently_ignore_writes:
            return []
        if name == "mkdir":
            parent = arguments["path"].strip("/")
            self.entries.setdefault(parent, []).append((arguments["name"], "dir"))
            self.entries.setdefault(f"{parent}/{arguments['name']}", [])
            return []
        if name == "fileop":
            parent, _, base = arguments["sourcefiles"].strip("/").rpartition("/")
            self.entries[parent] = [e for e in self.entries.get(parent, []) if e[0] != base]
            return []
        raise AssertionError(f"unexpected call: {name}")


@pytest.mark.asyncio
async def test_mkdir_creates_a_directory_and_verifies_it_from_the_listing(harness, admin) -> None:
    harness.cpanel = FilesCPanel()
    prepared = await harness.prepare_action(
        admin,
        "api2.Fileman.mkdir",
        "acctalpha",
        {"path": "public_html", "name": "assets", "permissions": "0750"},
    )

    assert prepared["risk"] == "reversible_write"
    assert prepared["requires_confirmation"] is False
    assert [item["file"] for item in prepared["before_state"]["data"]] == ["cgi-bin"]

    result = await harness.execute_action(admin, prepared["preparation_id"])

    assert (result.ok, result.verified) == (True, True)
    assert harness.cpanel.calls[-2] == (
        "mkdir",
        {"path": "public_html", "name": "assets", "permissions": "0750"},
    )


@pytest.mark.asyncio
async def test_mkdir_that_changed_nothing_is_reported_as_unverified(harness, admin) -> None:
    cpanel = FilesCPanel()
    cpanel.silently_ignore_writes = True
    harness.cpanel = cpanel
    prepared = await harness.prepare_action(
        admin, "api2.Fileman.mkdir", "acctalpha", {"path": "public_html", "name": "ghost"}
    )

    result = await harness.execute_action(admin, prepared["preparation_id"])

    assert result.ok is False
    assert result.verified is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    ["public_html/../etc", "etc", "/public_html", ".", "mail", "public_html/.ssh", "a,b", ""],
)
async def test_mkdir_is_confined_to_public_html(harness, admin, path: str) -> None:
    harness.cpanel = FilesCPanel()
    with pytest.raises(HarnessError) as error:
        await harness.prepare_action(
            admin, "api2.Fileman.mkdir", "acctalpha", {"path": path, "name": "x"}
        )
    assert error.value.code in {"PATH_OUTSIDE_ALLOWED_ROOT", "INVALID_ARGUMENTS"}
    assert harness.cpanel.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["a/b", "..", ".hidden", "", "-x", "a b", "x" * 129])
async def test_mkdir_name_must_be_a_single_safe_segment(harness, admin, name: str) -> None:
    harness.cpanel = FilesCPanel()
    with pytest.raises(HarnessError) as error:
        await harness.prepare_action(
            admin, "api2.Fileman.mkdir", "acctalpha", {"path": "public_html", "name": name}
        )
    assert error.value.code == "INVALID_ARGUMENTS"


@pytest.mark.asyncio
async def test_trash_needs_the_confirmation_phrase_and_verifies_removal(harness, admin) -> None:
    harness.cpanel = FilesCPanel({"public_html": [("cgi-bin", "dir"), ("old", "dir")]})
    prepared = await harness.prepare_action(
        admin,
        "api2.Fileman.fileop",
        "acctalpha",
        {"op": "trash", "sourcefiles": "public_html/old"},
    )

    assert prepared["risk"] == "destructive"
    assert prepared["confirmation_phrase"] == "CONFIRM fileop acctalpha"
    with pytest.raises(HarnessError) as error:
        await harness.execute_action(admin, prepared["preparation_id"], "nope")
    assert error.value.code == "CONFIRMATION_REQUIRED"

    result = await harness.execute_action(
        admin, prepared["preparation_id"], prepared["confirmation_phrase"]
    )

    assert (result.ok, result.verified) == (True, True)
    assert [entry[0] for entry in harness.cpanel.entries["public_html"]] == ["cgi-bin"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "source",
    [
        "public_html",
        "public_html/",
        "etc/passwd",
        "../x",
        "/public_html/a",
        "public_html/a,public_html/b",
    ],
)
async def test_trash_refuses_the_root_and_paths_outside_public_html(
    harness, admin, source: str
) -> None:
    harness.cpanel = FilesCPanel()
    with pytest.raises(HarnessError) as error:
        await harness.prepare_action(
            admin,
            "api2.Fileman.fileop",
            "acctalpha",
            {"op": "trash", "sourcefiles": source},
        )
    assert error.value.code in {"PATH_OUTSIDE_ALLOWED_ROOT", "INVALID_ARGUMENTS"}


@pytest.mark.asyncio
@pytest.mark.parametrize("op", ["unlink", "copy", "move", "chmod", "extract"])
async def test_only_the_trash_operation_is_accepted(harness, admin, op: str) -> None:
    harness.cpanel = FilesCPanel()
    with pytest.raises(HarnessError) as error:
        await harness.prepare_action(
            admin,
            "api2.Fileman.fileop",
            "acctalpha",
            {"op": op, "sourcefiles": "public_html/x", "destfiles": "public_html/y"},
        )
    assert error.value.code == "INVALID_ARGUMENTS"


def test_mkdir_and_fileop_are_curated_with_the_right_risk(tmp_path) -> None:
    capabilities = {item.id: item for item in Catalog(tmp_path / "missing.json").load()}

    mkdir = capabilities["api2.Fileman.mkdir"]
    assert (mkdir.risk, mkdir.required_role, mkdir.curated) == (
        Risk.REVERSIBLE_WRITE,
        Role.OPERATOR,
        True,
    )
    fileop = capabilities["api2.Fileman.fileop"]
    assert (fileop.risk, fileop.required_role) == (Risk.DESTRUCTIVE, Role.ADMIN)
    assert fileop.input_schema["properties"]["op"]["enum"] == ["trash"]
    assert fileop.input_schema["additionalProperties"] is False
