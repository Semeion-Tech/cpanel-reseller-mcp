from __future__ import annotations

from typing import Any

import pytest

from reseller_mcp.catalog import Catalog
from reseller_mcp.cpanel import CPanelError
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

    HOME = "/home2/acct"

    def _strip_home(self, path: str) -> str:
        return path.removeprefix(f"{self.HOME}/").strip("/")

    def _resolve_destination(self, path: str) -> str:
        if path.startswith(f"{self.HOME}/"):
            return self._strip_home(path)
        return f"public_html/{path.strip('/')}"

    async def call(self, capability, account, arguments, *, retry_safe=False):
        name = capability.id.rsplit(".", 1)[-1]
        self.calls.append((name, dict(arguments)))
        if name == "listfiles":
            directory = arguments["dir"].strip("/")
            if directory not in self.entries and directory not in {"", "."}:
                raise CPanelError(
                    f"The directory “/home2/acct/{directory}” does not exist.",
                    code="UPSTREAM_OPERATION_FAILED",
                )
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
            source = self._strip_home(arguments["sourcefiles"])
            parent, _, base = source.rpartition("/")
            kind = next((k for f, k in self.entries.get(parent, []) if f == base), "dir")
            if arguments["op"] in {"copy", "move"}:
                # Live behaviour: a relative destfiles is read from public_html, not the home.
                destination = self._resolve_destination(arguments["destfiles"])
                if destination in self.entries:  # an existing directory receives the item
                    self.entries[destination].append((base, kind))
                    self.entries[f"{destination}/{base}"] = list(self.entries.get(source, []))
                else:  # the destination is the final path
                    dest_parent, _, dest_name = destination.rpartition("/")
                    self.entries.setdefault(dest_parent, []).append((dest_name, kind))
                    self.entries[destination] = list(self.entries.get(source, []))
            if arguments["op"] in {"trash", "move"}:
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
@pytest.mark.parametrize("op", ["unlink", "rename", "chmod", "extract", "compress"])
async def test_only_trash_copy_and_move_are_accepted(harness, admin, op: str) -> None:
    harness.cpanel = FilesCPanel()
    with pytest.raises(HarnessError) as error:
        await harness.prepare_action(
            admin,
            "api2.Fileman.fileop",
            "acctalpha",
            {"op": op, "sourcefiles": "public_html/x", "destfiles": "public_html/y"},
        )
    assert error.value.code == "INVALID_ARGUMENTS"


async def _run_fileop(harness, admin, arguments: dict[str, str]):
    prepared = await harness.prepare_action(admin, "api2.Fileman.fileop", "acctalpha", arguments)
    assert prepared["confirmation_phrase"] == "CONFIRM fileop acctalpha"
    return await harness.execute_action(
        admin, prepared["preparation_id"], prepared["confirmation_phrase"]
    )


@pytest.mark.asyncio
async def test_copy_to_a_new_path_is_verified_as_the_final_path(harness, admin) -> None:
    harness.cpanel = FilesCPanel({"public_html": [("cgi-bin", "dir"), ("a", "dir")]})
    result = await _run_fileop(
        harness, admin, {"op": "copy", "sourcefiles": "public_html/a", "destfiles": "public_html/b"}
    )

    assert (result.ok, result.verified) == (True, True)
    assert result.after_state["placed_as"] == "final_path"
    assert {e[0] for e in harness.cpanel.entries["public_html"]} == {"cgi-bin", "a", "b"}


@pytest.mark.asyncio
async def test_copy_into_an_existing_directory_is_verified_as_inside_it(harness, admin) -> None:
    harness.cpanel = FilesCPanel(
        {"public_html": [("a", "dir"), ("target", "dir")], "public_html/target": []}
    )
    result = await _run_fileop(
        harness,
        admin,
        {"op": "copy", "sourcefiles": "public_html/a", "destfiles": "public_html/target"},
    )

    assert (result.ok, result.verified) == (True, True)
    assert result.after_state["placed_as"] == "inside_directory"
    assert ("a", "dir") in harness.cpanel.entries["public_html/target"]


@pytest.mark.asyncio
async def test_move_places_the_item_and_removes_the_source(harness, admin) -> None:
    harness.cpanel = FilesCPanel({"public_html": [("a", "dir")]})
    result = await _run_fileop(
        harness, admin, {"op": "move", "sourcefiles": "public_html/a", "destfiles": "public_html/b"}
    )

    assert (result.ok, result.verified) == (True, True)
    assert {e[0] for e in harness.cpanel.entries["public_html"]} == {"b"}


@pytest.mark.asyncio
@pytest.mark.parametrize("op", ["copy", "move"])
async def test_a_copy_or_move_that_changed_nothing_is_unverified(harness, admin, op: str) -> None:
    cpanel = FilesCPanel({"public_html": [("a", "dir")]})
    cpanel.silently_ignore_writes = True
    harness.cpanel = cpanel
    result = await _run_fileop(
        harness, admin, {"op": op, "sourcefiles": "public_html/a", "destfiles": "public_html/b"}
    )

    assert result.ok is False
    assert result.verified is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        ({"op": "copy", "sourcefiles": "public_html/a"}, "INVALID_ARGUMENTS"),
        ({"op": "move", "sourcefiles": "public_html/a", "destfiles": ""}, "INVALID_ARGUMENTS"),
        (
            {"op": "trash", "sourcefiles": "public_html/a", "destfiles": "public_html/b"},
            "INVALID_ARGUMENTS",
        ),
        (
            {"op": "copy", "sourcefiles": "public_html/a", "destfiles": "etc/a"},
            "PATH_OUTSIDE_ALLOWED_ROOT",
        ),
        (
            {"op": "move", "sourcefiles": "public_html/a", "destfiles": "public_html/../x"},
            "PATH_OUTSIDE_ALLOWED_ROOT",
        ),
        (
            {"op": "copy", "sourcefiles": "public_html/a", "destfiles": "public_html/a"},
            "PATH_OUTSIDE_ALLOWED_ROOT",
        ),
        (
            {"op": "copy", "sourcefiles": "public_html/a", "destfiles": "public_html/a/inside"},
            "PATH_OUTSIDE_ALLOWED_ROOT",
        ),
        (
            {
                "op": "copy",
                "sourcefiles": "public_html/a",
                "destfiles": "public_html/x,public_html/y",
            },
            "PATH_OUTSIDE_ALLOWED_ROOT",
        ),
        (
            {"op": "move", "sourcefiles": "public_html", "destfiles": "public_html/x"},
            "PATH_OUTSIDE_ALLOWED_ROOT",
        ),
    ],
)
async def test_copy_and_move_paths_are_confined_and_consistent(
    harness, admin, arguments: dict[str, str], code: str
) -> None:
    harness.cpanel = FilesCPanel()
    with pytest.raises(HarnessError) as error:
        await harness.prepare_action(admin, "api2.Fileman.fileop", "acctalpha", arguments)
    assert error.value.code == code
    assert harness.cpanel.calls == []


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
    assert fileop.input_schema["properties"]["op"]["enum"] == ["trash", "copy", "move"]
    assert fileop.input_schema["additionalProperties"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("entries", "arguments", "code"),
    [
        (
            {"public_html": [("a", "dir"), ("b", "file")]},
            {"op": "copy", "sourcefiles": "public_html/a", "destfiles": "public_html/b"},
            "DESTINATION_EXISTS",
        ),
        (
            {
                "public_html": [("a", "dir"), ("target", "dir")],
                "public_html/target": [("a", "dir")],
            },
            {"op": "move", "sourcefiles": "public_html/a", "destfiles": "public_html/target"},
            "DESTINATION_EXISTS",
        ),
        (
            {"public_html": [("cgi-bin", "dir")]},
            {"op": "copy", "sourcefiles": "public_html/ghost", "destfiles": "public_html/b"},
            "SOURCE_NOT_FOUND",
        ),
        (
            {"public_html": [("a", "dir")]},
            {"op": "copy", "sourcefiles": "public_html/a", "destfiles": "public_html/nope/b"},
            "DESTINATION_PARENT_MISSING",
        ),
    ],
)
async def test_copy_and_move_never_overwrite_and_need_an_existing_source(
    harness, admin, entries, arguments: dict[str, str], code: str
) -> None:
    harness.cpanel = FilesCPanel(entries)
    with pytest.raises(HarnessError) as error:
        await harness.prepare_action(admin, "api2.Fileman.fileop", "acctalpha", arguments)
    assert error.value.code == code
    assert not any(name in {"fileop"} for name, _ in harness.cpanel.calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("op", ["copy", "move"])
async def test_copy_and_move_send_absolute_paths_built_from_the_account_home(
    harness, admin, op: str
) -> None:
    harness.cpanel = FilesCPanel({"public_html": [("a", "dir")]})
    result = await _run_fileop(
        harness, admin, {"op": op, "sourcefiles": "public_html/a", "destfiles": "public_html/b"}
    )

    assert (result.ok, result.verified) == (True, True)
    sent = next(args for name, args in harness.cpanel.calls if name == "fileop")
    assert sent == {
        "op": op,
        "sourcefiles": "/home2/acct/public_html/a",
        "destfiles": "/home2/acct/public_html/b",
    }
    assert {e[0] for e in harness.cpanel.entries["public_html"]} >= {"b"}
    assert "public_html" not in harness.cpanel.entries.get("public_html", [])


@pytest.mark.asyncio
async def test_trash_keeps_the_relative_source_path(harness, admin) -> None:
    harness.cpanel = FilesCPanel({"public_html": [("a", "dir")]})
    await _run_fileop(harness, admin, {"op": "trash", "sourcefiles": "public_html/a"})

    sent = next(args for name, args in harness.cpanel.calls if name == "fileop")
    assert sent == {"op": "trash", "sourcefiles": "public_html/a"}
