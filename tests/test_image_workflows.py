from __future__ import annotations

import hashlib
import io
from typing import Any

import pytest
from PIL import Image

from reseller_mcp.catalog import Catalog
from reseller_mcp.cpanel import CPanelError
from reseller_mcp.harness import HarnessError
from reseller_mcp.models import Risk, Role

HOME = "/home1/acct"


def image(fmt: str = "PNG", color: tuple[int, int, int] = (0, 25, 103)) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (4, 4), color).save(buffer, format=fmt)
    return buffer.getvalue()


class ImageCPanel:
    """listfiles (API 2), domains_data and the session upload, in the live response shapes."""

    def __init__(self) -> None:
        self.dirs: dict[str, dict[str, bytes]] = {
            "public_html": {},
            "public_html/news/images": {"old.png": b"old"},
        }
        self.uploads: list[tuple[str, str, list[str]]] = []
        self.reject: set[str] = set()
        self.on_listing: Any = None

    async def call(self, capability, account, arguments, *, retry_safe=False):
        name = capability.id.rsplit(".", 1)[-1]
        if name == "listfiles":
            if self.on_listing:
                self.on_listing()
            directory = arguments["dir"].strip("/")
            if directory not in self.dirs:
                raise CPanelError(
                    f"The directory “{HOME}/{directory}” does not exist.",
                    code="UPSTREAM_OPERATION_FAILED",
                )
            return [
                {
                    "file": file,
                    "type": "file",
                    "size": str(len(data)),
                    "path": f"{HOME}/{directory}",
                    "fullpath": f"{HOME}/{directory}/{file}",
                }
                for file, data in self.dirs[directory].items()
            ]
        if name == "domains_data":
            return {
                "status": 1,
                "data": {
                    "main_domain": {
                        "domain": "example.com",
                        "documentroot": f"{HOME}/public_html",
                    },
                    "sub_domains": [
                        {"domain": "news.example.com", "documentroot": f"{HOME}/public_html/news"}
                    ],
                    "addon_domains": [],
                    "parked_domains": [],
                },
            }
        raise AssertionError(f"unexpected call {capability.id}")

    async def upload_files(self, account, directory, files, *, profile="operator"):
        self.uploads.append((account, directory, [file for file, _, _ in files]))
        target = self.dirs[directory]
        uploads = []
        for file, data, _ in files:
            ok = file not in self.reject
            if ok:
                target[file] = data
            uploads.append({"file": file, "size": len(data), "status": int(ok), "reason": ""})
        result = {
            "succeeded": sum(item["status"] for item in uploads),
            "failed": sum(1 - item["status"] for item in uploads),
            "uploads": uploads,
        }
        if result["failed"]:
            raise CPanelError(
                "cPanel did not accept every uploaded file", code="UPLOAD_FAILED", details=result
            )
        return result

    def public(self, url: str) -> bytes | None:
        prefix = {
            "https://news.example.com/": "public_html/news/",
            "https://example.com/": "public_html/",
        }
        for base, root in prefix.items():
            if url.startswith(base):
                directory, _, file = (root + url[len(base) :]).rpartition("/")
                return self.dirs.get(directory, {}).get(file)
        return None


@pytest.fixture
def env(harness, admin):
    cpanel = ImageCPanel()
    harness.cpanel = cpanel
    served: dict[str, bytes | None] = {}

    async def fetch(url: str) -> bytes | None:
        return served[url] if url in served else cpanel.public(url)

    harness.images.fetch = fetch
    return harness, admin, cpanel, served


def stage(harness, admin, name: str, data: bytes) -> str:
    return harness.image_staging.store(admin.user_id, name, data).id


def test_images_publish_is_a_curated_reversible_operator_write(tmp_path) -> None:
    capability = next(
        item
        for item in Catalog(tmp_path / "missing.json").load()
        if item.id == "workflow.images_publish"
    )
    assert (capability.risk, capability.required_role, capability.upstream_profile) == (
        Risk.REVERSIBLE_WRITE,
        Role.OPERATOR,
        "operator",
    )
    assert capability.curated


@pytest.mark.asyncio
async def test_batch_is_published_and_verified_by_public_sha256(env) -> None:
    harness, admin, cpanel, _ = env
    png, jpg = image("PNG"), image("JPEG")
    a = stage(harness, admin, "a.png", png)
    b = stage(harness, admin, "b.jpg", jpg)

    prepared = await harness.prepare_action(
        admin,
        "workflow.images_publish",
        "acctalpha",
        {
            "dir": "public_html/news/images",
            "items": [{"staging_id": a}, {"staging_id": b, "name": "hero-02.jpg"}],
        },
    )
    assert prepared["requires_confirmation"] is False
    urls = [item["url"] for item in prepared["before_state"]["items"]]
    assert urls == [
        "https://news.example.com/images/a.png",
        "https://news.example.com/images/hero-02.jpg",
    ]

    result = await harness.execute_action(admin, prepared["preparation_id"])

    assert (result.ok, result.verified) == (True, True), result
    assert cpanel.uploads == [("acctalpha", "public_html/news/images", ["a.png", "hero-02.jpg"])]
    published = {item["name"]: item for item in result.data["data"]["published"]}
    assert published["hero-02.jpg"]["sha256"] == hashlib.sha256(jpg).hexdigest()
    assert {item["public_sha256"] for item in published.values()} == {"match"}
    with pytest.raises(CPanelError):
        harness.image_staging.get(admin.user_id, a)


@pytest.mark.asyncio
async def test_existing_name_is_refused_at_prepare(env) -> None:
    harness, admin, _, _ = env
    staged = stage(harness, admin, "old.png", image())

    with pytest.raises((HarnessError, CPanelError)) as error:
        await harness.prepare_action(
            admin,
            "workflow.images_publish",
            "acctalpha",
            {"dir": "public_html/news/images", "items": [{"staging_id": staged}]},
        )
    assert "DESTINATION_EXISTS" in f"{getattr(error.value, 'code', '')} {error.value}"


@pytest.mark.asyncio
async def test_missing_directory_is_refused_at_prepare(env) -> None:
    harness, admin, _, _ = env
    staged = stage(harness, admin, "a.png", image())
    with pytest.raises((HarnessError, CPanelError)) as error:
        await harness.prepare_action(
            admin,
            "workflow.images_publish",
            "acctalpha",
            {"dir": "public_html/nope", "items": [{"staging_id": staged}]},
        )
    assert "DESTINATION_PARENT_MISSING" in f"{getattr(error.value, 'code', '')} {error.value}"


@pytest.mark.asyncio
@pytest.mark.parametrize("directory", ["public_html/../etc", "/home1/acct/public_html", "mail"])
async def test_directory_must_stay_inside_public_html(env, directory) -> None:
    harness, admin, _, _ = env
    staged = stage(harness, admin, "a.png", image())
    with pytest.raises((HarnessError, CPanelError)):
        await harness.prepare_action(
            admin,
            "workflow.images_publish",
            "acctalpha",
            {"dir": directory, "items": [{"staging_id": staged}]},
        )


@pytest.mark.asyncio
async def test_duplicate_names_and_wrong_extension_are_refused(env) -> None:
    harness, admin, _, _ = env
    a = stage(harness, admin, "a.png", image())
    b = stage(harness, admin, "b.png", image())
    for items, code in (
        ([{"staging_id": a}, {"staging_id": b, "name": "a.png"}], "DUPLICATE_NAME"),
        ([{"staging_id": a, "name": "a.jpg"}], "IMAGE_EXTENSION_MISMATCH"),
    ):
        with pytest.raises((HarnessError, CPanelError)) as error:
            await harness.prepare_action(
                admin,
                "workflow.images_publish",
                "acctalpha",
                {"dir": "public_html/news/images", "items": items},
            )
        assert code in f"{getattr(error.value, 'code', '')} {error.value}"


@pytest.mark.asyncio
async def test_staged_image_of_another_user_is_not_found(env) -> None:
    harness, admin, _, _ = env
    foreign = harness.image_staging.store("someone-else", "a.png", image()).id
    with pytest.raises((HarnessError, CPanelError)) as error:
        await harness.prepare_action(
            admin,
            "workflow.images_publish",
            "acctalpha",
            {"dir": "public_html/news/images", "items": [{"staging_id": foreign}]},
        )
    assert "STAGING_NOT_FOUND" in f"{getattr(error.value, 'code', '')} {error.value}"


@pytest.mark.asyncio
async def test_file_that_appears_before_execute_is_never_overwritten(env) -> None:
    harness, admin, cpanel, _ = env
    staged = stage(harness, admin, "a.png", image())
    prepared = await harness.prepare_action(
        admin,
        "workflow.images_publish",
        "acctalpha",
        {"dir": "public_html/news/images", "items": [{"staging_id": staged}]},
    )
    cpanel.dirs["public_html/news/images"]["a.png"] = b"someone else's"

    result = await harness.execute_action(admin, prepared["preparation_id"])

    assert result.ok is False
    assert result.error["code"] == "DESTINATION_EXISTS"
    assert cpanel.uploads == []
    assert cpanel.dirs["public_html/news/images"]["a.png"] == b"someone else's"


@pytest.mark.asyncio
async def test_public_url_serving_other_bytes_is_unverified(env) -> None:
    harness, admin, _, served = env
    staged = stage(harness, admin, "a.png", image())
    served["https://news.example.com/images/a.png"] = b"cached old bytes"
    prepared = await harness.prepare_action(
        admin,
        "workflow.images_publish",
        "acctalpha",
        {"dir": "public_html/news/images", "items": [{"staging_id": staged}]},
    )

    result = await harness.execute_action(admin, prepared["preparation_id"])

    assert result.verified is False
    assert result.data["data"]["published"][0]["public_sha256"] == "mismatch"
    assert any("different bytes" in warning for warning in result.warnings)


@pytest.mark.asyncio
async def test_partial_upload_reports_published_and_failed(env) -> None:
    harness, admin, cpanel, _ = env
    a = stage(harness, admin, "a.png", image())
    b = stage(harness, admin, "b.png", image(color=(255, 0, 0)))
    cpanel.reject = {"b.png"}
    prepared = await harness.prepare_action(
        admin,
        "workflow.images_publish",
        "acctalpha",
        {"dir": "public_html/news/images", "items": [{"staging_id": a}, {"staging_id": b}]},
    )

    result = await harness.execute_action(admin, prepared["preparation_id"])

    assert result.verified is False
    assert [item["name"] for item in result.data["data"]["published"]] == ["a.png"]
    assert result.data["data"]["failed"] == [{"name": "b.png"}]
    assert harness.image_staging.get(admin.user_id, b).name == "b.png"


@pytest.mark.asyncio
async def test_directory_outside_any_domain_root_publishes_without_url(env) -> None:
    harness, admin, cpanel, _ = env
    cpanel.dirs["public_html/assets"] = {}

    original = cpanel.call

    async def call(capability, account, arguments, *, retry_safe=False):
        if capability.id.endswith("domains_data"):
            raise CPanelError("unavailable")
        return await original(capability, account, arguments, retry_safe=retry_safe)

    cpanel.call = call  # type: ignore[method-assign]
    staged = stage(harness, admin, "a.png", image())
    prepared = await harness.prepare_action(
        admin,
        "workflow.images_publish",
        "acctalpha",
        {"dir": "public_html/assets", "items": [{"staging_id": staged}]},
    )
    assert prepared["before_state"]["items"][0]["url"] is None

    result = await harness.execute_action(admin, prepared["preparation_id"])

    assert (result.ok, result.verified) == (True, True)
    assert result.data["data"]["published"][0]["public_sha256"] is None
