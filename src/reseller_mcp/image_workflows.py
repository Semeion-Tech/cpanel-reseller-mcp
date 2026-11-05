from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx

from .cpanel import CPanelError
from .image_staging import MAX_BATCH_BYTES, MAX_BATCH_FILES, extension_matches, validate_image_name
from .models import Preparation

if TYPE_CHECKING:
    from .harness import Harness

# The user preparing an action; prepare hooks only receive (account, arguments).
PREPARING_USER: ContextVar[str | None] = ContextVar("preparing_user", default=None)

Fetch = Callable[[str], Awaitable[bytes | None]]


async def fetch_public(url: str) -> bytes | None:
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            response = await client.get(url, headers={"Cache-Control": "no-cache"})
    except httpx.HTTPError:
        return None
    return response.content if response.status_code == 200 else None


class ImageWorkflows:
    """Publish staged images into a directory inside public_html, never overwriting.

    The bytes reach the server through POST /staging/images (reseller-mcp-upload); this
    workflow only references staging IDs. The upload goes through a cPanel user session
    (CPanelClient.upload_files) with overwrite=0, and each file is verified by listing and,
    when the directory maps to a domain, by the SHA-256 of its public URL.
    """

    def __init__(self, harness: Harness, fetch: Fetch = fetch_public):
        self.harness = harness
        self.fetch = fetch

    async def prepare_publish(
        self, account: str | None, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        if not account:
            raise CPanelError("image workflows require an account", code="ACCOUNT_REQUIRED")
        user_id = PREPARING_USER.get()
        if not user_id:
            raise CPanelError("the preparing user is unknown", code="STAGING_NOT_FOUND")
        directory = str(arguments["dir"]).strip().strip("/")
        items = list(arguments["items"])
        if len(items) > MAX_BATCH_FILES:
            raise CPanelError(
                f"publish at most {MAX_BATCH_FILES} images per action",
                code="BATCH_TOO_LARGE",
                category="validation",
            )
        planned: list[dict[str, Any]] = []
        for entry in items:
            staged = self.harness.image_staging.get(user_id, str(entry["staging_id"]))
            name = validate_image_name(str(entry.get("name") or staged.name))
            if not extension_matches(name, staged.format):
                raise CPanelError(
                    f"{name} has the extension of another format; the image is {staged.format}",
                    code="IMAGE_EXTENSION_MISMATCH",
                    category="validation",
                )
            planned.append(
                {
                    "staging_id": staged.id,
                    "name": name,
                    "format": staged.format,
                    "mime": staged.mime,
                    "size": staged.size,
                    "sha256": staged.sha256,
                }
            )
        names = [item["name"] for item in planned]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise CPanelError(
                "the batch repeats file names",
                code="DUPLICATE_NAME",
                category="validation",
                details={"names": duplicates},
            )
        if sum(item["size"] for item in planned) > MAX_BATCH_BYTES:
            raise CPanelError(
                f"the batch exceeds {MAX_BATCH_BYTES} bytes",
                code="BATCH_TOO_LARGE",
                category="validation",
            )
        listing = await self._listing(account, directory)
        self._refuse_existing(listing, names)
        base_url = await self._public_base(account, directory)
        for item in planned:
            item["url"] = f"{base_url}/{quote(item['name'])}" if base_url else None
        return {"dir": directory, "items": planned, "listing": listing}

    async def execute_publish(self, preparation: Preparation) -> dict[str, Any]:
        account = str(preparation.account)
        before = preparation.before_state or {}
        directory = str(before["dir"])
        planned: list[dict[str, Any]] = list(before["items"])
        staging = self.harness.image_staging
        files: list[tuple[str, bytes, str]] = []
        for item in planned:
            staged = staging.get(preparation.principal_user_id, item["staging_id"])
            files.append((item["name"], staging.read(staged), item["mime"]))
        # Something may have appeared between prepare and execute; never overwrite it.
        self._refuse_existing(await self._listing(account, directory), [n for n, _, _ in files])
        failure: CPanelError | None = None
        try:
            result = await self.harness.cpanel.upload_files(account, directory, files)
            uploaded = {item["file"] for item in result["uploads"] if item["status"] == 1}
        except CPanelError as exc:
            if exc.code != "UPLOAD_FAILED":
                raise
            failure = exc
            uploads = (exc.details or {}).get("uploads") or []
            uploaded = {item["file"] for item in uploads if item.get("status") == 1}
        after = await self._listing(account, directory)
        sizes = {str(entry.get("file")): str(entry.get("size", "")) for entry in after}
        published: list[dict[str, Any]] = []
        failed: list[dict[str, Any]] = []
        warnings: list[str] = []
        verified = failure is None
        for item in planned:
            name = item["name"]
            listed = name in sizes and sizes[name] in {"", str(item["size"])}
            if name not in uploaded and not listed:
                failed.append({"name": name})
                verified = False
                continue
            if not listed:
                warnings.append(f"{name} is not listed with the expected size after the upload")
                verified = False
            check: str | None = None
            if item.get("url"):
                body = await self.fetch(item["url"])
                if body is None:
                    check = "unreachable"
                    warnings.append(f"{item['url']} did not answer HTTP 200")
                elif hashlib.sha256(body).hexdigest() != item["sha256"]:
                    check = "mismatch"
                    warnings.append(f"{item['url']} serves different bytes than were staged")
                else:
                    check = "match"
                if check != "match":
                    verified = False
            published.append(
                {
                    "name": name,
                    "path": f"{directory}/{name}",
                    "url": item.get("url"),
                    "size": item["size"],
                    "sha256": item["sha256"],
                    "public_sha256": check,
                }
            )
            staging.discard(item["staging_id"])
        if failure is not None:
            warnings.append(f"cPanel did not accept every file: {failure}")
        return {
            "data": {"dir": directory, "published": published, "failed": failed},
            "after_state": after,
            "verified": verified and not failed,
            "warnings": warnings,
        }

    async def _listing(self, account: str, directory: str) -> list[dict[str, Any]]:
        capability = self.harness._get_capability("api2.Fileman.listfiles")
        try:
            result = await self.harness.cpanel.call(
                capability, account, {"dir": directory}, retry_safe=True
            )
        except CPanelError as exc:
            if "does not exist" in str(exc) or "não existe" in str(exc):
                raise CPanelError(
                    f"the directory {directory} does not exist",
                    code="DESTINATION_PARENT_MISSING",
                    category="validation",
                    hint="Create it first with api2.Fileman.mkdir.",
                ) from None
            raise
        return [
            item for item in (result if isinstance(result, list) else []) if isinstance(item, dict)
        ]

    @staticmethod
    def _refuse_existing(listing: list[dict[str, Any]], names: list[str]) -> None:
        present = {str(entry.get("file")) for entry in listing}
        clash = sorted(name for name in names if name in present)
        if clash:
            raise CPanelError(
                "files with these names already exist; images are never overwritten",
                code="DESTINATION_EXISTS",
                category="validation",
                details={"names": clash},
                hint="Publish under a new name (for example with a -02 suffix).",
            )

    async def _public_base(self, account: str, directory: str) -> str | None:
        """https://<domain>/<path> of the directory, from the most specific document root."""
        capability = self.harness._get_capability("uapi.DomainInfo.domains_data")
        try:
            result = await self.harness.cpanel.call(
                capability, account, {"format": "hash"}, retry_safe=True
            )
        except CPanelError:
            return None
        data = result.get("data") if isinstance(result, dict) else None
        if not isinstance(data, dict):
            return None
        main = data.get("main_domain")
        root = str(main.get("documentroot", "")) if isinstance(main, dict) else ""
        home = root.rstrip("/").removesuffix("/public_html")
        if not home.startswith("/"):
            return None
        target = f"{home}/{directory}".rstrip("/")
        candidates: list[tuple[str, str]] = []
        for key in ("main_domain", "sub_domains", "addon_domains"):
            value = data.get(key)
            for entry in value if isinstance(value, list) else [value]:
                if isinstance(entry, dict) and entry.get("domain") and entry.get("documentroot"):
                    candidates.append(
                        (str(entry["documentroot"]).rstrip("/"), str(entry["domain"]))
                    )
        matches = [
            (docroot, domain)
            for docroot, domain in candidates
            if target == docroot or target.startswith(f"{docroot}/")
        ]
        if not matches:
            return None
        docroot, domain = max(matches, key=lambda pair: len(pair[0]))
        relative = target[len(docroot) :].strip("/")
        path = "/".join(quote(part) for part in relative.split("/") if part)
        return f"https://{domain}" + (f"/{path}" if path else "")
