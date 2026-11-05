from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Annotated

import httpx
import typer

from .image_staging import IMAGE_NAME, MAX_BATCH_BYTES, MAX_BATCH_FILES, MAX_FILE_BYTES

DEFAULT_URL = "https://mcp-reseller.semeiontech.com/mcp"
MIME = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "webp": "image/webp",
    "gif": "image/gif",
    "avif": "image/avif",
}

app = typer.Typer(
    help=(
        "Send local images to the MCP staging area. Prints the staging IDs to pass to "
        "workflow.images_publish."
    ),
    add_completion=False,
)


def staging_url(mcp_url: str) -> str:
    base = mcp_url.rstrip("/")
    base = base.removesuffix("/mcp")
    return f"{base}/staging/images"


def collect(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(
                sorted(
                    item
                    for item in path.iterdir()
                    if item.is_file() and item.suffix.lower().lstrip(".") in MIME
                )
            )
        elif path.is_file():
            files.append(path)
        else:
            raise typer.BadParameter(f"{path} does not exist")
    if not files:
        raise typer.BadParameter("no image files to send")
    if len(files) > MAX_BATCH_FILES:
        raise typer.BadParameter(f"send at most {MAX_BATCH_FILES} files per batch")
    for file in files:
        if not IMAGE_NAME.match(file.name):
            raise typer.BadParameter(
                f"{file.name}: use lowercase letters, digits, '.', '_' or '-' and an image "
                "extension"
            )
        if file.stat().st_size > MAX_FILE_BYTES:
            raise typer.BadParameter(f"{file.name} exceeds {MAX_FILE_BYTES} bytes")
    if sum(file.stat().st_size for file in files) > MAX_BATCH_BYTES:
        raise typer.BadParameter(f"the batch exceeds {MAX_BATCH_BYTES} bytes")
    return files


@app.command()
def upload(
    paths: Annotated[list[Path], typer.Argument(help="Image files or folders (not recursive).")],
) -> None:
    token = os.environ.get("RESELLER_MCP_ACCESS_TOKEN", "")
    if not token:
        raise SystemExit("RESELLER_MCP_ACCESS_TOKEN is required")
    files = collect(paths)
    url = staging_url(os.environ.get("RESELLER_MCP_URL", DEFAULT_URL))
    parts = [
        (
            f"file-{index}",
            (file.name, file.read_bytes(), MIME[file.suffix.lower().lstrip(".")]),
        )
        for index, file in enumerate(files, start=1)
    ]
    try:
        response = httpx.post(
            url, headers={"Authorization": f"Bearer {token}"}, files=parts, timeout=300
        )
    except httpx.HTTPError as exc:
        raise SystemExit(f"could not reach {url}: {type(exc).__name__}") from None
    try:
        body = response.json()
    except ValueError:
        raise SystemExit(f"{url} answered HTTP {response.status_code} without JSON") from None
    typer.echo(json.dumps(body, ensure_ascii=False, indent=2))
    if response.status_code != 200 or body.get("rejected"):
        raise typer.Exit(1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
