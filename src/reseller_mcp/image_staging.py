from __future__ import annotations

import hashlib
import io
import re
import uuid
import warnings
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from PIL import Image

from .cpanel import CPanelError
from .db import Database

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_BATCH_BYTES = 40 * 1024 * 1024
MAX_BATCH_FILES = 20
MAX_PIXELS = 40_000_000
STAGING_TTL_SECONDS = 3600
# Pillow warns above this many pixels and refuses at twice as many; both become errors here.
Image.MAX_IMAGE_PIXELS = MAX_PIXELS

# Pillow format -> (MIME, extensions accepted for that format).
ALLOWED_FORMATS: dict[str, tuple[str, frozenset[str]]] = {
    "PNG": ("image/png", frozenset({"png"})),
    "JPEG": ("image/jpeg", frozenset({"jpg", "jpeg"})),
    "WEBP": ("image/webp", frozenset({"webp"})),
    "GIF": ("image/gif", frozenset({"gif"})),
    "AVIF": ("image/avif", frozenset({"avif"})),
}
IMAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,99}\.(png|jpe?g|webp|gif|avif)$")


@dataclass(frozen=True)
class StagedImage:
    id: str
    user_id: str
    name: str
    format: str
    mime: str
    width: int
    height: int
    size: int
    sha256: str
    created_at: str
    expires_at: str

    def public(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("user_id")
        value["staging_id"] = value.pop("id")
        return value


def validate_image_name(name: str) -> str:
    if not IMAGE_NAME.match(name) or ".." in name:
        raise CPanelError(
            f"{name!r} is not a valid image file name",
            code="IMAGE_NAME_INVALID",
            category="validation",
            hint="Use lowercase letters, digits, '.', '_' or '-' and an image extension.",
        )
    return name


def extension_matches(name: str, image_format: str) -> bool:
    return name.rsplit(".", 1)[-1] in ALLOWED_FORMATS[image_format][1]


def inspect_image(name: str, data: bytes) -> tuple[str, str, int, int]:
    """(format, mime, width, height) of a decodable image whose extension matches its bytes."""
    validate_image_name(name)
    if len(data) > MAX_FILE_BYTES:
        raise CPanelError(
            f"{name} exceeds {MAX_FILE_BYTES} bytes",
            code="IMAGE_TOO_LARGE",
            category="validation",
        )
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as probe:
                probe.verify()
            with Image.open(io.BytesIO(data)) as image:
                image_format = str(image.format or "")
                width, height = image.size
                image.load()
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise CPanelError(
            f"{name} exceeds {MAX_PIXELS} pixels",
            code="IMAGE_TOO_LARGE",
            category="validation",
        ) from None
    except Exception:
        raise CPanelError(
            f"{name} is not a decodable image",
            code="IMAGE_FORMAT_NOT_ALLOWED",
            category="validation",
        ) from None
    if image_format not in ALLOWED_FORMATS:
        raise CPanelError(
            f"{name} is {image_format or 'an unknown format'}; only "
            f"{', '.join(sorted(ALLOWED_FORMATS))} are allowed",
            code="IMAGE_FORMAT_NOT_ALLOWED",
            category="validation",
        )
    if width * height > MAX_PIXELS:
        raise CPanelError(
            f"{name} exceeds {MAX_PIXELS} pixels", code="IMAGE_TOO_LARGE", category="validation"
        )
    if not extension_matches(name, image_format):
        raise CPanelError(
            f"{name} has the extension of another format; its bytes are {image_format}",
            code="IMAGE_EXTENSION_MISMATCH",
            category="validation",
        )
    return image_format, ALLOWED_FORMATS[image_format][0], width, height


class ImageStaging:
    """Images received over HTTP, kept for a short while until a workflow publishes them.

    Files live next to the SQLite database (data/staging/<id>), rows in image_staging. A row is
    only visible to the user who uploaded it, and expires after STAGING_TTL_SECONDS.
    """

    def __init__(self, db: Database, root: Path):
        self.db = db
        self.root = root

    def _path(self, staging_id: str) -> Path:
        return self.root / staging_id

    def store(self, user_id: str, name: str, data: bytes) -> StagedImage:
        self.purge_expired()
        image_format, mime, width, height = inspect_image(name, data)
        now = datetime.now(UTC)
        item = StagedImage(
            id=uuid.uuid4().hex,
            user_id=user_id,
            name=name,
            format=image_format,
            mime=mime,
            width=width,
            height=height,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            created_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=STAGING_TTL_SECONDS)).isoformat(),
        )
        self.root.mkdir(parents=True, exist_ok=True)
        self._path(item.id).write_bytes(data)
        self.db.insert_staged_image(asdict(item))
        return item

    def get(self, user_id: str, staging_id: str) -> StagedImage:
        row = (
            self.db.get_staged_image(staging_id)
            if re.fullmatch(r"[0-9a-f]{32}", staging_id)
            else None
        )
        if (
            row is None
            or row["user_id"] != user_id
            or datetime.fromisoformat(row["expires_at"]) <= datetime.now(UTC)
            or not self._path(staging_id).is_file()
        ):
            raise CPanelError(
                f"staged image {staging_id!r} was not found or has expired",
                code="STAGING_NOT_FOUND",
                category="validation",
                hint="Upload it again with reseller-mcp-upload.",
            )
        return StagedImage(**row)

    def read(self, item: StagedImage) -> bytes:
        data = self._path(item.id).read_bytes()
        if hashlib.sha256(data).hexdigest() != item.sha256:
            raise CPanelError(f"staged image {item.id} changed on disk", code="STAGING_NOT_FOUND")
        return data

    def discard(self, staging_id: str) -> None:
        self._path(staging_id).unlink(missing_ok=True)
        self.db.delete_staged_image(staging_id)

    def purge_expired(self) -> int:
        expired = self.db.list_expired_staged_images()
        for staging_id in expired:
            self.discard(staging_id)
        return len(expired)
