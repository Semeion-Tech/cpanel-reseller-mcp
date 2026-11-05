from __future__ import annotations

import io
from datetime import UTC, datetime, timedelta

import pytest
from PIL import Image

from reseller_mcp.cpanel import CPanelError
from reseller_mcp.image_staging import ImageStaging, inspect_image


def image_bytes(fmt: str, size: tuple[int, int] = (8, 6)) -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", size, (0, 25, 103)).save(buffer, format=fmt)
    return buffer.getvalue()


@pytest.fixture
def staging(db, tmp_path) -> ImageStaging:
    return ImageStaging(db, tmp_path / "staging")


@pytest.mark.parametrize(
    ("name", "fmt", "mime"),
    [
        ("a.png", "PNG", "image/png"),
        ("b.jpg", "JPEG", "image/jpeg"),
        ("b.jpeg", "JPEG", "image/jpeg"),
        ("c.webp", "WEBP", "image/webp"),
        ("d.gif", "GIF", "image/gif"),
        ("e.avif", "AVIF", "image/avif"),
    ],
)
def test_allowed_formats_are_detected_from_bytes(name, fmt, mime) -> None:
    assert inspect_image(name, image_bytes(fmt)) == (fmt, mime, 8, 6)


@pytest.mark.parametrize(
    ("name", "data", "code"),
    [
        ("shell.png", b"<?php system($_GET['c']); ?>", "IMAGE_FORMAT_NOT_ALLOWED"),
        ("logo.svg", b"<svg xmlns='http://www.w3.org/2000/svg'/>", "IMAGE_NAME_INVALID"),
        ("photo.png", None, "IMAGE_EXTENSION_MISMATCH"),
        ("cut.png", "truncated", "IMAGE_FORMAT_NOT_ALLOWED"),
        ("Upper.png", None, "IMAGE_NAME_INVALID"),
        (".hidden.png", None, "IMAGE_NAME_INVALID"),
        ("a..png", None, "IMAGE_NAME_INVALID"),
        ("x.bmp", None, "IMAGE_NAME_INVALID"),
        ("anim.tiff", None, "IMAGE_NAME_INVALID"),
    ],
)
def test_rejected_files(name, data, code) -> None:
    if data is None:
        data = image_bytes("JPEG")
    elif data == "truncated":
        data = image_bytes("PNG")[:40]
    with pytest.raises(CPanelError) as error:
        inspect_image(name, data)
    assert error.value.code == code


def test_tiff_disguised_with_png_extension_is_rejected() -> None:
    with pytest.raises(CPanelError) as error:
        inspect_image("a.png", image_bytes("TIFF"))
    assert error.value.code == "IMAGE_FORMAT_NOT_ALLOWED"


def test_decompression_bomb_is_rejected() -> None:
    with pytest.raises(CPanelError) as error:
        inspect_image("big.png", image_bytes("PNG", (8000, 6000)))
    assert error.value.code == "IMAGE_TOO_LARGE"


def test_file_over_size_limit_is_rejected(monkeypatch) -> None:
    monkeypatch.setattr("reseller_mcp.image_staging.MAX_FILE_BYTES", 10)
    with pytest.raises(CPanelError) as error:
        inspect_image("a.png", image_bytes("PNG"))
    assert error.value.code == "IMAGE_TOO_LARGE"


def test_store_and_get_roundtrip(staging) -> None:
    data = image_bytes("PNG")
    item = staging.store("user-1", "a.png", data)

    again = staging.get("user-1", item.id)
    assert again == item
    assert staging.read(again) == data
    assert item.public()["staging_id"] == item.id and "user_id" not in item.public()


def test_other_users_cannot_see_staged_images(staging) -> None:
    item = staging.store("user-1", "a.png", image_bytes("PNG"))
    with pytest.raises(CPanelError) as error:
        staging.get("user-2", item.id)
    assert error.value.code == "STAGING_NOT_FOUND"


def test_unknown_or_malformed_ids_are_not_found(staging) -> None:
    for value in ("0" * 32, "../../etc/passwd", ""):
        with pytest.raises(CPanelError) as error:
            staging.get("user-1", value)
        assert error.value.code == "STAGING_NOT_FOUND"


def test_expired_images_are_purged(staging, db) -> None:
    item = staging.store("user-1", "a.png", image_bytes("PNG"))
    past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    with db.connect() as conn:
        conn.execute("UPDATE image_staging SET expires_at=? WHERE id=?", (past, item.id))

    with pytest.raises(CPanelError):
        staging.get("user-1", item.id)
    assert staging.purge_expired() == 1
    assert not (staging.root / item.id).exists()
    assert db.get_staged_image(item.id) is None


def test_discard_removes_file_and_row(staging, db) -> None:
    item = staging.store("user-1", "a.png", image_bytes("PNG"))
    staging.discard(item.id)
    assert not (staging.root / item.id).exists()
    assert db.get_staged_image(item.id) is None
