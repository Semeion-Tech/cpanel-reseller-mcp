from __future__ import annotations

import io

import pytest
from PIL import Image
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from reseller_mcp.auth import TokenService
from reseller_mcp.models import Role
from reseller_mcp.runtime import Runtime
from reseller_mcp.staging_route import staging_images_endpoint


def png() -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (4, 4), (0, 25, 103)).save(buffer, format="PNG")
    return buffer.getvalue()


@pytest.fixture
def env(settings, db, harness):
    tokens = TokenService(db, settings.token_pepper.get_secret_value())
    db.create_user("ops", Role.OPERATOR, ["*"])
    db.create_user("look", Role.VIEWER, ["*"])
    runtime = Runtime(
        settings=settings, db=db, tokens=tokens, cpanel=harness.cpanel, harness=harness
    )
    app = Starlette(
        routes=[Route("/staging/images", staging_images_endpoint(runtime), methods=["POST"])]
    )
    return {
        "client": TestClient(app),
        "operator": tokens.issue("ops", "test"),
        "viewer": tokens.issue("look", "test"),
        "harness": harness,
        "db": db,
    }


def post(env, token: str | None, files):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return env["client"].post("/staging/images", headers=headers, files=files)


def test_requires_a_valid_bearer_token(env) -> None:
    files = [("file-1", ("a.png", png(), "image/png"))]
    assert post(env, None, files).status_code == 401
    assert post(env, "rmcp_bad_token", files).status_code == 401


def test_viewer_role_is_forbidden(env) -> None:
    response = post(env, env["viewer"], [("file-1", ("a.png", png(), "image/png"))])
    assert response.status_code == 403


def test_mixed_batch_stages_valid_files_and_reports_rejected(env) -> None:
    response = post(
        env,
        env["operator"],
        [
            ("file-1", ("a.png", png(), "image/png")),
            ("file-2", ("x.png", b"<?php echo 1; ?>", "image/png")),
            ("file-3", ("logo.svg", b"<svg/>", "image/svg+xml")),
        ],
    )

    assert response.status_code == 200
    body = response.json()
    assert [item["name"] for item in body["items"]] == ["a.png"]
    assert {item["name"]: item["code"] for item in body["rejected"]} == {
        "x.png": "IMAGE_FORMAT_NOT_ALLOWED",
        "logo.svg": "IMAGE_NAME_INVALID",
    }
    item = body["items"][0]
    assert item["format"] == "PNG" and item["width"] == 4 and len(item["sha256"]) == 64
    user = env["db"].get_user("ops")
    assert env["harness"].image_staging.get(user["id"], item["staging_id"]).name == "a.png"
    rows = env["db"].audit_rows(None, 5)
    event = next(row for row in rows if row["capability_id"] == "staging.images")
    assert "a.png" in event["details"] and "<?php" not in event["details"]


def test_batch_over_limit_is_rejected_and_nothing_stays_staged(env, monkeypatch) -> None:
    monkeypatch.setattr("reseller_mcp.staging_route.MAX_BATCH_BYTES", len(png()) + 10)
    response = post(
        env,
        env["operator"],
        [("file-1", ("a.png", png(), "image/png")), ("file-2", ("b.png", png(), "image/png"))],
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "BATCH_TOO_LARGE"
    with env["db"].connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM image_staging").fetchone()[0] == 0


def test_request_without_files_is_invalid(env) -> None:
    response = env["client"].post(
        "/staging/images",
        headers={"Authorization": f"Bearer {env['operator']}"},
        data={"x": "1"},
    )
    assert response.status_code == 400
