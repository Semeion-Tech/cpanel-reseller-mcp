from __future__ import annotations

from reseller_mcp.normalizer import normalize_result


def test_file_content_normalization_keeps_metadata_without_raw_content() -> None:
    payload = {
        "status": 1,
        "data": {
            "dir": "/home2/outpromo/reservadesalas.outpromo.com.br",
            "file": "error_log",
            "encoding": "utf-8",
            "content": "line 1\nline 2\nline 3",
        },
    }

    normalized = normalize_result("uapi.Fileman.get_file_content", payload, "outpromo")

    assert normalized["dir"] == "/home2/outpromo/reservadesalas.outpromo.com.br"
    assert normalized["file"] == "error_log"
    assert normalized["encoding"] == "utf-8"
    assert normalized["content_present"] is True
    assert normalized["content_length_chars"] == 20
    assert normalized["line_count"] == 3
    assert "content" not in normalized
    assert "text" not in normalized
    assert "body" not in normalized


def test_file_content_normalization_summarizes_string_payload() -> None:
    normalized = normalize_result(
        "uapi.Fileman.get_file_content",
        "small payload",
        "outpromo",
    )

    assert normalized == {"content_present": True, "content_length_chars": 13, "line_count": 1}
