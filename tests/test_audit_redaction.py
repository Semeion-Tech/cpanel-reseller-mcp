from __future__ import annotations

from reseller_mcp.audit import redact

PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"


def test_key_and_certificate_fields_are_redacted() -> None:
    parameters = {
        "domain": "example.com",
        "key": "anything",
        "cert": "anything",
        "cabundle": "anything",
        "csr": "anything",
        "private_key": "anything",
        "ssh_key": "anything",
        "password": "anything",
        "content": "anything",
    }

    redacted = redact(parameters)

    assert redacted["domain"] == "example.com"
    assert all(value == "[REDACTED]" for name, value in redacted.items() if name != "domain")


def test_a_private_key_pem_is_redacted_whatever_the_field_is_called() -> None:
    result = {"data": {"text": PEM, "items": [{"blob": PEM}, "plain"]}, "zone": "example.com"}

    redacted = redact(result)

    assert redacted["data"]["text"] == "[REDACTED]"
    assert redacted["data"]["items"] == [{"blob": "[REDACTED]"}, "plain"]
    assert redacted["zone"] == "example.com"


def test_a_public_certificate_and_ordinary_fields_are_kept() -> None:
    certificate = "-----BEGIN CERTIFICATE-----\nMIIDdz\n-----END CERTIFICATE-----"
    parameters = {
        "zone": "example.com",
        "name": "app",
        "value": "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A",
        "certificate_text": certificate,
        "idempotency": "abc",
    }

    assert redact(parameters) == parameters
