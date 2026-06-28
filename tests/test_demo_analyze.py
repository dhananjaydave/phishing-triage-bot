"""Tests for the public /demo/analyze endpoint - the only way someone
besides the bot owner can actually try the triage pipeline, since the
Telegram bot itself is private/allowlisted."""

from io import BytesIO
from pathlib import Path

import pytest

from triage import web
from triage.web import app

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def client():
    return app.test_client()


@pytest.fixture(autouse=True)
def _clear_demo_rate_limit():
    web._demo_request_log.clear()
    yield
    web._demo_request_log.clear()


def test_rejects_empty_submission(client):
    resp = client.post("/demo/analyze", data={})
    assert resp.status_code == 400


def test_analyzes_pasted_raw_text(client):
    raw_text = (FIXTURES / "phishing_sample.eml").read_text(encoding="utf-8", errors="replace")
    resp = client.post("/demo/analyze", data={"raw_text": raw_text})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["verdict"] == "phishing"
    assert any(e["severity"] == "malicious" for e in body["evidence"])


def test_analyzes_uploaded_file(client):
    raw_bytes = (FIXTURES / "legitimate_sample.eml").read_bytes()
    resp = client.post(
        "/demo/analyze",
        data={"file": (BytesIO(raw_bytes), "legitimate_sample.eml")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    assert resp.get_json()["verdict"] == "likely legitimate"


def test_eicar_attachment_flagged_via_dangerous_extension(client):
    """The EICAR test string is a standard, harmless file every AV vendor is
    designed to detect - used here purely to confirm a malicious-looking
    attachment gets flagged, without using any real malware. The attachment
    is only ever hashed (for IOC lookup) and structurally parsed by Python's
    stdlib email package - never executed, never written anywhere
    web-accessible, never opened by a vulnerable parser."""
    raw_bytes = (FIXTURES / "eicar_attachment_sample.eml").read_bytes()
    resp = client.post(
        "/demo/analyze",
        data={"file": (BytesIO(raw_bytes), "eicar_attachment_sample.eml")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["verdict"] == "phishing"
    attachment_evidence = [e for e in body["evidence"] if e["category"] == "attachment"]
    assert attachment_evidence and attachment_evidence[0]["severity"] == "malicious"


def test_rejects_garbage_input(client):
    resp = client.post("/demo/analyze", data={"raw_text": "\x00\x01 not an email at all"})
    # Garbage still "parses" under a permissive MIME reader (just empty
    # fields), so this should succeed with an empty/low-signal report rather
    # than crash - the real assertion is just that it doesn't 500.
    assert resp.status_code in (200, 400)


def test_rate_limit_enforced_per_ip(client, monkeypatch):
    monkeypatch.setattr(web, "DEMO_RATE_LIMIT_MAX_REQUESTS", 2)
    raw_text = (FIXTURES / "legitimate_sample.eml").read_text(encoding="utf-8", errors="replace")

    for _ in range(2):
        resp = client.post("/demo/analyze", data={"raw_text": raw_text}, headers={"CF-Connecting-IP": "203.0.113.9"})
        assert resp.status_code == 200

    blocked = client.post("/demo/analyze", data={"raw_text": raw_text}, headers={"CF-Connecting-IP": "203.0.113.9"})
    assert blocked.status_code == 429


def test_rate_limit_not_bypassable_via_spoofed_xff(client, monkeypatch):
    monkeypatch.setattr(web, "DEMO_RATE_LIMIT_MAX_REQUESTS", 1)
    raw_text = (FIXTURES / "legitimate_sample.eml").read_text(encoding="utf-8", errors="replace")
    real_ip = "203.0.113.10"

    client.post(
        "/demo/analyze", data={"raw_text": raw_text},
        headers={"CF-Connecting-IP": real_ip, "X-Forwarded-For": "1.1.1.1"},
    )
    blocked = client.post(
        "/demo/analyze", data={"raw_text": raw_text},
        headers={"CF-Connecting-IP": real_ip, "X-Forwarded-For": "9.9.9.9"},
    )
    assert blocked.status_code == 429


def test_oversized_text_rejected(client):
    huge_text = "From: a@b.com\n\n" + ("a" * (web.DEMO_MAX_BYTES + 1000))
    resp = client.post("/demo/analyze", data={"raw_text": huge_text})
    assert resp.status_code in (400, 413)


def test_response_never_leaks_raw_body_content(client):
    """The JSON response should only carry summary fields (subject, from,
    evidence, enrichment) - never the full body text/HTML, to avoid
    reflecting arbitrary attacker-controlled HTML back into API responses
    unnecessarily."""
    raw_text = (FIXTURES / "phishing_sample.eml").read_text(encoding="utf-8", errors="replace")
    resp = client.post("/demo/analyze", data={"raw_text": raw_text})
    body = resp.get_json()
    assert "body_text" not in body
    assert "body_html" not in body
    assert "<html>" not in str(body)
