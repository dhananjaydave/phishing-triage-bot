from unittest.mock import patch

import pytest

from triage import telegram_bot
from triage.heuristics import Evidence
from triage.pipeline import TriageReport
from triage.web import app


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(telegram_bot, "WEBHOOK_SECRET", "test-secret")
    monkeypatch.setattr(telegram_bot, "ALLOWED_CHAT_IDS", {"111"})
    return app.test_client()


def _post(client, payload, secret="test-secret"):
    headers = {"X-Telegram-Bot-Api-Secret-Token": secret} if secret else {}
    return client.post("/telegram/webhook", json=payload, headers=headers)


def test_rejects_wrong_secret(client):
    resp = _post(client, {"message": {"chat": {"id": 111}, "text": "/start"}}, secret="wrong")
    assert resp.status_code == 403


def test_rejects_non_allowed_chat(client):
    sent = []
    with patch.object(telegram_bot, "send_message", side_effect=lambda cid, text: sent.append((cid, text))):
        resp = _post(client, {"message": {"chat": {"id": 999}, "text": "/start"}})
    assert resp.status_code == 200
    assert sent == [(999, "This bot is private.")]


def test_start_command_sends_help(client):
    sent = []
    with patch.object(telegram_bot, "send_message", side_effect=lambda cid, text: sent.append((cid, text))):
        _post(client, {"message": {"chat": {"id": 111}, "text": "/start"}})
    assert sent and "Phishing Triage Bot" in sent[0][1]


def _fake_report() -> TriageReport:
    from triage.email_parser import ParsedEmail

    parsed = ParsedEmail(
        subject="test", from_address="a@b.com", from_display_name="A",
        reply_to=None, return_path=None, auth_results_raw="", spf="fail", dkim="none", dmarc="fail",
    )
    return TriageReport(
        parsed=parsed,
        evidence=[Evidence("authentication", "malicious", "SPF/DKIM/DMARC failed")],
        enrichment_results=[{"indicator": "b.com", "status": "ok", "verdict": "malicious"}],
        verdict="phishing",
    )


def test_pasted_raw_email_text_triggers_triage(client):
    sent = []
    raw_email = "From: a@b.com\nSubject: test\n\nbody"

    async def fake_triage(raw: bytes):
        assert b"From: a@b.com" in raw
        return _fake_report()

    with patch.object(telegram_bot, "send_message", side_effect=lambda cid, text: sent.append((cid, text))), \
         patch("triage.telegram_bot.triage_email", side_effect=fake_triage):
        _post(client, {"message": {"chat": {"id": 111}, "text": raw_email}})

    assert any("LIKELY PHISHING" in text for _, text in sent)
    assert any("Analyzing" in text for _, text in sent)


def test_document_upload_triggers_triage(client):
    sent = []

    async def fake_download(file_id: str) -> bytes:
        assert file_id == "file123"
        return b"From: a@b.com\n\nbody"

    async def fake_triage(raw: bytes):
        return _fake_report()

    with patch.object(telegram_bot, "send_message", side_effect=lambda cid, text: sent.append((cid, text))), \
         patch("triage.telegram_bot._download_telegram_file", side_effect=fake_download), \
         patch("triage.telegram_bot.triage_email", side_effect=fake_triage):
        _post(client, {
            "message": {
                "chat": {"id": 111},
                "document": {"file_id": "file123", "file_name": "sample.eml", "file_size": 1024},
            }
        })

    assert any("LIKELY PHISHING" in text for _, text in sent)


def test_oversized_document_is_rejected_without_download(client):
    sent = []
    with patch.object(telegram_bot, "send_message", side_effect=lambda cid, text: sent.append((cid, text))), \
         patch("triage.telegram_bot._download_telegram_file") as mock_download:
        _post(client, {
            "message": {
                "chat": {"id": 111},
                "document": {"file_id": "big", "file_name": "huge.eml", "file_size": 50 * 1024 * 1024},
            }
        })
    mock_download.assert_not_called()
    assert any("too large" in text for _, text in sent)
