"""Webhook-based Telegram bot for phishing email triage. Send a .eml file
(or paste raw email source as text) and get a verdict + full evidence report.

Private by design, same pattern as the Amul stock bot in the sibling
project: only chat ids in ALLOWED_TELEGRAM_CHAT_IDS get a response from
anything, verified after the X-Telegram-Bot-Api-Secret-Token header check.
"""

from __future__ import annotations

import asyncio
import logging
import os

import httpx
from flask import Blueprint, request

from .pipeline import TriageReport, triage_email

logger = logging.getLogger(__name__)

bp = Blueprint("telegram_bot", __name__)

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
WEBHOOK_SECRET = os.environ.get("TELEGRAM_WEBHOOK_SECRET")
API_BASE = f"https://api.telegram.org/bot{BOT_TOKEN}" if BOT_TOKEN else None

ALLOWED_CHAT_IDS = {
    chat_id.strip()
    for chat_id in os.environ.get("ALLOWED_TELEGRAM_CHAT_IDS", "").split(",")
    if chat_id.strip()
}

# Telegram's bot-API file download cap is 20MB; keep well under that.
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024

_SEVERITY_EMOJI = {"malicious": "\U0001F534", "suspicious": "\U0001F7E1", "info": "\U0001F7E2"}
_VERDICT_LABEL = {
    "phishing": "\U0001F6A8 LIKELY PHISHING",
    "suspicious": "⚠️ SUSPICIOUS",
    "likely legitimate": "✅ LIKELY LEGITIMATE",
}


def send_message(chat_id: int, text: str) -> None:
    if not API_BASE:
        logger.warning("TELEGRAM_BOT_TOKEN not set, dropping message to %s: %s", chat_id, text)
        return
    try:
        resp = httpx.post(f"{API_BASE}/sendMessage", json={"chat_id": chat_id, "text": text}, timeout=15)
        resp.raise_for_status()
    except Exception:
        logger.exception("Failed to send Telegram message to %s", chat_id)


def register_webhook(base_url: str) -> None:
    if not API_BASE:
        logger.info("TELEGRAM_BOT_TOKEN not set - bot disabled")
        return
    if not WEBHOOK_SECRET:
        logger.warning("TELEGRAM_WEBHOOK_SECRET not set - bot disabled (need it to verify webhook calls)")
        return
    if not ALLOWED_CHAT_IDS:
        logger.warning("ALLOWED_TELEGRAM_CHAT_IDS not set - bot will reject everyone until it's set")
    try:
        resp = httpx.post(
            f"{API_BASE}/setWebhook",
            json={"url": f"{base_url}/telegram/webhook", "secret_token": WEBHOOK_SECRET},
            timeout=15,
        )
        resp.raise_for_status()
        logger.info("Telegram webhook registered: %s", resp.json())
    except Exception:
        logger.exception("Failed to register Telegram webhook")


def _help_text() -> str:
    return (
        "Phishing Triage Bot\n\n"
        "Send me a .eml file - export the suspicious email as raw source "
        "first (Gmail: open it, click the three dots, 'Show original', then "
        "'Download original'; Outlook: File > Save As > choose .eml) - and "
        "I'll analyze headers, links, attachments, and sender authentication "
        "for phishing indicators, then send back a full evidence report.\n\n"
        "No file handy? Paste the raw email source as a text message instead."
    )


async def _download_telegram_file(file_id: str) -> bytes:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(f"{API_BASE}/getFile", params={"file_id": file_id})
        resp.raise_for_status()
        file_path = resp.json()["result"]["file_path"]
        file_resp = await client.get(f"https://api.telegram.org/file/bot{BOT_TOKEN}/{file_path}")
        file_resp.raise_for_status()
        return file_resp.content


def _format_report(report: TriageReport) -> str:
    lines = [
        _VERDICT_LABEL[report.verdict],
        "",
        f"Subject: {report.parsed.subject or '(none)'}",
        f"From: {report.parsed.from_display_name or ''} <{report.parsed.from_address or 'unknown'}>",
        "",
        "Evidence:",
    ]
    for evidence in report.evidence:
        lines.append(f"{_SEVERITY_EMOJI.get(evidence.severity, '')} [{evidence.category}] {evidence.description}")

    if report.enrichment_results:
        lines.append("")
        lines.append("IOC enrichment:")
        for result in report.enrichment_results:
            indicator = result.get("indicator", "?")
            status = result.get("status")
            if status == "skipped":
                lines.append(f"⚪ {indicator}: enrichment API not configured")
            elif status == "error":
                lines.append(f"⚪ {indicator}: lookup failed")
            else:
                verdict = result.get("verdict", "unknown")
                lines.append(f"{_SEVERITY_EMOJI.get(verdict, '')} {indicator}: {verdict}")

    return "\n".join(lines)


def _handle_eml_bytes(chat_id: int, raw: bytes) -> None:
    try:
        report = asyncio.run(triage_email(raw))
    except Exception:
        logger.exception("Triage failed for chat %s", chat_id)
        send_message(chat_id, "Couldn't parse that as an email - is it a valid .eml file or raw email source?")
        return
    send_message(chat_id, _format_report(report))


@bp.route("/telegram/webhook", methods=["POST"])
def webhook():
    if WEBHOOK_SECRET and request.headers.get("X-Telegram-Bot-Api-Secret-Token") != WEBHOOK_SECRET:
        return "forbidden", 403

    update = request.get_json(silent=True) or {}
    message = update.get("message") or {}
    chat_id = (message.get("chat") or {}).get("id")
    if not chat_id:
        return "ok", 200

    if str(chat_id) not in ALLOWED_CHAT_IDS:
        logger.warning("Rejected message from non-allowed chat_id=%s", chat_id)
        send_message(chat_id, "This bot is private.")
        return "ok", 200

    document = message.get("document")
    text = (message.get("text") or "").strip()

    if document:
        if document.get("file_size", 0) > MAX_FILE_SIZE_BYTES:
            send_message(chat_id, "That file's too large - keep it under 5MB.")
            return "ok", 200
        try:
            raw = asyncio.run(_download_telegram_file(document["file_id"]))
        except Exception:
            logger.exception("Failed to download document from chat %s", chat_id)
            send_message(chat_id, "Couldn't download that file from Telegram - try again.")
            return "ok", 200
        send_message(chat_id, "Analyzing...")
        _handle_eml_bytes(chat_id, raw)
        return "ok", 200

    if text in ("/start", "/help"):
        send_message(chat_id, _help_text())
        return "ok", 200

    if text and ("\nfrom:" in f"\n{text.lower()}"):
        send_message(chat_id, "Analyzing...")
        _handle_eml_bytes(chat_id, text.encode("utf-8", errors="replace"))
        return "ok", 200

    send_message(chat_id, "Send me a .eml file, or paste raw email source (starting with the headers). /help for details.")
    return "ok", 200
