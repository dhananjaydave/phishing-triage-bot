"""Flask app hosting /health, the Telegram webhook, and a rate-limited
public demo of the triage pipeline (the bot itself is private/allowlisted,
so this is the only way someone besides the owner can actually try it).
Run locally: python -m triage.web
Run in prod: gunicorn wsgi:app   (see Procfile)
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path

from flask import Flask, jsonify, request

from . import telegram_bot
from .pipeline import triage_email

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.register_blueprint(telegram_bot.bp)
# Without this, Werkzeug buffers the entire request body into memory during
# parsing, before any in-route size check gets a chance to run - a large
# enough request could exhaust memory before _demo_max_bytes is ever checked.
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")
_STATIC_DIR = Path(__file__).resolve().parent / "static"

_initialized = False

# Public demo of the triage pipeline - separate from the private bot, so it
# needs its own abuse guards rather than relying on the Telegram allowlist.
DEMO_MAX_BYTES = 2 * 1024 * 1024  # 2MB - generous for a single email, not for abuse
DEMO_RATE_LIMIT_WINDOW_SECONDS = 3600
DEMO_RATE_LIMIT_MAX_REQUESTS = 5
_demo_request_log: dict[str, list[float]] = defaultdict(list)


@app.route("/")
def index():
    return (_STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.route("/health")
def health():
    return "ok", 200


def _client_ip() -> str:
    # CF-Connecting-IP is set by Cloudflare's edge and can't be spoofed by the
    # client - X-Forwarded-For can, which would otherwise make this rate
    # limit trivially bypassable (see the same fix in ioc-enrichment-api).
    cf_ip = request.headers.get("CF-Connecting-IP")
    return cf_ip.strip() if cf_ip else (request.remote_addr or "unknown")


def _demo_rate_limited(ip: str) -> bool:
    now = time.time()
    attempts = _demo_request_log[ip]
    attempts[:] = [t for t in attempts if now - t < DEMO_RATE_LIMIT_WINDOW_SECONDS]
    if len(attempts) >= DEMO_RATE_LIMIT_MAX_REQUESTS:
        return True
    attempts.append(now)
    return False


def _report_to_json(report) -> dict:
    return {
        "verdict": report.verdict,
        "subject": report.parsed.subject,
        "from_display_name": report.parsed.from_display_name,
        "from_address": report.parsed.from_address,
        "evidence": [asdict(e) for e in report.evidence],
        "enrichment_results": report.enrichment_results,
    }


@app.route("/demo/analyze", methods=["POST"])
def demo_analyze():
    if _demo_rate_limited(_client_ip()):
        return jsonify({"error": "Demo rate limit reached - try again later."}), 429

    raw: bytes | None = None

    uploaded = request.files.get("file")
    if uploaded and uploaded.filename:
        raw = uploaded.read(DEMO_MAX_BYTES + 1)
    else:
        raw_text = (request.form.get("raw_text") or "").strip()
        if raw_text:
            raw = raw_text.encode("utf-8", errors="replace")

    if not raw:
        return jsonify({"error": "Provide a .eml file or paste raw email source."}), 400
    if len(raw) > DEMO_MAX_BYTES:
        return jsonify({"error": f"Too large - keep it under {DEMO_MAX_BYTES // (1024 * 1024)}MB."}), 400

    try:
        report = asyncio.run(triage_email(raw))
    except Exception:
        logger.exception("Demo analyze failed")
        return jsonify({"error": "Couldn't parse that as an email."}), 400

    return jsonify(_report_to_json(report))


def init_app() -> None:
    """Runs once per real process start - kept separate from module-level
    code so importing this module never has side effects on its own."""
    global _initialized
    if _initialized:
        return
    _initialized = True
    telegram_bot.register_webhook(BASE_URL)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    init_app()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), debug=False)
