"""Flask app hosting only /health and the Telegram webhook - no public
routes. Run locally: python -m triage.web
Run in prod:        gunicorn wsgi:app   (see Procfile)
"""

from __future__ import annotations

import logging
import os

from flask import Flask

from . import telegram_bot

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.register_blueprint(telegram_bot.bp)

BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")

_initialized = False


@app.route("/health")
def health():
    return "ok", 200


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
