# Phishing Triage Bot

Send a suspicious email to a private Telegram bot and get back a verdict
**plus the full evidence behind it** - which headers failed authentication,
which links don't go where their text says, which brand the sender is
impersonating, which attachment is dangerous - not just a "phishing/safe"
label you have to trust blindly.

```
🚨 LIKELY PHISHING

Subject: Urgent: Your account will be suspended - verify now
From: PayPal Security <support@paypa1-secure.tk>

Evidence:
🔴 [authentication] SPF/DMARC failed - the sending server isn't authorized to send as this domain.
🔴 [sender_spoofing] Display name claims to be 'PayPal Security' (brand: paypal), but the actual sending domain is 'paypa1-secure.tk', not paypal.com.
🟡 [reply_to] Reply-To domain (randommail.example) differs from the From domain (paypa1-secure.tk) - replies get redirected somewhere other than the apparent sender.
🟡 [social_engineering] Urgency/pressure language found: urgent, act now, immediately, click here, unusual activity.
🔴 [suspicious_url] Link uses a raw IP address instead of a domain: http://192.168.45.10/paypal-verify
🔴 [link_mismatch] Link text 'https://paypal.com/verify' doesn't match where it actually points (http://192.168.45.10/paypal-verify).
🔴 [attachment] Attachment 'invoice.exe' has a dangerous extension for an email attachment.
```

## Why this exists

This is the second piece in a small security-automation series (the first
is [ioc-enrichment-api](https://github.com/dhananjaydave/ioc-enrichment-api),
which this bot calls for every indicator it extracts). Together they're a
real, runnable version of the classic "phishing email triage" SOAR workflow
you'd otherwise build in Tines or Splunk SOAR - except this one you can
actually demo and explain line by line.

## How it works

1. **`email_parser.py`** parses a raw `.eml` (stdlib `email` package only -
   no third-party mail-parsing dependency) into headers, body text/HTML,
   every URL, every `<a>` tag's (visible text, actual href) pair, and every
   attachment's filename + SHA256.
2. **`heuristics.py`** runs seven independent checks, each returning
   evidence at `malicious`/`suspicious`/`info` severity - including the
   "this looks fine" results, not just red flags, so the report stays
   auditable:
   - SPF/DKIM/DMARC authentication results
   - Display-name brand impersonation (e.g. "PayPal" display name, non-PayPal
     sending domain)
   - Reply-To vs From domain mismatch
   - Urgency/pressure language ("verify your account", "act now", ...)
   - Suspicious URLs: raw IP links, URL shorteners, abused TLDs, and
     Levenshtein-distance lookalike domains (`paypa1.com` vs `paypal.com`)
   - Link text that doesn't match where it actually points
   - Dangerous attachment extensions
3. **`enrichment_client.py`** sends every extracted indicator (sender
   domain, each URL's domain, each attachment hash) to the IOC Enrichment
   API and folds its verdict into the report. If that service isn't
   configured or is unreachable, those entries just show "not configured" -
   the heuristic checks above don't depend on it.
4. **`verdict.py`** combines heuristic evidence + enrichment verdicts into
   one overall call: any `malicious` signal anywhere means `phishing`, any
   `suspicious` signal short of that means `suspicious`, otherwise `likely
   legitimate`. Deliberately simple and auditable rather than a tuned score
   nobody can explain.
5. **`telegram_bot.py`** + **`web.py`** - a private, webhook-based Telegram
   bot (same allowlist pattern as a sibling project: wrong webhook secret or
   a chat id not in `ALLOWED_TELEGRAM_CHAT_IDS` gets nothing). Send it a
   `.eml` file, or paste raw email source as text if you don't have a file
   to upload.

## Setup

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
copy .env.example .env
```

1. Message [@BotFather](https://t.me/BotFather), `/newbot`, put the token in
   `TELEGRAM_BOT_TOKEN`. **Use a separate bot from any other project** -
   Telegram allows only one webhook per token.
2. Generate a webhook secret: `python -c "import secrets; print(secrets.token_urlsafe(32))"`
   → `TELEGRAM_WEBHOOK_SECRET`.
3. Message [@userinfobot](https://t.me/userinfobot) for your numeric chat id
   → `ALLOWED_TELEGRAM_CHAT_IDS`.
4. If you've deployed [ioc-enrichment-api](https://github.com/dhananjaydave/ioc-enrichment-api),
   set `IOC_ENRICHMENT_API_URL` (and `IOC_ENRICHMENT_API_KEY` if you set one
   there). Leave both unset to skip enrichment - the heuristic checks still
   run fully on their own.
5. Set `BASE_URL` to wherever this is publicly reachable (your Render URL in
   prod; a tunnel like `ngrok http 8000` to test the bot against a local run
   - plain `localhost` can't receive Telegram's webhook calls).

```powershell
python -m triage.web
pytest -v   # 33 tests, all mocked - no API keys or live Telegram needed
```

## Deploying for free on Render.com

Same pattern as the sibling Amul-stock project: `render.yaml` + `Procfile`
are ready for Render's free tier. Push to GitHub, **New + Blueprint** on
Render, fill in the env vars it leaves blank, done. Free tier sleeps after
~15 min idle - a free pinger (cron-job.org/UptimeRobot) hitting `/health`
keeps it awake if you want it always-on.

## Known limitations

- Triage runs synchronously inside the webhook handler. For a personal,
  low-volume bot this is fine (a handful of parallel enrichment calls
  finishes in a few seconds); a sibling project hit a real bug from this
  exact pattern once volume/latency grew (see `/recheck` in the Amul repo) -
  worth revisiting with a background job if this ever gets busy.
- The brand list for impersonation/lookalike detection is small and
  deliberately curated (well-known brands), not exhaustive.
- No OCR/image analysis - a phishing email that's just an image with no
  text/links won't trigger much.
