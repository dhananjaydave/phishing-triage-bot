"""Checks how recently the sender's domain was registered via WHOIS.

This exists to close a real gap found by testing, not by review: a
sophisticated phishing email that registers its own domain (so SPF/DKIM/
DMARC genuinely pass), avoids known-brand names, and avoids urgency
wording sails straight past every other heuristic *and* IOC enrichment
(a brand-new domain has no reputation history yet - "unknown", not
"malicious"). A domain that's only days old sending a payment/credential
themed email is a strong signal on its own, regardless of what else
passes.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import whois

from .heuristics import Evidence

logger = logging.getLogger(__name__)

YOUNG_DOMAIN_MALICIOUS_DAYS = 7
YOUNG_DOMAIN_SUSPICIOUS_DAYS = 30
WHOIS_TIMEOUT_SECONDS = 5


def _lookup_creation_date(domain: str) -> datetime | None:
    try:
        result = whois.whois(domain)
    except Exception:
        return None

    created = result.creation_date
    if isinstance(created, list):
        created = created[0] if created else None
    if created is None:
        return None
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return created


async def check_domain_age(domain: str) -> Evidence | None:
    """Returns None if WHOIS data isn't available/times out - this degrades
    gracefully like every other enrichment step, rather than blocking or
    failing the whole report because one WHOIS server is slow or a TLD's
    registry doesn't expose creation dates."""
    try:
        created = await asyncio.wait_for(
            asyncio.to_thread(_lookup_creation_date, domain), timeout=WHOIS_TIMEOUT_SECONDS
        )
    except Exception:
        logger.warning("WHOIS lookup failed or timed out for %s", domain)
        return None

    if created is None:
        return None

    age_days = (datetime.now(timezone.utc) - created).days
    if age_days < 0:
        return None  # clock skew / bad data - don't report a nonsensical negative age

    if age_days < YOUNG_DOMAIN_MALICIOUS_DAYS:
        return Evidence(
            "domain_age", "malicious",
            f"Sending domain '{domain}' was registered only {age_days} day(s) ago.",
        )
    if age_days < YOUNG_DOMAIN_SUSPICIOUS_DAYS:
        return Evidence(
            "domain_age", "suspicious",
            f"Sending domain '{domain}' was registered {age_days} days ago - still quite new.",
        )
    return Evidence("domain_age", "info", f"Sending domain '{domain}' was registered {age_days} days ago.")
