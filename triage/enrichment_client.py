"""Calls the separately-deployed IOC Enrichment API for each indicator
extracted from an email (sender domain, URL domains, attachment hashes).
Degrades gracefully if that service is unreachable or unconfigured - a
triage report with partial enrichment beats one that crashes entirely.
"""

from __future__ import annotations

import logging
import os
import re

import httpx

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 15


def _base_url() -> str | None:
    url = os.environ.get("IOC_ENRICHMENT_API_URL")
    return url.rstrip("/") if url else None


async def enrich_indicator(indicator: str) -> dict:
    base_url = _base_url()
    if not base_url:
        return {"indicator": indicator, "status": "skipped", "reason": "IOC_ENRICHMENT_API_URL not configured"}

    headers = {}
    api_key = os.environ.get("IOC_ENRICHMENT_API_KEY")
    if api_key:
        headers["X-API-Key"] = api_key

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(f"{base_url}/enrich", params={"indicator": indicator}, headers=headers)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError as exc:
        logger.warning("Enrichment lookup failed for %s: %s", indicator, exc)
        return {"indicator": indicator, "status": "error", "reason": str(exc)}


def url_domain(url: str) -> str | None:
    match = re.search(r"https?://([^/\s]+)", url)
    if not match:
        return None
    return match.group(1).split("@")[-1].split(":")[0]
