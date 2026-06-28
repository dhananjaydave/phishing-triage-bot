"""Orchestrates the full triage: parse -> heuristics -> IOC enrichment -> verdict."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from .email_parser import ParsedEmail, parse_eml
from .enrichment_client import enrich_indicator, url_domain
from .heuristics import Evidence, run_all_heuristics
from .verdict import compute_overall_verdict


@dataclass
class TriageReport:
    parsed: ParsedEmail
    evidence: list[Evidence]
    enrichment_results: list[dict]
    verdict: str


async def triage_email(raw: bytes) -> TriageReport:
    parsed = parse_eml(raw)
    evidence = run_all_heuristics(parsed)

    indicators: set[str] = set()
    if parsed.from_address and "@" in parsed.from_address:
        indicators.add(parsed.from_address.split("@")[-1].lower())
    for url in parsed.urls:
        domain = url_domain(url)
        if domain:
            indicators.add(domain)
    for attachment in parsed.attachments:
        indicators.add(attachment.sha256)

    enrichment_results = (
        list(await asyncio.gather(*(enrich_indicator(ind) for ind in indicators))) if indicators else []
    )

    verdict = compute_overall_verdict(evidence, enrichment_results)
    return TriageReport(parsed=parsed, evidence=evidence, enrichment_results=enrichment_results, verdict=verdict)
