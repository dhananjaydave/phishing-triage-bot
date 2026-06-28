"""Turns heuristic evidence + IOC enrichment results into one overall call.
Deliberately simple (any malicious signal wins, any suspicious signal short
of that) - the point of the report is the full evidence list, not a finely
tuned score the analyst can't audit."""

from __future__ import annotations

from .heuristics import Evidence


def compute_overall_verdict(evidence: list[Evidence], enrichment_results: list[dict]) -> str:
    malicious = any(e.severity == "malicious" for e in evidence) or any(
        r.get("verdict") == "malicious" for r in enrichment_results
    )
    if malicious:
        return "phishing"

    suspicious = any(e.severity == "suspicious" for e in evidence) or any(
        r.get("verdict") == "suspicious" for r in enrichment_results
    )
    if suspicious:
        return "suspicious"

    return "likely legitimate"
