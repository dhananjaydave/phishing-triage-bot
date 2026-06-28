from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch

import pytest

from triage.pipeline import MAX_INDICATORS_PER_EMAIL, triage_email

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(autouse=True)
def _no_real_whois_lookups():
    """Domain age is covered by its own test_domain_age.py with mocked WHOIS -
    these tests shouldn't also make real, slow network WHOIS calls."""
    with patch("triage.pipeline.check_domain_age", return_value=None):
        yield


async def _fake_enrich(indicator: str) -> dict:
    if indicator == "paypa1-secure.tk":
        return {"indicator": indicator, "status": "ok", "verdict": "malicious"}
    return {"indicator": indicator, "status": "ok", "verdict": "clean"}


async def test_phishing_sample_end_to_end_is_phishing():
    raw = (FIXTURES / "phishing_sample.eml").read_bytes()
    with patch("triage.pipeline.enrich_indicator", side_effect=_fake_enrich):
        report = await triage_email(raw)

    assert report.verdict == "phishing"
    assert any(e.severity == "malicious" for e in report.evidence)
    assert report.enrichment_results  # sender domain + URL domain + attachment hash all queried


async def test_legitimate_sample_end_to_end_is_legitimate():
    raw = (FIXTURES / "legitimate_sample.eml").read_bytes()
    with patch("triage.pipeline.enrich_indicator", side_effect=_fake_enrich):
        report = await triage_email(raw)

    assert report.verdict == "likely legitimate"


async def test_pipeline_gathers_expected_indicator_types():
    raw = (FIXTURES / "phishing_sample.eml").read_bytes()
    queried = []

    async def capturing_enrich(indicator: str) -> dict:
        queried.append(indicator)
        return {"indicator": indicator, "status": "ok", "verdict": "clean"}

    with patch("triage.pipeline.enrich_indicator", side_effect=capturing_enrich):
        await triage_email(raw)

    assert "paypa1-secure.tk" in queried  # sender domain
    assert "192.168.45.10" in queried  # URL "domain" (it's a bare IP here)
    assert any(len(q) == 64 for q in queried)  # attachment sha256


async def test_many_urls_are_capped_not_all_enriched():
    msg = EmailMessage()
    msg["Subject"] = "many links"
    msg["From"] = "a@example.com"
    body = "\n".join(f"http://site{i}.example.com/path" for i in range(50))
    msg.set_content(body)

    queried = []

    async def capturing_enrich(indicator: str) -> dict:
        queried.append(indicator)
        return {"indicator": indicator, "status": "ok", "verdict": "clean"}

    with patch("triage.pipeline.enrich_indicator", side_effect=capturing_enrich):
        await triage_email(msg.as_bytes())

    assert len(queried) <= MAX_INDICATORS_PER_EMAIL
