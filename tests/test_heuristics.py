from pathlib import Path

from triage.email_parser import parse_eml
from triage.heuristics import run_all_heuristics

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _evidence_for(email_path: str):
    parsed = parse_eml((FIXTURES / email_path).read_bytes())
    return run_all_heuristics(parsed)


def test_phishing_sample_flags_auth_failure():
    evidence = _evidence_for("phishing_sample.eml")
    auth = [e for e in evidence if e.category == "authentication"]
    assert auth and auth[0].severity == "malicious"


def test_phishing_sample_flags_display_name_spoofing():
    evidence = _evidence_for("phishing_sample.eml")
    spoof = [e for e in evidence if e.category == "sender_spoofing"]
    assert spoof and spoof[0].severity == "malicious"
    assert "paypal" in spoof[0].description.lower()


def test_phishing_sample_flags_reply_to_mismatch():
    evidence = _evidence_for("phishing_sample.eml")
    reply_to = [e for e in evidence if e.category == "reply_to"]
    assert reply_to and reply_to[0].severity == "suspicious"


def test_phishing_sample_flags_urgency_language():
    evidence = _evidence_for("phishing_sample.eml")
    urgency = [e for e in evidence if e.category == "social_engineering"]
    assert urgency and urgency[0].severity == "suspicious"


def test_phishing_sample_flags_ip_based_url():
    evidence = _evidence_for("phishing_sample.eml")
    url_evidence = [e for e in evidence if e.category == "suspicious_url"]
    assert any("raw IP" in e.description for e in url_evidence)


def test_phishing_sample_flags_link_text_mismatch():
    evidence = _evidence_for("phishing_sample.eml")
    mismatches = [e for e in evidence if e.category == "link_mismatch"]
    assert mismatches and mismatches[0].severity == "malicious"


def test_phishing_sample_flags_dangerous_attachment():
    evidence = _evidence_for("phishing_sample.eml")
    attachments = [e for e in evidence if e.category == "attachment"]
    assert attachments and attachments[0].severity == "malicious"
    assert "invoice.exe" in attachments[0].description


def test_legitimate_sample_has_no_malicious_evidence():
    evidence = _evidence_for("legitimate_sample.eml")
    assert not any(e.severity == "malicious" for e in evidence)


def test_legitimate_sample_auth_passes():
    evidence = _evidence_for("legitimate_sample.eml")
    auth = [e for e in evidence if e.category == "authentication"]
    assert auth and auth[0].severity == "info"
    assert "pass" in auth[0].description.lower()


def test_legitimate_sample_no_spoofing_flag():
    evidence = _evidence_for("legitimate_sample.eml")
    spoof = [e for e in evidence if e.category == "sender_spoofing"]
    assert spoof and spoof[0].severity == "info"
