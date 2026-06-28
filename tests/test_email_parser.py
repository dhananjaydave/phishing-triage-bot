from pathlib import Path

from triage.email_parser import parse_eml

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_parses_phishing_sample():
    parsed = parse_eml((FIXTURES / "phishing_sample.eml").read_bytes())

    assert parsed.from_display_name == "PayPal Security"
    assert parsed.from_address == "support@paypa1-secure.tk"
    assert parsed.reply_to == "scammer@randommail.example"
    assert parsed.spf == "fail"
    assert parsed.dkim == "none"
    assert parsed.dmarc == "fail"
    assert "45.33.32.156" in parsed.received_ips
    assert any("192.168.45.10" in url for url in parsed.urls)
    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].filename == "invoice.exe"
    # link text says paypal.com, href is a raw IP - exactly the mismatch this should catch
    assert any(m.display_text.startswith("https://paypal.com") for m in parsed.link_mismatches)


def test_parses_legitimate_sample():
    parsed = parse_eml((FIXTURES / "legitimate_sample.eml").read_bytes())

    assert parsed.from_display_name == "GitHub"
    assert parsed.from_address == "notifications@github.com"
    assert parsed.reply_to == "notifications@github.com"
    assert parsed.spf == "pass"
    assert parsed.dkim == "pass"
    assert parsed.dmarc == "pass"
    assert not parsed.attachments
    assert not parsed.link_mismatches
    assert any("github.com" in url for url in parsed.urls)


def test_private_received_ips_are_excluded():
    # 192.168.x.x in a Received header shouldn't show up as an "originating IP" IOC
    raw = b"From: a@b.com\nReceived: from x (x [192.168.1.5]) by y\n\nbody"
    parsed = parse_eml(raw)
    assert parsed.received_ips == []
