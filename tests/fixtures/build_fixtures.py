"""Generates the .eml fixtures used by the test suite. Run manually if the
fixtures ever need regenerating:
    python tests/fixtures/build_fixtures.py
"""

from email.message import EmailMessage
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent


def build_phishing_sample() -> bytes:
    msg = EmailMessage()
    msg["Subject"] = "Urgent: Your account will be suspended - verify now"
    msg["From"] = '"PayPal Security" <support@paypa1-secure.tk>'
    msg["To"] = "victim@example.com"
    msg["Reply-To"] = "scammer@randommail.example"
    msg["Authentication-Results"] = "mx.example.com; spf=fail smtp.mailfrom=paypa1-secure.tk; dkim=none; dmarc=fail"
    msg["Received"] = "from unknown (unknown [45.33.32.156]) by mx.example.com"

    msg.set_content(
        "Dear Customer,\n\n"
        "We have detected unusual activity on your account. Your account will be "
        "suspended unless you verify your identity immediately. Click here to confirm: "
        "http://192.168.45.10/paypal-verify\n\n"
        "Act now to avoid suspension.\n"
    )
    msg.add_alternative(
        """\
        <html><body>
        <p>Dear Customer,</p>
        <p>We have detected unusual activity on your account. Your account will be
        suspended unless you verify your identity immediately.</p>
        <p><a href="http://192.168.45.10/paypal-verify">https://paypal.com/verify</a></p>
        <p>Act now to avoid suspension.</p>
        </body></html>
        """,
        subtype="html",
    )
    msg.add_attachment(b"MZ\x90\x00fake-binary-content", maintype="application", subtype="octet-stream", filename="invoice.exe")
    return msg.as_bytes()


def build_legitimate_sample() -> bytes:
    msg = EmailMessage()
    msg["Subject"] = "Your weekly digest"
    msg["From"] = '"GitHub" <notifications@github.com>'
    msg["To"] = "user@example.com"
    msg["Reply-To"] = "notifications@github.com"
    msg["Authentication-Results"] = "mx.example.com; spf=pass smtp.mailfrom=github.com; dkim=pass header.i=@github.com; dmarc=pass"
    msg["Received"] = "from out-1.smtp.github.com (out-1.smtp.github.com [140.82.112.1]) by mx.example.com"

    msg.set_content(
        "Hi there,\n\nHere's your weekly digest of activity. "
        "View it at https://github.com/notifications\n\nThanks,\nThe GitHub Team\n"
    )
    msg.add_alternative(
        """\
        <html><body>
        <p>Hi there,</p>
        <p>Here's your weekly digest of activity.</p>
        <p><a href="https://github.com/notifications">View on GitHub</a></p>
        <p>Thanks,<br>The GitHub Team</p>
        </body></html>
        """,
        subtype="html",
    )
    return msg.as_bytes()


def build_eicar_attachment_sample() -> bytes:
    """Uses the standard EICAR test string (https://en.wikipedia.org/wiki/EICAR_test_file)
    - a harmless string every AV vendor is designed to flag as malicious, used
    precisely so malware-handling code paths can be tested without using any
    real malware."""
    eicar = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    msg = EmailMessage()
    msg["Subject"] = "Test attachment"
    msg["From"] = "tester@example.com"
    msg.set_content("See attached.")
    msg.add_attachment(eicar, maintype="application", subtype="octet-stream", filename="eicar_test.com")
    return msg.as_bytes()


if __name__ == "__main__":
    (FIXTURES_DIR / "phishing_sample.eml").write_bytes(build_phishing_sample())
    (FIXTURES_DIR / "legitimate_sample.eml").write_bytes(build_legitimate_sample())
    (FIXTURES_DIR / "eicar_attachment_sample.eml").write_bytes(build_eicar_attachment_sample())
    print("Wrote phishing_sample.eml, legitimate_sample.eml, and eicar_attachment_sample.eml")
