"""Each check returns a list of Evidence - including the "looks fine" cases,
not just red flags, since the point is a transparent report an analyst can
review, not a black-box label.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .email_parser import ParsedEmail

Severity = str  # "malicious" | "suspicious" | "info"


@dataclass
class Evidence:
    category: str
    severity: Severity
    description: str


URGENCY_PHRASES = [
    "urgent", "verify your account", "act now", "account suspended",
    "immediately", "click here", "limited time", "confirm your identity",
    "unusual activity", "will be closed", "final notice", "verify your identity",
    "your account will be", "security alert", "unauthorized access",
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly",
}

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".click", ".work", ".icu", ".info"}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".ps1",
    ".docm", ".xlsm", ".pptm", ".iso", ".lnk", ".msi", ".com",
}

# Brand -> its legitimate domains. Deliberately small and well-known rather
# than exhaustive - the point is catching obvious impersonation, not being a
# brand-protection product.
KNOWN_BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "microsoft": {"microsoft.com", "outlook.com", "live.com", "office.com"},
    "google": {"google.com", "gmail.com"},
    "apple": {"apple.com", "icloud.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "linkedin": {"linkedin.com"},
    "bank of america": {"bankofamerica.com"},
    "irs": {"irs.gov"},
}


def _domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower() if "@" in address else address.lower()


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
        previous = current
    return previous[-1]


def check_auth_results(email: ParsedEmail) -> list[Evidence]:
    if email.spf == "pass" and email.dkim == "pass" and email.dmarc == "pass":
        return [Evidence("authentication", "info", "SPF, DKIM, and DMARC all pass.")]

    failures = [m for m, v in (("SPF", email.spf), ("DKIM", email.dkim), ("DMARC", email.dmarc)) if v == "fail"]
    if failures:
        return [Evidence(
            "authentication", "malicious",
            f"{'/'.join(failures)} failed - the sending server isn't authorized to send as this domain.",
        )]

    if email.spf == "none" and email.dkim == "none" and email.dmarc == "none":
        return [Evidence("authentication", "suspicious", "No SPF/DKIM/DMARC results found in headers.")]

    return [Evidence(
        "authentication", "info",
        f"SPF={email.spf}, DKIM={email.dkim}, DMARC={email.dmarc} - partial or soft results.",
    )]


def check_display_name_spoofing(email: ParsedEmail) -> list[Evidence]:
    if not email.from_display_name or not email.from_address:
        return []
    display = email.from_display_name.lower()
    sender_domain = _domain_of(email.from_address)

    for brand, real_domains in KNOWN_BRANDS.items():
        if brand in display and sender_domain not in real_domains:
            return [Evidence(
                "sender_spoofing", "malicious",
                f"Display name claims to be '{email.from_display_name}' (brand: {brand}), "
                f"but the actual sending domain is '{sender_domain}', not {'/'.join(real_domains)}.",
            )]
    return [Evidence("sender_spoofing", "info", "Display name doesn't impersonate a known brand.")]


def check_reply_to_mismatch(email: ParsedEmail) -> list[Evidence]:
    if not email.reply_to or not email.from_address:
        return []
    reply_domain = _domain_of(email.reply_to)
    from_domain = _domain_of(email.from_address)
    if reply_domain != from_domain:
        return [Evidence(
            "reply_to", "suspicious",
            f"Reply-To domain ({reply_domain}) differs from the From domain ({from_domain}) - "
            "replies get redirected somewhere other than the apparent sender.",
        )]
    return [Evidence("reply_to", "info", "Reply-To matches the From domain.")]


def check_urgency_language(email: ParsedEmail) -> list[Evidence]:
    haystack = f"{email.subject}\n{email.body_text}".lower()
    matched = [phrase for phrase in URGENCY_PHRASES if phrase in haystack]
    if matched:
        return [Evidence(
            "social_engineering", "suspicious",
            f"Urgency/pressure language found: {', '.join(matched)}.",
        )]
    return [Evidence("social_engineering", "info", "No urgency/pressure language detected.")]


def check_suspicious_urls(email: ParsedEmail) -> list[Evidence]:
    evidence = []
    for url in email.urls:
        match = re.search(r"https?://([^/\s]+)", url)
        if not match:
            continue
        domain = match.group(1).split("@")[-1].lower()
        host = domain.split(":")[0]

        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            evidence.append(Evidence("suspicious_url", "malicious", f"Link uses a raw IP address instead of a domain: {url}"))
            continue

        if host in SHORTENER_DOMAINS:
            evidence.append(Evidence("suspicious_url", "suspicious", f"Shortened URL hides its real destination: {url}"))

        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            evidence.append(Evidence("suspicious_url", "suspicious", f"Link uses a TLD commonly abused for phishing: {url}"))

        for brand, real_domains in KNOWN_BRANDS.items():
            for real_domain in real_domains:
                if host == real_domain:
                    break
                distance = _levenshtein(host, real_domain)
                if 0 < distance <= 2 and abs(len(host) - len(real_domain)) <= 2:
                    evidence.append(Evidence(
                        "suspicious_url", "malicious",
                        f"Domain '{host}' closely resembles '{real_domain}' ({brand}) - likely a lookalike: {url}",
                    ))
                    break

    if not evidence and email.urls:
        evidence.append(Evidence("suspicious_url", "info", f"{len(email.urls)} link(s) found, none matched known suspicious patterns."))
    return evidence


def check_link_text_mismatch(email: ParsedEmail) -> list[Evidence]:
    if not email.link_mismatches:
        return []
    return [
        Evidence(
            "link_mismatch", "malicious",
            f"Link text '{m.display_text}' doesn't match where it actually points ({m.href}).",
        )
        for m in email.link_mismatches
    ]


def check_dangerous_attachments(email: ParsedEmail) -> list[Evidence]:
    evidence = []
    for attachment in email.attachments:
        lower_name = attachment.filename.lower()
        if any(lower_name.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
            evidence.append(Evidence(
                "attachment", "malicious",
                f"Attachment '{attachment.filename}' has a dangerous extension for an email attachment.",
            ))
        else:
            evidence.append(Evidence("attachment", "info", f"Attachment '{attachment.filename}' ({attachment.content_type})."))
    return evidence


def run_all_heuristics(email: ParsedEmail) -> list[Evidence]:
    checks = [
        check_auth_results,
        check_display_name_spoofing,
        check_reply_to_mismatch,
        check_urgency_language,
        check_suspicious_urls,
        check_link_text_mismatch,
        check_dangerous_attachments,
    ]
    evidence = []
    for check in checks:
        evidence.extend(check(email))
    return evidence
