"""Parses a raw .eml file into structured fields the heuristics/enrichment
steps can work with. Uses only the stdlib `email` package - no third-party
mail parsing dependency needed for this.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser

_URL_RE = re.compile(r"https?://[^\s<>\"'()\]\[]+")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass
class LinkMismatch:
    display_text: str
    href: str


@dataclass
class ParsedEmail:
    subject: str
    from_address: str | None
    from_display_name: str | None
    reply_to: str | None
    return_path: str | None
    auth_results_raw: str
    spf: str
    dkim: str
    dmarc: str
    received_ips: list[str] = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    urls: list[str] = field(default_factory=list)
    link_mismatches: list[LinkMismatch] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)


class _AnchorExtractor(HTMLParser):
    """Pulls out (visible text, href) pairs for every <a> tag, to catch the
    classic "link text says one thing, href goes somewhere else" phishing
    pattern."""

    def __init__(self) -> None:
        super().__init__()
        self.pairs: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            self._current_href = href
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._current_href is not None:
            text = "".join(self._current_text).strip()
            if text and self._current_href.startswith(("http://", "https://")):
                self.pairs.append((text, self._current_href))
            self._current_href = None
            self._current_text = []


def _extract_domain(url_or_text: str) -> str | None:
    match = re.search(r"https?://([^/\s]+)", url_or_text)
    if match:
        return match.group(1).split("@")[-1].lower()
    # bare domain mentioned as link text, e.g. "paypal.com"
    match = re.match(r"^([a-z0-9.-]+\.[a-z]{2,})(/.*)?$", url_or_text.strip().lower())
    return match.group(1) if match else None


def _find_link_mismatches(anchor_pairs: list[tuple[str, str]]) -> list[LinkMismatch]:
    mismatches = []
    for text, href in anchor_pairs:
        text_domain = _extract_domain(text)
        href_domain = _extract_domain(href)
        if text_domain and href_domain and text_domain != href_domain:
            mismatches.append(LinkMismatch(display_text=text, href=href))
    return mismatches


def _parse_auth_results(msg: EmailMessage) -> tuple[str, str, str, str]:
    raw = "\n".join(msg.get_all("Authentication-Results", []))

    def _extract(mechanism: str) -> str:
        match = re.search(rf"{mechanism}=(\w+)", raw, re.IGNORECASE)
        return match.group(1).lower() if match else "none"

    return raw, _extract("spf"), _extract("dkim"), _extract("dmarc")


def _extract_received_ips(msg: EmailMessage) -> list[str]:
    ips: list[str] = []
    for header in msg.get_all("Received", []):
        for candidate in _IPV4_RE.findall(header):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if ip.is_global and candidate not in ips:
                ips.append(candidate)
    return ips


def _get_bodies(msg: EmailMessage) -> tuple[str, str]:
    text_parts, html_parts = [], []
    if msg.is_multipart():
        parts = msg.walk()
    else:
        parts = [msg]
    for part in parts:
        if part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        try:
            content = part.get_content()
        except Exception:
            continue
        if content_type == "text/plain" and isinstance(content, str):
            text_parts.append(content)
        elif content_type == "text/html" and isinstance(content, str):
            html_parts.append(content)
    return "\n".join(text_parts), "\n".join(html_parts)


def _get_attachments(msg: EmailMessage) -> list[Attachment]:
    attachments = []
    if not msg.is_multipart():
        return attachments
    for part in msg.walk():
        if part.get_content_disposition() != "attachment":
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        attachments.append(
            Attachment(
                filename=part.get_filename() or "unnamed",
                content_type=part.get_content_type(),
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )
    return attachments


def parse_eml(raw: bytes) -> ParsedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    from_addresses = getaddresses(msg.get_all("From", []))
    from_display_name, from_address = (from_addresses[0] if from_addresses else (None, None))

    reply_to_addresses = getaddresses(msg.get_all("Reply-To", []))
    reply_to = reply_to_addresses[0][1] if reply_to_addresses else None

    return_path_addresses = getaddresses(msg.get_all("Return-Path", []))
    return_path = return_path_addresses[0][1] if return_path_addresses else None

    auth_results_raw, spf, dkim, dmarc = _parse_auth_results(msg)
    body_text, body_html = _get_bodies(msg)

    anchor_extractor = _AnchorExtractor()
    if body_html:
        try:
            anchor_extractor.feed(body_html)
        except Exception:
            pass

    urls = set(_URL_RE.findall(body_text))
    urls.update(_URL_RE.findall(body_html))
    urls.update(href for _, href in anchor_extractor.pairs)

    return ParsedEmail(
        subject=str(msg.get("Subject", "")),
        from_address=from_address or None,
        from_display_name=from_display_name or None,
        reply_to=reply_to,
        return_path=return_path,
        auth_results_raw=auth_results_raw,
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        received_ips=_extract_received_ips(msg),
        body_text=body_text,
        body_html=body_html,
        urls=sorted(urls),
        link_mismatches=_find_link_mismatches(anchor_extractor.pairs),
        attachments=_get_attachments(msg),
    )
