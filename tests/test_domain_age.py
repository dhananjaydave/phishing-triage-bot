from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from triage.domain_age import check_domain_age


def _mock_creation_date(days_ago: int):
    return datetime.now(timezone.utc) - timedelta(days=days_ago)


async def test_very_young_domain_is_malicious():
    with patch("triage.domain_age._lookup_creation_date", return_value=_mock_creation_date(2)):
        evidence = await check_domain_age("freshly-registered.example")
    assert evidence is not None
    assert evidence.severity == "malicious"
    assert "2 day" in evidence.description


async def test_moderately_young_domain_is_suspicious():
    with patch("triage.domain_age._lookup_creation_date", return_value=_mock_creation_date(15)):
        evidence = await check_domain_age("somewhat-new.example")
    assert evidence is not None
    assert evidence.severity == "suspicious"


async def test_old_domain_is_just_info():
    with patch("triage.domain_age._lookup_creation_date", return_value=_mock_creation_date(3650)):
        evidence = await check_domain_age("old.example")
    assert evidence is not None
    assert evidence.severity == "info"


async def test_unavailable_whois_data_degrades_to_none():
    with patch("triage.domain_age._lookup_creation_date", return_value=None):
        evidence = await check_domain_age("no-whois-data.example")
    assert evidence is None


async def test_lookup_exception_degrades_to_none_not_a_crash():
    with patch("triage.domain_age._lookup_creation_date", side_effect=RuntimeError("WHOIS server unreachable")):
        evidence = await check_domain_age("broken-lookup.example")
    assert evidence is None


async def test_lookup_timeout_degrades_to_none():
    def slow_lookup(domain):
        import time
        time.sleep(2)

    with patch("triage.domain_age._lookup_creation_date", side_effect=slow_lookup), \
         patch("triage.domain_age.WHOIS_TIMEOUT_SECONDS", 0.1):
        evidence = await check_domain_age("slow-whois.example")
    assert evidence is None
