import respx
from httpx import Response

from triage.enrichment_client import enrich_indicator, url_domain


async def test_skips_when_url_not_configured(monkeypatch):
    monkeypatch.delenv("IOC_ENRICHMENT_API_URL", raising=False)
    result = await enrich_indicator("evil.com")
    assert result["status"] == "skipped"


async def test_calls_configured_enrichment_api(monkeypatch):
    monkeypatch.setenv("IOC_ENRICHMENT_API_URL", "https://ioc.example.com")
    monkeypatch.delenv("IOC_ENRICHMENT_API_KEY", raising=False)
    with respx.mock:
        respx.get("https://ioc.example.com/enrich", params={"indicator": "evil.com"}).mock(
            return_value=Response(200, json={"indicator": "evil.com", "verdict": "malicious"})
        )
        result = await enrich_indicator("evil.com")
    assert result == {"indicator": "evil.com", "verdict": "malicious"}


async def test_sends_api_key_header_when_configured(monkeypatch):
    monkeypatch.setenv("IOC_ENRICHMENT_API_URL", "https://ioc.example.com")
    monkeypatch.setenv("IOC_ENRICHMENT_API_KEY", "secret")
    captured_headers = {}

    def responder(request):
        captured_headers.update(request.headers)
        return Response(200, json={"indicator": "evil.com", "verdict": "clean"})

    with respx.mock:
        respx.get("https://ioc.example.com/enrich").mock(side_effect=responder)
        await enrich_indicator("evil.com")

    assert captured_headers.get("x-api-key") == "secret"


async def test_error_result_on_http_failure(monkeypatch):
    monkeypatch.setenv("IOC_ENRICHMENT_API_URL", "https://ioc.example.com")
    with respx.mock:
        respx.get("https://ioc.example.com/enrich").mock(return_value=Response(500))
        result = await enrich_indicator("evil.com")
    assert result["status"] == "error"


def test_url_domain_extraction():
    assert url_domain("https://evil.com/path?x=1") == "evil.com"
    assert url_domain("http://1.2.3.4:8080/x") == "1.2.3.4"
    assert url_domain("not a url") is None
