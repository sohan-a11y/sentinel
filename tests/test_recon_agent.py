from __future__ import annotations

import contextlib
from datetime import datetime, timezone
from unittest.mock import MagicMock

import httpx
import pytest
import respx

from sentinel.agents import recon_agent
from sentinel.config import settings
from sentinel.db.models import TargetRegistration
from sentinel.security import audit_log
from sentinel.security.guardrails import UnauthorizedTargetError

DOMAIN = "example-recon.test"
EXTERNAL_URL = "https://external-site.test/partner"

ROOT_HTML = """
<html><head><title>Home</title></head>
<body>
<a href="/about">About</a>
<a href="/contact">Contact</a>
<a href="https://external-site.test/partner">Partner</a>
<form action="/search" method="get">
  <input type="text" name="q" />
  <input type="submit" value="Go" />
</form>
<script src="/static/app.js"></script>
</body></html>
"""

ABOUT_HTML = """
<html><body>
<a href="/">Home</a>
<a href="/contact">Contact</a>
</body></html>
"""

CONTACT_HTML = """
<html><body>
<a href="/">Home</a>
<p>Contact us</p>
</body></html>
"""

APP_JS = "console.log('bootstrapping'); /* built with jquery */"

ROOT_HEADERS = {
    "server": "nginx",
    "x-powered-by": "Express",
    "content-type": "text/html",
    "set-cookie": "sessionid=abc123; Path=/; HttpOnly; Secure",
}


def _make_registration(db_session, domain: str = DOMAIN) -> TargetRegistration:
    reg = TargetRegistration(
        domain=domain,
        account_owner="tester@corp.com",
        verification_token="tok",
        verification_passed_at=datetime.now(timezone.utc),
        canary_marker="marker",
        canary_check_url_template=f"https://{domain}/api/{{marker}}",
    )
    db_session.add(reg)
    db_session.flush()
    return reg


def _mock_site() -> None:
    respx.get(f"https://{DOMAIN}/").mock(return_value=httpx.Response(200, text=ROOT_HTML, headers=ROOT_HEADERS))
    respx.get(f"https://{DOMAIN}/about").mock(
        return_value=httpx.Response(200, text=ABOUT_HTML, headers={"content-type": "text/html"})
    )
    respx.get(f"https://{DOMAIN}/contact").mock(
        return_value=httpx.Response(200, text=CONTACT_HTML, headers={"content-type": "text/html"})
    )
    respx.get(f"https://{DOMAIN}/static/app.js").mock(
        return_value=httpx.Response(200, text=APP_JS, headers={"content-type": "application/javascript"})
    )
    respx.get(url__regex=rf"https://{DOMAIN}/sentinel-recon-check-.*").mock(
        return_value=httpx.Response(404, text="Cannot GET /sentinel-recon-check-xxxx")
    )


@contextlib.contextmanager
def _fake_get_session(db_session):
    yield db_session


def _fast_settings(monkeypatch) -> None:
    monkeypatch.setattr(settings, "recon_max_pages", 50)
    monkeypatch.setattr(settings, "recon_max_requests_per_second", 1000.0)


@respx.mock
def test_same_origin_pages_all_captured(monkeypatch, db_session):
    _fast_settings(monkeypatch)
    _mock_site()
    reg = _make_registration(db_session)

    crawler = recon_agent.Crawler(reg)
    site_map = crawler.crawl()
    crawler.close()

    crawled_urls = {e["url"] for e in site_map["endpoints"]}
    assert f"https://{DOMAIN}/" in crawled_urls
    assert f"https://{DOMAIN}/about" in crawled_urls
    assert f"https://{DOMAIN}/contact" in crawled_urls
    assert len(crawler.visited) == 3


@respx.mock
def test_external_link_recorded_but_never_crawled(monkeypatch, db_session):
    _fast_settings(monkeypatch)
    _mock_site()
    reg = _make_registration(db_session)

    crawler = recon_agent.Crawler(reg)
    site_map = crawler.crawl()
    crawler.close()

    assert EXTERNAL_URL in crawler.external_links_seen
    assert all(e["url"] != EXTERNAL_URL for e in site_map["endpoints"])
    assert EXTERNAL_URL not in crawler.visited


@respx.mock
def test_forms_parsed_with_inputs(monkeypatch, db_session):
    _fast_settings(monkeypatch)
    _mock_site()
    reg = _make_registration(db_session)

    crawler = recon_agent.Crawler(reg)
    site_map = crawler.crawl()
    crawler.close()

    root_endpoint = next(e for e in site_map["endpoints"] if e["url"] == f"https://{DOMAIN}/")
    assert site_map["forms_count"] == 1
    assert len(root_endpoint["forms"]) == 1
    form = root_endpoint["forms"][0]
    assert form["action"] == f"https://{DOMAIN}/search"
    assert form["method"] == "GET"
    input_names = {field["name"] for field in form["inputs"]}
    assert "q" in input_names
    assert "GET" in root_endpoint["methods"]
    assert "q" in root_endpoint["params"]


@respx.mock
def test_tech_stack_detected_from_headers_and_js_bundle(monkeypatch, db_session):
    _fast_settings(monkeypatch)
    _mock_site()
    reg = _make_registration(db_session)

    crawler = recon_agent.Crawler(reg)
    site_map = crawler.crawl()
    crawler.close()

    assert "express" in site_map["tech_stack"]
    assert "nginx" in site_map["tech_stack"]
    assert "jquery" in site_map["tech_stack"]


@respx.mock
def test_cookies_and_response_headers_collected(monkeypatch, db_session):
    _fast_settings(monkeypatch)
    _mock_site()
    reg = _make_registration(db_session)

    crawler = recon_agent.Crawler(reg)
    site_map = crawler.crawl()
    crawler.close()

    cookie_names = {c["name"] for c in site_map["cookies"]}
    assert "sessionid" in cookie_names
    session_cookie = next(c for c in site_map["cookies"] if c["name"] == "sessionid")
    assert session_cookie["secure"] is True
    assert session_cookie["httponly"] is True

    assert site_map["response_headers"].get("x-powered-by") == "Express"
    assert site_map["domain"] == DOMAIN
    datetime.fromisoformat(site_map["crawled_at"])


@respx.mock
def test_page_cap_respected(monkeypatch, db_session):
    monkeypatch.setattr(settings, "recon_max_pages", 2)
    monkeypatch.setattr(settings, "recon_max_requests_per_second", 1000.0)
    _mock_site()
    reg = _make_registration(db_session)

    crawler = recon_agent.Crawler(reg)
    site_map = crawler.crawl()
    crawler.close()

    assert len(crawler.visited) == 2
    assert len(site_map["endpoints"]) == 2


@respx.mock
def test_rate_limit_throttles_between_requests(monkeypatch, db_session):
    monkeypatch.setattr(settings, "recon_max_pages", 50)
    monkeypatch.setattr(settings, "recon_max_requests_per_second", 2.0)
    _mock_site()
    reg = _make_registration(db_session)

    sleep_mock = MagicMock()
    monkeypatch.setattr(recon_agent.time, "sleep", sleep_mock)

    crawler = recon_agent.Crawler(reg)
    crawler.crawl()
    crawler.close()

    assert sleep_mock.call_count >= 1
    for call in sleep_mock.call_args_list:
        assert call.args[0] > 0


@respx.mock
def test_recon_node_returns_site_map_and_audits(monkeypatch, db_session):
    _fast_settings(monkeypatch)
    _mock_site()
    _make_registration(db_session)
    monkeypatch.setattr(recon_agent, "get_session", lambda: _fake_get_session(db_session))

    result = recon_agent.recon_node({"target_domain": DOMAIN})

    assert result["current_phase"] == "recon_complete"
    site_map = result["site_map"]
    assert site_map["domain"] == DOMAIN
    assert site_map["forms_count"] == 1

    actions = [e.action for e in db_session.query(audit_log.AuditLogEntry).all()]
    assert "crawl_started" in actions
    assert "crawl_completed" in actions

    ok, reason = audit_log.verify_chain(db_session)
    assert ok, reason


def test_recon_node_rejects_unregistered_domain(monkeypatch, db_session):
    monkeypatch.setattr(recon_agent, "get_session", lambda: _fake_get_session(db_session))

    with pytest.raises(UnauthorizedTargetError):
        recon_agent.recon_node({"target_domain": "never-registered.test"})


def test_recon_node_refuses_to_crawl_a_halted_session(monkeypatch, db_session):
    from sentinel.db.models import ScanSession, ScanStatus
    from sentinel.security.guardrails import ScanHaltedError

    _mock_site()
    reg = _make_registration(db_session)
    scan_session = ScanSession(target_id=reg.id, status=ScanStatus.HALTED, halted_reason="anomaly")
    db_session.add(scan_session)
    db_session.flush()
    monkeypatch.setattr(recon_agent, "get_session", lambda: _fake_get_session(db_session))

    with pytest.raises(ScanHaltedError):
        recon_agent.recon_node({"target_domain": DOMAIN, "scan_session_id": scan_session.id})


def test_process_scripts_skips_non_http_scheme_src_without_crashing(db_session):
    """Regression: guardrails.normalize_host now raises PivotViolationError
    for a non-http(s) scheme (file://, data:, etc). A <script src="file://...">
    on a crawled page must not abort the whole crawl over one odd tag."""
    reg = _make_registration(db_session)
    crawler = recon_agent.Crawler(reg)
    try:
        crawler._process_scripts(f"https://{DOMAIN}/", ["file://internal-host/x.js"])
    finally:
        crawler.close()
    assert crawler.endpoints == []
