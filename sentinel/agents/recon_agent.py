"""Agent 1: Recon.

Crawls the registered target starting from https://{domain}, staying strictly
same-origin (sentinel.security.guardrails.normalize_host decides "same
origin", not string prefix matching). Off-target links are recorded for
visibility only — they are never enqueued, dispatched, or fetched. This is
the recon-side half of the no-pivot boundary; the dispatch-side half is
guardrails.enforce_no_pivot, used by the scan-engine modules.
"""
from __future__ import annotations

import time
import uuid
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

from sentinel.agents.state import EndpointInfo, SentinelState, SiteMap
from sentinel.config import settings
from sentinel.db.models import ScanSession, TargetRegistration
from sentinel.db.session import get_session
from sentinel.security import audit_log, guardrails
from sentinel.security.guardrails import PivotViolationError, normalize_host

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_MAX_SCRIPT_FETCH_BYTES = 200_000
_AUTH_URL_HINTS = ("login", "signin", "sign-in", "account", "dashboard", "admin", "profile", "settings", "auth")

_FRAMEWORK_SIGNATURES: dict[str, list[str]] = {
    "react": ["react-dom", "data-reactroot", "/react/", "react.production", "react.development"],
    "vue": ["vue.global", "vue.runtime", "__vue__", "/vue/"],
    "angular": ["ng-version", "@angular", "angular.js"],
    "jquery": ["jquery"],
    "htmx": ["htmx.org", "htmx.min.js", "hx-get", "hx-post"],
    "next.js": ["_next/static", "__next_data__", "next/dist"],
    "django": ["csrfmiddlewaretoken", "django"],
    "laravel": ["laravel"],
    "wordpress": ["wp-content", "wp-includes", "wp-json"],
    "express": ["express"],
}

_HEADER_TECH_HINTS: dict[str, list[str]] = {
    "nginx": ["nginx"],
    "apache": ["apache"],
    "iis": ["microsoft-iis"],
    "cloudflare": ["cloudflare"],
    "php": ["php"],
    "express": ["express"],
    "asp.net": ["asp.net"],
}

_COOKIE_TECH_HINTS: dict[str, list[str]] = {
    "java": ["jsessionid"],
    "php": ["phpsessid"],
    "django": ["csrftoken"],
    "laravel": ["laravel_session"],
    "wordpress": ["wordpress_logged_in", "wp-settings"],
}

_ERROR_PAGE_SIGNATURES: dict[str, list[str]] = {
    "express": ["cannot get", "cannot post", "cannot put", "cannot delete"],
    "django": ["django", "csrf verification failed"],
    "laravel": ["laravel", "whoops"],
    "wordpress": ["wp-content", "error404"],
    "rails": ["ruby on rails", "routing error"],
    "flask": ["werkzeug"],
}


def _parse_set_cookie(raw: str) -> dict[str, Any]:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts and parts[0] else ""
    flags = {p.lower() for p in parts[1:]}
    return {"name": name, "secure": "secure" in flags, "httponly": "httponly" in flags}


class _PageParser(HTMLParser):
    """Extracts links, forms (with inputs), and script srcs. No external deps."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.script_srcs: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "a" and values.get("href"):
            self.links.append(values["href"])
        elif tag == "script" and values.get("src"):
            self.script_srcs.append(values["src"])
        elif tag == "form":
            self._current_form = {
                "action": values.get("action") or "",
                "method": (values.get("method") or "GET").upper(),
                "inputs": [],
            }
        elif tag in ("input", "select", "textarea") and self._current_form is not None:
            name = values.get("name")
            if name:
                field_type = values.get("type") or ("text" if tag == "input" else tag)
                self._current_form["inputs"].append({"name": name, "type": field_type})

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


class Crawler:
    """Same-origin crawler for one registered, verified target.

    Every network call — page, script, or the closing error-page probe —
    goes through _get(), so the rate limit and page cap apply uniformly.
    """

    def __init__(self, registration: TargetRegistration, client: httpx.Client | None = None) -> None:
        self.registration = registration
        self.target_host = normalize_host(registration.domain)
        self._owns_client = client is None
        self.client = client or httpx.Client(timeout=10.0, follow_redirects=False)

        self.visited: set[str] = set()
        self.external_links_seen: list[str] = []
        self._external_seen: set[str] = set()
        self.cookies: list[dict[str, Any]] = []
        self._cookie_names_seen: set[str] = set()
        self.response_headers: dict[str, str] = {}
        self.tech_stack: set[str] = set()
        self.endpoints: list[EndpointInfo] = []
        self.forms_count = 0
        self._fetched_scripts: set[str] = set()
        self._last_request_at: float | None = None

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def crawl(self) -> SiteMap:
        start_url = f"https://{self.registration.domain}/"
        queue: deque[str] = deque([start_url])
        enqueued = {start_url}
        is_first_response = True

        while queue and len(self.visited) < settings.recon_max_pages:
            url = queue.popleft()
            if url in self.visited:
                continue
            response = self._get(url)
            self.visited.add(url)
            if response is None:
                continue

            if is_first_response:
                self.response_headers = dict(response.headers)
                is_first_response = False
            self._collect_cookies(response)
            self._detect_tech_from_headers(response)

            if response.status_code in _REDIRECT_STATUSES and "location" in response.headers:
                self._process_link(url, response.headers["location"], queue, enqueued)
                continue

            content_type = response.headers.get("content-type", "")
            if content_type and "text/html" not in content_type:
                self._register_endpoint(url, response, forms=[], source="crawl")
                continue

            forms, links, script_srcs = self._parse_html(response.text)
            processed_forms = self._process_forms(url, forms)
            self._register_endpoint(url, response, forms=processed_forms, source="crawl")
            self._process_scripts(url, script_srcs)
            for href in links:
                self._process_link(url, href, queue, enqueued)

        self._detect_tech_from_error_page()
        return self._build_site_map()

    def _get(self, url: str) -> httpx.Response | None:
        self._throttle()
        try:
            return self.client.get(url)
        except httpx.HTTPError:
            return None

    def _throttle(self) -> None:
        rate = settings.recon_max_requests_per_second
        if rate <= 0:
            return
        min_interval = 1.0 / rate
        now = time.monotonic()
        if self._last_request_at is not None:
            wait = min_interval - (now - self._last_request_at)
            if wait > 0:
                time.sleep(wait)
        self._last_request_at = time.monotonic()

    def _parse_html(self, html_text: str) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        parser = _PageParser()
        try:
            parser.feed(html_text)
        except Exception:
            pass
        return parser.forms, parser.links, parser.script_srcs

    def _process_link(self, base_url: str, href: str, queue: deque[str], enqueued: set[str]) -> None:
        href = (href or "").strip()
        if not href or href.startswith("#"):
            return
        lowered = href.lower()
        if lowered.startswith(("mailto:", "tel:", "javascript:")):
            return
        absolute = urljoin(base_url, href).split("#", 1)[0]
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            return
        host = normalize_host(absolute)
        if host == self.target_host:
            if absolute not in enqueued and absolute not in self.visited:
                enqueued.add(absolute)
                queue.append(absolute)
        elif absolute not in self._external_seen:
            self._external_seen.add(absolute)
            self.external_links_seen.append(absolute)

    def _process_forms(self, base_url: str, raw_forms: list[dict[str, Any]]) -> list[dict[str, Any]]:
        processed: list[dict[str, Any]] = []
        for form in raw_forms:
            action = form.get("action") or base_url
            processed.append(
                {
                    "action": urljoin(base_url, action),
                    "method": (form.get("method") or "GET").upper(),
                    "inputs": form.get("inputs", []),
                }
            )
        self.forms_count += len(processed)
        return processed

    def _process_scripts(self, base_url: str, script_srcs: list[str]) -> None:
        for src in script_srcs:
            absolute = urljoin(base_url, src)
            self._match_any(absolute.lower(), _FRAMEWORK_SIGNATURES)
            if absolute in self._fetched_scripts:
                continue
            self._fetched_scripts.add(absolute)
            try:
                same_host = normalize_host(absolute) == self.target_host
            except PivotViolationError:
                # A non-http(s) scheme (file://, data:, etc.) snuck through
                # urljoin — not a fetchable resource, skip it rather than
                # letting one odd <script src> abort the whole crawl.
                continue
            if not same_host:
                continue
            response = self._get(absolute)
            if response is None:
                continue
            content_type = response.headers.get("content-type", "")
            if content_type and "javascript" not in content_type and "text" not in content_type:
                continue
            if len(response.content) > _MAX_SCRIPT_FETCH_BYTES:
                continue
            self._match_any(response.text.lower(), _FRAMEWORK_SIGNATURES)

    def _register_endpoint(
        self, url: str, response: httpx.Response, *, forms: list[dict[str, Any]], source: str
    ) -> None:
        methods = {"GET"}
        for form in forms:
            methods.add(str(form.get("method", "GET")).upper())
        params: list[str] = []
        parsed = urlparse(url)
        if parsed.query:
            params.extend(parse_qs(parsed.query).keys())
        for form in forms:
            for field in form.get("inputs", []):
                name = field.get("name")
                if name and name not in params:
                    params.append(name)
        endpoint: EndpointInfo = {
            "url": url,
            "methods": sorted(methods),
            "params": params,
            "forms": forms,
            "requires_auth": self._guess_requires_auth(url, response),
            "source": source,
        }
        self.endpoints.append(endpoint)

    def _guess_requires_auth(self, url: str, response: httpx.Response) -> bool:
        if response.status_code in (401, 403):
            return True
        lowered = url.lower()
        return any(hint in lowered for hint in _AUTH_URL_HINTS)

    def _collect_cookies(self, response: httpx.Response) -> None:
        for raw in response.headers.get_list("set-cookie"):
            cookie = _parse_set_cookie(raw)
            if cookie["name"] and cookie["name"] not in self._cookie_names_seen:
                self._cookie_names_seen.add(cookie["name"])
                self.cookies.append(cookie)

    def _detect_tech_from_headers(self, response: httpx.Response) -> None:
        server = response.headers.get("server", "")
        powered_by = response.headers.get("x-powered-by", "")
        combined = f"{server} {powered_by}".lower().strip()
        if combined:
            self._match_any(combined, _HEADER_TECH_HINTS)
            self._match_any(combined, _FRAMEWORK_SIGNATURES)
        for raw_cookie in response.headers.get_list("set-cookie"):
            self._match_any(raw_cookie.lower(), _COOKIE_TECH_HINTS)

    def _detect_tech_from_error_page(self) -> None:
        probe_path = f"/sentinel-recon-check-{uuid.uuid4().hex[:12]}"
        response = self._get(f"https://{self.registration.domain}{probe_path}")
        if response is None or response.status_code not in (404, 500):
            return
        self._match_any(response.text.lower(), _ERROR_PAGE_SIGNATURES)
        server = response.headers.get("server", "")
        if server:
            self._match_any(server.lower(), _ERROR_PAGE_SIGNATURES)

    def _match_any(self, haystack: str, signature_map: dict[str, list[str]]) -> None:
        for tech, patterns in signature_map.items():
            if tech in self.tech_stack:
                continue
            if any(pattern in haystack for pattern in patterns):
                self.tech_stack.add(tech)

    def _build_site_map(self) -> SiteMap:
        return {
            "domain": self.target_host,
            "endpoints": self.endpoints,
            "cookies": self.cookies,
            "response_headers": self.response_headers,
            "tech_stack": sorted(self.tech_stack),
            "forms_count": self.forms_count,
            "crawled_at": datetime.now(timezone.utc).isoformat(),
        }


def recon_node(state: SentinelState) -> dict:
    domain = state["target_domain"]
    with get_session() as db:
        # Phase 0 is executing here: Agent 1 (recon) cannot crawl a single
        # page until enforce_target_authorized confirms this domain is
        # registered and ownership-verified.
        registration = guardrails.enforce_target_authorized(db, domain)
        scan_session_id = state.get("scan_session_id")
        if scan_session_id is not None:
            scan_session = db.get(ScanSession, scan_session_id)
            if scan_session is not None:
                guardrails.enforce_not_halted(db, scan_session)
        audit_log.record(
            db,
            agent="recon_agent",
            action="crawl_started",
            payload={"domain": registration.domain},
        )
        crawler = Crawler(registration)
        try:
            site_map = crawler.crawl()
        finally:
            crawler.close()
        audit_log.record(
            db,
            agent="recon_agent",
            action="crawl_completed",
            payload={
                "domain": registration.domain,
                "pages_crawled": len(crawler.visited),
                "external_links_seen_count": len(crawler.external_links_seen),
                "external_links_seen_sample": crawler.external_links_seen[:10],
                "forms_count": site_map["forms_count"],
                "tech_stack": site_map["tech_stack"],
            },
        )
    return {"site_map": site_map, "current_phase": "recon_complete"}
