from __future__ import annotations

import httpx
import pytest
import respx

from sentinel.security import safe_http
from sentinel.security.guardrails import PivotViolationError


class TestRequestSameHost:
    @respx.mock
    def test_direct_response_no_redirect(self):
        respx.get("https://example.com/page").mock(return_value=httpx.Response(200, text="ok"))
        response = safe_http.get_same_host("https://example.com/page", "example.com")
        assert response.status_code == 200
        assert response.text == "ok"

    @respx.mock
    def test_follows_same_host_redirect(self):
        respx.get("https://example.com/old").mock(
            return_value=httpx.Response(302, headers={"location": "https://example.com/new"})
        )
        respx.get("https://example.com/new").mock(return_value=httpx.Response(200, text="landed"))
        response = safe_http.get_same_host("https://example.com/old", "example.com")
        assert response.status_code == 200
        assert response.text == "landed"

    @respx.mock
    def test_blocks_redirect_to_different_host(self):
        respx.get("https://example.com/old").mock(
            return_value=httpx.Response(302, headers={"location": "https://attacker.example/collect"})
        )
        with pytest.raises(PivotViolationError):
            safe_http.get_same_host("https://example.com/old", "example.com")

    @respx.mock
    def test_blocks_initial_url_off_host(self):
        with pytest.raises(PivotViolationError):
            safe_http.get_same_host("https://attacker.example/x", "example.com")

    @respx.mock
    def test_blocks_relative_redirect_that_resolves_off_host(self):
        # Location headers are resolved relative to the current URL — a
        # scheme-relative "//attacker.example/x" must still be caught.
        respx.get("https://example.com/old").mock(
            return_value=httpx.Response(302, headers={"location": "//attacker.example/x"})
        )
        with pytest.raises(PivotViolationError):
            safe_http.get_same_host("https://example.com/old", "example.com")

    @respx.mock
    def test_caps_redirect_chain_length(self):
        for i in range(10):
            respx.get(f"https://example.com/hop{i}").mock(
                return_value=httpx.Response(302, headers={"location": f"https://example.com/hop{i+1}"})
            )
        with pytest.raises(PivotViolationError, match="Too many redirects"):
            safe_http.get_same_host("https://example.com/hop0", "example.com")

    @respx.mock
    def test_does_not_leak_cookies_to_off_host_redirect_target(self):
        """The actual attack this closes: a cookie attached via the dict
        kwarg has no domain restriction in httpx/http.cookiejar, so if a
        redirect were followed transparently it would be resent anywhere."""
        respx.get("https://example.com/old").mock(
            return_value=httpx.Response(302, headers={"location": "https://attacker.example/collect"})
        )
        attacker_route = respx.get("https://attacker.example/collect").mock(return_value=httpx.Response(200))

        with pytest.raises(PivotViolationError):
            safe_http.get_same_host(
                "https://example.com/old", "example.com", cookies={"session": "secret-token"}
            )
        assert attacker_route.call_count == 0

    @respx.mock
    def test_post_same_host_works(self):
        respx.post("https://example.com/signup").mock(return_value=httpx.Response(201, json={"id": "abc"}))
        response = safe_http.post_same_host("https://example.com/signup", "example.com", json={"email": "x"})
        assert response.status_code == 201
