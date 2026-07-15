from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from sentinel.config import settings
from sentinel.db.models import VerificationMethod
from sentinel.phase0 import verification


class TestWellKnownCheck:
    @respx.mock
    def test_passes_when_token_present_in_body(self):
        domain = "example-test.com"
        token = "abc123token"
        respx.get(f"https://{domain}{settings.well_known_path}").mock(
            return_value=httpx.Response(200, text=f"sentinel-verify={token}\n")
        )
        assert verification.check_well_known(domain, token) is True

    @respx.mock
    def test_fails_when_token_absent(self):
        domain = "example-test.com"
        respx.get(f"https://{domain}{settings.well_known_path}").mock(
            return_value=httpx.Response(200, text="nothing-relevant-here")
        )
        assert verification.check_well_known(domain, "abc123token") is False

    @respx.mock
    def test_fails_closed_on_404(self):
        domain = "example-test.com"
        respx.get(f"https://{domain}{settings.well_known_path}").mock(return_value=httpx.Response(404))
        assert verification.check_well_known(domain, "abc123token") is False

    @respx.mock
    def test_fails_closed_on_network_error(self):
        domain = "unreachable-test.com"
        respx.get(f"https://{domain}{settings.well_known_path}").mock(side_effect=httpx.ConnectError("boom"))
        assert verification.check_well_known(domain, "abc123token") is False

    @respx.mock
    def test_fails_closed_on_timeout(self):
        domain = "slow-test.com"
        respx.get(f"https://{domain}{settings.well_known_path}").mock(
            side_effect=httpx.TimeoutException("timed out")
        )
        assert verification.check_well_known(domain, "abc123token") is False


class TestDnsTxtCheck:
    def _fake_txt_record(self, value: str):
        record = MagicMock()
        record.strings = [value.encode("utf-8")]
        return record

    def test_passes_when_token_present_in_txt(self):
        domain = "example-test.com"
        token = "abc123token"
        fake_answer = [self._fake_txt_record(f"sentinel-verify={token}")]
        with patch("dns.resolver.Resolver.resolve", return_value=fake_answer):
            assert verification.check_dns_txt(domain, token) is True

    def test_fails_when_token_absent(self):
        domain = "example-test.com"
        fake_answer = [self._fake_txt_record("something-else")]
        with patch("dns.resolver.Resolver.resolve", return_value=fake_answer):
            assert verification.check_dns_txt(domain, "abc123token") is False

    def test_fails_closed_on_nxdomain(self):
        import dns.resolver

        domain = "nonexistent-test.com"
        with patch("dns.resolver.Resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
            assert verification.check_dns_txt(domain, "abc123token") is False

    def test_queries_expected_record_name(self):
        captured = {}

        def fake_resolve(self, name, rdtype):
            captured["name"] = str(name)
            raise __import__("dns").resolver.NXDOMAIN()

        with patch("dns.resolver.Resolver.resolve", fake_resolve):
            verification.check_dns_txt("example-test.com", "token")
        assert captured["name"] == f"{settings.dns_txt_prefix}.example-test.com"


class TestVerifyDomainOwnership:
    @respx.mock
    def test_prefers_well_known_when_both_would_pass(self):
        domain = "example-test.com"
        token = "abc123token"
        respx.get(f"https://{domain}{settings.well_known_path}").mock(
            return_value=httpx.Response(200, text=token)
        )
        result = verification.verify_domain_ownership(domain, token)
        assert result == VerificationMethod.WELL_KNOWN_HTTP

    @respx.mock
    def test_falls_back_to_dns_when_well_known_fails(self):
        domain = "example-test.com"
        token = "abc123token"
        respx.get(f"https://{domain}{settings.well_known_path}").mock(return_value=httpx.Response(404))
        fake_answer = [self._make_txt(token)]
        with patch("dns.resolver.Resolver.resolve", return_value=fake_answer):
            result = verification.verify_domain_ownership(domain, token)
        assert result == VerificationMethod.DNS_TXT

    @respx.mock
    def test_returns_none_when_neither_passes(self):
        domain = "example-test.com"
        respx.get(f"https://{domain}{settings.well_known_path}").mock(return_value=httpx.Response(404))
        import dns.resolver as dr

        with patch("dns.resolver.Resolver.resolve", side_effect=dr.NXDOMAIN()):
            result = verification.verify_domain_ownership(domain, "abc123token")
        assert result is None

    @staticmethod
    def _make_txt(value: str):
        record = MagicMock()
        record.strings = [value.encode("utf-8")]
        return record


def test_generate_verification_token_is_unique_and_nontrivial():
    tokens = {verification.generate_verification_token() for _ in range(50)}
    assert len(tokens) == 50
    assert all(len(t) >= 16 for t in tokens)
