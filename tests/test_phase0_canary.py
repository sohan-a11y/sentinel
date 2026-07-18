from __future__ import annotations

import httpx
import pytest
import respx

from sentinel.db.models import EnvironmentTier
from sentinel.phase0 import canary


def test_render_canary_url_substitutes_marker():
    url = canary.render_canary_url("https://app.test/api/users/{marker}", "deadbeef")
    assert url == "https://app.test/api/users/deadbeef"


def test_render_canary_url_requires_placeholder():
    with pytest.raises(ValueError):
        canary.render_canary_url("https://app.test/api/users/42", "deadbeef")


class TestCanaryConfiguration:
    def test_accepts_only_same_origin_read_only_probe(self):
        method = canary.validate_canary_configuration(
            "app.test", "https://app.test/api/users/{marker}", "head"
        )
        assert method == "HEAD"

    @pytest.mark.parametrize(
        ("url_template", "method"),
        [
            ("https://other.test/api/users/{marker}", "GET"),
            ("http://app.test/api/users/{marker}", "GET"),
            ("https://app.test:8443/api/users/{marker}", "GET"),
            ("https://app.test/api/users/{marker}", "POST"),
        ],
    )
    def test_rejects_unscoped_or_mutating_configuration(self, url_template, method):
        with pytest.raises(ValueError):
            canary.validate_canary_configuration("app.test", url_template, method)


class TestProbeCanary:
    @respx.mock
    def test_true_when_marker_echoed_back(self):
        marker = "deadbeef"
        respx.get("https://app.test/api/users/deadbeef").mock(
            return_value=httpx.Response(200, json={"id": marker, "name": "seeded-canary-user"})
        )
        assert canary.probe_canary("https://app.test/api/users/{marker}", marker) is True

    @respx.mock
    def test_false_when_marker_missing_from_response(self):
        marker = "deadbeef"
        respx.get("https://app.test/api/users/deadbeef").mock(
            return_value=httpx.Response(200, json={"error": "not found"})
        )
        assert canary.probe_canary("https://app.test/api/users/{marker}", marker) is False

    @respx.mock
    def test_false_on_non_2xx(self):
        marker = "deadbeef"
        respx.get("https://app.test/api/users/deadbeef").mock(return_value=httpx.Response(404))
        assert canary.probe_canary("https://app.test/api/users/{marker}", marker) is False

    @respx.mock
    def test_false_on_network_error_fails_closed(self):
        marker = "deadbeef"
        respx.get("https://app.test/api/users/deadbeef").mock(side_effect=httpx.ConnectError("refused"))
        assert canary.probe_canary("https://app.test/api/users/{marker}", marker) is False

    def test_rejects_mutating_method_without_sending_a_request(self):
        marker = "deadbeef"
        assert (
            canary.probe_canary("https://app.test/api/debug/echo?id={marker}", marker, method="post")
            is False
        )


class TestDetermineEnvironmentTier:
    @respx.mock
    def test_verified_safe_when_probe_succeeds(self):
        marker = "deadbeef"
        respx.get("https://app.test/api/users/deadbeef").mock(return_value=httpx.Response(200, text=marker))
        tier = canary.determine_environment_tier("https://app.test/api/users/{marker}", marker)
        assert tier == EnvironmentTier.VERIFIED_SAFE

    @respx.mock
    def test_unverified_when_probe_fails_downgrade_not_exception(self):
        marker = "deadbeef"
        respx.get("https://app.test/api/users/deadbeef").mock(return_value=httpx.Response(500))
        tier = canary.determine_environment_tier("https://app.test/api/users/{marker}", marker)
        assert tier == EnvironmentTier.UNVERIFIED

    @respx.mock
    def test_unverified_when_marker_wrong_even_if_user_claims_otherwise(self):
        """The tool never trusts a user's claim over the live probe result."""
        marker = "deadbeef"
        respx.get("https://app.test/api/users/deadbeef").mock(
            return_value=httpx.Response(200, text="totally-different-value")
        )
        tier = canary.determine_environment_tier("https://app.test/api/users/{marker}", marker)
        assert tier == EnvironmentTier.UNVERIFIED


def test_generate_canary_marker_is_unique():
    markers = {canary.generate_canary_marker() for _ in range(50)}
    assert len(markers) == 50
