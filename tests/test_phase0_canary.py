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

    @respx.mock
    def test_supports_post_method(self):
        marker = "deadbeef"
        respx.post("https://app.test/api/debug/echo?id=deadbeef").mock(
            return_value=httpx.Response(200, text=f"echo:{marker}")
        )
        assert (
            canary.probe_canary("https://app.test/api/debug/echo?id={marker}", marker, method="post")
            is True
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
