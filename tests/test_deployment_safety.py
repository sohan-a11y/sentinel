from __future__ import annotations

from pathlib import Path


_COMPOSE_PATH = Path(__file__).resolve().parents[1] / "docker" / "docker-compose.yml"


def test_local_zap_api_is_keyed_and_loopback_only():
    """The demo scanner must not become an unauthenticated scanning proxy."""
    compose = _COMPOSE_PATH.read_text(encoding="utf-8")

    assert "api.disablekey=true" not in compose
    assert "api.key=$" + "{SENTINEL_ZAP_API_KEY}" in compose
    assert '"127.0.0.1:8080:8080"' in compose
