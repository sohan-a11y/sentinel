from __future__ import annotations

import ipaddress
import json
import os
from datetime import datetime, timezone

import pytest
from cryptography import x509

from sentinel import demo_mode
from sentinel.config import settings


def test_prepare_demo_site_creates_only_a_disposable_loopback_site(tmp_path):
    site = demo_mode.prepare_demo_site(tmp_path)

    assert (site / "index.html").is_file()
    assert (site / "docs" / "index.html").is_file()
    assert (site / "login" / "index.html").is_file()
    assert (site / ".well-known").is_dir()
    assert "Disposable local demo" in (site / "index.html").read_text(encoding="utf-8")
    assert "customer" not in (site / "index.html").read_text(encoding="utf-8").lower()


def test_create_demo_certificate_is_limited_to_loopback_identities(tmp_path):
    certificate_path, private_key_path = demo_mode.create_demo_certificate(tmp_path)

    certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
    names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value

    assert "localhost" in names.get_values_for_type(x509.DNSName)
    assert ipaddress.ip_address("127.0.0.1") in names.get_values_for_type(x509.IPAddress)
    authority = certificate.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    assert authority.key_identifier is not None
    key_usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert key_usage.key_encipherment is True
    assert key_usage.key_cert_sign is False
    assert private_key_path.is_file()


def test_demo_state_never_serializes_an_operator_secret(tmp_path):
    state = demo_mode.DemoState(
        demo_root=tmp_path,
        database_url="sqlite:///demo-sentinel.db",
        audit_log_file=tmp_path / "audit.ndjson",
        scan_session_id=7,
        contract_id=3,
        target_url="https://127.0.0.1",
        started_at=datetime.now(timezone.utc),
    )

    encoded = json.dumps(state.to_dict())

    assert "api_key" not in encoded.lower()
    assert "token" not in encoded.lower()
    assert state.to_dict()["target_url"] == "https://127.0.0.1"


def test_cli_dashboard_matches_the_dashboard_information_without_raw_evidence():
    output = demo_mode.format_dashboard(
        scan={
            "scan_session_id": 7,
            "status": "completed",
            "environment_tier": "tier_a",
            "headline": "3/5 applicable CWEs tested, 0 confirmed exploitable, 1 unconfirmed",
            "applicable_cwe_count": 5,
            "not_applicable_cwe_count": 2,
            "tested_cwe_count": 3,
            "confirmed_count": 0,
            "unconfirmed_count": 1,
            "pending_count": 0,
            "halted_reason": None,
            "ai_enabled": True,
            "ai_provider": "TokenRouter",
            "ai_model": "openai:gpt-4o",
            "ai_judged_count": 6,
        },
        findings=[
            {
                "cwe_id": "CWE-79",
                "endpoint": "https://127.0.0.1/search",
                "status": "unconfirmed",
                "confidence": 0.42,
                "poc_evidence": "raw request body must never be printed",
            }
        ],
        audit={"chain_intact": True, "reason": "ok"},
    )

    assert "SCAN STATUS" in output
    assert "CWE COVERAGE" in output
    assert "FINDINGS" in output
    assert "AUDIT LOG" in output
    assert "AI TRIAGE" in output
    assert "TokenRouter" in output
    assert "synthetic local site map only" in output
    assert "CWE-79" in output
    assert "raw request body" not in output
    assert "H = halt" in output


def test_cli_parser_starts_the_simple_interactive_operator_demo():
    parser = demo_mode.build_parser()

    assert parser.parse_args(["start"]).command == "start"
    assert parser.parse_args(["start", "--no-menu"]).no_menu is True
    assert parser.parse_args(["start", "--use-ai"]).use_ai is True


def test_ai_demo_environment_preserves_only_the_tokenrouter_key(monkeypatch, tmp_path):
    # _configure_demo_environment deliberately changes process state for the
    # short-lived launcher process. Restore it in this unit test so later
    # HTTP-mocking tests never inherit its disposable CA path.
    original_environment = os.environ.copy()
    try:
        monkeypatch.setenv("SENTINEL_TOKENROUTER_API_KEY", "tr_demo_key")
        monkeypatch.setenv("SENTINEL_ANTHROPIC_API_KEY", "must-be-cleared")
        monkeypatch.setenv("SENTINEL_OPENROUTER_API_KEY", "must-be-cleared")
        monkeypatch.setenv("SENTINEL_OPENAI_API_KEY", "must-be-cleared")

        demo_mode._configure_demo_environment(tmp_path, tmp_path / "demo-ca.pem", use_ai=True)

        assert os.environ["SENTINEL_TOKENROUTER_API_KEY"] == "tr_demo_key"
        assert os.environ["SENTINEL_ANTHROPIC_API_KEY"] == ""
        assert os.environ["SENTINEL_OPENROUTER_API_KEY"] == ""
        assert os.environ["SENTINEL_OPENAI_API_KEY"] == ""
        assert os.environ["SENTINEL_LLM_MAX_CWE_JUDGMENTS"] == "6"
    finally:
        os.environ.clear()
        os.environ.update(original_environment)


def test_ai_demo_accepts_the_project_tokenrouter_endpoint_and_glm_model(monkeypatch):
    monkeypatch.setattr(settings, "tokenrouter_api_key", "local-demo-key")
    monkeypatch.setattr(settings, "tokenrouter_base_url", "https://api.tokenrouter.com/v1")
    monkeypatch.setattr(settings, "tokenrouter_model", "z-ai/glm-5.2-free")

    provider, model = demo_mode._require_tokenrouter_ai_demo_configuration()

    assert provider == "TokenRouter"
    assert model == "z-ai/glm-5.2-free"


def test_ai_demo_refuses_to_start_without_a_local_tokenrouter_key(monkeypatch):
    monkeypatch.setattr(settings, "tokenrouter_api_key", None)

    with pytest.raises(demo_mode.DemoModeError, match="SENTINEL_TOKENROUTER_API_KEY"):
        demo_mode._require_tokenrouter_ai_demo_configuration()
