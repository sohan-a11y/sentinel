from __future__ import annotations

import contextlib
import re

import pytest

from sentinel.agents import cwe_mapping_agent
from sentinel.agents.cwe_mapping_agent import (
    LLM_UNAVAILABLE_REASON,
    apply_llm_pass,
    apply_rule_based_pass,
    cwe_mapping_node,
)
from sentinel.cwe.mapping import load_cwe_catalog
from sentinel.db.models import CweApplicability, ScanSession, ScanStatus, TargetRegistration
from sentinel.llm.client import LlmConfigurationError

CWE_ID_PATTERN = re.compile(r"^CWE-\d+$")


class TestCwecatalog:
    def test_catalog_loads_and_is_within_expected_size(self):
        catalog = load_cwe_catalog()
        assert 150 <= len(catalog) <= 250

    def test_every_entry_has_valid_shape_and_id_format(self):
        catalog = load_cwe_catalog()
        for entry in catalog:
            assert set(entry.keys()) == {"cwe_id", "name", "category"}
            assert CWE_ID_PATTERN.match(entry["cwe_id"]), entry["cwe_id"]
            assert entry["name"]
            assert entry["category"]

    def test_no_duplicate_cwe_ids(self):
        catalog = load_cwe_catalog()
        ids = [entry["cwe_id"] for entry in catalog]
        assert len(ids) == len(set(ids))


def _find_item(items, cwe_id):
    for item in items:
        if item["cwe_id"] == cwe_id:
            return item
    return None


class TestRuleBasedApplicability:
    def test_no_forms_means_file_upload_cwe_not_applicable(self):
        catalog = load_cwe_catalog()
        site_map = {"domain": "example.com", "endpoints": [], "cookies": [], "forms_count": 0}

        decided, undecided = apply_rule_based_pass(catalog, site_map)

        item = _find_item(decided, "CWE-434")
        assert item is not None
        assert item["applicable"] is False
        assert "file upload" in item["reason"].lower()

    def test_wordpress_tech_stack_marks_a_wordpress_relevant_cwe_applicable(self):
        catalog = load_cwe_catalog()
        site_map = {"domain": "example.com", "tech_stack": ["WordPress 6.4"], "endpoints": [], "cookies": []}

        decided, _undecided = apply_rule_based_pass(catalog, site_map)

        wordpress_hits = [
            item
            for item in decided
            if item["cwe_id"] in {"CWE-1392", "CWE-1104", "CWE-937", "CWE-1035"} and item["applicable"] is True
        ]
        assert wordpress_hits, "expected at least one wordpress-relevant CWE marked applicable"
        assert any("wordpress" in item["reason"].lower() for item in wordpress_hits)

    def test_no_cookies_means_session_cwe_not_applicable(self):
        catalog = load_cwe_catalog()
        site_map = {"domain": "example.com", "endpoints": [], "cookies": []}

        decided, _undecided = apply_rule_based_pass(catalog, site_map)

        item = _find_item(decided, "CWE-384")  # Session Fixation
        assert item is not None
        assert item["applicable"] is False
        assert "cookie" in item["reason"].lower()

    def test_cookies_present_means_session_cwe_applicable(self):
        catalog = load_cwe_catalog()
        site_map = {
            "domain": "example.com",
            "endpoints": [],
            "cookies": [{"name": "session_id", "value": "abc"}],
        }

        decided, _undecided = apply_rule_based_pass(catalog, site_map)

        item = _find_item(decided, "CWE-384")
        assert item is not None
        assert item["applicable"] is True

    def test_input_surface_present_marks_injection_applicable(self):
        catalog = load_cwe_catalog()
        site_map = {
            "domain": "example.com",
            "endpoints": [{"url": "https://example.com/search", "params": ["q"], "methods": ["GET"]}],
            "cookies": [],
        }

        decided, _undecided = apply_rule_based_pass(catalog, site_map)

        item = _find_item(decided, "CWE-89")  # SQL Injection
        assert item is not None
        assert item["applicable"] is True

    def test_no_input_surface_marks_injection_not_applicable(self):
        catalog = load_cwe_catalog()
        site_map = {"domain": "example.com", "endpoints": [], "cookies": [], "forms_count": 0}

        decided, _undecided = apply_rule_based_pass(catalog, site_map)

        item = _find_item(decided, "CWE-89")
        assert item is not None
        assert item["applicable"] is False

    def test_every_catalog_entry_ends_up_decided_or_undecided_exactly_once(self):
        catalog = load_cwe_catalog()
        site_map = {
            "domain": "example.com",
            "endpoints": [{"url": "https://example.com/x", "params": ["id"], "methods": ["GET", "POST"]}],
            "cookies": [{"name": "session_id"}],
            "forms_count": 1,
            "tech_stack": ["nginx"],
        }

        decided, undecided = apply_rule_based_pass(catalog, site_map)

        decided_ids = {item["cwe_id"] for item in decided}
        undecided_ids = {entry["cwe_id"] for entry in undecided}
        assert not (decided_ids & undecided_ids)
        assert decided_ids | undecided_ids == {entry["cwe_id"] for entry in catalog}

    def test_empty_site_map_defers_business_logic_but_not_the_specific_rules(self):
        """An entirely empty site map should not blow up, and categories with
        no concrete signal at all should end up decided (not applicable) via
        the no-endpoints fallback rather than crashing or hanging on the LLM."""
        catalog = load_cwe_catalog()
        decided, undecided = apply_rule_based_pass(catalog, {})

        assert len(decided) + len(undecided) == len(catalog)
        item = _find_item(decided, "CWE-840")  # Business Logic Errors
        assert item is not None
        assert item["applicable"] is False


class TestLlmPassUnavailableFallback:
    def test_defaults_to_applicable_when_llm_client_raises_configuration_error(self, monkeypatch):
        def _raise_configuration_error():
            raise LlmConfigurationError("no API key configured")

        monkeypatch.setattr(cwe_mapping_agent, "get_llm_client", _raise_configuration_error)

        undecided = [
            {"cwe_id": "CWE-840", "name": "Business Logic Errors", "category": "business_logic"},
            {"cwe_id": "CWE-841", "name": "Improper Enforcement of Behavioral Workflow", "category": "business_logic"},
        ]
        items, llm_available = apply_llm_pass(undecided, {})

        assert llm_available is False
        assert len(items) == 2
        for item in items:
            assert item["applicable"] is True
            assert item["reason"] == LLM_UNAVAILABLE_REASON
            assert item["tested"] is False
            assert item["detection_method"] is None

    def test_empty_undecided_list_short_circuits_without_touching_llm_client(self, monkeypatch):
        def _fail_if_called():
            raise AssertionError("get_llm_client should not be called when nothing is undecided")

        monkeypatch.setattr(cwe_mapping_agent, "get_llm_client", _fail_if_called)

        items, llm_available = apply_llm_pass([], {})

        assert items == []
        assert llm_available is True

    def test_uses_llm_verdicts_when_client_available(self, monkeypatch):
        class _FakeClient:
            def complete_json(self, *, system, user, json_schema, schema_name):
                return {
                    "verdicts": [
                        {"cwe_id": "CWE-840", "applicable": False, "reason": "no multi-step workflow observed"},
                    ]
                }

        monkeypatch.setattr(cwe_mapping_agent, "get_llm_client", lambda: _FakeClient())

        undecided = [{"cwe_id": "CWE-840", "name": "Business Logic Errors", "category": "business_logic"}]
        items, llm_available = apply_llm_pass(undecided, {})

        assert llm_available is True
        assert len(items) == 1
        assert items[0]["applicable"] is False
        assert items[0]["reason"] == "no multi-step workflow observed"


@contextlib.contextmanager
def _session_scope(db_session):
    yield db_session


class TestCweMappingNodeIntegration:
    def _make_scan_session(self, db_session) -> ScanSession:
        registration = TargetRegistration(
            domain="example-test.com",
            account_owner="alice@corp.com",
            verification_token="tok",
            canary_marker="marker",
            canary_check_url_template="https://x/{marker}",
        )
        db_session.add(registration)
        db_session.flush()

        scan_session = ScanSession(target_id=registration.id, status=ScanStatus.RUNNING)
        db_session.add(scan_session)
        db_session.flush()
        return scan_session

    def test_node_persists_checklist_and_returns_expected_shape(self, db_session, monkeypatch):
        monkeypatch.setattr(cwe_mapping_agent, "get_session", lambda: _session_scope(db_session))

        def _raise_configuration_error():
            raise LlmConfigurationError("no API key configured")

        monkeypatch.setattr(cwe_mapping_agent, "get_llm_client", _raise_configuration_error)

        scan_session = self._make_scan_session(db_session)
        state = {
            "scan_session_id": scan_session.id,
            "site_map": {"domain": "example-test.com", "endpoints": [], "cookies": []},
        }

        result = cwe_mapping_node(state)

        catalog = load_cwe_catalog()
        assert result["current_phase"] == "cwe_mapping_complete"
        assert len(result["cwe_checklist"]) == len(catalog)
        assert result["applicable_count"] + result["not_applicable_count"] == len(catalog)

        persisted = (
            db_session.query(CweApplicability)
            .filter(CweApplicability.scan_session_id == scan_session.id)
            .all()
        )
        assert len(persisted) == len(catalog)

        db_session.refresh(scan_session)
        assert scan_session.applicable_cwe_count == result["applicable_count"]
        assert scan_session.not_applicable_cwe_count == result["not_applicable_count"]

    def test_node_raises_for_missing_scan_session(self, db_session, monkeypatch):
        monkeypatch.setattr(cwe_mapping_agent, "get_session", lambda: _session_scope(db_session))
        state = {"scan_session_id": 999999, "site_map": {}}
        with pytest.raises(ValueError):
            cwe_mapping_node(state)
