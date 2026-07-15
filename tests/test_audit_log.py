from __future__ import annotations

import json
import os

from sentinel.security import audit_log


def test_record_chains_entries_from_genesis(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(audit_log.settings, "audit_log_file", str(tmp_path / "audit.ndjson"))

    e1 = audit_log.record(db_session, agent="test", action="a1", payload={"x": 1})
    e2 = audit_log.record(db_session, agent="test", action="a2", payload={"x": 2})

    assert e1.prev_hash == audit_log.GENESIS_HASH
    assert e2.prev_hash == e1.entry_hash
    assert e1.entry_hash != e2.entry_hash


def test_verify_chain_passes_for_untouched_log(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(audit_log.settings, "audit_log_file", str(tmp_path / "audit.ndjson"))
    for i in range(5):
        audit_log.record(db_session, agent="test", action=f"a{i}", payload={"i": i})

    ok, reason = audit_log.verify_chain(db_session)
    assert ok is True
    assert reason is None


def test_verify_chain_detects_payload_tampering(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(audit_log.settings, "audit_log_file", str(tmp_path / "audit.ndjson"))
    audit_log.record(db_session, agent="test", action="a1", payload={"amount": 1})
    entry = audit_log.record(db_session, agent="test", action="a2", payload={"amount": 2})

    entry.payload_json = json.dumps({"amount": 999})
    db_session.flush()

    ok, reason = audit_log.verify_chain(db_session)
    assert ok is False
    assert "tampered" in reason


def test_verify_chain_detects_broken_link(db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(audit_log.settings, "audit_log_file", str(tmp_path / "audit.ndjson"))
    audit_log.record(db_session, agent="test", action="a1", payload={})
    e2 = audit_log.record(db_session, agent="test", action="a2", payload={})

    e2.prev_hash = "f" * 64
    db_session.flush()

    ok, reason = audit_log.verify_chain(db_session)
    assert ok is False
    assert "chain broken" in reason


def test_record_also_appends_to_ndjson_file(db_session, tmp_path, monkeypatch):
    log_path = tmp_path / "audit.ndjson"
    monkeypatch.setattr(audit_log.settings, "audit_log_file", str(log_path))

    audit_log.record(db_session, agent="test", action="a1", payload={"k": "v"})
    audit_log.record(db_session, agent="test", action="a2", payload={"k": "v2"})

    assert log_path.exists()
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    parsed = json.loads(lines[0])
    assert parsed["action"] == "a1"
    assert parsed["payload"] == {"k": "v"}


class TestHmacUpgrade:
    def test_no_key_configured_uses_plain_sha256(self, db_session, tmp_path, monkeypatch):
        monkeypatch.setattr(audit_log.settings, "audit_log_file", str(tmp_path / "audit.ndjson"))
        monkeypatch.setattr(audit_log.settings, "audit_log_hmac_key", None)
        entry = audit_log.record(db_session, agent="test", action="a1", payload={"x": 1})

        import hashlib

        expected = hashlib.sha256(
            f"{audit_log.GENESIS_HASH}|{entry.timestamp}|test|a1|{entry.payload_json}".encode("utf-8")
        ).hexdigest()
        assert entry.entry_hash == expected

    def test_key_configured_uses_hmac_not_plain_sha256(self, db_session, tmp_path, monkeypatch):
        monkeypatch.setattr(audit_log.settings, "audit_log_file", str(tmp_path / "audit.ndjson"))
        monkeypatch.setattr(audit_log.settings, "audit_log_hmac_key", "top-secret-key")
        entry = audit_log.record(db_session, agent="test", action="a1", payload={"x": 1})

        import hashlib
        import hmac as hmac_module

        plain_sha256 = hashlib.sha256(
            f"{audit_log.GENESIS_HASH}|{entry.timestamp}|test|a1|{entry.payload_json}".encode("utf-8")
        ).hexdigest()
        assert entry.entry_hash != plain_sha256

        expected_hmac = hmac_module.new(
            b"top-secret-key",
            f"{audit_log.GENESIS_HASH}|{entry.timestamp}|test|a1|{entry.payload_json}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        assert entry.entry_hash == expected_hmac

    def test_verify_chain_still_passes_with_key_configured(self, db_session, tmp_path, monkeypatch):
        monkeypatch.setattr(audit_log.settings, "audit_log_file", str(tmp_path / "audit.ndjson"))
        monkeypatch.setattr(audit_log.settings, "audit_log_hmac_key", "top-secret-key")
        for i in range(3):
            audit_log.record(db_session, agent="test", action=f"a{i}", payload={"i": i})

        ok, reason = audit_log.verify_chain(db_session)
        assert ok is True, reason

    def test_tampering_plus_forged_plain_sha256_is_caught_when_key_is_set(self, db_session, tmp_path, monkeypatch):
        """The actual point of the HMAC upgrade: an attacker with DB access
        but NOT the key cannot forge a valid forward chain after editing a
        row — they can only recompute the plain SHA-256 they can see in this
        module's source, which no longer matches once a key is configured."""
        monkeypatch.setattr(audit_log.settings, "audit_log_file", str(tmp_path / "audit.ndjson"))
        monkeypatch.setattr(audit_log.settings, "audit_log_hmac_key", "top-secret-key")
        entry = audit_log.record(db_session, agent="test", action="a1", payload={"amount": 1})

        # Attacker edits the row and "forges" using the public, unkeyed
        # algorithm (the only one they could realistically reproduce without
        # the secret key).
        import hashlib

        tampered_payload = json.dumps({"amount": 999})
        forged_hash = hashlib.sha256(
            f"{audit_log.GENESIS_HASH}|{entry.timestamp}|test|a1|{tampered_payload}".encode("utf-8")
        ).hexdigest()
        entry.payload_json = tampered_payload
        entry.entry_hash = forged_hash
        db_session.flush()

        ok, reason = audit_log.verify_chain(db_session)
        assert ok is False
        assert "tampered" in reason
