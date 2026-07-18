"""Tests for the offline-only customer runner permit bootstrap command."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import socket

import pytest

from sentinel.zero_trust import permit_cli
from sentinel.zero_trust.policy import Permit, generate_ed25519_keypair


START = datetime(2026, 7, 18, 10, 0, tzinfo=timezone.utc)
END = START + timedelta(hours=1)


@pytest.fixture()
def signed_permit():
    private_key, public_key = generate_ed25519_keypair()
    permit = Permit.issue(
        permit_id="sandbox-run-001",
        allowed_hosts=("api.customer.test", "app.customer.test"),
        allowed_methods=("GET", "HEAD"),
        allowed_path_prefixes=("/api", "/health"),
        not_before=START,
        expires_at=END,
        request_budget=12,
        private_signing_key=private_key,
    )
    return private_key, public_key, permit


def write_local_inputs(tmp_path, *, permit: Permit, public_key: str):
    permit_path = tmp_path / "permit.json"
    public_key_path = tmp_path / "issuer-public.key"
    permit_path.write_text(json.dumps(permit.to_dict()), encoding="utf-8")
    public_key_path.write_text(public_key + "\n", encoding="utf-8")
    return permit_path, public_key_path


def test_cli_verifies_local_files_and_prints_only_a_minimal_scope_summary(
    tmp_path,
    monkeypatch,
    capsys,
    signed_permit,
):
    private_key, public_key, permit = signed_permit
    permit_path, public_key_path = write_local_inputs(
        tmp_path,
        permit=permit,
        public_key=public_key,
    )
    expected_issuer_id = hashlib.sha256(public_key.encode("ascii")).hexdigest()[:16]
    monkeypatch.setattr(permit_cli, "_current_time", lambda: START + timedelta(minutes=1))

    def network_used(*args, **kwargs):
        raise AssertionError("the offline bootstrap CLI must not use the network")

    monkeypatch.setattr(socket, "create_connection", network_used)

    exit_code = permit_cli.main(
        [
            "--permit-path",
            str(permit_path),
            "--public-key-path",
            str(public_key_path),
            "--issuer-key-id",
            expected_issuer_id,
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert json.loads(captured.out) == {
        "allowed_hosts": ["api.customer.test", "app.customer.test"],
        "allowed_methods": ["GET", "HEAD"],
        "allowed_path_prefixes": ["/api", "/health"],
        "expires_at": "2026-07-18T11:00:00.000000Z",
        "issuer_key_id": expected_issuer_id,
        "not_before": "2026-07-18T10:00:00.000000Z",
        "permit_id": "sandbox-run-001",
        "request_budget": 12,
    }
    assert private_key not in captured.out
    assert public_key not in captured.out
    assert permit.signature not in captured.out


@pytest.mark.parametrize(
    "payload_factory",
    [
        lambda permit: "{not valid json: secret-value-that-must-not-print",
        lambda permit: json.dumps(permit.to_dict()).replace(
            '"version": 1,',
            '"version": 1, "version": 1,',
            1,
        ),
        lambda permit: json.dumps({**permit.to_dict(), "request_budget": 999}),
    ],
)
def test_cli_fails_closed_without_echoing_malformed_or_tampered_permit_content(
    tmp_path,
    monkeypatch,
    capsys,
    signed_permit,
    payload_factory,
):
    _, public_key, permit = signed_permit
    permit_path, public_key_path = write_local_inputs(
        tmp_path,
        permit=permit,
        public_key=public_key,
    )
    permit_path.write_text(payload_factory(permit), encoding="utf-8")
    monkeypatch.setattr(permit_cli, "_current_time", lambda: START + timedelta(minutes=1))

    exit_code = permit_cli.main(
        ["--permit-path", str(permit_path), "--public-key-path", str(public_key_path)]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "error: permit verification failed\n"
    assert "secret-value-that-must-not-print" not in captured.err
    assert permit.signature not in captured.err


def test_cli_rejects_an_issuer_key_id_that_does_not_match_the_local_public_key(
    tmp_path,
    monkeypatch,
    capsys,
    signed_permit,
):
    _, public_key, permit = signed_permit
    permit_path, public_key_path = write_local_inputs(
        tmp_path,
        permit=permit,
        public_key=public_key,
    )
    monkeypatch.setattr(permit_cli, "_current_time", lambda: START + timedelta(minutes=1))

    exit_code = permit_cli.main(
        [
            "--permit-path",
            str(permit_path),
            "--public-key-path",
            str(public_key_path),
            "--issuer-key-id",
            "0" * 16,
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "error: permit verification failed\n"


@pytest.mark.parametrize("now", [START - timedelta(microseconds=1), END])
def test_cli_rejects_permits_outside_their_active_time_window(
    tmp_path,
    monkeypatch,
    capsys,
    signed_permit,
    now,
):
    _, public_key, permit = signed_permit
    permit_path, public_key_path = write_local_inputs(
        tmp_path,
        permit=permit,
        public_key=public_key,
    )
    monkeypatch.setattr(permit_cli, "_current_time", lambda: now)

    exit_code = permit_cli.main(
        ["--permit-path", str(permit_path), "--public-key-path", str(public_key_path)]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "error: permit verification failed\n"


def test_cli_rejects_bad_public_key_file_without_exposing_its_contents(
    tmp_path,
    monkeypatch,
    capsys,
    signed_permit,
):
    _, _, permit = signed_permit
    permit_path = tmp_path / "permit.json"
    public_key_path = tmp_path / "issuer-public.key"
    permit_path.write_text(json.dumps(permit.to_dict()), encoding="utf-8")
    public_key_path.write_text("not-a-public-key-secret-looking-value", encoding="utf-8")
    monkeypatch.setattr(permit_cli, "_current_time", lambda: START + timedelta(minutes=1))

    exit_code = permit_cli.main(
        ["--permit-path", str(permit_path), "--public-key-path", str(public_key_path)]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert captured.err == "error: permit verification failed\n"
    assert "not-a-public-key-secret-looking-value" not in captured.err


def test_programmatic_bootstrap_failure_does_not_retain_a_secret_bearing_error_chain(
    tmp_path,
    monkeypatch,
    signed_permit,
):
    _, public_key, permit = signed_permit
    permit_path, public_key_path = write_local_inputs(
        tmp_path,
        permit=permit,
        public_key=public_key,
    )
    permit_path.write_text("{not-json: customer-secret-value}", encoding="utf-8")
    monkeypatch.setattr(permit_cli, "_current_time", lambda: START + timedelta(minutes=1))

    with pytest.raises(permit_cli.PermitBootstrapError) as captured:
        permit_cli.load_and_verify_local_permit(
            permit_path=permit_path,
            public_key_path=public_key_path,
        )

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
