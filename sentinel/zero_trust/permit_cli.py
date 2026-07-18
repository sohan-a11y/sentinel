"""Offline bootstrap verifier for a customer-local runner permit.

This module deliberately has no HTTP client, socket use, telemetry, or
credential handling.  It reads one serialized permit and one public
verification key from explicit local file paths, verifies the Ed25519
signature, checks the active time window, and writes a small JSON scope
summary to stdout.  It never makes a test request.

Run with ``python -m sentinel.zero_trust.permit_cli --help``.  The public key
is supplied out of band during customer onboarding; this command must never be
given a control-plane API key or a private signing key.
"""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

from sentinel.zero_trust.policy import Permit, PermitSignatureError, PermitValidationError


_MAX_PERMIT_BYTES = 64 * 1024
_MAX_PUBLIC_KEY_BYTES = 4 * 1024
_ISSUER_KEY_ID_RE = re.compile(r"[0-9a-f]{16}\Z")


class PermitBootstrapError(Exception):
    """Raised when an offline permit bootstrap input cannot be trusted."""


@dataclass(frozen=True)
class PermitScopeSummary:
    """The intentionally small, non-secret result emitted by the CLI."""

    permit_id: str
    issuer_key_id: str
    allowed_hosts: tuple[str, ...]
    allowed_methods: tuple[str, ...]
    allowed_path_prefixes: tuple[str, ...]
    not_before: str
    expires_at: str
    request_budget: int

    def to_dict(self) -> dict[str, object]:
        return {
            "permit_id": self.permit_id,
            "issuer_key_id": self.issuer_key_id,
            "allowed_hosts": list(self.allowed_hosts),
            "allowed_methods": list(self.allowed_methods),
            "allowed_path_prefixes": list(self.allowed_path_prefixes),
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "request_budget": self.request_budget,
        }


def _current_time() -> datetime:
    """Read the local UTC clock at the verification boundary."""
    return datetime.now(timezone.utc)


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Make duplicate JSON member names fail rather than silently overwrite."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PermitBootstrapError()
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    """Reject JSON extensions such as NaN and Infinity."""
    raise PermitBootstrapError()


def _read_small_utf8_file(path: Path, *, maximum_bytes: int) -> str:
    """Read a bounded local UTF-8 file without returning filesystem errors."""
    _reject_nonlocal_path(path)
    try:
        with path.open("rb") as source:
            raw = source.read(maximum_bytes + 1)
    except OSError:
        raw = None
    if not raw or len(raw) > maximum_bytes:
        raise PermitBootstrapError()
    try:
        decoded = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        decoded = None
    if decoded is None:
        raise PermitBootstrapError()
    return decoded


def _reject_nonlocal_path(path: Path) -> None:
    """Reject URL-like and UNC inputs so this command cannot fetch over a network."""
    raw_path = str(path)
    normalized = raw_path.replace("\\", "/")
    if normalized.startswith("//") or "://" in normalized:
        raise PermitBootstrapError()


def _load_public_verification_key(path: Path) -> str:
    """Load exactly one public key, allowing only one normal terminal newline."""
    value = _read_small_utf8_file(path, maximum_bytes=_MAX_PUBLIC_KEY_BYTES)
    if value.endswith("\r\n"):
        value = value[:-2]
    elif value.endswith("\n"):
        value = value[:-1]
    if not value or value != value.strip() or "\r" in value or "\n" in value:
        raise PermitBootstrapError()
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        is_ascii = False
    else:
        is_ascii = True
    if not is_ascii:
        raise PermitBootstrapError()
    return value


def _load_serialized_permit(path: Path) -> Permit:
    """Parse a bounded permit document with strict JSON object semantics."""
    raw_document = _read_small_utf8_file(path, maximum_bytes=_MAX_PERMIT_BYTES)
    try:
        value = json.loads(
            raw_document,
            object_pairs_hook=_reject_duplicate_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, PermitBootstrapError, RecursionError, ValueError, TypeError):
        value = None
    if not isinstance(value, dict):
        raise PermitBootstrapError()
    try:
        permit = Permit.from_dict(value)
    except PermitValidationError:
        permit = None
    if permit is None:
        raise PermitBootstrapError()
    return permit


def issuer_key_id(public_verification_key: str) -> str:
    """Return the API-compatible, non-secret issuer fingerprint identifier."""
    try:
        encoded_key = public_verification_key.encode("ascii")
    except UnicodeEncodeError:
        encoded_key = None
    if encoded_key is None:
        raise PermitBootstrapError()
    return hashlib.sha256(encoded_key).hexdigest()[:16]


def _validate_expected_issuer_key_id(expected: str | None, actual: str) -> None:
    if expected is None:
        return
    if _ISSUER_KEY_ID_RE.fullmatch(expected) is None or expected != actual:
        raise PermitBootstrapError()


def _verify_active_time_window(permit: Permit) -> None:
    current_time = _current_time()
    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise PermitBootstrapError()
    current_time = current_time.astimezone(timezone.utc)
    if current_time < permit.not_before or current_time >= permit.expires_at:
        raise PermitBootstrapError()


def load_and_verify_local_permit(
    *,
    permit_path: Path,
    public_key_path: Path,
    expected_issuer_key_id: str | None = None,
) -> PermitScopeSummary:
    """Verify local bootstrap inputs and return only their safe scope summary.

    This function has no network side effects.  It raises
    :class:`PermitBootstrapError` for every malformed, untrusted, expired, or
    mismatched input and intentionally does not include raw input in errors.
    """
    summary: PermitScopeSummary | None = None
    try:
        permit = _load_serialized_permit(permit_path)
        public_verification_key = _load_public_verification_key(public_key_path)
        actual_issuer_key_id = issuer_key_id(public_verification_key)
        _validate_expected_issuer_key_id(expected_issuer_key_id, actual_issuer_key_id)
        permit.verify(public_verification_key)
        _verify_active_time_window(permit)

        serialized = permit.to_dict()
        not_before = serialized["not_before"]
        expires_at = serialized["expires_at"]
        if not isinstance(not_before, str) or not isinstance(expires_at, str):
            # ``Permit.to_dict`` guarantees these fields, but retain a hard fail
            # boundary if that invariant changes.
            raise PermitBootstrapError()
        summary = PermitScopeSummary(
            permit_id=permit.permit_id,
            issuer_key_id=actual_issuer_key_id,
            allowed_hosts=permit.allowed_hosts,
            allowed_methods=permit.allowed_methods,
            allowed_path_prefixes=permit.allowed_path_prefixes,
            not_before=not_before,
            expires_at=expires_at,
            request_budget=permit.request_budget,
        )
    except (PermitBootstrapError, PermitSignatureError, PermitValidationError):
        summary = None
    except Exception:
        # The CLI must fail closed and never surface potentially sensitive
        # parser, filesystem, or crypto diagnostics to the user.
        summary = None
    if summary is None:
        # Raise outside an ``except`` suite, so library callers cannot walk an
        # exception chain back to a parser document, file path, or key value.
        raise PermitBootstrapError()
    return summary


def build_parser() -> argparse.ArgumentParser:
    """Build the intentionally narrow, offline-only command-line interface."""
    parser = argparse.ArgumentParser(
        description="Verify a signed customer-runner permit from local files only."
    )
    parser.add_argument(
        "--permit-path",
        required=True,
        type=Path,
        help="Local path to the serialized signed permit JSON.",
    )
    parser.add_argument(
        "--public-key-path",
        required=True,
        type=Path,
        help="Local path to the out-of-band Ed25519 public verification key.",
    )
    parser.add_argument(
        "--issuer-key-id",
        help="Optional expected 16-character lowercase-hex issuer key ID.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the offline verifier and return a conventional process exit status."""
    arguments = build_parser().parse_args(argv)
    try:
        summary = load_and_verify_local_permit(
            permit_path=arguments.permit_path,
            public_key_path=arguments.public_key_path,
            expected_issuer_key_id=arguments.issuer_key_id,
        )
    except PermitBootstrapError:
        print("error: permit verification failed", file=sys.stderr)
        return 1
    print(json.dumps(summary.to_dict(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via the module entry point.
    raise SystemExit(main())
