"""Pure, customer-local policy checks for zero-trust test runners.

This module deliberately has no HTTP client, credential store, database, or
telemetry dependency.  Its only job is to authenticate a bounded permit and
decide whether one proposed request is inside that permit.  A successful
decision atomically reserves one in-memory request-budget unit.

The issuer signs with an Ed25519 private key; a customer-local runner needs
only the corresponding public verification key.  Neither key is serialized,
logged, or sent anywhere by this module.  Customer API credentials, request
bodies, responses, and other customer data are outside this API by design.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
import threading
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import unquote_to_bytes, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


_POLICY_VERSION = 1
_RAW_ED25519_KEY_LENGTH = 32
_RAW_ED25519_SIGNATURE_LENGTH = 64
_UNPADDED_KEY_LENGTH = 43
_UNPADDED_SIGNATURE_LENGTH = 86
_BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]+")
_HTTP_TOKEN_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Z-]+")
_DNS_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_ENCODED_SEPARATOR_RE = re.compile(r"%(?:2f|5c)", re.IGNORECASE)


def _current_time() -> datetime:
    """Read trusted local UTC time at the enforcement boundary.

    Request callers must never choose the time used for permit expiry. Tests
    patch this private function rather than exposing a public ``now`` escape
    hatch on the evaluator API.
    """
    return datetime.now(timezone.utc)


class PolicyDeniedError(Exception):
    """Raised when a request cannot be authorized by the local policy."""


class PermitValidationError(PolicyDeniedError):
    """Raised when a permit or request has an unsafe or malformed shape."""


class PermitSignatureError(PolicyDeniedError):
    """Raised when a permit is missing a valid Ed25519 signature."""


@dataclass(frozen=True)
class _PermitScope:
    permit_id: str
    allowed_hosts: tuple[str, ...]
    allowed_methods: tuple[str, ...]
    allowed_path_prefixes: tuple[str, ...]
    not_before: datetime
    expires_at: datetime
    request_budget: int


@dataclass(frozen=True)
class Permit:
    """An Ed25519-authenticated, bounded request permit.

    Call :meth:`issue` instead of constructing a permit directly.  Directly
    constructed permits are still revalidated and signature-checked by the
    evaluator, so they cannot silently gain authority.
    """

    permit_id: str
    allowed_hosts: tuple[str, ...]
    allowed_methods: tuple[str, ...]
    allowed_path_prefixes: tuple[str, ...]
    not_before: datetime
    expires_at: datetime
    request_budget: int
    signature: str | None = None

    @classmethod
    def issue(
        cls,
        *,
        permit_id: str,
        allowed_hosts: Iterable[str],
        allowed_methods: Iterable[str],
        allowed_path_prefixes: Iterable[str],
        not_before: datetime,
        expires_at: datetime,
        request_budget: int,
        private_signing_key: str,
    ) -> "Permit":
        """Validate and sign a new permit using a canonical JSON payload."""
        candidate = cls(
            permit_id=permit_id,
            allowed_hosts=_materialize_collection(allowed_hosts, "allowed_hosts"),
            allowed_methods=_materialize_collection(allowed_methods, "allowed_methods"),
            allowed_path_prefixes=_materialize_collection(
                allowed_path_prefixes,
                "allowed_path_prefixes",
            ),
            not_before=not_before,
            expires_at=expires_at,
            request_budget=request_budget,
        )
        scope = _canonical_scope(candidate)
        unsigned = cls(
            permit_id=scope.permit_id,
            allowed_hosts=scope.allowed_hosts,
            allowed_methods=scope.allowed_methods,
            allowed_path_prefixes=scope.allowed_path_prefixes,
            not_before=scope.not_before,
            expires_at=scope.expires_at,
            request_budget=scope.request_budget,
        )
        signature = _sign(unsigned.canonical_payload(), private_signing_key)
        return replace(unsigned, signature=signature)

    def canonical_payload(self) -> bytes:
        """Return the one strict serialization used for signing and checking."""
        scope = _canonical_scope(self)
        document = {
            "allowed_hosts": list(scope.allowed_hosts),
            "allowed_methods": list(scope.allowed_methods),
            "allowed_path_prefixes": list(scope.allowed_path_prefixes),
            "expires_at": _timestamp(scope.expires_at),
            "not_before": _timestamp(scope.not_before),
            "permit_id": scope.permit_id,
            "request_budget": scope.request_budget,
            "version": _POLICY_VERSION,
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

    def verify(self, public_verification_key: str) -> None:
        """Raise if this permit is malformed, unsigned, or not authentic."""
        _verify_signature(self, public_verification_key)

    def to_dict(self) -> dict[str, object]:
        """Serialize the signed policy without including any key material."""
        scope = _canonical_scope(self)
        return {
            "version": _POLICY_VERSION,
            "permit_id": scope.permit_id,
            "allowed_hosts": list(scope.allowed_hosts),
            "allowed_methods": list(scope.allowed_methods),
            "allowed_path_prefixes": list(scope.allowed_path_prefixes),
            "not_before": _timestamp(scope.not_before),
            "expires_at": _timestamp(scope.expires_at),
            "request_budget": scope.request_budget,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "Permit":
        """Parse the exact permit JSON received by a customer-local runner.

        Only the canonical wire shape is accepted.  Unknown fields and
        alternate timestamps are rejected rather than ignored, so a lenient
        JSON parser cannot turn a differently represented value into an
        authority-bearing permit.  The returned permit still must be verified
        with the customer runner's public key before any request is made.
        """
        if not isinstance(value, Mapping):
            raise PermitValidationError("Serialized permit must be an object")
        expected_fields = {
            "version",
            "permit_id",
            "allowed_hosts",
            "allowed_methods",
            "allowed_path_prefixes",
            "not_before",
            "expires_at",
            "request_budget",
            "signature",
        }
        if set(value.keys()) != expected_fields:
            raise PermitValidationError("Serialized permit has an unexpected shape")
        version = value["version"]
        if isinstance(version, bool) or not isinstance(version, int) or version != _POLICY_VERSION:
            raise PermitValidationError("Serialized permit version is unsupported")
        collection_fields = ("allowed_hosts", "allowed_methods", "allowed_path_prefixes")
        if any(not isinstance(value[field], list) for field in collection_fields):
            raise PermitValidationError("Serialized permit scopes must be JSON arrays")
        signature = value["signature"]
        try:
            _decode_base64url(
                signature,
                expected_length=_RAW_ED25519_SIGNATURE_LENGTH,
                label="Permit signature",
            )
        except PermitValidationError as exc:
            raise PermitValidationError("Serialized permit has an invalid signature") from exc

        candidate = cls(
            permit_id=value["permit_id"],  # type: ignore[arg-type]
            allowed_hosts=tuple(value["allowed_hosts"]),  # type: ignore[arg-type]
            allowed_methods=tuple(value["allowed_methods"]),  # type: ignore[arg-type]
            allowed_path_prefixes=tuple(value["allowed_path_prefixes"]),  # type: ignore[arg-type]
            not_before=_parse_timestamp(value["not_before"], "not_before"),
            expires_at=_parse_timestamp(value["expires_at"], "expires_at"),
            request_budget=value["request_budget"],  # type: ignore[arg-type]
            signature=signature,
        )
        scope = _canonical_scope(candidate)
        return cls(
            permit_id=scope.permit_id,
            allowed_hosts=scope.allowed_hosts,
            allowed_methods=scope.allowed_methods,
            allowed_path_prefixes=scope.allowed_path_prefixes,
            not_before=scope.not_before,
            expires_at=scope.expires_at,
            request_budget=scope.request_budget,
            signature=signature,
        )


@dataclass(frozen=True)
class PolicyDecision:
    """A local authorization result; callers may now send exactly one request."""

    permit_id: str
    request_number: int
    remaining_requests: int
    method: str
    host: str
    path: str


class PermitEvaluator:
    """Fail-closed, thread-safe local evaluator for signed permits.

    Budget accounting intentionally lives only in this evaluator.  A
    production private runner should keep one evaluator (or a durable local
    equivalent) for a run; constructing a new evaluator is not a replacement
    for durable run state in an orchestration layer.
    """

    def __init__(self, public_verification_key: str) -> None:
        self._verification_key = _public_key_from_material(public_verification_key)
        self._lock = threading.Lock()
        self._requests_used: dict[str, int] = {}

    def evaluate(
        self,
        permit: Permit,
        *,
        method: str,
        url: str,
    ) -> PolicyDecision:
        """Authorize and reserve one request, or raise without consuming budget."""
        if not isinstance(permit, Permit):
            raise PermitValidationError("A Permit instance is required")

        # Signature verification happens before a request is considered.
        _verify_signature(permit, self._verification_key)
        scope = _canonical_scope(permit)
        current_time = _canonical_datetime(_current_time(), "now")
        if current_time < scope.not_before:
            raise PolicyDeniedError("Permit is not active yet")
        if current_time >= scope.expires_at:
            raise PolicyDeniedError("Permit has expired")

        normalized_method = _canonical_method(method)
        request_host, request_path = _parse_https_url(url)
        if request_host not in scope.allowed_hosts:
            raise PolicyDeniedError("Request host is not inside the permit")
        if normalized_method not in scope.allowed_methods:
            raise PolicyDeniedError("Request method is not inside the permit")
        if not _path_is_allowed(request_path, scope.allowed_path_prefixes):
            raise PolicyDeniedError("Request path is not inside the permit")

        permit_fingerprint = hashlib.sha256(
            permit.canonical_payload() + b"." + permit.signature.encode("ascii")
        ).hexdigest()
        with self._lock:
            used = self._requests_used.get(permit_fingerprint, 0)
            if used >= scope.request_budget:
                raise PolicyDeniedError("Permit request budget is exhausted")
            request_number = used + 1
            self._requests_used[permit_fingerprint] = request_number

        return PolicyDecision(
            permit_id=scope.permit_id,
            request_number=request_number,
            remaining_requests=scope.request_budget - request_number,
            method=normalized_method,
            host=request_host,
            path=request_path,
        )


def _canonical_scope(permit: Permit) -> _PermitScope:
    permit_id = _canonical_permit_id(permit.permit_id)
    hosts = _canonical_collection(permit.allowed_hosts, _canonical_host, "allowed_hosts")
    methods = _canonical_collection(permit.allowed_methods, _canonical_method, "allowed_methods")
    prefixes = _canonical_collection(
        permit.allowed_path_prefixes,
        _canonical_path_prefix,
        "allowed_path_prefixes",
    )
    not_before = _canonical_datetime(permit.not_before, "not_before")
    expires_at = _canonical_datetime(permit.expires_at, "expires_at")
    if not_before >= expires_at:
        raise PermitValidationError("Permit expiry must be later than not_before")
    if isinstance(permit.request_budget, bool) or not isinstance(permit.request_budget, int):
        raise PermitValidationError("request_budget must be an integer")
    if permit.request_budget < 1:
        raise PermitValidationError("request_budget must be at least 1")
    return _PermitScope(
        permit_id=permit_id,
        allowed_hosts=hosts,
        allowed_methods=methods,
        allowed_path_prefixes=prefixes,
        not_before=not_before,
        expires_at=expires_at,
        request_budget=permit.request_budget,
    )


def _canonical_collection(
    values: object,
    normalizer: Any,
    field_name: str,
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Iterable):
        raise PermitValidationError(f"{field_name} must be a non-empty collection")
    try:
        normalized = tuple(normalizer(value) for value in values)
    except TypeError as exc:
        raise PermitValidationError(f"{field_name} must be a non-empty collection") from exc
    if not normalized:
        raise PermitValidationError(f"{field_name} must not be empty")
    if len(set(normalized)) != len(normalized):
        raise PermitValidationError(f"{field_name} must not contain duplicate values")
    return tuple(sorted(normalized))


def _materialize_collection(value: object, field_name: str) -> tuple[object, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise PermitValidationError(f"{field_name} must be a non-empty collection")
    try:
        return tuple(value)
    except TypeError as exc:
        raise PermitValidationError(f"{field_name} must be a non-empty collection") from exc


def _canonical_permit_id(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 200:
        raise PermitValidationError("permit_id must be a non-empty trimmed string")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise PermitValidationError("permit_id contains a control character")
    return value


def _canonical_host(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise PermitValidationError("Host must be a non-empty trimmed string")
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value):
        raise PermitValidationError("Host contains whitespace or a control character")
    if any(character in value for character in "/\\@?#[]"):
        raise PermitValidationError("Host must not contain URL syntax")
    raw_host = value[:-1] if value.endswith(".") else value
    if not raw_host:
        raise PermitValidationError("Host must not be only a trailing dot")
    try:
        return ipaddress.ip_address(raw_host).compressed.lower()
    except ValueError:
        pass
    try:
        host = raw_host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise PermitValidationError("Host is not valid IDNA") from exc
    if len(host) > 253 or not host or host.endswith("."):
        raise PermitValidationError("Host is not a valid DNS name")
    labels = host.split(".")
    if not all(_DNS_LABEL_RE.fullmatch(label) for label in labels):
        raise PermitValidationError("Host is not a valid DNS name")
    # Reject dotted-decimal lookalikes which are not a canonical IPv4 literal.
    if all(label.isdigit() for label in labels):
        raise PermitValidationError("Host must use a canonical IP literal or DNS name")
    return host


def _canonical_method(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise PermitValidationError("HTTP method must be a non-empty trimmed string")
    if not value.isascii():
        raise PermitValidationError("HTTP method must use ASCII token characters")
    method = value.upper()
    if not _HTTP_TOKEN_RE.fullmatch(method):
        raise PermitValidationError("HTTP method is not a valid token")
    return method


def _canonical_path_prefix(value: object) -> str:
    path = _safe_path(value, "Allowed path prefix")
    if path.startswith("//"):
        raise PermitValidationError("Allowed path prefix must not begin with '//'")
    return path


def _safe_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or not value.startswith("/"):
        raise PermitValidationError(f"{label} must start with '/'")
    # Until an independently enforced proxy owns URI normalization, reject
    # non-ASCII paths rather than relying on a scanner, HTTP client, and
    # target framework to agree about Unicode-to-percent encoding semantics.
    if not value.isascii():
        raise PermitValidationError(f"{label} must use ASCII characters")
    if "?" in value or "#" in value:
        raise PermitValidationError(f"{label} must not contain a query or fragment")
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value):
        raise PermitValidationError(f"{label} contains whitespace or a control character")
    if "\\" in value or _ENCODED_SEPARATOR_RE.search(value):
        raise PermitValidationError(f"{label} contains an ambiguous path separator")
    try:
        decoded_bytes = unquote_to_bytes(value)
        decoded = decoded_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise PermitValidationError(f"{label} is not valid UTF-8") from exc
    # A second decoding pass in an upstream router must not turn a permitted
    # path into a dot segment or separator.  Treat any escaped percent sign as
    # ambiguous instead of guessing how a target normalizes it.
    if b"%" in decoded_bytes:
        raise PermitValidationError(f"{label} contains repeated percent encoding")
    if "\\" in decoded or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in decoded):
        raise PermitValidationError(f"{label} contains an unsafe decoded character")
    if any(segment in {".", ".."} for segment in decoded.split("/")):
        raise PermitValidationError(f"{label} contains a dot path segment")
    return value


def _canonical_datetime(value: object, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise PermitValidationError(f"{field_name} must be a timezone-aware datetime")
    try:
        offset = value.utcoffset()
    except (TypeError, ValueError) as exc:
        raise PermitValidationError(f"{field_name} must be a timezone-aware datetime") from exc
    if value.tzinfo is None or offset is None:
        raise PermitValidationError(f"{field_name} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return _canonical_datetime(value, "timestamp").isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: object, field_name: str) -> datetime:
    """Accept only the exact UTC timestamp representation emitted by ``to_dict``."""
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PermitValidationError(f"{field_name} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PermitValidationError(f"{field_name} must be a canonical UTC timestamp") from exc
    normalized = _canonical_datetime(parsed, field_name)
    if _timestamp(normalized) != value:
        raise PermitValidationError(f"{field_name} must be a canonical UTC timestamp")
    return normalized


def generate_ed25519_keypair() -> tuple[str, str]:
    """Create unpadded URL-safe base64 raw Ed25519 private/public material.

    This is a bootstrap helper for an issuer.  The private value must stay in
    the control plane; only the returned public value belongs on a customer
    runner.
    """
    private_key = Ed25519PrivateKey.generate()
    private_material = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_material = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return _encode_base64url(private_material), _encode_base64url(public_material)


def public_verification_key_from_private(private_signing_key: str) -> str:
    """Derive public-only verification material without serializing the private key."""
    private_key = _private_key_from_material(private_signing_key)
    public_material = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return _encode_base64url(public_material)


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_base64url(value: object, *, expected_length: int, label: str) -> bytes:
    expected_encoded_length = (
        _UNPADDED_KEY_LENGTH
        if expected_length == _RAW_ED25519_KEY_LENGTH
        else _UNPADDED_SIGNATURE_LENGTH
    )
    if (
        not isinstance(value, str)
        or len(value) != expected_encoded_length
        or _BASE64URL_RE.fullmatch(value) is None
    ):
        raise PermitValidationError(f"{label} must be unpadded URL-safe base64 raw material")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, UnicodeEncodeError) as exc:
        raise PermitValidationError(f"{label} is not valid URL-safe base64") from exc
    if len(decoded) != expected_length or _encode_base64url(decoded) != value:
        raise PermitValidationError(f"{label} is not canonical raw material")
    return decoded


def _private_key_from_material(value: str) -> Ed25519PrivateKey:
    material = _decode_base64url(
        value,
        expected_length=_RAW_ED25519_KEY_LENGTH,
        label="Ed25519 private signing key",
    )
    try:
        return Ed25519PrivateKey.from_private_bytes(material)
    except ValueError as exc:
        raise PermitValidationError("Ed25519 private signing key is invalid") from exc


def _public_key_from_material(value: str) -> Ed25519PublicKey:
    material = _decode_base64url(
        value,
        expected_length=_RAW_ED25519_KEY_LENGTH,
        label="Ed25519 public verification key",
    )
    try:
        return Ed25519PublicKey.from_public_bytes(material)
    except ValueError as exc:
        raise PermitValidationError("Ed25519 public verification key is invalid") from exc


def _sign(payload: bytes, private_signing_key: str) -> str:
    return _encode_base64url(_private_key_from_material(private_signing_key).sign(payload))


def _verify_signature(
    permit: Permit,
    public_verification_key: str | Ed25519PublicKey,
) -> None:
    signature = permit.signature
    try:
        signature_bytes = _decode_base64url(
            signature,
            expected_length=_RAW_ED25519_SIGNATURE_LENGTH,
            label="Permit signature",
        )
    except PermitValidationError as exc:
        raise PermitSignatureError("Permit is missing a valid signature") from exc
    public_key = (
        public_verification_key
        if isinstance(public_verification_key, Ed25519PublicKey)
        else _public_key_from_material(public_verification_key)
    )
    try:
        public_key.verify(signature_bytes, permit.canonical_payload())
    except InvalidSignature as exc:
        raise PermitSignatureError("Permit signature verification failed") from exc


def _parse_https_url(value: object) -> tuple[str, str]:
    if not isinstance(value, str) or not value or value != value.strip():
        raise PermitValidationError("Request URL must be a non-empty trimmed string")
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value):
        raise PermitValidationError("Request URL contains whitespace or a control character")
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise PermitValidationError("Request URL is malformed") from exc
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        raise PolicyDeniedError("Request URL must use HTTPS with an authority")
    if "\\" in parsed.netloc or parsed.username is not None or parsed.password is not None:
        raise PolicyDeniedError("Request URL must not contain userinfo or an ambiguous authority")
    try:
        port = parsed.port
    except ValueError as exc:
        raise PermitValidationError("Request URL has an invalid port") from exc
    if port not in (None, 443):
        raise PolicyDeniedError("Request URL port is outside the HTTPS policy")
    if not parsed.hostname:
        raise PermitValidationError("Request URL has no host")
    if parsed.fragment:
        raise PolicyDeniedError("Request URL must not contain a fragment")
    if parsed.query or "?" in value:
        # Query parameters can trigger state-changing behavior even for GET;
        # a future typed recipe may add an explicit canonical query policy.
        raise PolicyDeniedError("Request URL must not contain a query")
    host = _canonical_host(parsed.hostname)
    path = _safe_path(parsed.path or "/", "Request URL path")
    return host, path


def _path_is_allowed(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(
        prefix == "/"
        or (path.startswith(prefix) if prefix.endswith("/") else path == prefix or path.startswith(prefix + "/"))
        for prefix in prefixes
    )
