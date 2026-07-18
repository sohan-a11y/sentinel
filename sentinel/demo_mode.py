"""A friendly, CLI-only local demo for Sentinel.

Run ``python -m sentinel.demo_mode start`` (or double-click the launcher in
the repository root).  Demo mode never accepts a target from the command
line.  It creates a disposable HTTPS site on ``127.0.0.1:443`` and exercises
the real ownership, contract, recon, reporting, audit, and halt boundaries
against that site only.

The FastAPI service remains an integration surface, but is not required for
this local operator demo.  Keeping the fixture and operator console in one
process avoids Docker, a browser, a hosts-file edit, a system trust-store
change, and any accidental request to an external system.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import secrets
import socket
import ssl
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


DEMO_HOST = "127.0.0.1"
DEMO_PORT = 443
DEMO_URL = f"https://{DEMO_HOST}"
_DEMO_DIRECTORY = ".sentinel-demo"


class DemoModeError(RuntimeError):
    """A clear, local-only demo setup error safe to show to an operator."""


@dataclass(frozen=True)
class DemoState:
    """Non-secret facts about the current local demo.

    This type deliberately has no API key, ownership proof, canary value, or
    signing secret.  The disposable proof/canary files and local TLS key
    remain in the ignored run folder after exit so the local report and audit
    artifacts stay inspectable; they are never printed or serialized here.
    """

    demo_root: Path
    database_url: str
    audit_log_file: Path
    scan_session_id: int
    contract_id: int
    target_url: str
    started_at: datetime
    ai_enabled: bool = False
    ai_provider: str | None = None
    ai_model: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "demo_root": str(self.demo_root),
            "database_url": self.database_url,
            "audit_log_file": str(self.audit_log_file),
            "scan_session_id": self.scan_session_id,
            "contract_id": self.contract_id,
            "target_url": self.target_url,
            "started_at": self.started_at.isoformat(),
            "ai_enabled": self.ai_enabled,
            "ai_provider": self.ai_provider,
            "ai_model": self.ai_model,
        }


@dataclass
class DemoContext:
    """Runtime handles for one interactive, disposable CLI demo."""

    run_root: Path
    site_root: Path
    certificate_path: Path
    private_key_path: Path
    ca_certificate_path: Path
    database_url: str
    audit_log_file: Path
    scan_session_id: int
    contract_id: int
    server: ThreadingHTTPServer
    server_thread: threading.Thread
    ai_enabled: bool = False
    ai_provider: str | None = None
    ai_model: str | None = None
    runner_thread: threading.Thread | None = None
    pipeline_error: str | None = None
    closed: bool = False
    _state_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


def repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def prepare_demo_site(run_root: Path) -> Path:
    """Create a tiny harmless site that exists only for the local demo."""

    site = run_root / "site"
    well_known = site / ".well-known"
    for directory in (site, well_known, site / "docs", site / "login"):
        directory.mkdir(parents=True, exist_ok=True)

    (site / "index.html").write_text(
        """<!doctype html>
<html><head><title>Sentinel demo target</title></head>
<body>
  <h1>Disposable local demo target</h1>
  <p>This harmless site exists only on this computer for Sentinel recon.</p>
  <nav><a href=\"/docs/\">Docs</a> <a href=\"/login/\">Login</a> <a href=\"/slow.html\">Status</a></nav>
</body></html>""",
        encoding="utf-8",
    )
    (site / "docs" / "index.html").write_text(
        "<html><body><h1>Demo docs</h1><a href=\"/\">Home</a></body></html>", encoding="utf-8"
    )
    (site / "login" / "index.html").write_text(
        "<html><body><h1>Demo login page</h1><a href=\"/\">Home</a></body></html>", encoding="utf-8"
    )
    # The intentional short delay makes the halt command observable in a
    # recording without creating a vulnerability or sending any active test.
    (site / "slow.html").write_text(
        "<html><body><h1>Demo status</h1><a href=\"/\">Home</a></body></html>", encoding="utf-8"
    )
    return site


def _ca_certificate_path(directory: Path) -> Path:
    return directory / "demo-ca.pem"


def create_demo_certificate(directory: Path) -> tuple[Path, Path]:
    """Create a per-demo CA and leaf certificate for loopback TLS only.

    The CA private key is intentionally never written to disk.  The leaf key
    is only for the disposable local fixture and is kept inside the ignored
    demo directory.  Sentinel trusts the per-demo CA through ``SSL_CERT_FILE``
    only in this process; the machine trust store is never modified.
    """

    directory.mkdir(parents=True, exist_ok=True)
    certificate_path = directory / "demo-server.pem"
    private_key_path = directory / "demo-server-key.pem"
    ca_path = _ca_certificate_path(directory)
    if certificate_path.exists() and private_key_path.exists() and ca_path.exists():
        return certificate_path, private_key_path

    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sentinel local demo CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DEMO_HOST)])
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(DEMO_HOST)), x509.DNSName("localhost")]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    certificate_path.write_bytes(server_certificate.public_bytes(serialization.Encoding.PEM))
    private_key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    ca_path.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
    try:
        os.chmod(private_key_path, 0o600)
    except OSError:
        # Windows ACLs are not controlled by chmod.  The key remains inside
        # the user-local, ignored demo folder and is discarded with that demo.
        pass
    return certificate_path, private_key_path


class _LoopbackDemoServer(ThreadingHTTPServer):
    address_family = socket.AF_INET
    allow_reuse_address = False


class _DemoRequestHandler(SimpleHTTPRequestHandler):
    """Quiet static handler with one deliberately slow, harmless HTML page."""

    def do_GET(self) -> None:  # noqa: N802 - required stdlib handler name
        if self.path.split("?", 1)[0] == "/slow.html":
            time.sleep(5)
        super().do_GET()

    def log_message(self, _format: str, *_args: object) -> None:
        # Do not print proof/canary request details to the operator console.
        return


def _assert_loopback_port_available(port: int = DEMO_PORT) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((DEMO_HOST, port))
    except OSError as exc:
        raise DemoModeError(
            f"Port {port} is already in use. Close the local program using it, then start Sentinel Demo again."
        ) from exc


def _start_demo_server(site_root: Path, certificate_path: Path, private_key_path: Path) -> tuple[ThreadingHTTPServer, threading.Thread]:
    _assert_loopback_port_available()
    handler = partial(_DemoRequestHandler, directory=str(site_root))
    try:
        server = _LoopbackDemoServer((DEMO_HOST, DEMO_PORT), handler)
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.load_cert_chain(certfile=certificate_path, keyfile=private_key_path)
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    except OSError as exc:
        raise DemoModeError("Sentinel could not start its loopback-only HTTPS demo site.") from exc

    thread = threading.Thread(target=server.serve_forever, name="sentinel-demo-target", daemon=True)
    thread.start()
    return server, thread


def _wait_for_local_target(ca_certificate_path: Path) -> None:
    deadline = time.monotonic() + 5
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            response = httpx.get(DEMO_URL, verify=str(ca_certificate_path), timeout=0.5, trust_env=False)
            if response.status_code == 200:
                return
        except httpx.HTTPError as exc:
            last_error = exc
        time.sleep(0.05)
    raise DemoModeError("The local HTTPS demo site did not become ready.") from last_error


def _run_directory() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return repository_root() / _DEMO_DIRECTORY / f"run-{stamp}-{secrets.token_hex(3)}"


def _sqlite_url(path: Path) -> str:
    return "sqlite:///" + path.resolve().as_posix()


def _configure_demo_environment(
    run_root: Path, ca_certificate_path: Path, *, use_ai: bool = False
) -> tuple[str, Path]:
    """Install only disposable, process-scoped settings before Sentinel imports."""

    database_url = _sqlite_url(run_root / "sentinel-demo.db")
    audit_log_file = run_root / "audit.ndjson"
    for proxy_variable in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        os.environ.pop(proxy_variable, None)
    environment = {
        "SENTINEL_DATABASE_URL": database_url,
        "SENTINEL_AUDIT_LOG_FILE": str(audit_log_file),
        "SENTINEL_AUDIT_LOG_HMAC_KEY": secrets.token_urlsafe(32),
        "SENTINEL_CONTROL_PLANE_SIGNING_KEY": secrets.token_urlsafe(32),
        "SENTINEL_RECON_MAX_PAGES": "10",
        "SENTINEL_RECON_MAX_REQUESTS_PER_SECOND": "3",
        # The AI demo is deliberately an opt-in TokenRouter-only mode.  This
        # prevents an inherited Anthropic/OpenRouter/OpenAI key from routing
        # the synthetic demo site map to a different provider.
        "SENTINEL_ANTHROPIC_API_KEY": "",
        "SENTINEL_OPENROUTER_API_KEY": "",
        "SENTINEL_OPENAI_API_KEY": "",
        "SSL_CERT_FILE": str(ca_certificate_path),
        "NO_PROXY": "127.0.0.1,localhost",
    }
    if use_ai:
        # Six CWEs is a clearly labelled preview, not a claim that the AI
        # reviewed the whole catalog.  It keeps a live demo comfortably short.
        environment["SENTINEL_LLM_MAX_CWE_JUDGMENTS"] = "6"
    else:
        # An ordinary local demo must never pick up a provider key from .env.
        environment["SENTINEL_TOKENROUTER_API_KEY"] = ""
        os.environ.pop("SENTINEL_LLM_MAX_CWE_JUDGMENTS", None)
    os.environ.update(environment)
    return database_url, audit_log_file


def _require_tokenrouter_ai_demo_configuration() -> tuple[str, str]:
    """Validate the local opt-in before starting any demo resources.

    This validates configuration only.  The real TokenRouter request happens
    inside the CWE mapping step and the CLI reports it as completed only after
    that step has successfully recorded the result.
    """

    from sentinel.config import settings

    api_key = (settings.tokenrouter_api_key or "").strip()
    if not api_key:
        raise DemoModeError(
            "AI demo requires SENTINEL_TOKENROUTER_API_KEY in your local .env. "
            "Use a newly issued TokenRouter key; do not paste it into the CLI."
        )
    model = settings.tokenrouter_model.strip()
    if not model:
        raise DemoModeError(
            "AI demo requires SENTINEL_TOKENROUTER_MODEL in your local .env."
        )
    return "TokenRouter", model


def _build_authorized_demo_run(
    site_root: Path, *, ai_provider: str | None = None, ai_model: str | None = None
) -> tuple[int, int]:
    """Exercise the production-shaped gates against the immutable local target."""

    # These imports intentionally happen after _configure_demo_environment.
    # Settings and the SQLAlchemy engine are constructed from that process-only
    # environment, not from a caller's usual database or credentials.
    from sentinel.control_plane import service
    from sentinel.db.models import ActionTier
    from sentinel.db.session import get_session, init_db
    from sentinel.phase0 import registry
    from sentinel.security import audit_log

    init_db()
    with get_session() as db:
        registration = registry.register_target(
            db,
            domain=DEMO_HOST,
            account_owner="local-demo-operator",
            canary_check_url_template=f"{DEMO_URL}/.well-known/canary-{{marker}}.txt",
            canary_check_method="GET",
        )
        well_known = site_root / ".well-known"
        # These values are never printed or placed in the CLI state object.
        (well_known / "sentinel-auth.txt").write_text(registration.verification_token, encoding="utf-8")
        (well_known / f"canary-{registration.canary_marker}.txt").write_text(
            registration.canary_marker, encoding="utf-8"
        )
        verified_registration = registry.run_ownership_verification(
            db,
            DEMO_HOST,
            # Do not let a failed local HTTPS proof fall back to the system
            # DNS resolver. Demo mode must remain loopback-only on failure.
            allow_dns_fallback=False,
        )
        if not verified_registration.is_ownership_verified:
            raise DemoModeError("Sentinel could not prove control of its local demo target.")
        contract = service.create_scan_contract(
            db,
            registration=verified_registration,
            approved_by="Local Demo Operator",
            customer_authorization_reference="LOCAL-DEMO-ONLY",
            allowed_tier=ActionTier.TIER_A,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
            max_scan_sessions=1,
            max_requests=25,
        )
        scan_session = service.start_contract_run(db, contract_id=contract.id)
        if ai_provider and ai_model:
            audit_log.record(
                db,
                agent="demo_mode",
                action="demo_ai_mode_enabled",
                payload={
                    "scan_session_id": scan_session.id,
                    "provider": ai_provider,
                    "requested_model": ai_model,
                    "data_scope": "synthetic local site map only",
                    "cwe_judgment_cap": 6,
                },
            )
        return scan_session.id, contract.id


def _run_pipeline(context: DemoContext) -> None:
    from sentinel.agents.graph import run_scan_pipeline
    from sentinel.security.guardrails import ScanHaltedError

    try:
        run_scan_pipeline(context.scan_session_id)
    except ScanHaltedError:
        # Halt is an expected operator action, not a demo failure.
        return
    except Exception as exc:  # pragma: no cover - safety net for an interactive process
        with context._state_lock:
            context.pipeline_error = type(exc).__name__


def start_demo(*, use_ai: bool = False) -> DemoContext:
    """Start one safe local run and return its interactive operator context."""

    run_root = _run_directory()
    run_root.mkdir(parents=True, exist_ok=False)
    site_root = prepare_demo_site(run_root)
    tls_directory = run_root / "tls"
    certificate_path, private_key_path = create_demo_certificate(tls_directory)
    ca_certificate_path = _ca_certificate_path(tls_directory)
    database_url, audit_log_file = _configure_demo_environment(
        run_root, ca_certificate_path, use_ai=use_ai
    )
    ai_provider: str | None = None
    ai_model: str | None = None
    if use_ai:
        ai_provider, ai_model = _require_tokenrouter_ai_demo_configuration()
    server, server_thread = _start_demo_server(site_root, certificate_path, private_key_path)
    try:
        _wait_for_local_target(ca_certificate_path)
        scan_session_id, contract_id = _build_authorized_demo_run(
            site_root, ai_provider=ai_provider, ai_model=ai_model
        )
    except Exception:
        server.shutdown()
        server.server_close()
        raise

    context = DemoContext(
        run_root=run_root,
        site_root=site_root,
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        ca_certificate_path=ca_certificate_path,
        database_url=database_url,
        audit_log_file=audit_log_file,
        scan_session_id=scan_session_id,
        contract_id=contract_id,
        server=server,
        server_thread=server_thread,
        ai_enabled=use_ai,
        ai_provider=ai_provider,
        ai_model=ai_model,
    )
    metadata = DemoState(
        demo_root=run_root,
        database_url=database_url,
        audit_log_file=audit_log_file,
        scan_session_id=scan_session_id,
        contract_id=contract_id,
        target_url=DEMO_URL,
        started_at=datetime.now(timezone.utc),
        ai_enabled=use_ai,
        ai_provider=ai_provider,
        ai_model=ai_model,
    )
    (run_root / "demo-info.json").write_text(
        json.dumps(metadata.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
    )
    runner = threading.Thread(target=_run_pipeline, args=(context,), name="sentinel-demo-recon", daemon=True)
    context.runner_thread = runner
    runner.start()
    return context


def _audit_payload_for_scan(db: Any, *, agent: str, action: str, scan_session_id: int) -> dict[str, object] | None:
    """Read a non-secret audit payload for this isolated local scan."""

    from sentinel.db.models import AuditLogEntry

    entries = (
        db.query(AuditLogEntry)
        .filter(AuditLogEntry.agent == agent, AuditLogEntry.action == action)
        .order_by(AuditLogEntry.id.desc())
    )
    for entry in entries:
        try:
            payload = json.loads(entry.payload_json)
        except (TypeError, json.JSONDecodeError):
            continue
        if payload.get("scan_session_id") == scan_session_id:
            return payload
    return None


def _dashboard_data(context: DemoContext) -> tuple[dict[str, object], list[dict[str, object]], dict[str, object]]:
    from sentinel.agents.report_agent import build_summary
    from sentinel.db.models import Finding, ScanSession
    from sentinel.db.session import get_session
    from sentinel.security import audit_log

    with get_session() as db:
        scan_session = db.get(ScanSession, context.scan_session_id)
        if scan_session is None:
            raise DemoModeError("The local demo scan record is no longer available.")
        summary = build_summary(db, context.scan_session_id)
        scan: dict[str, object] = {
            "scan_session_id": context.scan_session_id,
            "target": DEMO_URL,
            "status": scan_session.status.value,
            "environment_tier": scan_session.environment_tier.value,
            "halted_reason": scan_session.halted_reason,
            **summary,
        }
        if context.ai_enabled:
            mapping_payload = _audit_payload_for_scan(
                db,
                agent="cwe_mapping_agent",
                action="cwe_mapping_complete",
                scan_session_id=context.scan_session_id,
            )
            unavailable_payload = _audit_payload_for_scan(
                db,
                agent="cwe_mapping_agent",
                action="llm_unavailable_default",
                scan_session_id=context.scan_session_id,
            )
            ai_judged_count = int((mapping_payload or {}).get("llm_judged_count", 0))
            if mapping_payload is None:
                ai_status = "waiting for live TokenRouter triage"
            elif unavailable_payload is not None and ai_judged_count:
                ai_status = "partly completed; manual triage is still required"
            elif unavailable_payload is not None:
                ai_status = "could not complete; manual triage is required"
            else:
                ai_status = "completed with live AI triage"
            scan.update(
                {
                    "ai_enabled": True,
                    "ai_provider": context.ai_provider,
                    "ai_model": context.ai_model,
                    "ai_judged_count": ai_judged_count,
                    "ai_status": ai_status,
                }
            )
        else:
            scan["ai_enabled"] = False
        findings = [finding.to_dict() for finding in db.query(Finding).filter(Finding.scan_session_id == context.scan_session_id)]
        chain_intact, reason = audit_log.verify_chain(db)
    return scan, findings, {"chain_intact": chain_intact, "reason": reason}


def format_dashboard(
    *, scan: dict[str, object], findings: list[dict[str, object]], audit: dict[str, object]
) -> str:
    """Render the useful dashboard facts in plain terminal English.

    Evidence bodies are intentionally excluded.  The CLI exposes the same
    useful dashboard facts—status, coverage, findings, audit health, and a
    halt control—without leaking raw request/response material.
    """

    lines = ["", "=" * 72, "SENTINEL — LOCAL DEMO STATUS", "=" * 72]
    lines.extend(
        [
            "", "SCAN STATUS",
            f"  Target:           {scan.get('target', DEMO_URL)} (this computer only)",
            f"  Run ID:           {scan.get('scan_session_id', 'n/a')}",
            f"  State:            {str(scan.get('status', 'unknown')).upper()}",
            f"  Allowed activity:  recon.v1 only (no active exploit tools)",
            f"  Environment tier: {scan.get('environment_tier', 'n/a')}",
        ]
    )
    if scan.get("halted_reason"):
        lines.append(f"  Stop reason:      {scan['halted_reason']}")

    lines.extend(["", "AI TRIAGE"])
    if scan.get("ai_enabled"):
        lines.extend(
            [
                f"  Provider:         {scan.get('ai_provider', 'TokenRouter')}",
                f"  Requested model:  {scan.get('ai_model', 'not recorded')}",
                "  Data scope:       synthetic local site map only",
                f"  Status:           {scan.get('ai_status', 'waiting for live TokenRouter triage')}",
                f"  AI-reviewed CWEs: {scan.get('ai_judged_count', 0)} (of the six-CWE demo preview)",
            ]
        )
    else:
        lines.append("  Disabled for this run. Use the AI demo launcher to opt in with TokenRouter.")

    lines.extend(
        [
            "", "CWE COVERAGE",
            f"  Applicable checks:     {scan.get('applicable_cwe_count', 0)}",
            f"  Not applicable checks: {scan.get('not_applicable_cwe_count', 0)}",
            f"  Checks completed:      {scan.get('tested_cwe_count', 0)}",
            f"  Confirmed findings:    {scan.get('confirmed_count', 0)}",
            f"  Unconfirmed signals:   {scan.get('unconfirmed_count', 0)}",
            f"  Summary: {scan.get('headline', 'No summary yet.')}",
            "", "FINDINGS",
        ]
    )
    if findings:
        for finding in findings:
            lines.append(
                "  "
                + f"{finding.get('cwe_id', 'Unknown')} | {finding.get('status', 'unknown')} | "
                + f"confidence {float(finding.get('confidence', 0)):.2f} | {finding.get('endpoint', 'n/a')}"
            )
    else:
        lines.append("  No findings recorded. This is not a claim that an application is secure.")

    audit_state = "PASS" if audit.get("chain_intact") else "CHECK REQUIRED"
    lines.extend(
        [
            "", "AUDIT LOG",
            f"  Integrity: {audit_state}",
            "", "CONTROLS",
            "  Enter = refresh status    H = halt run    R = export report    Q = exit demo",
            "=" * 72,
        ]
    )
    return "\n".join(lines)


def show_status(context: DemoContext) -> None:
    scan, findings, audit = _dashboard_data(context)
    print(format_dashboard(scan=scan, findings=findings, audit=audit))
    with context._state_lock:
        if context.pipeline_error:
            print(f"\nNote: the recon worker stopped with {context.pipeline_error}. See the local audit file for details.")


def halt_demo(
    context: DemoContext, reason: str = "local demo: operator stop", *, announce: bool = True
) -> None:
    from sentinel.agents.kill_switch import manual_halt
    from sentinel.db.models import ScanSession, ScanStatus
    from sentinel.db.session import get_session

    with get_session() as db:
        scan_session = db.get(ScanSession, context.scan_session_id)
        if scan_session is None:
            raise DemoModeError("The local demo scan record is no longer available.")
        if scan_session.status == ScanStatus.RUNNING:
            manual_halt(db, context.scan_session_id, reason=reason)
            if announce:
                print("\nStop requested. Sentinel will not make another authorized request after the current check returns.")
        elif announce:
            print(f"\nThe run is already {scan_session.status.value}; there is nothing left to stop.")


def export_report(context: DemoContext) -> Path:
    from sentinel.agents.report_agent import export_markdown
    from sentinel.db.session import get_session

    report_directory = context.run_root / "reports"
    report_directory.mkdir(exist_ok=True)
    report_path = report_directory / f"sentinel-local-demo-{context.scan_session_id}.md"
    with get_session() as db:
        report_path.write_text(export_markdown(db, context.scan_session_id), encoding="utf-8")
    return report_path


def close_demo(context: DemoContext) -> None:
    """Stop only this process's loopback server; preserve evidence files."""

    if context.closed:
        return
    context.closed = True
    try:
        halt_demo(context, reason="local demo closed", announce=False)
    except DemoModeError:
        pass
    if context.runner_thread is not None:
        context.runner_thread.join(timeout=7)
    context.server.shutdown()
    context.server.server_close()
    context.server_thread.join(timeout=2)


def _wait_for_completion(context: DemoContext, timeout_seconds: float = 30) -> None:
    deadline = time.monotonic() + timeout_seconds
    while context.runner_thread is not None and context.runner_thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.2)
    show_status(context)


def interactive_console(context: DemoContext) -> None:
    print("\nSafe local demo started. Sentinel is testing only https://127.0.0.1 on this computer.")
    if context.ai_enabled:
        print("TokenRouter receives only the synthetic local site map for AI triage; target traffic stays loopback-only.")
    else:
        print("No Docker, browser, real credential, external host, or active exploit engine is used.")
    while True:
        show_status(context)
        try:
            command = input("\nChoose an action [Enter/H/R/Q]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nClosing the local demo.")
            return
        if command in {"", "s", "status"}:
            continue
        if command in {"h", "halt"}:
            halt_demo(context)
            continue
        if command in {"r", "report"}:
            report_path = export_report(context)
            print(f"\nReport saved locally: {report_path}")
            continue
        if command in {"q", "quit", "exit"}:
            return
        print("Please use Enter, H, R, or Q.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m sentinel.demo_mode",
        description="Start Sentinel's safe, CLI-only local demo.",
    )
    commands = parser.add_subparsers(dest="command")
    start = commands.add_parser("start", help="start the safe local demo (default)")
    start.add_argument("--no-menu", action="store_true", help="wait for the local run, print one status view, then exit")
    start.add_argument(
        "--use-ai",
        action="store_true",
        help="opt in to TokenRouter AI triage of the synthetic local demo site map",
    )
    parser.set_defaults(command="start", no_menu=False, use_ai=False)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "start":  # Defensive; the parser currently has one safe command only.
        raise DemoModeError("Only the safe local demo start command is available.")

    context: DemoContext | None = None
    try:
        context = start_demo(use_ai=args.use_ai)
        if args.no_menu:
            _wait_for_completion(context)
        else:
            interactive_console(context)
        return 0
    except DemoModeError as exc:
        print(f"\nSentinel Demo could not start: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nClosing the local demo.")
        return 130
    finally:
        if context is not None:
            close_demo(context)


if __name__ == "__main__":  # pragma: no cover - exercised through the launcher
    raise SystemExit(main())
