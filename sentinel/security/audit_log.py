"""Immutable, hash-chained audit log — independent of agent self-reporting.

Every guardrail decision, every dispatch call, every kill-switch trip is
written here by *code* (guardrails.py, dispatcher, kill_switch.py), not by an
LLM narrating what it did. Each entry embeds a keyed digest of the previous
entry, so any retroactive edit or deletion breaks the chain and is detected
by verify_chain(). Entries are written to both the DB (queryable) and an
append-only NDJSON file.

SECURITY NOTE on what this chain actually protects against: with
SENTINEL_AUDIT_LOG_HMAC_KEY unset, `_hash_entry` is plain SHA-256 — anyone
with DB write access (the Sentinel process itself, or an operator/admin) can
edit a past row and recompute every hash forward using this same public
function, and verify_chain() would report the chain as intact. Set
SENTINEL_AUDIT_LOG_HMAC_KEY to a secret kept OUTSIDE the database (env var,
secrets manager — never a DB-stored value) and every hash becomes an HMAC
keyed on it: recomputing a valid forward chain after tampering with a row
then requires that secret, not just DB access. This raises the bar; it does
not by itself defend against a party who can also read the app's environment
(a genuinely separate, append-only signing service would be needed for
that), and the NDJSON file is an operational convenience for grepping, not an
independent proof — nothing here cross-checks it against the DB rows.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from sentinel.config import settings
from sentinel.db.models import AuditLogEntry

GENESIS_HASH = "0" * 64

_write_lock = threading.Lock()


def _hash_entry(prev_hash: str, timestamp: str, agent: str, action: str, payload_json: str) -> str:
    digest_input = f"{prev_hash}|{timestamp}|{agent}|{action}|{payload_json}".encode("utf-8")
    key = settings.audit_log_hmac_key
    if key:
        return hmac.new(key.encode("utf-8"), digest_input, hashlib.sha256).hexdigest()
    return hashlib.sha256(digest_input).hexdigest()


def _last_hash(session: Session) -> str:
    last = session.query(AuditLogEntry).order_by(AuditLogEntry.id.desc()).first()
    return last.entry_hash if last else GENESIS_HASH


def record(session: Session, *, agent: str, action: str, payload: dict[str, Any]) -> AuditLogEntry:
    """Append one audit entry. Thread-safe; call this and only this to write."""
    with _write_lock:
        prev_hash = _last_hash(session)
        now = datetime.now(timezone.utc)
        timestamp = now.isoformat()
        payload_json = json.dumps(payload, sort_keys=True, default=str)
        entry_hash = _hash_entry(prev_hash, timestamp, agent, action, payload_json)

        entry = AuditLogEntry(
            timestamp=timestamp,
            agent=agent,
            action=action,
            payload_json=payload_json,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        session.add(entry)
        session.flush()

        _append_to_file(entry.id, timestamp, agent, action, payload_json, prev_hash, entry_hash)
        return entry


def _append_to_file(
    entry_id: int, timestamp: str, agent: str, action: str, payload_json: str, prev_hash: str, entry_hash: str
) -> None:
    line = json.dumps(
        {
            "id": entry_id,
            "timestamp": timestamp,
            "agent": agent,
            "action": action,
            "payload": json.loads(payload_json),
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
        },
        sort_keys=True,
    )
    path = settings.audit_log_file
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def verify_chain(session: Session) -> tuple[bool, str | None]:
    """Recompute the hash chain from genesis. Returns (ok, first_bad_reason)."""
    prev_hash = GENESIS_HASH
    entries = session.query(AuditLogEntry).order_by(AuditLogEntry.id.asc()).all()
    for entry in entries:
        if entry.prev_hash != prev_hash:
            return False, f"entry {entry.id}: prev_hash mismatch (chain broken/reordered)"
        recomputed = _hash_entry(entry.prev_hash, entry.timestamp, entry.agent, entry.action, entry.payload_json)
        if recomputed != entry.entry_hash:
            return False, f"entry {entry.id}: entry_hash mismatch (payload tampered)"
        prev_hash = entry.entry_hash
    return True, None
