# Sentinel

Autonomous, multi-agent CWE-coverage pentesting platform. Sentinel scans domains a company
already owns and has cryptographically proven ownership of — never anything else — and reports
exactly how much of the web-relevant CWE catalog it tested, what it confirmed, and what needs a
human look.

**Sentinel runs unattended once a scan starts.** No agent asks a human to approve an individual
request. What makes that safe to say is not a prompt telling the LLM to behave — it's that every
scan action passes through two files that are plain Python, not English:

- [`sentinel/security/guardrails.py`](sentinel/security/guardrails.py) — hard boundaries. Every
  dispatch call starts with `enforce_target_authorized`, `enforce_tier`, `enforce_no_pivot`, or
  `enforce_not_halted`. These raise real exceptions. There is no `force=`, `override=`, or env var
  that changes their behavior — changing them means editing this file, which means a reviewed
  commit.
- [`sentinel/phase0/`](sentinel/phase0) — the gate that runs *before* any of the above even has a
  registered target to check against.

If you take nothing else from this README: **read Phase 0 and guardrails.py before you extend
anything.** Every other module in this repo is built to call into them, not around them.

## Architecture

```
                         ┌─────────────────────────────────────────┐
                         │  PHASE 0 — cannot be disabled by config  │
                         │  1. Domain ownership (HTTP/DNS token)    │
                         │  2. Environment canary (live probe)      │
                         │  3. Registration record (SQL, audited)   │
                         └───────────────────┬───────────────────┘
                                             │ start_scan_session()
                                             ▼
                         ┌─────────────────────────────────────────┐
                         │        sentinel.security.guardrails      │◄──── every agent below
                         │  enforce_target_authorized / _tier /     │      calls into this,
                         │  _no_pivot / _not_halted /                │      not around it
                         │  _demonstration_budget                   │
                         └───────────────────┬───────────────────┘
                                             │
    ┌───────────────┬────────────────────────┼────────────────────────┬───────────────┐
    ▼               ▼                        ▼                        ▼               ▼
 Agent 1         Agent 2                  Agent 3                 Agent 4         Agent 5
 Recon      CWE Mapping Agent          Dispatcher            Verification      Report Agent
 (crawl,    (150-250 web-relevant   ┌───────────────┐        (independent    (dashboard,
  fingerprint)  CWEs, applicable/    │ nuclei_wrapper │        re-check via    markdown/PDF
                not-applicable +     │ zap_wrapper    │        a 2nd method    export)
                reason)              │ idor_agent     │        before
                                     │  (CWE-639,     │        "confirmed")
                                     │   LLM-driven)  │
                                     └───────────────┘

                         ┌─────────────────────────────────────────┐
                         │   Agent 6 — Kill Switch Monitor           │
                         │   Runs alongside everything above:        │
                         │   watches error-rate/latency, auto-halts,  │
                         │   exposes the ONE human touchpoint after   │
                         │   Phase 0 (manual halt), writes an          │
                         │   immutable hash-chained audit log entry   │
                         │   for every halt, automatic or manual.     │
                         └─────────────────────────────────────────┘
```

All six agents are [LangGraph](https://github.com/langchain-ai/langgraph) nodes sharing one state
object, [`SentinelState`](sentinel/agents/state.py) — the single contract every module in this
build agreed on, which is what let recon/cwe-mapping/nuclei/zap/idor/verification/report get
built independently and land without merge conflicts. The graph itself
([`sentinel/agents/graph.py`](sentinel/agents/graph.py)) is:

```
recon -> cwe_mapping -> dispatch -> sync_cwe_checklist -+-(halted)-> finalize_halted -+-> persist_findings -> report -> END
                                                          +-(clean)-> verification    -+
```

If the kill switch trips mid-dispatch, the conditional edge routes straight to
`finalize_halted` instead of `verification` — verification makes its own live requests to the
target to independently re-check findings, so running it after a halt would violate the halt it's
supposed to respect. Raw findings from before the halt are kept and demoted to `unconfirmed`
rather than lost.

## Why this is safe to run unattended

| Boundary | Enforced by | What happens if violated |
|---|---|---|
| Scan only registered, ownership-verified domains | `guardrails.enforce_target_authorized` reading `target_registrations` | `UnauthorizedTargetError`, scan action never sent |
| No pivoting to hosts discovered during recon | `guardrails.enforce_no_pivot`, called before every request in nuclei/zap/idor wrappers | `PivotViolationError` |
| No pivoting via a redirect either | `sentinel/security/safe_http.py` — manually walks redirect chains, re-validating the host at every hop, instead of letting httpx follow `Location` headers unchecked | `PivotViolationError`, and cookies attached to the original request are never resent to the redirect target |
| Only http/https URLs are ever treated as "the same host" | `guardrails.normalize_host` rejects `file://`, `ftp://`, etc. outright rather than extracting a same-looking hostname from them | `PivotViolationError` |
| Destructive (Tier B) tests only in a proven-safe environment | `guardrails.enforce_tier`, gated on a **live** canary probe re-run every session (never cached) | `TierViolationError`, session silently downgraded to Tier A |
| No mass account creation, ever, for a given target | `guardrails.enforce_demonstration_budget` — a **persistent, cross-session** counter on the target's own DB row, not a per-call argument a new scan session could reset | `DemonstrationBudgetExceededError` |
| A halted scan cannot keep dispatching, even from a different thread/session | `guardrails.enforce_not_halted` re-reads the DB (`db.refresh`) on every check rather than trusting a possibly-stale in-memory flag | `ScanHaltedError` |
| Every decision is attributable and tamper-evident | `sentinel.security.audit_log` — hash-chained (HMAC-SHA256 when `SENTINEL_AUDIT_LOG_HMAC_KEY` is set), written to DB + an append-only NDJSON file | `audit_log.verify_chain()` detects any retroactive edit |
| Only the domain's own registrant can start/halt/deregister its scans | `sentinel.api.deps.require_api_key` on every mutating route | `401` without `Authorization: Bearer <SENTINEL_API_KEY>` |

None of this is "ask the LLM nicely." `tests/test_guardrails.py::test_no_scan_flag_or_config_can_bypass_this`
asserts, by inspecting function signatures, that no `enforce_*` function even accepts a
force/override/skip parameter.

### Independent security review

Before calling this done, a security-reviewer pass was run specifically against the boundary files
(`phase0/`, `security/guardrails.py`, `security/audit_log.py`, `kill_switch.py`, `idor_agent.py`,
`dispatcher_agent.py`, `graph.py`, and the API routes) — not the whole codebase, just the parts
that make the "runs unattended" claim true. It found seven real issues, six of which are fixed
above (each with a regression test proving the fix, not just the finding):

1. **Redirect-based pivot** (critical) — `follow_redirects=True` in Phase 0 and the IDOR agent let
   a target's `Location:` header carry the request (and an attached session cookie) to an
   unvalidated host. Fixed by `safe_http.py`, which walks redirects manually and re-validates the
   host at each hop. See `tests/test_safe_http.py::test_does_not_leak_cookies_to_off_host_redirect_target`.
2. **Stale halt check across sessions** (critical) — `enforce_not_halted` read an in-memory flag
   that a manual API halt (a different DB session/thread than a long-running dispatch loop) would
   never update. Fixed by refreshing from the DB on every check. See
   `tests/test_guardrails.py::test_picks_up_a_halt_committed_by_a_different_session`.
3. **No caller-identity auth** (high) — Phase 0 verifies domain ownership, never requester
   identity, so anyone who could reach the API could start/halt scans a different party
   registered. Fixed with an opt-in bearer-token dependency (`SENTINEL_API_KEY`) — opt-in rather
   than mandatory-by-default so local dev and the test suite aren't forced through it, but treated
   as required for any deployment reachable by anyone else.
4. **Demonstration budget wasn't persistent** (high) — `enforce_demonstration_budget` compared a
   caller-supplied count against the cap, so it always "passed"; nothing tracked prior creations.
   Fixed with a lifetime counter on `TargetRegistration`. See
   `tests/test_idor_agent.py::test_demo_account_budget_is_actually_persistent_across_two_real_calls`.
5. **Audit log forgeable with DB access alone** (medium-high) — plain SHA-256 means anyone who can
   edit a row can also recompute the chain forward with the same public function. Fixed with an
   optional HMAC key kept outside the database.
6. **Scheme confusion** (medium) — `normalize_host` compared only hostnames, so
   `file://example.com/etc/passwd` normalized identically to the real target and relied on httpx's
   own scheme rejection (not this codebase's boundary) to actually stay safe. Fixed by rejecting
   non-http(s) schemes explicitly.
7. **Audit log write lock is process-local** (low, **not fixed**) — `threading.Lock` doesn't
   coordinate across multiple worker processes. Run Sentinel as a single process, or accept that
   `verify_chain()` may report a false-positive "chain broken" under multi-worker races (it will
   never silently miss real tampering, only occasionally flag benign concurrency as suspicious).
   A real fix needs a DB-level advisory lock (e.g. Postgres `pg_advisory_lock`) and was out of
   scope for this pass.

## Phase 0 — Authorization & Environment Verification

Two independent checks, both fail-closed (any network error, timeout, or missing token means
"not verified" — never "verified by default"):

1. **Domain ownership.** `sentinel/phase0/verification.py`. Place the token Sentinel generates at
   `https://{domain}/.well-known/sentinel-auth.txt`, **or** as a DNS TXT record at
   `_sentinel-verify.{domain}`. Either is sufficient.
2. **Environment canary.** `sentinel/phase0/canary.py`. Seed the UUID Sentinel generates into your
   target's own database (a throwaway test-user row is enough), and give Sentinel a URL template
   (containing the literal placeholder `{marker}`) that reads it back. This is re-probed **fresh,
   live, every scan session** — a prior pass is never trusted. If the marker doesn't come back,
   the whole session is silently downgraded to Tier A (read-only) regardless of what the caller
   claims, and that downgrade is written to the audit log.

`sentinel/phase0/registry.py` ties both together: `register_target()` creates an unverified row,
`run_ownership_verification()` flips it to verified, and `start_scan_session()` is the one
function the API/agents call to begin a scan — it re-authorizes via guardrails, re-probes the
canary, and stamps the resulting tier onto a brand-new `ScanSession` row.

Register via the API (add `-H "Authorization: Bearer $SENTINEL_API_KEY"` to every call below once
you've set `SENTINEL_API_KEY` — see [Why this is safe to run unattended](#why-this-is-safe-to-run-unattended)):

```bash
curl -X POST http://localhost:8000/api/targets/register \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "staging.yourcompany.com",
    "account_owner": "you@yourcompany.com",
    "canary_check_url_template": "https://staging.yourcompany.com/api/internal/canary/{marker}"
  }'
# -> { "verification_token": "...", "canary_marker": "...", ... }

# place the token per the response's instructions, then:
curl -X POST http://localhost:8000/api/targets/staging.yourcompany.com/verify
```

Then run the scan:

```bash
curl -X POST http://localhost:8000/api/scans/start -d '{"domain": "staging.yourcompany.com"}' \
  -H "Content-Type: application/json"
# -> { "scan_session_id": 1, "status": "running", "environment_tier": "verified_safe" }

curl http://localhost:8000/api/scans/1                # headline + coverage counts
curl http://localhost:8000/api/scans/1/findings        # every finding, confirmed and unconfirmed
curl -X POST http://localhost:8000/api/scans/1/halt \
  -d '{"reason": "stopping early"}' -H "Content-Type: application/json"   # the one human touchpoint
curl http://localhost:8000/api/audit-log/verify         # proves (or disproves) the audit trail is untampered
```

`/api/scans/start` returns immediately (202) and runs the actual pipeline in a background task —
recon, CWE mapping, dispatch, verification, and persistence all happen after the response is sent,
so poll `/api/scans/{id}` or watch the dashboard for progress.

## The six agents

1. **Recon** ([`sentinel/agents/recon_agent.py`](sentinel/agents/recon_agent.py)) — same-origin
   crawl (off-target links are recorded, never followed), endpoint/form/param/cookie mapping,
   tech-stack fingerprinting from headers, cookies, error pages, and JS bundles — no external
   scraping dependency, just `html.parser`.
2. **CWE Mapping** ([`sentinel/agents/cwe_mapping_agent.py`](sentinel/agents/cwe_mapping_agent.py))
   — a curated, web-application-relevant slice of the CWE catalog
   ([`sentinel/cwe/data/cwe_web_relevant.json`](sentinel/cwe/data/cwe_web_relevant.json), refreshable
   from the live MITRE catalog via `scripts/fetch_cwe_data.py`), cross-referenced against the recon
   site map — rule-based where the answer is deterministic (no upload form → CWE-434 not
   applicable), LLM-reasoned where it isn't.
3. **Detection Dispatcher** ([`sentinel/agents/dispatcher_agent.py`](sentinel/agents/dispatcher_agent.py))
   — routes the checklist across:
   - [`nuclei_wrapper.py`](sentinel/agents/dispatch/nuclei_wrapper.py) — Tier A, template-based
     (dos/fuzz tags excluded by construction).
   - [`zap_wrapper.py`](sentinel/agents/dispatch/zap_wrapper.py) — spider + passive scan (Tier A),
     active scan (Tier B, gated on the canary tier).
   - [`idor_agent.py`](sentinel/agents/dispatch/idor_agent.py) — the differentiator: an
     LLM-driven CWE-639 (IDOR) agent that reasons over the *specific* site's endpoints to generate
     per-endpoint test strategies dynamically, rather than trying one fixed manipulation against
     everything.
4. **Verification** ([`sentinel/agents/verification_agent.py`](sentinel/agents/verification_agent.py))
   — every raw finding is re-checked by a method genuinely different from the one that produced
   it before being marked `confirmed`. Anything that fails re-verification becomes `unconfirmed —
   needs review`, never silently dropped.
5. **Report** ([`sentinel/agents/report_agent.py`](sentinel/agents/report_agent.py) +
   [`sentinel/dashboard/app.py`](sentinel/dashboard/app.py)) — the headline metric is always
   `X/Y applicable CWEs tested, Z confirmed exploitable, W unconfirmed`. Live Streamlit dashboard,
   Markdown/PDF export.
6. **Kill Switch Monitor** ([`sentinel/agents/kill_switch.py`](sentinel/agents/kill_switch.py)) —
   runs throughout, not sequentially. Tracks rolling error-rate/latency per scan session and
   auto-halts on anomaly; exposes the one human touchpoint after Phase 0
   (`POST /api/scans/{id}/halt`); every halt (automatic or manual) is written to the immutable
   audit log before this module returns control.

## Quickstart

```bash
python -m venv .venv && .venv/Scripts/activate   # or source .venv/bin/activate on Linux/macOS
pip install -r requirements.txt
cp .env.example .env   # fill in SENTINEL_ANTHROPIC_API_KEY (or SENTINEL_OPENAI_API_KEY)

pytest tests/ -q                     # 200+ tests: foundation, every agent, the full graph
                                      # end-to-end, and a security-review regression suite —
                                      # all mocked, no live nuclei/ZAP/network needed

uvicorn sentinel.api.main:app --reload --port 8000     # REST API
streamlit run sentinel/dashboard/app.py                 # live dashboard
```

### Local test lab (a target you actually own: your own Docker containers)

```bash
cd docker && docker compose up -d       # OWASP Juice Shop on :3000, ZAP daemon on :8080, Postgres on :5432
```

Register `localhost:3000` (or the container's reachable hostname) through Phase 0 exactly like
any other target — Sentinel does not special-case "local" targets, which is the point: the same
authorization gate applies whether you're testing your own throwaway container or a real
production domain your company owns.

Nuclei is a separate binary (not a Python package) — install per
[projectdiscovery.io/nuclei](https://github.com/projectdiscovery/nuclei#install-nuclei) and set
`SENTINEL_NUCLEI_BINARY_PATH` if it's not on `PATH`. If it isn't installed, `nuclei_wrapper.py`
logs `nuclei_unavailable` to the audit log and returns no findings rather than crashing the
dispatcher — the rest of the pipeline (ZAP, IDOR agent, CWE mapping) still runs.

## How this was built

Every agent module past Phase 0 was built by an independent AI subagent, in parallel, against a
fixed set of shared contracts written first and never touched by the parallel agents:

- [`sentinel/agents/state.py`](sentinel/agents/state.py) — the LangGraph state shape
- [`sentinel/db/models.py`](sentinel/db/models.py) — the SQL schema
- [`sentinel/security/guardrails.py`](sentinel/security/guardrails.py) — the boundaries
- [`sentinel/security/audit_log.py`](sentinel/security/audit_log.py) — the audit trail
- [`sentinel/llm/client.py`](sentinel/llm/client.py) — the one place LLM calls happen

Each scan-engine module (nuclei/zap/idor) additionally agreed on one function signature —
`run(db, scan_session, registration, cwe_items) -> list[RawFinding]` — which is what let
`dispatcher_agent.py` route across all three without any adapter code. Every module shipped with
its own pytest suite, mocking subprocess/HTTP boundaries (respx for httpx, `unittest.mock` for
`subprocess`) so the full suite runs with no live nuclei/ZAP/network dependency.

Two real bugs this process caught are worth calling out, because both are the specific failure
mode of building independently-tested modules in parallel: every module's own unit tests passed,
and the bug only showed up once the pieces were run together.

1. **The audit log's hash chain didn't actually verify.** The first version of `audit_log.py`
   computed the hash over a timestamp that was never the one actually stored — SQLite silently
   drops timezone info when a `DateTime(timezone=True)` column gets re-queried inside the same
   session, so a freshly-computed hash and a re-fetched row's recomputed hash disagreed even
   though nothing had been tampered with. Fixed by storing the timestamp as the exact ISO string
   that was hashed, not as a `DateTime` column at all — caught by
   `tests/test_audit_log.py::test_verify_chain_passes_for_untouched_log` failing on entirely
   untouched data.
2. **Verification would have silently rubber-stamped every finding "unconfirmed."** Agent 4
   (verification) was built against an assumed `poc_evidence` format —
   `"matched-at: X\npattern: Y"` key/value lines — and its own unit tests supplied exactly that
   format, so they all passed. But `nuclei_wrapper.py`, `zap_wrapper.py`, and `idor_agent.py` were
   each built by a different parallel agent and produced human-readable prose instead
   (`"template-id | url | extracted=..."`, `"Baseline GET ... Manipulated GET ..."`). Real findings
   from any of the three would have hit verification's `poc_evidence` parser, found none of the
   expected keys, and — worst case, for IDOR — returned `"poc_evidence missing manipulated-url/
   unauthorized-marker; cannot re-probe"` for every single confirmed-worthy finding, undermining
   the platform's flagship feature. This surfaced only when
   [`tests/test_graph.py`](tests/test_graph.py) ran the full pipeline end-to-end with each engine's
   *actual* output shape. Fixed by having each wrapper additionally emit the specific `key: value`
   lines verification needs, and by making the IDOR marker check optional (idor_agent's detector is
   shape/status based, not a single reproducible substring, so verification now re-applies the same
   shape heuristic on a fresh reprobe when no marker is present) — see
   `tests/test_verification_agent.py::TestCustomIdorVerificationWithoutMarker` for the regression
   test.

The lesson generalizes: parallel-built modules need an end-to-end test exercising real output
shapes, not just each module's own mocked unit tests, before you can trust the seams between them.

## Repository layout

```
sentinel/
  phase0/                  domain ownership + canary verification, registration workflow
  security/                guardrails.py (hard boundaries) + audit_log.py (hash-chained log)
  db/                      SQLAlchemy models + session factory
  agents/
    state.py               the shared LangGraph state contract
    graph.py                LangGraph wiring (recon -> ... -> report, with halt routing)
    recon_agent.py           Agent 1
    cwe_mapping_agent.py      Agent 2
    dispatcher_agent.py       Agent 3 orchestration + kill-switch traffic feed
    dispatch/                 nuclei_wrapper.py, zap_wrapper.py, idor_agent.py
    verification_agent.py    Agent 4
    report_agent.py          Agent 5
    kill_switch.py           Agent 6
    persistence.py           state <-> DB sync points (CweApplicability, Finding rows)
  cwe/                     curated CWE dataset + applicability mapping
  llm/                     single LLM client wrapper (Anthropic/OpenAI)
  api/                     FastAPI app + routes (targets, scans, kill-switch)
  dashboard/               Streamlit live dashboard
scripts/
  fetch_cwe_data.py        refresh the CWE dataset from the live MITRE catalog
docker/
  docker-compose.yml       Juice Shop + ZAP + Postgres local test lab
tests/                     one test file per module + tests/test_graph.py end-to-end,
                           every external boundary mocked
```
