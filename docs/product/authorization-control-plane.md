# Sentinel Authorization and Safety Control Plane

## Status and scope

This document distinguishes the implemented MVP from the customer-governed control plane it is
intended to become. The distinction matters: the MVP has real, fail-closed controls, but it is
**not ready for customer-facing or production deployment**.

### Implemented MVP

- Every `/api` route fails closed unless `SENTINEL_API_KEY` is configured and supplied as a bearer
  token. This is a single operator credential, not a tenant identity system.
- A Tier-A `ScanContract` binds one previously registered target, an expiry window, a scan-session
  count, and a request budget. Its immutable policy fields are HMAC-signed with
  `SENTINEL_CONTROL_PLANE_SIGNING_KEY`; contract creation and contract-backed execution fail
  closed when that key is absent.
- A public caller starts a run by contract ID. `/api/scans/start` is retired, so a caller cannot
  submit a free-form target domain to begin execution. The opaque Action Lease token is internal
  and is never returned by the API.
- Immediately before a run, the service performs a fresh ownership proof and a fresh environment
  canary, then binds one short-lived lease to one new `ScanSession`.
- The only enabled recipe is `recon.v1`: same-origin HTTPS recon of the exact registered host on
  port 443, with each target request atomically reserved against the lease budget immediately
  before egress. Nuclei, ZAP, IDOR, and live verification are blocked for contract runs.
- Contract revocation, a manual or automatic halt, expiry, budget exhaustion, and an unexpected
  worker failure make the run terminal and revoke or close its active lease.
- A limited customer-boundary library foundation can issue an Ed25519-signed Tier-A local permit,
  verify it offline against a separately pinned public key, reduce a finding to a customer-keyed
  HMAC envelope, and generate generic local remediation guidance from that envelope. The issuance
  endpoint is disabled by default and remains an operator-only development aid; it is not runner
  enrollment or an active-scanning route.

### Release blockers

Do not expose this MVP to customers, an untrusted network, or production targets until all of the
following are delivered:

1. Tenant-scoped identity, per-asset authorization, RBAC/ABAC, and an independently authenticated
   approval record. `approved_by` is currently a caller-provided operator label; it is not proof
   of an approver's identity and does not provide approval separation.
2. A mandatory external egress proxy with DNS/IP policy enforcement and no direct network path
   from a runner to a target. Current URL/origin checks and request leases do not prevent DNS
   rebinding, IP-range bypasses, or a compromised worker bypassing in-process checks.
3. PostgreSQL-backed state, durable queued workers, idempotency, resumability, distributed locks,
   and per-asset concurrency control. The MVP's additive local schema migration and FastAPI
   background task are not a durable execution system.
4. Production audit controls: mandatory externalized signing/anchoring, retention and redaction
   policy, and multi-worker-safe ordering.
5. Customer-runner enrollment and mTLS, customer-side mandatory proxy/network enforcement,
   durable permit redemption/revocation, isolated secret-local execution, and a redacted-only
   reporting data flow. The local permit library does not enforce those deployment controls.

| Control area | Current MVP | Required before release |
|---|---|---|
| API access | One configured shared API key | Tenant identity, scoped service/user identities, RBAC/ABAC |
| Approval | Signed policy plus `approved_by` label | Independently authenticated, immutable, tenant-scoped approval |
| Network enforcement | In-process URL checks and lease reservations | Mandatory DNS/IP-aware egress proxy and isolated runners |
| Execution | Short-lived lease and FastAPI background task | Durable queue, PostgreSQL, idempotency, locks, recovery |
| Testing | Tier-A `recon.v1` only | Reviewed recipes behind the external enforcement boundary |

## Current implementation contract

### Authorization flow

1. **Register and prove the asset.** Phase 0 records a target and verifies control through the
   configured HTTP well-known file or DNS TXT token. A canary is also required to attest the
   target environment for the individual session.
2. **Create a contract.** The API accepts only Tier A for an active, ownership-verified target.
   The resulting policy includes the target, expiry, session budget, request budget, and the
   supplied `approved_by` label. It is stored with a policy hash and HMAC signature.
3. **Start by contract ID.** The control plane re-verifies ownership and runs the canary again,
   verifies the signed contract, issues a short-lived opaque lease, creates the session, and binds
   the lease before scheduling the worker.
4. **Reserve each request.** The recon worker opens a short database transaction immediately
   before each target request, rechecks halt/revocation/expiry state, verifies the exact HTTPS
   host and lease epoch, and atomically consumes one request allowance.
5. **End or revoke.** Completion closes the lease. A halt, contract revocation, expiration, budget
   exhaustion, or unexpected worker error terminates the run and prevents a later guarded request
   from receiving authority.

The lease is an internal execution capability, not a customer credential. A caller receives a
scan-session ID and recipe name, never an action token or a way to select an arbitrary URL,
scanner, tier, or raw command.

### Fixed MVP boundaries

- Contract-backed execution is Tier A and recon-only. There is no Tier-B contract path.
- The recon target must be the exact registered host over HTTPS on the default HTTPS port. Links
  outside that origin are recorded rather than followed.
- A fresh ownership proof and fresh canary are required for every contract run; a historical proof
  is insufficient.
- Contract policy integrity, expiry, target state, revocation epoch, lease state, action tier, and
  request budget are checked before a contract-run request proceeds.
- No LLM, scanner argument, configuration flag, or API parameter can widen the active contract at
  runtime.

### Explicit limitations

- A shared API key authenticates access to the MVP API, but it cannot establish which organization,
  person, or asset owner made a request. It is not a substitute for tenant isolation.
- `approved_by` is audit metadata supplied at contract creation. It is not a second signer, a
  verified human identity, or a separation-of-duties control.
- The runner makes network calls directly. Same-host URL validation is useful defense in depth, but
  it is not independent enforcement of resolved DNS/IP destinations or network reachability.
- A SQLite/local migration plus in-process background work cannot safely provide durable recovery,
  ordering, or concurrency guarantees across multiple workers.
- The HMAC covers immutable contract scope, not the mutable database lifecycle. The MVP therefore
  treats database writes as trusted; defending against a database writer resurrecting a contract
  or lease requires an externally protected lifecycle authority or immutable remote audit anchor.
- A background task has no durable worker claim, heartbeat, or reaper. It must not be retried or
  run concurrently as if the short-lived lease alone established worker ownership.
- The broader modules in this repository are not an authorization to scan. In particular, the
  presence of Nuclei, ZAP, IDOR, or verification code does not make those tools allowed in a
  contract run.

## Target product architecture (not yet implemented)

The credible enterprise product is a customer-governed continuous validation service: a customer
proves asset control, a separately authenticated approver accepts a bounded policy, and isolated
workers execute only reviewed actions that an independent policy and egress layer allow. No model,
scanner, or worker may expand scope, risk, or authority at runtime.

### Required surfaces

1. **Organization and identity** — OIDC or mTLS identities, tenant isolation, per-asset
   permissions, and independently attributable approvals.
2. **Asset and policy** — versioned origins, path/method scope, exclusions, action tiers,
   concurrency/rate budgets, retention rules, and immutable approval records linked to a contract
   hash.
3. **Planning** — a typed action plan drawn only from signed, reviewed recipes; no free-form shell
   commands or unconstrained URLs.
4. **Execution and egress** — short-lived action leases presented to a mandatory proxy that checks
   canonical origin, resolved DNS/IP policy, HTTP method, path class, tier, rate, remaining budget,
   and revocation epoch before every byte leaves an isolated worker.
5. **Evidence and remediation** — durable `TestExecution` records with recipe/tool provenance,
   redacted evidence hashes, verifier outcomes, policy decisions, and scoped retests after a fix.

### Non-negotiable product rules

- Ownership proof, caller identity, customer approval, and environment safety are separate checks.
- A successful canary never substitutes for tenant authorization or independently authenticated
  approval.
- Scope expansion to a new host, tenant, cloud account, or third party always requires a new
  approval.
- Tier B requires customer-provided synthetic fixtures or identities, an explicit rollback plan,
  fixed budgets, and a separate approval.
- Social engineering, denial of service, persistence, credential theft, production data
  extraction, funds movement, permission changes, deletion, and external disclosure are outside
  unattended automation.
- Tool output, web content, URLs, JavaScript, and LLM output are untrusted data. They may inform a
  typed proposal but never authorize an action.

## Delivery roadmap

### P0 — close production release blockers

1. Put every runner and scanner behind a private network and mandatory DNS/IP-aware egress proxy;
   remove all direct target network paths.
2. Add tenant identity, asset ownership bindings, scoped roles, and a separately authenticated
   approval workflow. Make production startup fail closed without them.
3. Move state to PostgreSQL with managed migrations; replace background tasks with durable,
   idempotent workers, distributed locks, cancellation, recovery, and per-asset concurrency caps.
4. Require production audit signing, externally anchor audit state, and implement retention,
   redaction, and evidence access controls.

### P1 — expand only behind the new boundary

1. Add typed, versioned contracts with path/method scope, exclusions, rate/concurrency limits,
   policy versions, and contract revisions.
2. Add customer-provisioned synthetic test identities, tenant fixtures, cleanup hooks, and rollback
   proofs.
3. Add durable `TestExecution` and `EvidenceArtifact` records so coverage reports distinguish
   blocked, unsupported, executed, unverified, and independently confirmed work.
4. Only then allow reviewed passive scanning, active validation, or independently verified recipes
   through the proxy on a per-tier basis.

### P2 — differentiated application/API validation

1. Ingest OpenAPI, GraphQL, Postman, browser-flow, gateway-log, and selected source/IaC context.
2. Build customer-fixture-based authorization regression matrices across role, tenant, resource,
   and operation.
3. Trigger scoped retests from deployments, asset changes, and API-schema changes.
4. Create redacted developer evidence packs and approved ticketing/SIEM integrations.

## Non-goals

- Sentinel does not replace expert-led testing of novel business logic, human workflows, or
  ambiguous impact.
- Sentinel is not a general-purpose exploitation framework or a scanner for unproven assets.
- Sentinel does not treat LLM confidence as exploit proof or scan results as compliance
  certification.
- Sentinel does not use customer production credentials or production data as test fixtures by
  default.

## Handoff

The signed contract and short-lived lease are a deliberately narrow first vertical slice, not the
end state. The next implementation lane is tenant identity and independent approval together with
an external DNS/IP-aware egress proxy, isolated runners, PostgreSQL, and durable workers. Do not
add more autonomous test engines until those controls are in place and enforce every network
action independently of the process running it.
