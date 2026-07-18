# Zero-Trust Customer-Hosted Runner

## Status

A limited local-control foundation is implemented. It is **not** yet a deployed zero-trust
customer runner and it does not authorize unrestricted or production testing.

The implemented foundation provides:

- an operator-only API that can issue a short-lived, Ed25519-signed runner permit for an active,
  contract-bound Tier-A engagement;
- a local permit evaluator that verifies the signature and enforces the permit's expiry, exact
  HTTPS host, port, HTTP method, path prefix, and in-memory request budget;
- a **LocalRunner** facade that evaluates the permit before a caller-supplied local action and
  re-checks its required local stop source before any result is exported; and
- a local, customer-keyed HMAC redacted finding envelope that intentionally omits raw request and
  response bodies from its exported structure, converts scanner-controlled titles to fixed
  taxonomy labels, and exports route classes rather than record identifiers;
- an offline permit bootstrap command that verifies a local permit against an out-of-band pinned
  public key without making a network request; and
- offline, generic remediation guidance that consumes only a redacted envelope and never reads
  its evidence identifiers, route class, or scanner text.

These are library-level controls, not an independently enforced network boundary. In particular,
the current implementation does **not** include:

- customer-runner enrollment, mTLS, or tenant-scoped runner identity;
- a mandatory egress proxy, network namespace, DNS/IP policy, or protection against an executor
  making direct network calls outside the local facade;
- durable, shared permit redemption, request budgets, revocation delivery, or revocation epochs;
- an isolated customer-deployed workload, vault integration, workspace destruction, or durable
  lifecycle/cleanup service;
- an end-to-end evidence ingestion and persistence path proven to contain only redacted data; or
- Nuclei, ZAP, IDOR, live verification, or other active engines connected to this runner path.

The current **POST /api/contracts/{id}/runner-permits** route is an **operator-only development
boundary**. It uses the existing shared **SENTINEL_API_KEY** service authentication and is not a
customer-runner fetch endpoint. No customer runner should receive that shared key. A production
flow must replace it with enrolled, tenant-scoped runner identity and outbound mTLS; the public
verification key must be pinned through a separate approved onboarding channel rather than trusted
from a permit response. The route is disabled by default and requires the explicit development
`SENTINEL_DEPLOYMENT_MODE=development` plus
`SENTINEL_ENABLE_DEVELOPMENT_RUNNER_PERMIT_ISSUANCE=true` operator opt-in; those settings must
not be used as a substitute for the production identity and proxy boundary.

Until the missing controls are implemented and independently validated, active testing remains
**sandbox-only and gated**. Supported contract runs remain recon and coverage/triage; they do not
turn scanner signals into confirmed exploit findings.

## Customer privacy promise

The target product keeps the customer's test environment, credentials, data, and network boundary
under customer control. Sentinel should receive only what it needs to operate an approved test and
produce a useful report:

- the approved target and time window;
- authorization and policy metadata;
- run health and progress signals; and
- redacted finding evidence and remediation context.

Sentinel should not require the customer to send API keys, passwords, session tokens, database
contents, raw request or response bodies, source code, or production data. Credentials must remain
in a customer-managed vault or secret store and be used only within the customer-controlled
execution boundary.

The implemented **LocalRunner** envelope is a useful first privacy control, not a blanket proof
that every execution path is safe: it redacts a bounded finding structure using a customer-local
HMAC key, but it is not yet wired into every legacy scanner, log, queue, or persistence path.

This is a product design objective, not a claim that every customer system is safe by declaration.
The customer remains responsible for preparing an isolated test/UAT environment and selecting
synthetic or masked data. Sentinel does not inspect the customer's database to decide whether data
is dummy.

## Architecture

~~~mermaid
flowchart LR
  Operator["Authorized Sentinel operator\nnot a customer runner"]
  Issue["Current: operator-only permit API\nshared service authentication\ndevelopment boundary"]
  Permit["Current: short-lived\nEd25519-signed permit"]

  subgraph Current["Current local library foundation"]
    Eval["Permit evaluator\nhost/method/path/window/budget"]
    Local["LocalRunner facade\ncaller-supplied local executor"]
    Envelope["Local redacted envelope\ncustomer-keyed HMAC"]
    Eval --> Local --> Envelope
  end

  subgraph Target["Required customer-controlled production boundary — not implemented"]
    Runner["Enrolled ephemeral runner\ntenant identity + mTLS"]
    Proxy["Mandatory egress proxy / network namespace\nDNS, IP, rate, and revoke enforcement"]
    Vault["Customer vault\ntest-only credentials"]
    UAT["Approved UAT target\nsynthetic or masked data"]
    Vault --> Runner --> Proxy --> UAT
  end

  Operator --> Issue --> Permit --> Eval
  Envelope --> Report["Future: redacted-only reporting path"]
  Permit -. "future: pinned key +\noutbound mTLS enrollment" .-> Runner
~~~

Today there is no deployed customer runner process. An authorized operator can obtain a permit
through the development API; a future runner must receive it through an enrolled, authenticated
customer-side channel. The customer runner must never call the current route or be given
**SENTINEL_API_KEY**.

The current permit narrows a local action to a signed scope. It cannot by itself stop a malicious
or misconfigured executor from opening a direct connection, reset a budget shared by several
workers, or learn that a central revocation occurred while disconnected. Those guarantees require
the missing proxy/network boundary and durable control-plane services.

### Offline permit bootstrap

After an authorized operator has delivered the signed permit through an approved customer channel,
the customer can inspect it locally before any future runner process accepts it:

```bash
python -m sentinel.zero_trust.permit_cli \
  --permit-path ./permit.json \
  --public-key-path ./sentinel-issuer-public.key \
  --issuer-key-id 0123456789abcdef
```

The command accepts local bounded files only, validates the Ed25519 signature and time window, and
prints only the permitted hosts, methods, paths, times, budget, and issuer key ID. It sends no
network traffic and must never be given a private signing key, test credential, or
**SENTINEL_API_KEY**. Verification of a permit is not execution authority and does not enable a
scanner.

## Official authorization procedure

Before a run, the customer designates a security owner or other authorized approver. Their
authorization is a business and legal record, not a transfer of secrets. It should identify:

1. The exact test/UAT target and environment owner.
2. The approved testing window and emergency-stop contact.
3. Confirmation that the environment is customer-controlled and contains only approved synthetic
   or masked test data for this engagement.
4. Confirmation that any credentials, integrations, queues, and third-party endpoints used by the
   test are test-only or otherwise explicitly in scope.
5. The permitted test tier and any excluded routes, methods, tenants, or integrations.
6. The reset, rollback, or cleanup procedure after the test.

An official email can record this authorization during early operations. The control plane stores a
keyed reference digest rather than the email text in the signed contract policy. A production
product should replace or supplement email with tenant-scoped identity, authenticated approval,
immutable approval records, and separation of duties. An approval declaration never gives the
runner a right to access an unlisted host, a different environment, or a wider action tier.

## Local secrets and data handling

### Credentials stay local

The target runner obtains short-lived test credentials through the customer's own vault
integration. It keeps them only in its ephemeral workload and disposes of its workspace after the
run. The control plane must never log or return a secret value.

The current source tree does not yet implement a vault integration or an ephemeral customer
workload. Do not treat the permit API, a local environment file, or the shared service API key as a
credential-delivery mechanism for a customer runner.

The runner should use only test identities and disposable objects seeded by the customer. For
example, authorization testing needs distinct synthetic users, roles, tenants, and records so it
can observe access-control differences without involving real users or records.

### No raw evidence export by default

The implemented local envelope excludes raw request and response bodies, scanner-supplied titles,
and customer record identifiers. It derives its evidence identifier with a customer-local HMAC key
and emits a fixed category title, endpoint class, severity, and timestamp without exporting the
HMAC key itself. A local remediation module can turn that bounded envelope into generic fix and
validation advice without reading the evidence identifier or route class.

This does not yet prove that all data leaving the product is redacted. Before active engines are
enabled, every scanner output, application log, queue, retry store, telemetry event, and reporting
database must be routed through and validated against an approved redaction/DLP boundary.

Customers may elect to provide additional evidence or source code through a separate approved
workflow. That is optional and must not be required for baseline testing or AI remediation
guidance.

## Required local network and execution controls

The following are production requirements, not current capabilities. A mandatory customer-side
proxy or network namespace must be the enforcement point for every target request. It must prevent
direct runner egress and check the current approved scope before traffic leaves the runner.

Required checks include:

- exact approved hostname and canonical origin;
- resolved DNS and IP-range policy, with no direct runner bypass path;
- approved port, HTTP method, path class, and request body policy;
- active test window, remaining request/rate/concurrency budget, and durable revocation state;
- approved recipe and action tier; and
- per-run tenant identity and audit correlation.

The current evaluator performs only a subset of local URL and budget checks. It does not resolve
or pin DNS/IP addresses, enforce rate or concurrency limits, mediate a process's network stack, or
provide durable cross-worker state. The **LocalRunner** facade is therefore not sufficient to attach
an active scanner or to claim no-bypass enforcement. It also deliberately accepts only ASCII path
scopes until the future proxy owns URI canonicalization across the runner and target stack.

## Evidence, AI analysis, and remediation

AI can provide meaningful remediation without source-code access. From redacted, bounded evidence
it can describe the affected endpoint or flow, likely vulnerability category, risk and confidence,
what was observed, compensating controls to check, and safe fix patterns.

Reports must distinguish clearly between:

- coverage or an untested area;
- a scanner signal or hypothesis;
- a bounded sandbox verification; and
- an independently confirmed finding.

AI must not claim to know the exact code change, exploit impact, or data exposure when the evidence
does not establish it. It may propose a generic remediation pattern and identify what a customer
developer should validate next.

## Emergency stop and lifecycle

The existing control plane can mark a contract revoked, and the local facade requires a revocation
callback. That is not yet a reliable emergency-stop mechanism for deployed runners: there is no
durable revocation feed, epoch, heartbeat, or shared permit-redemption store.

The production lifecycle must fail closed as follows:

~~~text
Customer prepares UAT and fixtures
  -> Customer authorizes bounded scope
  -> Enrolled runner receives short-lived permit through mTLS
  -> Mandatory proxy permits only contract-bound actions
  -> Local redaction creates finding envelopes
  -> Customer or policy revokes/finishes run
  -> Runner cleans up credentials and workspace
  -> Redacted report and remediation guidance are delivered
~~~

A failed cleanup, policy violation, proxy health failure, expired permit, unavailable approval
authority, or lost revocation state must make the run fail closed and require customer review before
any retry.

## Customer onboarding checklist

Before enabling sandbox-active testing after the production boundary exists, confirm that the
customer has:

- an isolated UAT/test target, distinct from production;
- synthetic or masked test data and disposable test identities;
- test-only integrations, queues, webhooks, and third-party sandbox endpoints, or explicit scoped
  exclusions for any integration that cannot be safely tested;
- a customer-managed secret store that can grant short-lived local test access;
- a reset, rollback, or cleanup mechanism;
- a customer-controlled location for an enrolled ephemeral runner and mandatory policy proxy;
- an approved hostname, paths, methods, rate limits, test window, and emergency-stop contact;
- a named, authenticated security approver; and
- an understanding that redacted evidence—not raw secrets or customer data—will be returned.

## Active testing policy

Active recipes are not connected to the current local foundation. They may be introduced only one
category at a time, inside the independently validated sandbox boundary:

| Recipe family | Conditions before future use |
|---|---|
| Passive Nuclei/ZAP analysis | Enrolled runner; reviewed, signed recipe; mandatory proxy; bounded target and budget |
| Active scanner checks | Sandbox-only; customer approval; test-only integrations; cleanup/reset plan; durable revocation |
| Authorization and IDOR validation | Synthetic multi-user/multi-tenant fixtures; disposable records; bounded verification |
| Live verification | Benign, reviewed replay through the same enforced permit and proxy; no destructive payloads |

No model, tool output, webpage content, or scanner finding may authorize a new action. The model
can choose only among reviewed, signed recipes already permitted by the contract.

## Explicit limitations and non-goals

- This design does not make a customer declaration technically prove that every dependency is
  non-production; it aims to keep secrets local and restrict the runner's authority.
- It does not support unrestricted testing of production systems, unverified assets, third parties,
  or any network outside the contract.
- It does not automate social engineering, denial of service, persistence, credential theft,
  production-data extraction, funds movement, permission changes, deletion, or external
  disclosure.
- It does not promise to find every web application vulnerability or replace expert-led assessment
  of novel business logic and complex human workflows.
- It is not a certification, compliance attestation, or guarantee that an application is secure.
- The present code must not be described as a complete zero-trust deployment. Active testing stays
  sandbox-only and gated until enrolled runner identity, mTLS, mandatory egress enforcement,
  durable redemption/revocation, redacted-only data flow, and approval workflow are built and
  validated together.

## Delivery dependency

The next implementation milestone is not enabling every scanner. It is delivering the missing
customer-side execution boundary as one enforceable system: tenant runner enrollment and mTLS,
mandatory egress proxy/network namespace, customer-local secret execution, durable permit
redemption and revocation, redacted-only evidence ingestion, isolated cleanup, and emergency stop.
Only then should reviewed active recipes be enabled one category at a time in a sandbox.
