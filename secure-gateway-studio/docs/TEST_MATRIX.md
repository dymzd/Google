# Secure Gateway acceptance test matrix

| ID | Test | Expected result | Automation now | Production evidence |
|---|---|---|---|---|
| T01 | HTTP backend local response | Private backend returns HTTP 200 | VM runtime probe and guest-attribute verification for the managed sample; operator evidence for an existing backend | Status, response hash, and timestamp |
| T02 | Offload-to-backend response | Every offload host receives HTTP 200 from upstream | VM runtime probes verified through Compute Engine API | Per-instance status, upstream, response hash, and timestamp |
| T03 | TLS termination | TLS 1.2/1.3, correct SAN, strategy-bound valid chain, HTTP 200 | Hostname-verifying TLS runtime probe on every offload VM; `public_trusted` uses system public roots, while enterprise/private and local-PoC strategies pin the presented chain | Per-instance TLS version, trust mode, SAN, response hash, and timestamp |
| T04 | Private DNS | Hostname resolves to internal offload/LB address | Exact Cloud DNS A record versus reserved internal address | Hostname, expected address, and persisted RR data |
| T05 | Secure Gateway route | Exact hostname, port, upstream VPC, and optional egress region | Exact BeyondCorp application GET verification | Application, hostname, port, network, region, and match result |
| T06 | Existing HTTPS regression control | An existing known-good Secure Gateway HTTPS application still opens in the same managed work profile without a certificate warning (the source guide uses `https://demo-server1.internal/`) | Operator evidence; a greenfield PoC may record `Skipped` with a reason when no pre-existing control application exists, while Production requires a pass | Sanitized hostname, browser result, and timestamp |
| T07 | Managed Chrome end to end | Authorized managed Chrome reaches backend on every selected OS | One required operator case per selected platform | Browser screenshot/hash plus correlated timestamp per OS |
| T08 | Log correlation | Gateway/offload/backend events correlate | Structured offload/backend JSON logs plus operator evidence | Sanitized log entries joined by the propagated request identifier |
| T09 | Unauthorized/unmanaged denial | Unapproved principal and unmanaged Chrome are independently denied | Two required operator cases | Separate denial screenshot/log evidence for principal and browser |

## Required execution order

The Nginx HTTP-offload architecture requires T01–T05. The internal Application
Load Balancer HTTPS-offload architecture requires automated T01, T04, and T05,
an operator-confirmed T03 against the ILB endpoint, T06, and one T07 case per
selected Chrome platform. The independent direct HTTPS architecture has no
backend or offload VM and therefore requires T05, T06, and one T07 case per
selected Chrome platform. Production also requires T08 and both T09 denial
cases for every architecture.

The internal Application Load Balancer path is a loopback FastAPI-app
capability in version 0.2.1. The Chrome extension hides that option and rejects
an `internal_https_lb` specification before any Google API call. Extension
acceptance therefore covers the Nginx and direct-HTTPS paths only.

1. Export the prepared plan before approval.
2. Apply only to the dedicated test OU.
3. Complete the architecture's required subset of T01–T05 before opening the
   browser-path test; record non-applicable cases as skipped with the reason.
4. Complete T06, then T07 with an authorized managed Chrome profile on every selected OS
   class represented in the rollout.
5. Complete both T09 cases with an unauthorized principal and an unmanaged Chrome
   profile.
6. Export the final evidence bundle and store its chain-head hash outside the
   workstation.

## Automated regression suite

Backend tests cover:

- strict production invariants and injection-resistant inputs;
- dedicated/existing VPC planning, proxy-only subnet validation, and resource
  collision handling;
- regional internal Application Load Balancer request bodies, certificate
  attachment, dependency ordering, discovery, and teardown coverage;
- billing, permissions, access-level, certificate, and immutable-image gates;
- cross-platform local PoC root/leaf generation, public-root artifact export,
  download protection, and rollback cleanup;
- no-external-IP instance bodies and production HA request bodies;
- runtime Chrome schema/target resolution and both extension IDs;
- conditional IAM merge and exact rollback before-images;
- approval expiry/single use, atomic concurrent-Apply exclusion with losing
  approval preservation, execution rollback, restart interruption;
- rejection of browser-supplied approval, Apply, and evidence actors, with
  trusted-preflight identity continuity through the audit chain;
- audit-chain tamper detection, evidence export, concurrent repository
  initialization, certificate rotation compensation, and T01–T05 fail-closed
  acceptance verification, scoped endpoint readiness, and lossless schema
  migration.

Frontend tests cover:

- persistent English / 日本語 switching;
- PoC-only release posture, disabled Production selection, and migration of
  saved Production drafts;
- the PoC-only Admin console trust handoff across managed Chrome platforms;
- all four managed Chrome platforms;
- bilingual seven-step Guide navigation and content;
- the local backend's Option A direct HTTPS, Option B ILB HTTPS offload, and
  Option C Nginx HTTPS offload choices, while extension mode exposes only A/C
  and hides and rejects the loopback-only Option B path;
- server-backed identity validation, server-attributed evidence, and nonce
  bootstrap;
- one-time user-data disclosure before extension authorization or tenant reads,
  with encrypted extension workflow state and unchanged local-mode persistence;
- explicit interrupted Apply and teardown resume after a page reload, including
  one-time recovery from a rotated loopback session nonce;
- functional evidence navigation, integrity display, and the T01–T09
  certification matrix.
- narrow-screen navigation and action controls at a 390-pixel viewport.

Extension release verification covers:

- route, cold-start, storage, authentication, approval, audit, evidence, and
  teardown contracts;
- Python/TypeScript planner, discovery, and Google request-sequence parity for
  the paths supported by the extension, plus a fail-closed capability test for
  the loopback-only Internal Application Load Balancer path;
- stable request IDs, long-running operation polling, resumable execution,
  exact before-images, IAM policy version 3, and ownership-bounded rollback;
- AES-GCM disk-state encryption, consent-gated 0.2.0 migration, fail-closed
  tamper/wrong-key handling, and session-only TLS private-key retention;
- immutable service-account/operator identity, exact live IAM pin checks, and
  actor continuity across approval, Apply, resume, teardown, CEP mutation, and
  operator acceptance;
- Enterprise CA CSR/key checkpointing and exact certificate revocation;
- live Chrome Policy target/schema grouping, CEP access-level handling,
  Cloud Identity DLP completion semantics, OU/licensing boundaries, and
  fail-closed retention of resources whose ownership cannot be proven.
