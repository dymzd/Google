# Enterprise readiness

## Readiness decision

The codebase is ready for a controlled staging acceptance run. It is not yet
certified for your production tenant because the keyless deployer still needs
its explicit high-impact deployment role approval, direct Chrome Policy and
Directory-read roles, the License Management privilege required by the CEP
licence gate, and live managed-Chrome T07/T09 evidence.

Production promotion is allowed only when every release gate below has evidence
from the target organization.

## Implemented engineering gates

| Control | Evidence in this repository |
|---|---|
| Loopback-only local service | Fixed `127.0.0.1` launcher and Trusted Host middleware |
| Browser mutation protection | Exact Origin allowlist plus per-launch nonce |
| Secret isolation | OAuth tokens stay in memory; extension-generated TLS server keys exist only in `chrome.storage.session` during an active run, never IndexedDB/`chrome.storage.local`/logs/downloads; local state file is `0600` |
| Keyless operator identity | ADC impersonates a dedicated service account; long-lived service-account key ADC is rejected |
| Product-scoped deployment role | Versioned custom-role manifest covers the project-permission union of extension A/C and local B; it is not a per-run role, while preflight and the approved plan require and call only the selected path's subset |
| Deterministic approval | Server-stored plan, configuration hash, expiry, single use, atomic approval/run transaction, one active Apply slot, and server-attested actor continuity |
| Least exposure | No external IPs; narrow gateway, health-check, and backend firewall rules |
| Managed Chrome only | Verified CAA level, conditional application IAM, two force-installed extensions |
| PoC certificate boundary | Public-root artifact only; administrator uploads it to the dedicated test OU and selected managed Chrome platforms in Google Admin console; no private-key download |
| Production HA and scale | Two-zone regional MIG, configurable CPU autoscaling, internal load balancer, two healthy backend requirement |
| Managed ILB TLS offload (loopback app only in 0.2.1) | Regional internal Application Load Balancer with proxy-only subnet, regional certificate, HTTP backend, ownership-bounded rollback, and manual Chrome Root Store trust handoff. The extension hides and rejects this path. |
| Supply-chain control | Immutable Production image, uv/pnpm locks, CycloneDX SBOMs, path-scoped CI, weekly Dependabot |
| Safe shared-resource handling | Etag read-modify-write and exact before-images; the extension checkpoints them in IndexedDB for MV3 resume |
| Failure behavior | Stop on first error, owned-resource rollback, interrupted-run fail-closed state |
| Auditability | SHA-256 event chain, run history, JSON evidence export |
| Actor integrity | Approval, Apply, resume, teardown, and operator evidence require the same Google-attested impersonation source user and immutable deployer service-account ID; browser actor overrides are forbidden |
| Localization | Persistent English / 日本語 selector across setup and evidence screens |
| Certificate lifecycle | Active-version alias, expiry-triggered renewal plan, offload refresh, disable/revoke compensation |
| Acceptance workflow | Fail-closed T01–T05 system verification plus durable T01–T09 evidence matrix |

## Required live release gates

1. Run preflight with the intended keyless deployer and its direct Chrome admin
   authority in a disposable staging project.
2. Confirm Cloud Billing, all required API states, and every reported
   permission.
3. Confirm the supplied image is vulnerability-scanned, versioned, contains
   Python 3 and Nginx, and has an internal patch/retirement policy.
4. Confirm the supplied Access Context Manager level contains both managed
   Chrome states and denies unmanaged or other-domain browsers.
5. Apply first to the dedicated test OU and retain the exported evidence.
6. For a local-CA PoC, download the public PEM root after Apply. In Google
   Admin console, add it as a Root certificate at **Chrome > Connectors >
   Chrome Root Store**, then connect that configuration to the dedicated test
   OU. Public APIs cannot reliably inspect the Root Store configuration,
   certificate details, or OU binding and cannot perform this handoff. Restart
   Chrome, verify the root at `chrome://certificate-manager` under Local
   certificates, and use the platform-specific T07 HTTPS result to prove that
   trust reached the endpoint. Production must use enterprise or public trust.
7. Run the built-in T01–T05 verification, then complete T06–T09 in
   `TEST_MATRIX.md`. T07 requires evidence from every selected OS. T09 requires
   separate denial evidence for an unauthorized principal and an unmanaged
   browser.
8. Run Apply a second time after a fresh preflight and confirm the plan contains
   only `reuse` / `no_change`.
9. Inject one safe failure in staging, confirm rollback scope, then restart the
   local service mid-run and exercise the interrupted-run reconciliation
   procedure.
10. Have Cloud, Workspace, network, PKI, and security owners review the plan and
   evidence before changing the production OU.

## Accepted operational limitations

- The core Secure Gateway path uses local keyless ADC to impersonate one
  dedicated deployer. Google Cloud IAM grants its project permissions; a
  direct Google Admin Console role grants only the required Chrome Policy
  privileges for the test OU. The separate extension CEP flow uses the
  signed-in administrator and its declared Directory OAuth scopes for OU,
  domain, and user operations; it does not infer Workspace authority from a
  Google Cloud project role.
- Organizations requiring strict dual-person control should require a separate
  approver for the custom-role grant and for each short-lived application plan
  approval.
- A local FastAPI process restart marks an in-flight mutation interrupted. The
  operator explicitly resumes the same hash-bound run or teardown in the Deploy
  screen; the backend reacquires the global lifecycle slot and reconciles
  durable `prepared` / `sending` / `applied` checkpoints before any retry or
  rollback. Ambiguous provider outcomes keep their ownership claim and fail
  closed for manual review. The MV3 extension instead resumes from IndexedDB
  operation checkpoints and exact before-images. If the browser session loses
  a generated TLS server key before it reaches Secret Manager, that extension
  run fails closed into ownership-bounded rollback. Operator reconciliation is
  required if the cleanup cannot complete.
- Certificate renewal is an operator-triggered planned change; unattended
  scheduling, continuous drift monitoring, and general stop/start are not
  exposed in this release. Owned-resource teardown requires a fresh immutable
  teardown preview and exact confirmation.
- The local SHA-256 chain detects accidental or partial tampering. For
  non-repudiation, store each exported bundle in your organization’s immutable
  evidence system or sign its chain-head hash externally.

## Go / no-go

- **Go for staging:** yes.
- **Go for production:** only after all ten live release gates pass.
