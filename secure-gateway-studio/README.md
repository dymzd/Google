# Secure Gateway Studio

Secure Gateway Studio is a loopback-only administration app for planning and
applying Chrome Enterprise Premium Secure Gateway deployments. It supports three
independent architectures: Nginx HTTPS-to-HTTP offload, direct routing to an
existing private HTTPS application, and HTTPS termination on a regional internal
Application Load Balancer that forwards HTTP to a private sample backend.
The current UI is intentionally focused on doing a Secure Gateway proof of
concept as quickly as possible. It supports English and Japanese, all four
managed Chrome platforms, and either a dedicated or existing VPC. Production
remains visible but disabled; the backend implementation is retained for a
future production-ready release.

## Current release posture

The implementation is a PoC-focused release candidate. Its local security,
planner, certificate handling, Google REST request builders, rollback rules,
audit chain, and UI are covered by automated tests. Production promotion still
requires the live acceptance run in
[ENTERPRISE_READINESS.md](docs/ENTERPRISE_READINESS.md) against your disposable
GCP project, Workspace customer, test OU, and managed Chrome endpoints.

The app does not claim that a cloud or browser-path test passed when only a
fixture test passed.

## Implemented controls

- Server-attested discovery, plan, short-lived approval, and single-use Apply.
  Approval consumption and run creation are one SQLite transaction, with one
  active Apply slot across concurrent local requests.
- Approval, Apply, and operator acceptance audit actors are inherited from the
  Google Cloud identity captured by trusted preflight. Browser-supplied actor
  fields are rejected.
- Direct REST orchestration for Service Usage, IAM, Compute Engine, Cloud DNS,
  Secret Manager, CA Service, BeyondCorp, Access Context Manager, and Chrome
  Policy.
- Production regional managed instance group across two zones, configurable
  CPU autoscaling (default 2-20 replicas), internal passthrough Network Load
  Balancer, SSL
  health check, private DNS, Cloud NAT, and no VM external IPs.
- Existing-VPC and dedicated-VPC strategies.
- **CEP PoC Deployer** (extension build only): applies a Chrome Enterprise
  Premium evaluation baseline — core threat-protection policies, forced Endpoint
  Verification, content-inspection connectors, a selectable Context-Aware Access
  level, and data-boundary policies — to one organizational unit, optionally creating
  `CEP Users` and `CEP Browsers` sub OUs so user-scoped and browser-scoped
  policies are separated. Every policy is validated against the tenant's live
  Chrome Policy schema before it is written, and each module is applied as its
  own batch so one unsupported policy does not fail the rest. Rollback returns
  all of it to the parent OU, app-scoped extension policies included. Also
  creates two least-privilege IAM roles and exports the same configuration as a
  standalone Python script.
  DLP detectors and starter DLP rules — including watermarking and screenshot
  blocking, which are rule action parameters rather than Chrome policies — are
  created through the Cloud Identity policy API (`settings/rule.dlp` and
  `settings/detector.url_list`); its mutation methods are still in beta. A
  refused call is reported as a skipped module with its reason while the rest of
  the deployment still applies. Sensitive content storage, OCR, and automatic
  CEP licensing remain Admin Console steps and are listed as such in the page.
- Existing private HTTP backends in GCP, AWS, Azure, or on premises, with an
  explicit private-connectivity prerequisite and T02 runtime verification.
  This PoC does not collect third-party credentials or create Cloud VPN,
  cross-cloud VPN, Interconnect, or on-premises routes. Establish routing,
  private DNS, and backend firewall access to the selected GCP offload subnet
  before Apply.
- Direct private HTTPS applications through an existing VPC, with an exact
  hostname:port matcher, optional egress region, delegating-service-account
  upstream access, and no Nginx VM, internal load balancer, Cloud NAT, managed
  DNS A record, or offload certificate. The operator confirms Cloud DNS private
  or forwarding resolution, TCP ingress from `136.124.16.0/20`, and the return
  path before Apply.
- Regional internal Application Load Balancer HTTPS offload, with a dedicated
  `REGIONAL_MANAGED_PROXY` subnet, regional self-managed server certificate,
  URL map, target HTTPS proxy, internal forwarding rule, HTTP health check, and
  a private sample backend. The load balancer terminates TLS and forwards HTTP;
  no Nginx offload tier is deployed. For a local PoC CA, only the public root PEM
  is handed to Chrome Root Store through the documented manual Admin console step.
- Enterprise CA, validated public certificate secret, and a local PoC CA. The
  app exports only the public root for upload to the dedicated test OU through
  Google Admin console, where the administrator selects the managed Chrome
  platforms. The local CA option remains disabled for Production.
- Immutable hardened image requirement in Production; the image must contain
  Python 3 and Nginx. Production startup never installs packages from a mutable
  repository.
- Verified managed-Chrome Access Context Manager level bound as an application
  IAM condition.
- Force installation of Secure Enterprise Browser and Endpoint Verification in
  the dedicated test OU.
- Runtime Chrome Policy schema discovery rather than fixed schema assumptions.
- Exact IAM and Chrome Policy before-images for in-process rollback.
- Ownership-bounded reverse-order rollback; shared resources are never deleted.
- Hash-bound approvals, SQLite operation checkpoints, interrupted-run
  detection, and a SHA-256 audit chain.
- Functional deployment-history and evidence screens plus portable JSON
  evidence export.
- Post-deployment management in the Deploy tab: sanitized Cloud Logging views
  for access decisions, gateway connections, administration, and collected
  Nginx requests; gateway logging enablement; an owned/shared resource
  inventory; and hash-bound teardown of only server-recorded owned resources.
  Teardown runs in reverse dependency order, retains shared resources and
  deletes a gateway only when no applications remain.
- Durable T01–T09 acceptance records. T01–T03 use sanitized VM runtime probes,
  T04–T05 use exact Google API verification, and endpoint-dependent cases are
  explicitly operator-confirmed. Production readiness requires T07 on every
  selected OS plus separate T09 evidence for an unauthorized principal and an
  unmanaged browser.
- JSON-escaped Nginx access logs with a generated request ID propagated from
  the TLS offload tier to the HTTP backend, enabling T08 correlation without
  logging credentials or query strings.
- Managed enterprise certificates use a Secret Manager `active` version alias,
  a 30-day Production renewal window, atomic alias promotion, offload-tier
  refresh, and compensating disable/revoke on failure.
- Exact loopback Host/Origin checks, per-launch session nonce, CSP, no-store
  responses, and a `0600` local state database.
- CycloneDX SBOMs and reproducible dependency locks for both runtimes.
- Path-scoped GitHub Actions gates for locked installs, backend lint/tests,
  frontend tests/build, and production dependency auditing, with weekly
  Dependabot coverage for uv, pnpm, and workflow actions.

## Prerequisites

- Python 3.12 or newer.
- Node.js 22 or newer and pnpm.
- Google Cloud CLI for keyless Application Default Credentials.
- A billing-enabled GCP project.
- Chrome Enterprise Premium licenses for target users.
- A dedicated non-production test OU.
- Additional Google services and Google Cloud access enabled for target users.
- Endpoint Verification device-signal collection enabled for the OU.
- An existing Access Context Manager custom access level whose CEL expression
  permits profile-managed Chrome, browser-managed Chrome, or both.
- For Production, a versioned Compute Engine image resource (not an image
  family) with Python 3, Nginx, systemd, and the standard Nginx filesystem
  layout.

In the ID step, **Create deployer and least-privilege role** automatically
creates or updates the dedicated service account, project custom role, project
bindings, the active gcloud user's Token Creator binding, and the configured
Access Context Manager policy's Policy Reader binding. The operation is
idempotent and uses argument-array gcloud invocations without a shell. Then
assign the service account a Chrome admin role scoped to the test OU in Google
Admin Console and authenticate ADC by impersonation:

```bash
gcloud auth application-default login \
  --impersonate-service-account=secure-gateway-deployer@PROJECT_ID.iam.gserviceaccount.com
gcloud auth application-default set-quota-project PROJECT_ID
```

The backend requests the Cloud Platform, Chrome Policy, Chrome Management,
Enterprise License Manager, and read-only Admin Directory scopes. Admin
Directory is called for the organizational-unit and group pickers, using the
impersonated service account's delegated authority; domain-wide delegation is
not required. Service-account JSON key ADC is rejected and key files must not
be added to this repository.

`SGSTUDIO_ACCESS_POLICY_ID` must be set before first run. It is the numeric
Access Context Manager policy ID, and both the access-level picker and the
deployer bootstrap's Policy Reader binding depend on it; without it the
access-level endpoint returns 428. Copy `.env.local.example` to `.env.local`
and fill it in.

## Install and run

From `backend/`:

```bash
python3 -m venv .venv
.venv/bin/pip install uv
UV_CACHE_DIR=/tmp/sgs-uv-cache .venv/bin/uv sync --locked --extra dev
```

From `frontend/`:

```bash
pnpm install --frozen-lockfile
```

Start the packaged single-origin app:

```bash
./scripts/run-local.sh
```

Open `http://127.0.0.1:8787`. The launcher rebuilds the frontend, then serves
both the UI and API from FastAPI on loopback. The bottom-left **Guide** tab
explains the API, safety, and infrastructure work performed in each of the
seven New setup steps.

For frontend development, `pnpm dev` uses
`http://127.0.0.1:5173` and proxies `/api` to port `8787`.

## Production input contracts

The public-certificate option references a Secret Manager secret in the
deployment project. Its latest version must be a UTF-8 JSON object containing:

```json
{
  "certificate_pem": "-----BEGIN CERTIFICATE-----...",
  "certificate_chain_pem": ["-----BEGIN CERTIFICATE-----..."],
  "private_key_pem": "-----BEGIN PRIVATE KEY-----..."
}
```

Preflight verifies parsing, key/certificate match, hostname SAN, and minimum
remaining validity. Private key material stays in process memory and is sent
directly to Secret Manager or read directly by the VM; it is not stored in the
browser, SQLite, startup metadata, or logs.

The Production image field accepts only:

```text
projects/PROJECT_ID/global/images/IMMUTABLE_IMAGE_NAME
```

Image families are rejected.

## Verification

```bash
cd backend
.venv/bin/ruff check src tests
PYTHONPATH=src .venv/bin/pytest \
  --cov=sgstudio --cov-report=term-missing --cov-fail-under=75

cd ../frontend
pnpm test -- --run
pnpm build
pnpm audit --prod --audit-level high

cd ../extension
npm run typecheck
npm run verify
```

`npm run verify` type-checks the extension and then runs the parity and
behaviour checks, including `verify-cep.ts`, which dispatches through `route()`
— the same entry point the service worker uses — and asserts on the Google
requests each CEP module produces. Route coverage checks compare declarations
textually and cannot catch a handler that fails to run, which is why that one
exercises the handlers directly.

The current automated suite contains 141 backend tests and 22 frontend tests,
with a 75% minimum backend coverage gate.
The exact environment and browser acceptance cases are in
[TEST_MATRIX.md](docs/TEST_MATRIX.md).

SBOMs:

- `backend/sbom.cdx.json` — CycloneDX 1.5.
- `frontend/sbom.cdx.json` — CycloneDX 1.7.

## State and recovery

Non-secret state defaults to `.local/secure-gateway-studio.db` and can be moved
with `SGSTUDIO_STATE_PATH`. If the process stops during Apply, the next start
marks the run and active operation `interrupted`. It does not automatically
continue or perform a blind rollback because sensitive provider before-images
are intentionally memory-only. Reconcile the exported operation record with
live cloud state, run preflight again, and approve the newly attested plan.

## Documentation

- [Implementation plan](../docs/CHROME_SECURE_GATEWAY_WEB_APP_IMPLEMENTATION_PLAN.md)
- [Enterprise readiness](docs/ENTERPRISE_READINESS.md)
- [Test matrix](docs/TEST_MATRIX.md)
