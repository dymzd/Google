# Secure Gateway Studio

Secure Gateway Studio contains two local administration runtimes for planning
and applying Chrome Enterprise Premium Secure Gateway deployments: a loopback
FastAPI app and a Chrome extension. Both support Nginx HTTPS-to-HTTP offload and
direct routing to an existing private HTTPS application. The regional internal
Application Load Balancer path is implemented only by the loopback app in
version 0.2.1; the extension hides and rejects that choice.
The current UI is intentionally focused on doing a Secure Gateway proof of
concept as quickly as possible. It supports English and Japanese, all four
managed Chrome platforms, and either a dedicated or existing VPC. Production
remains visible but disabled; the backend implementation is retained for a
future production-ready release.

## Not an official Google product

This is an independent open-source project. It is **not built, endorsed, or
supported by Google**, and it is not affiliated with Google LLC. "Google",
"Google Workspace", "Google Cloud", "Chrome", and "Chrome Enterprise Premium"
are trademarks of Google LLC.

It is provided as is, with no warranty and no support commitment. It changes
Chrome policy and cloud infrastructure in your own tenant, so evaluate it in a
non-production organizational unit first and review every plan before approving
it.

For questions about Chrome Enterprise Premium, Secure Gateway, or licensing,
contact your Google account team -- your Field Sales Representative or Customer
Success Manager. Google supports its own products; this is not one of them. For
problems with this tool, open a GitHub issue: best effort, no response time
commitment.

## Current release posture

The implementation is a PoC-focused release candidate. Its local security,
planner, certificate handling, Google REST request builders, rollback rules,
audit chain, and UI are covered by automated tests. Production promotion still
requires the live acceptance run in
[ENTERPRISE_READINESS.md](docs/ENTERPRISE_READINESS.md) against your disposable
GCP project, Workspace customer, test OU, and managed Chrome endpoints.

The app does not claim that a cloud or browser-path test passed when only a
fixture test passed.

### Version 0.2.1 capability boundary

| Capability | Chrome extension | Loopback FastAPI app |
|---|---:|---:|
| Nginx offload to managed sample | Yes | Yes |
| Nginx offload to existing HTTP backend | Yes | Yes |
| Direct private HTTPS application | Yes | Yes |
| Regional internal Application Load Balancer HTTPS offload | **No — hidden and rejected** | **PoC only — Production rejected** |
| Easy PoC for Chrome Enterprise Premium | Yes | No — hidden |

This is an explicit runtime capability boundary, not a promise of partial
support. A specification containing `internal_https_lb` fails before discovery
or mutation when it is submitted through the extension.

## Implemented controls

- Server-attested discovery, plan, short-lived approval, and single-use Apply.
  Approval consumption and run creation are one SQLite transaction, with one
  active Apply slot across concurrent local requests.
- Approval, Apply, resume, teardown, and operator acceptance bind both the
  Google-attested source user (`email` plus immutable `sub`) of impersonated
  ADC and the project deployer service account's immutable numeric ID. The live
  service-account IAM policy must still exactly match the reviewed bootstrap
  pin; browser-supplied actor fields and ordinary user ADC are rejected.
- Direct REST orchestration for Service Usage, IAM, Compute Engine, Cloud DNS,
  Secret Manager, CA Service, BeyondCorp, Access Context Manager, and Chrome
  Policy.
- Production regional managed instance group across two zones, configurable
  CPU autoscaling (default 2-20 replicas), internal passthrough Network Load
  Balancer, SSL
  health check, private DNS, Cloud NAT, and no VM external IPs.
- Existing-VPC and dedicated-VPC strategies.
- **Easy PoC for Chrome Enterprise Premium** (extension build only): applies a Chrome Enterprise
  Premium evaluation baseline — core threat-protection policies, forced Endpoint
  Verification, content-inspection connectors, a selectable Context-Aware Access
  level, and data-boundary policies — to one organizational unit, optionally creating
  `CEP Users` and `CEP Browsers` sub OUs as later organizational scaffolding.
  Policies remain on the selected populated pilot OU and inherit to those
  children unless overridden there; the tool does not silently move users or enrolled browsers. The OU picker remains unselected after discovery,
  blocks the Workspace root OU, and requires the administrator to type the
  freshly resolved exact OU path before each provision or licence mutation.
  Chrome and OU-scoped DLP policy can affect descendants through OU
  inheritance; licence assignment deliberately includes only users whose
  current Directory path exactly equals the selected OU. Every policy is
  validated against the tenant's live
  Chrome Policy schema before it is written, and each module is applied as its
  own batch so one unsupported policy does not fail the rest. CEP cleanup is a
  read-only inventory: it resolves the current Chrome Policy state and retains
  Chrome policies, organizational units, access levels, and Cloud Identity DLP
  rules for manual review because this release has no durable before-image and
  ownership attestation that would make an automated restore or DELETE safe.
  Workspace
  administrator roles must be assigned in the Google Admin console; project IAM
  roles cannot grant Chrome Policy authority. The deployer verifies the real
  Google APIs and can export the resolved Chrome Policy batches as a standalone
  Python script. Cloud Identity DLP, Access Context Manager, OU creation, and
  licence assignment remain extension-managed operations and are not claimed
  as part of that script.
  Starter DLP rules with explicit `LOW` alert-center severity — including an allow-with-warning URL rule whose action
  parameters add a watermark and restrict screenshots without blocking page
  navigation — are created through
  the Cloud Identity policy API (`settings/rule.dlp`) and use supported built-in
  DLP detectors. Internal URL prefixes are safely escaped into CEL; the
  unsupported `settings/detector.url_list` mutation is never sent. The
  Directory `customers.get` response is used to replace `my_customer` with the
  canonical `C...` customer ID required by Policy create; unresolved IDs fail
  closed. Access-level/BYOD DLP CEL is not generated because the public
  supported-settings reference does not document a compatible function; those
  conditions remain an explicit Admin console step. A
  refused call is reported as a skipped module with its reason while the rest of
  the deployment still applies. Sensitive content storage, OCR, and automatic
  licence policy remain Admin Console steps. The extension can list the exact
  users in the selected OU and assign CEP licences per user through Enterprise
  License Manager. This is a bounded pilot operation: at most 10 unique users
  whose current path exactly equals the selected OU, with complete enumeration
  required within four Directory pages before the first assignment. Over-limit,
  incomplete, failed, or empty listings make zero licence mutations. Each
  Directory and Licensing request has a five-second deadline (deployer identity
  verification has a ten-second route deadline); a timed-out or response-lost per-user POST
  is reconciled by exact product/SKU/user GET, and an unconfirmed outcome retains
  the durable CEP lease instead of being guessed as success or failure.
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
- Loopback-app-only, PoC-only regional internal Application Load Balancer HTTPS offload,
  with a dedicated
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
  Nginx requests; an owned/shared resource
  inventory; and hash-bound teardown of only server-recorded owned resources.
  Teardown runs in reverse dependency order, retains shared resources and
  deletes a gateway only when no applications remain.
- Durable T01–T09 acceptance records. T01–T03 use sanitized VM runtime probes;
  T03 uses system public roots for `public_trusted` and pins the presented chain
  only for enterprise/private and local-PoC certificate strategies;
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
- Node.js 22.13 or newer and pnpm 11.9.0 for the loopback frontend. The
  extension itself uses the locked npm toolchain documented below.
- Google Cloud CLI for keyless Application Default Credentials.
- A billing-enabled GCP project.
- Chrome Enterprise Premium licenses for target users.
- A dedicated non-production test OU.
- A dedicated Workspace Super Administrator when listing or creating Chrome
  DLP rules through the Cloud Identity Policy API. Other Chrome
  Policy, OU, group, and domain operations can use appropriately scoped roles.
- Additional Google services and Google Cloud access enabled for target users.
- Endpoint Verification device-signal collection enabled for the OU.
- An existing Access Context Manager custom access level whose CEL expression
  permits profile-managed Chrome, browser-managed Chrome, or both.
- For Production, a versioned Compute Engine image resource (not an image
  family) with Python 3, Nginx, systemd, and the standard Nginx filesystem
  layout.
- For a Shared VPC or any other cross-project upstream VPC, a manual
  upstream-project custom-role grant completed after deployer bootstrap and
  before validation/preflight, as described below. Entering the upstream
  project ID alone is not sufficient.

In the ID step, **Create deployer and product-scoped role** creates the
dedicated service account and all-supported-path project custom role, then records the service
account's immutable `uniqueId`, the role etag, and the audited service-account
IAM policy before granting project roles. Later runs reconcile only those
pinned identities. A reserved service-account or role name without that local
ownership record is never adopted or granted automatically.

An installation upgraded from 0.2.0 uses the separate, explicitly confirmed
**Migrate existing deployer** action. Migration first reads fresh Cloud state
and succeeds only when the role exactly matches a known 0.2.0/current
definition, its only member is the reserved deployer, the deployer has exactly
the three expected project bindings, and the service account has one
unconditional Token Creator principal—the current operator. Any additional
principal, condition, role, identity mismatch, or missing resource stops the
migration before the ownership pin or a new grant is written.

After those ownership checks, bootstrap grants the project bindings, the
active operator's Token Creator binding, and the configured Access Context
Manager policy's Policy Editor binding. Policy Editor is needed for CEP
`AUTO_CREATE_*` access-level creation in addition to catalogue reads; CEP
cleanup only inspects and retains candidates. Any existing Policy Reader
binding is left intact. IAM updates are repeatable read/modify/write operations,
and the local backend uses argument-array gcloud invocations without a shell.

### Shared VPC and cross-project upstream prerequisite

The normal bootstrap is deliberately limited to the deployment project. It
does **not** create a role or IAM binding in an upstream VPC project. Google
Cloud project custom roles can be granted only inside the project that owns
them, so the all-path role created in the deployment project cannot be reused
as a role in a Shared VPC host project.

After the deployment-project deployer exists, and **before cross-project
validation or preflight**, an administrator of the upstream project must create
and grant a separate project custom role there. The role must contain exactly:

- `compute.networks.get`
- `compute.networks.use`
- `resourcemanager.projects.get`
- `resourcemanager.projects.getIamPolicy`
- `resourcemanager.projects.setIamPolicy`

The last two permissions are required for the reviewed read/modify/write of the
delegating service account's `roles/beyondcorp.upstreamAccess` binding. No
broader predefined role is required by Secure Gateway Studio. The upstream
administrator needs permission to create project custom roles and manage that
project's allow policy (for example, Role Administrator and Project IAM Admin,
or equivalent custom authority).

From the repository root, replace both project IDs and run this as that
upstream-project administrator:

```bash
gcloud iam roles create secureGatewayStudioUpstream \
  --project=UPSTREAM_PROJECT_ID \
  --file=secure-gateway-studio/infrastructure/iam/secure-gateway-upstream-role.yaml

gcloud projects add-iam-policy-binding UPSTREAM_PROJECT_ID \
  --member=serviceAccount:secure-gateway-deployer@DEPLOYMENT_PROJECT_ID.iam.gserviceaccount.com \
  --role=projects/UPSTREAM_PROJECT_ID/roles/secureGatewayStudioUpstream \
  --condition=None
```

If the named role already exists, inspect and reconcile its definition through
your normal IAM change process instead of granting an unreviewed role. Secure
Gateway Studio verifies the five permissions during preflight but does not own,
broaden, delete, or revoke this manual cross-project prerequisite. Google Cloud
documents both the
[project boundary for custom roles](https://cloud.google.com/iam/docs/roles-overview#custom)
and the
[project-level role creation workflow](https://cloud.google.com/iam/docs/creating-custom-roles#create-custom-role).

Then assign the service account the minimum direct Workspace admin roles needed:
Chrome Policy for the pilot OU; OU, group, and user read access; and License
Management for the CEP licence gate. Enterprise License Manager has no
read-only OAuth scope, so even the read-only preflight needs that privilege.
Authenticate ADC by impersonation only after those assignments. For the extension's
optional DLP rule module, sign in with the dedicated Workspace Super
Administrator described above:

```bash
gcloud auth application-default login \
  --impersonate-service-account=secure-gateway-deployer@PROJECT_ID.iam.gserviceaccount.com
gcloud auth application-default set-quota-project PROJECT_ID
```

The backend requests the Cloud Platform, Chrome Policy, Chrome Management,
Enterprise License Manager, and read-only Admin Directory scopes. Admin
Directory is called for the organizational-unit and group pickers, using the
impersonated service account's directly assigned Workspace administrator role;
domain-wide delegation is not required. Service-account JSON key ADC is
rejected and key files must not be added to this repository.

`SGSTUDIO_ACCESS_POLICY_ID` must be set before first run. It is the numeric
Access Context Manager policy ID, and both the access-level picker and the
deployer bootstrap's Policy Editor binding depend on it; without it the
access-level endpoint returns 428. Before any grant or access-level write, SGS
requires the policy's `parent` to equal the project's organization and requires
an optional `scopes` entry to match the project's immutable number or an
ancestor folder. An organization policy scoped only to some other project or
folder is rejected. Copy `.env.local.example` to `.env.local` and fill it in.

## Install and run

On macOS/Linux, from `backend/`:

```bash
python3 -m venv .venv
.venv/bin/pip install uv
UV_CACHE_DIR=/tmp/sgs-uv-cache .venv/bin/uv sync --locked --extra dev
```

On Windows PowerShell, from `backend/`:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install uv
.\.venv\Scripts\uv.exe sync --locked --extra dev
```

From `frontend/`:

```bash
pnpm install --frozen-lockfile
```

Start the packaged single-origin app:

```bash
./scripts/run-local.sh
```

On Windows PowerShell, build the frontend and start the same loopback app with:

```powershell
$env:SGSTUDIO_ACCESS_POLICY_ID = "123456789012"
Set-Location frontend
pnpm build
Set-Location ..
.\backend\.venv\Scripts\python.exe -m uvicorn `
  --app-dir backend/src sgstudio.api.main:app `
  --host 127.0.0.1 --port 8787
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
remaining validity. The local app keeps private key material in process memory.
The extension keeps a generated server key only in `chrome.storage.session`
during the active run, encrypts public certificate material and non-secret
intent metadata at rest in IndexedDB, sends the bundle to Secret Manager, and
clears the session key when the run terminates. Private keys are never placed
in SQLite, disk-backed IndexedDB values, `chrome.storage.local`, startup
metadata, logs, evidence exports, or downloadable certificate files.

The Production image field accepts only:

```text
projects/PROJECT_ID/global/images/IMMUTABLE_IMAGE_NAME
```

Image families are rejected.

## Verification

macOS/Linux:

```bash
cd backend
.venv/bin/ruff check src tests
PYTHONPATH=src .venv/bin/pytest \
  --cov=sgstudio --cov-report=term-missing --cov-fail-under=75

cd ../frontend
pnpm test
pnpm build
pnpm audit --audit-level high

cd ../extension
npm run typecheck
npm run verify
```

Windows PowerShell, from `secure-gateway-studio/`:

```powershell
Set-Location backend
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m pytest `
  --cov=sgstudio --cov-report=term-missing --cov-fail-under=75

Set-Location ..\frontend
pnpm test
pnpm build
pnpm audit --audit-level high

Set-Location ..\extension
npm ci
npm run verify
npm audit --audit-level=high
```

`npm run verify` type-checks the extension and then runs the parity and
behaviour checks, including `verify-cep.ts`, which dispatches through `route()`
— the same entry point the service worker uses — and asserts on the Google
requests each CEP module produces. Route coverage checks compare declarations
textually and cannot catch a handler that fails to run, which is why that one
exercises the handlers directly.

Extension verification runs TypeScript checking plus 25 offline
parity/behaviour scripts. Frontend and backend test counts are reported by their
test runners at execution time, with a 75% minimum backend coverage gate; CI
output is the authoritative count as the suites grow.
The exact environment and browser acceptance cases are in
[TEST_MATRIX.md](docs/TEST_MATRIX.md).

To build the Chrome Web Store upload from the verified extension source:

```bash
cd extension
npm ci
npm run verify
npm run package
```

The last command creates `secure-gateway-studio-0.2.1.zip` with
`manifest.json` at the archive root and prints its SHA-256. Version 0.2.1 does
not produce a CRX.

SBOMs:

- `backend/sbom.cdx.json` — CycloneDX 1.5.
- `frontend/sbom.cdx.json` — CycloneDX 1.7.

## State and recovery

For the local app, non-secret state defaults to
`.local/secure-gateway-studio.db` and can be moved with
`SGSTUDIO_STATE_PATH`. If that process stops during Apply, the next start marks
the run and active operation `interrupted`. Open the saved Apply step and choose
**Resume interrupted Apply**; the backend reacquires the lifecycle slot,
reconciles the durable checkpoints against live cloud state, and continues the
same hash-bound run. An interrupted teardown is rediscovered from the
deployment manager after a reload and has its own explicit resume action. The extension
persists operation checkpoints and rollback before-images in IndexedDB so an
MV3 worker suspension can resume. If the Chrome session ends before an
ephemeral TLS key reaches Secret Manager, the extension fails closed into
ownership-bounded rollback instead of generating a mismatched replacement.
Operator reconciliation is required if cleanup cannot complete.

The local app checkpoints Enterprise CA ownership before its create request.
After an interrupted or rollback-failed run, only the exact resources still in
the state database's active ownership set are eligible for teardown. Preview
that scope before authorizing it:

```bash
python scripts/cleanup_demo_environment.py \
  --state-db .local/secure-gateway-studio.db \
  --run-id <run-id>
```

The command is read-only by default. Execution additionally requires
`--execute` and the exact plan-specific `--confirm` value printed by the dry
run; it never discovers deletion targets from a project-wide name prefix.

## Documentation

- [Implementation plan](../docs/CHROME_SECURE_GATEWAY_WEB_APP_IMPLEMENTATION_PLAN.md)
- [Enterprise readiness](docs/ENTERPRISE_READINESS.md)
- [Test matrix](docs/TEST_MATRIX.md)
