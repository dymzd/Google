# Permission justification

Written for two audiences that ask the same question: the Chrome Web Store
review, and the customer's security team assessing whether to allow the
extension. Every entry states what breaks if the permission is removed.

The host list is checked against both the reference implementation and the
extension provider constants. It is not aspirational and must be reconciled
with `manifest.json` whenever the provider surface changes. The local backend
hosts can be extracted with:

```bash
grep -rhoE "https://[a-z0-9.-]+\.googleapis\.com" backend/src/sgstudio/ --include=*.py | sort -u
```

## Extension permissions

| Permission | Why | Removed → |
|---|---|---|
| `identity` | Obtain an OAuth token for the signed-in administrator, attest that same token's verified email and immutable `sub` through Google UserInfo, then exchange it for a short-lived deployer service-account token via IAM Credentials. | No authentication or actor continuity at all. |
| `storage` | Generated TLS server keys use `chrome.storage.session` only during an active run. All disk-backed deployment and tenant state—drafts, plans, approvals, checkpoints, before-images, evidence, deployer references, public certificates, intents, and ownership pins—is AES-256-GCM encrypted in IndexedDB with a durable non-extractable `CryptoKey`. `chrome.storage.local` is read only during the explicitly accepted 0.2.0 migration and is then cleared. The non-sensitive UI locale (`en` or `ja`) alone remains unencrypted in page `localStorage`; it contains no tenant, authentication, configuration, or audit data and does not use this permission. | No workflow state survives the service worker stopping; interrupted-run detection, safe deployer reconciliation, and evidence export are impossible. |
| `unlimitedStorage` | Exempts the encrypted IndexedDB state above from automatic quota eviction. It is required because losing an approved plan, mutation checkpoint, before-image, or ownership record while Google resources still exist would make safe resume, rollback, and teardown impossible. It is not used to retain unrelated data or to send anything off-device. | Under storage pressure Chrome may evict IndexedDB while a mutation is in flight, leaving external resources without their local reconciliation and ownership ledger. |
| `alarms` | Long-running Google operations are polled across service-worker restarts. Browser startup and extension install/update both run the same consent-gated reconciliation, recreating a missing alarm for an active durable run without waiting for the UI. | An apply that outlives one worker lifetime cannot resume, and a partially applied deployment is left unreconciled. |
| `downloads` | Save the Apply-time public root PEM for a locally generated PoC CA so the administrator can upload it to Chrome Root Store. Evidence JSON, CEP scripts, and later manual certificate exports use in-page Blob downloads and do not use this permission. | The automatic Apply-time public-root handoff cannot occur; the in-page exports still work. |

No `tabs`, `scripting`, `webRequest`, `cookies`, or content scripts are
requested. The extension never reads or modifies any page.

## Host permissions

One host per Google service the orchestrator calls. Each is a documented public
Google API endpoint; none is a wildcard over `*://*/*`.

| Host | Used for |
|---|---|
| `iamcredentials.googleapis.com` | `generateAccessToken` — impersonate the dedicated product-scoped deployer service account so mutations do not run with the administrator's own authority |
| `cloudresourcemanager.googleapis.com` | Project and organization resolution, IAM policy read/write |
| `serviceusage.googleapis.com` | Enable only the APIs the selected path requires |
| `iam.googleapis.com` | Deployer service account and project custom role |
| `beyondcorp.googleapis.com` | Security gateway, application matchers, upstream bindings |
| `accesscontextmanager.googleapis.com` | Read existing access levels for Secure Gateway setup; the separate CEP deployer can explicitly create a managed-Chrome level, while CEP cleanup remains read-only until durable run ownership metadata exists |
| `chromepolicy.googleapis.com` | Discover schemas and apply selected Chrome security, connector, routing, and extension policies in the test OU |
| `chromemanagement.googleapis.com` | Managed-browser and profile signals |
| `admin.googleapis.com` | Organizational-unit and group pickers; immediately before CEP provision/licensing it freshly resolves the immutable OU id, rejects root, and requires an exact typed path. The CEP deployer can also create opted-in sub OUs, read the tenant's primary domain, and list exact-OU users for licence assignment |
| `cloudidentity.googleapis.com` | CEP deployer DLP rules; list/create mutations require a Workspace Super Administrator |
| `licensing.googleapis.com` | Chrome Enterprise Premium licence checks and explicit per-user assignment for users resolved in the selected OU |
| `compute.googleapis.com` | Path A offload tier: network, subnet, firewall, load balancer, and instance group. Direct HTTPS uses read-only probes for the selected VPC and, for an IP target, the matching regional forwarding rule and Global Access. |
| `dns.googleapis.com` | Path A private DNS record |
| `secretmanager.googleapis.com` | TLS bundle storage and alias promotion |
| `privateca.googleapis.com` | CA Service certificate issuance from an in-extension CSR |
| `cloudbilling.googleapis.com` | Confirm the project is billing-enabled before planning |
| `logging.googleapis.com` | Sanitized post-deployment log views |
| `openidconnect.googleapis.com` | Fetch the Google-attested signed-in user identity (`email`, `email_verified`, and immutable `sub`) used to bind privileged actions to the bootstrapped operator |

Deployer bootstrap checkpoints the service account `uniqueId`, custom-role
etag, and complete attached service-account IAM policy before project grants.
Unknown pre-existing reserved names fail closed. The explicit 0.2.0 migration
accepts only the sole current operator as unconditional Token Creator, an exact
known role with only the reserved deployer bound to it, and the exact three
deployer project roles. Access Policy grants additionally require an exact
organization parent and an organization-wide, target-project, or ancestor-folder
scope.

### Shared VPC / cross-project permission boundary

Deployer bootstrap is limited to the deployment project. Supplying an upstream
VPC project ID does not authorize that other project, and the extension does
not create or grant a cross-project role automatically. Google Cloud project
custom roles are grantable only within their owning project, so the deployment
project's all-path role cannot be reused in a Shared VPC host project.

Before validation or preflight, an administrator of the upstream project must
manually create a project custom role there and grant it to the active deployer
service-account email shown after bootstrap. This is normally
`secure-gateway-deployer@DEPLOYMENT_PROJECT_ID.iam.gserviceaccount.com`; a
fail-closed legacy migration may instead use the separately confirmed isolated
replacement `secure-gateway-studio-deployer@DEPLOYMENT_PROJECT_ID.iam.gserviceaccount.com`.
The role contains exactly these six supported permissions:

- `compute.networks.get`
- `compute.networks.list`
- `compute.networks.use`
- `resourcemanager.projects.get`
- `resourcemanager.projects.getIamPolicy`
- `resourcemanager.projects.setIamPolicy`

The Compute permissions verify and use the selected VPC. The Resource Manager
permissions verify the upstream project and perform the reviewed
read/modify/write of the delegating service account's
`roles/beyondcorp.upstreamAccess` binding. The checked-in exact role and safe
`gcloud` example are in
[`infrastructure/iam/README.md`](../../infrastructure/iam/README.md#shared-vpc-or-other-cross-project-upstream).
This manual prerequisite remains administrator-managed; extension teardown does
not delete the role or revoke its grant.

Path B (direct private HTTPS) makes no Compute mutation. It reads the selected
VPC to verify its existence and identity; when the application target is an IP
address, it also reads regional forwarding rules to verify the matching rule
and Global Access. It does not call the DNS, Secret Manager, or CA Service
hosts. Cloud Identity is reached only by the separate CEP DLP flow. Host
permission availability does not cause an API to be called; the approved plan
selects the request set.

## OAuth scopes

Otherwise as in the local application; see
`backend/src/sgstudio/providers/google_rest.py`.
`cloud-platform` is required because the product creates and reconciles
infrastructure across several services, and Google does not offer a narrower
scope spanning them. Administrator authority is limited to read-only preflight
and the explicitly confirmed initial creation and pinning of the deployer,
custom role, and minimum IAM bindings. Every post-bootstrap Cloud mutation
executes as the impersonated deployer service account, which holds a project
custom role rather than the administrator's authority.

After bootstrap, connection validation uses the impersonated deployer to call
project `testIamPermissions` for the Option B regional-health-check
create/delete/get permissions, `dns.managedZones.get/list`, and
`serviceusage.services.use`. Because Google documents that
`testIamPermissions` can fail open, this is not treated as authorization proof.
The extension also requires Service Usage to report `dns.googleapis.com` as
enabled and performs a non-mutating `managedZones.list` limited to one result.
When a zone exists, it follows with `managedZones.get` against that real zone;
an empty list is valid for a new project. It never creates a readiness resource.
The UI does not mark the deployer connected until that representative Cloud DNS
path succeeds. Automatic setup retries the proof for just over two minutes to
cover typical IAM propagation. A final failure reports only the sanitized HTTP
status or Google reason: ordinary HTTP 403 remains retryable, while API-disabled
and organization-restriction reasons such as `VPC_SERVICE_CONTROLS` stop
immediately with distinct errors.

Every requested OAuth scope is accounted for below:

| Scope | Why |
|---|---|
| `openid` | Request the immutable OpenID Connect subject (`sub`) used with the verified email to prevent a different signed-in Google account, or a later account reusing an email address, from inheriting another administrator's approval or deployment. |
| `userinfo.email` | Fetching the Google-attested, verified operator email used with the `openid` subject to bind bootstrap, approvals, mutations, resumes, teardown, CEP writes, and operator acceptance to the same administrator. |
| `admin.directory.group.readonly` | Listing groups for the pilot-principal picker; no group membership is changed. |
| `admin.directory.orgunit` | Reading the current OU tree to block root and verify the administrator's exact typed path; optionally creating the `CEP Users` and `CEP Browsers` sub OUs. This replaces the former `.readonly` variant, which cannot create them. |
| `admin.directory.customer.readonly` | Resolving the tenant's primary domain, which the data-boundary policies are written from. |
| `admin.directory.user.readonly` | Listing users only in the freshly resolved selected pilot OU before an explicit per-user licence assignment. The full exact-OU list must complete within four pages and contain at most 10 unique direct members before any licence POST; otherwise no assignment starts. Descendants are excluded. |
| `cloud-identity.policies` | Listing and creating supported `settings/rule.dlp` policies. `my_customer` is resolved through Directory to the canonical `C...` ID required by create, or the module fails closed. The mutation methods are in beta and require a Super Administrator; authorization failures are recorded explicitly. Unsupported URL-list detector and undocumented access-level/BYOD CEL are not sent. Watermark rules use `warnUser` action parameters so navigation is not blocked. Rollback retains DLP policies because a name prefix is not durable ownership proof. |
| `cloud-platform` | Reading preflight state; performing the explicitly confirmed initial deployer/custom-role/IAM bootstrap; and mutating administrator-approved Google Cloud resources. Post-bootstrap project mutations use a short-lived token for the pinned deployer service account. Its custom role is the project-permission union of all three supported implementations (extension A/C and local B), not a per-run role; the approved plan and preflight constrain each run to the selected path's request subset. |
| `chrome.management.policy` | Resolving Chrome schemas/targets and applying explicitly selected Chrome policies to the confirmed non-root pilot OU. Chrome OU inheritance can also affect descendant OUs, which the UI discloses before Apply. |
| `chrome.management.profiles.readonly` | Verifying managed-profile state and policy application without changing profiles. |
| `apps.licensing` | Reading current Chrome Enterprise Premium assignments and performing the separately selected per-user assignment in the selected pilot OU; this API offers no read-only scope. Each request has a five-second deadline. A timed-out/response-lost POST is followed by an exact product/SKU/user GET and retains the durable CEP lease when the outcome remains unknown. |

The write-capable organizational-unit scope, customer-read scope, and Cloud
Identity policy scope were added in version 0.2.0. Chrome re-prompts for consent
when the requested scope set grows, and the OAuth client in Google Cloud must
list the complete current set before that prompt can succeed. The Google Cloud
project that owns that OAuth client must also have Admin SDK, Chrome Policy,
Chrome Management, Enterprise License Manager, and Cloud Identity APIs enabled;
the deployment project's Apply-time API enablement does not configure the OAuth
consumer project. The exact pre-upload service list and read-only smoke test are
in [`WEB_STORE_SUBMISSION.md`](WEB_STORE_SUBMISSION.md#1-before-uploading).

## Content Security Policy

`connect-src` is restricted to `https://*.googleapis.com`. Manifest V3 already
forbids remote code; `script-src 'self'` and `default-src 'none'` make that
explicit, and `frame-ancestors 'none'` prevents the extension pages being
embedded.
