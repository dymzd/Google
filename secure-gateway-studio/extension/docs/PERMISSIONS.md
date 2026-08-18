# Permission justification

Written for two audiences that ask the same question: the Chrome Web Store
review, and the customer's security team assessing whether to allow the
extension. Every entry states what breaks if the permission is removed.

The host list is derived from the API hosts the reference implementation
actually calls, extracted from `backend/src/sgstudio/`. It is not aspirational
and must be regenerated, not extended by hand, when the provider surface
changes:

```bash
grep -rhoE "https://[a-z0-9.-]+\.googleapis\.com" backend/src/sgstudio/ --include=*.py | sort -u
```

## Extension permissions

| Permission | Why | Removed → |
|---|---|---|
| `identity` | Obtain an OAuth token for the signed-in administrator, then exchange it for a short-lived deployer service-account token via IAM Credentials. | No authentication at all. |
| `storage` | Deployment drafts, plans, approvals, run checkpoints, and the SHA-256 audit chain. | No state survives the service worker stopping; interrupted-run detection and evidence export are impossible. |
| `alarms` | Long-running Google operations are polled across service-worker restarts. | An apply that outlives one worker lifetime cannot resume, and a partially applied deployment is left unreconciled. |
| `downloads` | Export the local PoC CA root certificate for Chrome Root Store upload, and export the portable JSON evidence bundle. | The root cannot be distributed and evidence cannot leave the profile. |

No `tabs`, `scripting`, `webRequest`, `cookies`, or content scripts are
requested. The extension never reads or modifies any page.

## Host permissions

One host per Google service the orchestrator calls. Each is a documented public
Google API endpoint; none is a wildcard over `*://*/*`.

| Host | Used for |
|---|---|
| `iamcredentials.googleapis.com` | `generateAccessToken` — impersonate the least-privilege deployer service account so mutations do not run with the administrator's own authority |
| `cloudresourcemanager.googleapis.com` | Project and organization resolution, IAM policy read/write |
| `serviceusage.googleapis.com` | Enable only the APIs the selected path requires |
| `iam.googleapis.com` | Deployer service account and project custom role |
| `beyondcorp.googleapis.com` | Security gateway, application matchers, upstream bindings |
| `accesscontextmanager.googleapis.com` | Read the managed-Chrome access level bound as an IAM condition |
| `chromepolicy.googleapis.com` | Force-install the gateway and Endpoint Verification extensions in the test OU |
| `chromemanagement.googleapis.com` | Managed-browser and profile signals |
| `admin.googleapis.com` | Organizational-unit and group pickers; the CEP deployer also creates its sub OUs and reads the tenant's primary domain here |
| `cloudidentity.googleapis.com` | CEP deployer DLP rules and detectors |
| `licensing.googleapis.com` | Chrome Enterprise Premium license checks |
| `compute.googleapis.com` | Path A offload tier: network, subnet, firewall, load balancer, instance group |
| `dns.googleapis.com` | Path A private DNS record |
| `secretmanager.googleapis.com` | TLS bundle storage and alias promotion |
| `privateca.googleapis.com` | CA Service certificate issuance from an in-extension CSR |
| `cloudbilling.googleapis.com` | Confirm the project is billing-enabled before planning |
| `logging.googleapis.com` | Sanitized post-deployment log views |

Path B (direct private HTTPS) uses only the first ten (Cloud Identity aside, which is reached only by the CEP deployer). The Compute, DNS, Secret
Manager, and CA Service hosts are reachable but unused until a Path A
deployment is planned.

## OAuth scopes

Otherwise as in the local application; see
`backend/src/sgstudio/providers/google_rest.py`.
`cloud-platform` is required because the product creates and reconciles
infrastructure across several services, and Google does not offer a narrower
scope spanning them. The mitigation is that mutations execute as the
impersonated deployer service account, which holds a project custom role rather
than the administrator's authority.

Three scopes are specific to the CEP PoC Deployer:

| Scope | Why |
|---|---|
| `admin.directory.orgunit` | Creating the `CEP Users` and `CEP Browsers` sub OUs. This replaces the former `.readonly` variant, which the write scope includes. |
| `admin.directory.customer.readonly` | Resolving the tenant's primary domain, which the data-boundary policies are written from. |
| `cloud-identity.policies` | Creating and deleting DLP rules and detectors. The mutation methods are in beta; a refused call reports the module as skipped rather than failing the deployment. |

All three were added after the initial release. Chrome re-prompts for consent when
the requested scope set grows, and the OAuth client in Google Cloud must list
them before that prompt can succeed — an existing installation will fail
authentication until the client is updated.

## Content Security Policy

`connect-src` is restricted to `https://*.googleapis.com`. Manifest V3 already
forbids remote code; `script-src 'self'` and `default-src 'none'` make that
explicit, and `frame-ancestors 'none'` prevents the extension pages being
embedded.
