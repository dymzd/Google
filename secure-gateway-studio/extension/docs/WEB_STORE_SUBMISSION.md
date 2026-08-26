# Chrome Web Store submission

Copy-paste material for the Developer Dashboard, plus the OAuth verification
that runs separately in Google Cloud Console. Every justification here states
what the extension actually does; a reviewer who reads the source should find
nothing claimed that the code does not do.

Verified against `manifest.json` at version 0.2.24.

---

## 1. Before uploading

The store listing is not the blocker. These are.

- [ ] **Register the complete manifest scope set on client
      `414812060045-…`** in Google Cloud Console. Publishing the extension does
      not enable scopes. Version 0.2.1 newly adds `openid` so privileged actions
      can bind the verified email to Google's immutable `sub`; add it before
      uploading. Also confirm the three sensitive scopes introduced in 0.2.0
      are still present:
      - `openid` (new in 0.2.1)
      - `https://www.googleapis.com/auth/admin.directory.orgunit` (replaces the
        `.readonly` variant)
      - `https://www.googleapis.com/auth/admin.directory.customer.readonly`
      - `https://www.googleapis.com/auth/cloud-identity.policies`
- [ ] **Enable every Workspace/Cloud Identity API in the Google Cloud project
      that owns OAuth client `414812060045-…`.** This is the OAuth consumer
      project, not necessarily the administrator-selected deployment project;
      enabling APIs during an SGW Apply does not configure it. At minimum,
      confirm these services are `ENABLED` there:
      - `admin.googleapis.com`
      - `chromepolicy.googleapis.com`
      - `chromemanagement.googleapis.com`
      - `licensing.googleapis.com`
      - `cloudidentity.googleapis.com`

      For example, after selecting the exact OAuth client project:

      ```bash
      gcloud services enable \
        admin.googleapis.com \
        chromepolicy.googleapis.com \
        chromemanagement.googleapis.com \
        licensing.googleapis.com \
        cloudidentity.googleapis.com \
        --project=OAUTH_CLIENT_PROJECT_ID
      ```

      In a non-production tenant, sign in through the packaged extension and
      smoke-test Directory customer/OU reads, Chrome Policy schema/resolve,
      Chrome Management profile listing, Licensing assignment listing, and a
      read-only Cloud Identity `settings/rule.dlp` policy list. A legitimate
      empty result is acceptable; `accessNotConfigured` is not. Do not begin a
       mutating pilot until all five calls reach their APIs.
- [ ] **For a Shared VPC or other cross-project upstream, complete the manual
      upstream-project IAM prerequisite before validation/preflight.** The
      normal bootstrap changes only the deployment project. An upstream-project
      administrator must create a custom role in that project, grant it to the
      deployment-project deployer, and include exactly `compute.networks.get`,
      `compute.networks.list`, `compute.networks.use`, `resourcemanager.projects.get`,
      `resourcemanager.projects.getIamPolicy`, and
      `resourcemanager.projects.setIamPolicy`. Project custom roles cannot be
      granted outside their owning project. Follow
      [`infrastructure/iam/README.md`](../../infrastructure/iam/README.md#shared-vpc-or-other-cross-project-upstream).
- [ ] Confirm that this OAuth credential is a **Chrome Extension** client whose
      Item ID is `dpoipoafmkanaideagfiflihnbgbeffk`. That ID is derived from the
      fixed public `key` in `manifest.json`; it is the Studio item ID, not the
      managed Secure Enterprise Browser ID `ekajlcmdfcigmdbphhifahdfjbkciflj`.
      The `verify-auth` release check fails if either the key-derived Item ID or
      client ID drifts.
- [ ] **Enable GitHub Pages and verify the domain in Search Console.** The
      homepage and privacy policy must sit on a domain you have verified, and
      `github.com` cannot be verified. This gates branding verification, which
      sensitive scopes make mandatory. See "4b. Branding".
- [ ] **Start OAuth verification** if the client is not already verified.
      `admin.directory.orgunit` is a sensitive scope and its review is separate
      from, and usually slower than, the Web Store review.
- [ ] Confirm the uploaded ZIP is built from the published commit.
      `npm run package` prints a SHA-256 that is reproducible from source.

---

## 2. Store listing

### Name (max 75)

    Secure Gateway Studio

### Short description (max 132)

    Plan, apply, and verify Chrome Enterprise Premium and Secure Gateway deployments in your own Google Cloud projects.

### Category

    Developer Tools

### Language

    English (a complete Japanese UI is included)

### Detailed description (max 16,000)

    Secure Gateway Studio is an administrator tool for planning, applying, and
    verifying Chrome Enterprise Premium deployments against your own Google
    Cloud deployment project, optional upstream VPC project, and Google
    Workspace tenant.

    NOT AN OFFICIAL GOOGLE PRODUCT

    This extension is an independent open-source project. It is not built,
    endorsed, or supported by Google, and it is not affiliated with Google LLC.
    "Google", "Google Workspace", "Google Cloud", "Chrome" and "Chrome
    Enterprise Premium" are trademarks of Google LLC.

    It is provided as is, with no warranty and no support commitment of any
    kind. You are responsible for what it changes in your tenant. Evaluate it
    in a non-production organizational unit first, review the plan before
    approving it, and keep the rollback path in mind.

    WHERE TO GET HELP

    - Questions about Chrome Enterprise Premium, Secure Gateway, or your
      licences: contact your Google account team -- your Field Sales
      Representative or Customer Success Manager. They support the Google
      products; this extension is not one of them.
    - Problems with this extension itself: open an issue at
      https://github.com/dymzd/Google/issues. Best effort only, with no
      response time commitment.

    It is not a service. There is no account to create, no server operated by
    the developer, and no data sent anywhere except to Google's own APIs. Calls
    use either your administrator OAuth authority for Workspace/Chrome/Cloud
    Identity or a short-lived impersonated deployer token for Cloud-project
    mutations.

    WHAT IT DOES

    - Secure Gateway deployments. Designs and applies BeyondCorp Private
      Security Gateway architectures for direct private HTTPS applications or
      Nginx HTTPS-to-HTTP offload, or a PoC-only regional internal Application
      Load Balancer. Every deployment is planned first, approved explicitly,
      and applied as a single reviewed unit. An unfinished Apply or rollback is
      recovered before a replacement plan can be prepared.

    - Chrome Enterprise Premium evaluation. Applies a CEP baseline to one
      organizational unit: threat-protection policies, forced Endpoint
      Verification, content-inspection connectors, a Context-Aware Access
      level, data-boundary policies, and starter DLP rules. Each policy is
      checked against your tenant's live Chrome Policy schema before it is
      written, so a policy your tenant does not support is reported as skipped
      with the reason rather than failing silently.
      Optional direct licence assignment is restricted to at most 10 unique
      users whose current Directory path exactly equals the selected non-root
      OU. The complete list must finish within four pages before the first
      licence POST; otherwise zero assignments are started. Directory and
      Licensing calls have a five-second deadline (deployer identity verification
      has a ten-second route deadline), and an unconfirmed POST retains the durable CEP
      lease until an exact product/SKU/user GET can reconcile it.

    - Cleanup safety. Easy PoC cleanup resolves current Chrome Policy state and
      reports every candidate, but retains Chrome policies, organizational
      units, access levels, and DLP rules for manual review because this release
      does not persist the before-images and ownership proof needed for a safe
      restore or DELETE. Secure Gateway teardown mutates only resources whose
      durable ownership and managed-after state still match exactly; drift is
      retained for review.

    - Evidence. A SHA-256 audit chain of what was planned, approved, applied,
      and verified, exportable as JSON.

    - Dedicated mutation identity by construction. After the explicitly
      confirmed bootstrap creates and pins the service account, custom role,
      and minimum IAM bindings, Google Cloud mutations run as that account.
      Its role is limited to the project-permission union of all three
      supported implementations: extension paths A/C and local path B. It is
      not a per-run role; the approved plan and preflight limit each run to the
      selected path's request subset.

    HOW IT WORKS

    Everything runs locally in the extension. The service worker obtains an
    administrator OAuth token through chrome.identity for Workspace, Chrome,
    Cloud Identity, deployer bootstrap, and token exchange. Google Cloud
    mutations then use a short-lived token impersonating the dedicated scoped
    deployer; they never fall back to administrator authority. Plans, approvals,
    run checkpoints, and the audit chain are AES-256-GCM encrypted in the
    browser profile's IndexedDB and never sent to the developer. The data key
    is non-extractable and is persisted by IndexedDB structured clone.

    REQUIREMENTS

    - Chrome 142 or newer
    - A Google Workspace administrator account with the listed Chrome and
      License Management privileges, plus Directory read privileges for groups,
      users, and customer metadata. If automatic CEP sub-OU creation is selected,
      the account also needs permission to create Organizational Units. Those
      children are optional scaffolding: policy remains on the populated pilot
      OU and inherits down unless overridden, and the extension does not move any occupant. Cloud
      Identity DLP mutations additionally require a dedicated Super Administrator
    - A billing-enabled Google Cloud project
    - For Shared VPC or another cross-project upstream: a project administrator
      must manually grant the deployment-project deployer the documented exact
      five-permission custom role in the upstream project before validation.
      Bootstrap does not create this cross-project role or binding.
    - Chrome Enterprise Premium licences for the users you are evaluating

    The full source, a reproducible build, and a per-permission justification
    are published at https://github.com/dymzd/Google under
    secure-gateway-studio/. The packaged ZIP is byte-reproducible from that
    source, so you can confirm the artefact you install matches the code you
    read.

---

## 3. Privacy practices

### Single purpose

    Secure Gateway Studio plans and applies Chrome Enterprise Premium and
    BeyondCorp Security Gateway configurations to the administrator's own
    Google Cloud deployment project, optional explicitly selected upstream VPC
    project, and Google Workspace tenant, and records verifiable evidence of
    what it changed.

### Permission justifications

Paste each verbatim into the matching box.

**identity**

    Obtains an OAuth token for the signed-in Google Workspace administrator so
    the extension can attest that token's verified email and immutable OpenID
    Connect subject through Google UserInfo, call Workspace management APIs as
    that administrator, and mint the pinned deployer's short-lived Cloud token.
    This is the only authentication path; without it the extension cannot
    function or bind privileged actions to one Google account.

**storage**

    Keeps the deployer reference, approved specification, checkpoints,
    before-images, public certificates, intent metadata, and evidence in
    AES-256-GCM encrypted IndexedDB so work can resume after a service-worker
    restart. The random data key is a durable non-extractable CryptoKey.
    Generated TLS server private keys are held only in chrome.storage.session
    during an active run, then cleared at terminal success or failure.
    chrome.storage.local is used only as a one-time 0.2.0 migration source after
    affirmative consent and is cleared before resume is enabled. OAuth access
    tokens and service-account keys are never written to durable storage. The
    only unencrypted durable UI value is the page-local locale preference
    (`en` or `ja`); it contains no tenant, authentication, configuration, or
    audit data and does not use chrome.storage.

**unlimitedStorage**

    Protects the encrypted IndexedDB plan, mutation checkpoints, before-images,
    ownership records, and audit evidence from automatic quota eviction. Losing
    that ledger while Google resources still exist would make safe resume,
    rollback, and teardown impossible. This permission is not used to retain
    unrelated data, collect browsing data, or transmit anything off-device.

**alarms**

    Google's long-running operations outlast a Manifest V3 service worker. An
    alarm wakes the worker to continue polling an apply that is already in
    progress. If session-only key material is lost, execution fails closed into
    ownership-bounded rollback instead of silently generating a replacement.

**downloads**

    Saves the Apply-time public root PEM for a locally generated proof-of-concept
    CA so the administrator can upload it to Chrome Root Store. The extension
    generates that file locally and passes it as a data: URL; nothing is fetched
    from a remote server. Evidence JSON, CEP scripts, and later manual root
    exports use in-page Blob object URLs with an <a download> element and do not
    use chrome.downloads.

### Host permission justification

    Every host is a documented public Google API endpoint that the extension
    calls directly to read or change configuration in the administrator's own
    deployment project, explicitly selected upstream VPC project, and Workspace
    tenant. There is no wildcard host permission and no
    non-Google host. The extension never reads or modifies any web page: it
    requests no content scripts, no tabs, no webRequest, and no cookies access.

      iamcredentials.googleapis.com        impersonate the product-scoped deployer service account
      cloudresourcemanager.googleapis.com  project and organization lookup, IAM policy read and write
      serviceusage.googleapis.com          enable only the APIs the selected path needs
      iam.googleapis.com                   create the deployer service account and its project custom role
      beyondcorp.googleapis.com            security gateway, application matchers, upstream bindings
      accesscontextmanager.googleapis.com  read and create Context-Aware Access levels
      chromepolicy.googleapis.com          read policy schemas and apply Chrome policies to the target OU
      chromemanagement.googleapis.com      managed browser and profile signals used by preflight
      admin.googleapis.com                 organizational unit and group pickers; create the CEP sub OUs
      cloudidentity.googleapis.com         list and create supported Chrome DLP rules
      licensing.googleapis.com             confirm and assign CEP licences to users resolved in the selected OU
      compute.googleapis.com               read the selected VPC and IP-target forwarding-rule Global Access; create offload network, subnet, firewall, load balancer, and instance group resources
      dns.googleapis.com                   private DNS record for the deployed application
      secretmanager.googleapis.com         TLS bundle storage and alias promotion
      privateca.googleapis.com             certificate issuance from a CSR generated in the extension
      cloudbilling.googleapis.com          confirm the project is billing-enabled before planning
      logging.googleapis.com               sanitized post-deployment log views
      openidconnect.googleapis.com         Google-attested signed-in administrator email and immutable subject

### Remote code

Answer: **No, I am not using remote code.**

    The extension executes no remotely hosted code. Its content security policy
    is "default-src 'none'; script-src 'self'", which Chrome enforces, and the
    build is a plain esbuild bundle of the published source with no CDN, no
    eval, and no dynamically fetched script.

### Data usage

Declare the data the extension handles. In the Privacy practices tab select:

- **Personally identifiable information** — the signed-in administrator email,
  selected directory-user identifiers for optional licence assignment, and
  principal identifiers recorded in plans and evidence.
- **Authentication information** — short-lived Google OAuth access tokens and
  impersonated access tokens, held in memory only; and, only when the
  administrator selects an existing public-certificate secret, the TLS private
  key in that exact numeric SecretVersion, read into memory solely to validate
  the certificate/key match, DNS names, expiry, and digest.
- **User activity** — administrator approval/apply actions and the sanitized
  gateway/access diagnostic status, method, severity, and request identifiers
  the administrator explicitly opens or exports.

Do not select web history or website content: the extension has no content
scripts, `tabs`, `webRequest`, or cookie access and does not observe pages. Its
Cloud Logging request uses a strict partial-response field mask that excludes
URL paths and query strings, free-form payloads, caller IP addresses, and
principal identifiers; the response parser and offline regression check enforce
the same boundary.

When an administrator approves Security Gateway creation, the extension sends
the documented empty `logging` marker to enable full Secure Gateway connection
records in Cloud Logging in the selected Google Cloud project. The records'
contents, retention, and access follow the customer's Google Cloud
configuration. The developer receives none of these records. The extension
retrieves only the strict sanitized diagnostic field mask above; URL paths,
query strings, IP addresses, principals, and free-form log payloads remain
excluded.
Supporting statement for the review notes:

    This extension handles administrator and selected-directory-user email
    addresses, Google authentication information, Workspace tenant and Chrome
    policy configuration, Google Cloud resource metadata, and sanitized
    administrator/gateway diagnostic activity. These data are used only for
    the administrator-facing deployment, verification, evidence, and cleanup
    features described in the listing.

    Data is transmitted only over HTTPS to Google APIs that host the
    administrator's own Workspace tenant and explicitly selected Cloud
    projects. No tenant data is
    sent to or received by the developer, and there is no analytics,
    advertising, profiling, sale, or human review. The first extension screen
    prominently discloses these practices and requires an affirmative action
    before Google authorization or tenant access.

    Configuration, plans, approvals, run state, before-images, certificate
    material, and the audit chain are encrypted at rest in the browser
    profile's IndexedDB. AES-GCM authenticates the schema, store, and hashed
    record key; a missing/wrong key or modified ciphertext fails closed. They
    stay on the device. The non-sensitive locale (`en` or `ja`) is the only
    unencrypted page-local preference and contains no tenant, authentication,
    configuration, or audit data. Access tokens are held in memory only and are never written
    to storage, logs, audit events, or the evidence export; a redaction pass
    strips anything token-shaped before serialization. During certificate
    provisioning, a generated TLS server private key is kept only in
    chrome.storage.session for the active browser session, uploaded to the
    administrator's Secret Manager, and cleared when the run terminates. Only
    public certificate material and non-secret intent metadata are persisted as
    encrypted IndexedDB values. The chrome.downloads handoff contains public
    certificate material only. Evidence and other in-page downloads may contain
    the disclosed configuration or sanitized audit data, but never TLS private
    keys or access tokens. If the administrator instead selects an existing public-certificate
    secret, the extension reads its pinned numeric SecretVersion from that
    administrator's Secret Manager only to validate and configure the approved
    endpoint. The existing TLS private key stays in memory during validation;
    it is never persisted, logged, saved as a file, passed to chrome.downloads,
    retransmitted, included in evidence, or sent to the developer. The approved
    VM later reads the pinned version directly from the same Secret Manager.

    Version 0.2.1 does not inspect 0.2.0 IndexedDB, chrome.storage.local, setup,
    or workflow values before the administrator accepts the updated disclosure.
    It encrypts those values, clears the legacy unencrypted setup and workflow
    records, and only then marks consent complete and permits cold-start
    reconciliation. The non-sensitive locale remains. Existing
    audit hashes and semantic event payloads are preserved.

    Use of information received from Google APIs adheres to the Chrome Web
    Store User Data Policy, including its Limited Use requirements. The data is
    never used or transferred for an unrelated purpose, advertising,
    creditworthiness, or lending.

Certifications to tick:

- [x] I do not sell or transfer user data to third parties, outside of the approved use cases
- [x] I do not use or transfer user data for purposes that are unrelated to my item's single purpose
- [x] I do not use or transfer user data to determine creditworthiness or for lending purposes

---

## 4. OAuth verification (Google Cloud Console, separate from the store)

Scope-by-scope justification. The three write/read scopes marked **new in
0.2.0** remain part of the sensitive-scope review; `openid` is the one scope
added by 0.2.1.

| Scope | Sensitivity | Justification |
|---|---|---|
| `openid` **new in 0.2.1** | basic | Supplies the immutable OpenID Connect subject used with the verified email to prevent a different signed-in Google account, or a later account reusing an email address, from inheriting approvals or deployment authority. |
| `userinfo.email` | basic | Identifies the administrator in the audit chain and for the Token Creator binding; UserInfo must also return `email_verified: true`. |
| `admin.directory.group.readonly` | sensitive | Populates the group picker used to choose who may reach a deployed application. Read only. |
| `admin.directory.orgunit` **new in 0.2.0** | sensitive | Reads the fresh OU tree immediately before CEP provision/licensing, rejects the Workspace root OU, and verifies an exact path the administrator typed. It can also create opted-in `CEP Users` and `CEP Browsers` children beneath that confirmed pilot OU. Replaces the previous `.readonly` variant, which cannot create them. |
| `admin.directory.customer.readonly` **new in 0.2.0** | sensitive | Reads the tenant's primary domain, which the data-boundary policies are written from. A policy built from anything else silently fails to match. Read only. |
| `admin.directory.user.readonly` | sensitive | Lists only the users in the explicitly selected pilot OU before an optional per-user CEP licence assignment. Read only; an unresolved, failed, or empty listing aborts assignment. |
| `cloud-identity.policies` **new in 0.2.0** | sensitive | Lists and creates supported `settings/rule.dlp` policies using built-in detectors. Directory resolves `my_customer` to the canonical `C...` ID required by create; unresolved IDs fail closed. Listing prevents duplicate creation. Unsupported URL-list detector and undocumented access-level/BYOD CEL are never sent; internal URL prefixes are escaped into rule CEL. Watermark rules use the documented Chrome `warnUser` action with watermark/screenshot parameters rather than blocking navigation. Google requires a Super Administrator for these mutations. Rollback retains DLP policies because this release cannot durably prove ownership from a display name. |
| `cloud-platform` | sensitive | Reads preflight state, performs the explicitly confirmed initial creation and pinning of the deployer service account/custom role/IAM bindings with administrator authority, then creates and reconciles infrastructure across Compute Engine, IAM, Cloud DNS, Secret Manager, CA Service, BeyondCorp, and Access Context Manager. Google publishes no narrower scope spanning them. Every post-bootstrap Cloud mutation executes as the pinned deployer holding the product's all-supported-path custom role and never falls back to administrator authority. |
| `chrome.management.policy` | sensitive | Reads Chrome policy schemas and applies policies to the confirmed non-root target organizational unit. Chrome policy inheritance can also affect descendant OUs; the screen discloses that scope and requires the exact OU path again before each write. |
| `chrome.management.profiles.readonly` | sensitive | Preflight signals: managed profile counts and last policy sync, shown before a plan is approved. Read only. |
| `apps.licensing` | sensitive | Confirms Chrome Enterprise Premium licence availability and, only after an explicit click, assigns licences to the users resolved in the selected pilot OU. |

### Scope justification

The console caps this box at **1000 characters**, so this is the version
that fits. Paste it as-is; the per-scope table above stays as the working
reference, not as submission text.

#### Single box (1000 characters, the cap is 1000)

    Configures Chrome Enterprise Premium and Secure Gateway in one Workspace tenant, a deployment project, and an optional admin-selected upstream VPC project. No backend or developer data. openid/userinfo.email bind approvals to the verified admin.

    Directory scopes populate OU/group selectors, read the primary domain, list pilot-OU users, and optionally create CEP Users/CEP Browsers sub-OUs. chrome.management.policy reads live schemas and applies policies. cloud-identity.policies creates supported DLP rules; apps.licensing assigns pilot users. cloud-platform reads preflight and performs the confirmed initial deployer/IAM bootstrap; later Cloud mutations use only the pinned deployer custom role.

    Read-only scopes are used where possible. orgunit.readonly cannot create OUs, policies.readonly cannot create rules, chrome.management.policy has no narrower writable scope, apps.licensing has no read-only scope, and nothing narrower than cloud-platform spans the Cloud services used.

#### If the form asks per scope

Some consent-screen flows ask once per scope instead. Each of these is
independently under the limit.

**`admin.directory.orgunit`** (599 characters)

    Reads the OU tree to populate the picker and again immediately before a CEP write. The root OU is rejected, and the administrator must type the exact current non-root OU path. It can then create the opted-in children "CEP Users" and "CEP Browsers" beneath that pilot OU; an existing exact child is reused.

    This extension requested admin.directory.orgunit.readonly until this version. That is no longer sufficient, because creating an OU is a write. Google publishes no scope that permits creating an organizational unit without other directory writes, and we make none of those other writes.

**`admin.directory.customer.readonly`** (392 characters)

    Reads the tenant's primary domain. The data-boundary policy this tool writes limits Google apps to that domain (for example `example.com`); a policy built from anything other than the real primary domain silently matches nothing. It intentionally uses `AllowedDomainsForApps`, which covers managed Chrome on desktop and ChromeOS, instead of the mobile-only `RestrictAccountsToPatterns` policy.

    This is already the read-only variant. We deliberately do not request admin.directory.customer, which would permit writes we never make.

**`cloud-identity.policies`** (under 1000 characters)

    Lists and creates supported settings/rule.dlp policies that make up a Chrome Enterprise Premium evaluation. Directory supplies the canonical C-prefixed customer ID required by create. The rules use built-in detectors; unsupported URL-list detectors and undocumented BYOD CEL are never sent. Listing prevents duplicates.

    cloud-identity.policies.readonly is not sufficient because it cannot create a rule. Google publishes no create-only scope. This release deliberately retains DLP policies during rollback because a display name is not durable ownership proof.

**`cloud-platform`** (under 1000 characters)

    Creates and reconciles the infrastructure a Secure Gateway deployment needs, across Compute Engine, IAM, Cloud DNS, Secret Manager, Certificate Authority Service, BeyondCorp, Access Context Manager and Service Usage.

    No narrower scope exists: Google publishes none covering a subset of those services. The administrator token performs read-only preflight and, only after explicit confirmation, the initial creation and pinning of the deployer service account, project custom role, Token Creator binding, and required project IAM bindings. After that bootstrap, every Cloud mutation executes as the pinned account through short-lived impersonated tokens and never falls back to administrator authority. The administrator token remains necessary to mint those tokens and for CEP Workspace and Cloud Identity calls whose authorization comes from OAuth consent and Google Admin console roles, not project IAM.

    Bootstrap is limited to the deployment project. For an explicitly selected Shared VPC or other cross-project upstream, an administrator of that project must separately create and grant the deployment-project deployer the documented five-permission project custom role before validation; project custom roles cannot be granted outside their owning project.

**`chrome.management.policy`** (467 characters)

    Reads the tenant's live Chrome policy schemas and applies policies to the confirmed non-root organizational unit. Chrome policy inheritance can also affect descendant OUs; the UI states that scope and requires the exact current OU path before each mutation.

    Reading the schema first is deliberate: a policy written into a field the tenant does not advertise does nothing, silently, so the tool refuses and reports it rather than appearing to succeed.

    There is no read-only variant that still permits applying a policy, and applying policy is the whole purpose.

**`chrome.management.profiles.readonly`** (215 characters)

    Reads managed profile counts and the last policy sync time, shown to the administrator during preflight so a plan can be reviewed against the tenant's real state before it is approved. Already the read-only variant.

**`admin.directory.group.readonly`** (143 characters)

    Populates the group picker used to choose who may reach a deployed application. Already the read-only variant; the tool never modifies a group.

**`apps.licensing`**

    Confirms Chrome Enterprise Premium licence availability and, only after an explicit operator action, assigns licences to at most 10 unique direct members of the selected pilot OU. Descendants are excluded. The full list must complete within four Directory pages before any assignment starts; over-limit, incomplete, failed, or empty listings make zero licence mutations. Each Directory and Licensing request has a five-second deadline; deployer identity verification has a ten-second route deadline. A timed-out or response-lost POST is reconciled by exact product/SKU/user GET and retains the durable tenant/OU lease if still ambiguous. No read-only variant of this scope exists.

### Demo video

Verification requires a recording that shows each sensitive scope in use.
Cover, in order:

1. Sign in as a Workspace administrator, showing the consent screen with the
   scopes listed.
2. The setup screen reading the OU and group pickers
   (`admin.directory.orgunit` and `admin.directory.group.readonly`).
3. The Easy PoC for Chrome Enterprise Premium page: show that no OU is preselected and root is unavailable; select a non-root pilot OU, review the selected-and-descendant impact notice, type the exact OU path, optionally enable sub-OU creation, and apply.
   Show the created `CEP Users` and `CEP Browsers` OUs in Admin Console
   (`admin.directory.orgunit`), and show that the selected pilot OU remains the
   direct policy target so its existing occupants are covered; no user or
   enrolled browser is moved automatically.
4. The applied Chrome policies in Admin Console (`chrome.management.policy`).
5. The created DLP rules in Admin Console, under Data protection
   (`cloud-identity.policies`).
6. The read-only cleanup inspection resolving live Chrome Policy state and
   reporting all retained Chrome Policy, OU, access-level, and DLP candidates
   for manual ownership review.

### URLs

| Field | Value |
|---|---|
| Application homepage | `https://test-domain.dev/` |
| Privacy policy | `https://test-domain.dev/privacy.html` |
| Terms of service | optional; leave empty unless a separate Terms document is published. The source is licensed under Apache-2.0. |

Both must be on a domain verified in Search Console, which rules out
`github.com`. See "4b. Branding" below.

---

## 4b. Branding (Google Auth Platform)

Requesting sensitive scopes makes branding verification mandatory, and this page
is where a submission most often stalls. The blocker is not the logo, it is the
**Authorized domains** field.

### The domain trap

Every URL on this page — homepage, privacy policy, terms — must sit on a domain
listed under **Authorized domains**, and every authorized domain must be one you
have verified in [Google Search Console](https://search.google.com/search-console).

`github.com` cannot be verified, because it is not yours. Any URL of the form
`https://github.com/dymzd/Google/...` is therefore unusable here, however
convenient it is. `raw.githubusercontent.com` is unusable for the same reason.

This repository already publishes GitHub Pages through the custom domain
`test-domain.dev` (`docs/CNAME`). Use that canonical domain directly. Do not
enter the underlying `dymzd.github.io/Google/` URL: GitHub redirects it to the
custom domain, and Google OAuth verification rejects a homepage URL that
redirects to a different domain.

### Enabling the pages

`docs/index.md` and `docs/privacy.md` are already in the repository. To publish
them:

1. Repository **Settings → Pages**.
2. Source: **Deploy from a branch**, branch `main`, folder **`/docs`**.
3. Wait for the build, then confirm both canonical URLs load directly over
   HTTPS in a private window with no sign-in or cross-domain redirect:
   - `https://test-domain.dev/`
   - `https://test-domain.dev/privacy.html`
4. Confirm the deployed Privacy Policy describes administrator identity,
   authentication information, tenant configuration, local storage, Google
   API processing, and Limited Use exactly as version 0.2.1 does. The previous
   "collects no user data" wording is not valid for this extension.

### Verifying the domain

1. Open Search Console and add a **Domain** property for `test-domain.dev`.
2. Add the supplied DNS TXT record at the registrar, wait for it to resolve,
   and click Verify. Domain-property verification is the current OAuth review
   requirement; a URL-prefix-only property is insufficient.
3. Once verified, enter `test-domain.dev` under Authorized domains.

Verify with a Google account that is a **Project Owner or Project Editor** on
the OAuth client project. Verification by an unrelated account does not count.

### Field by field

| Field | Value |
|---|---|
| App name | `Secure Gateway Studio` |
| User support email | a monitored address — see the warning below |
| App logo | `extension/icons/oauth-logo-120.png` (120x120, PNG, 7.8 KB) |
| Application home page | `https://test-domain.dev/` |
| Application privacy policy link | `https://test-domain.dev/privacy.html` |
| Application terms of service link | leave empty unless a separate Terms document is published; the source licence is Apache-2.0 |
| Authorized domains | `test-domain.dev` |
| Developer contact information | your own address; Google uses it for project notices, and it is not shown to users |

### Two things to check before submitting

**The support email.** The screenshot shows `admin@test-domain.dev`. If that is
a scratch domain, replace it: it is displayed on the consent screen to every
user, reviewers do check that it resolves, and a test-looking address on a
tool that rewrites enterprise policy invites a rejection. It must also be
either the address that owns the Cloud project or a Google Group that address
owns.

**The app name.** `Secure Gateway Studio` is fine — it does not contain
"Google", "Chrome", or any Google mark, which the branding policy forbids in an
app name. Do not be tempted to add "for Chrome Enterprise" to make it clearer;
that is the change that would fail review.

---

## 5. Screenshots and images

The store requires at least one screenshot; five is the maximum and three is
usually enough to show what the tool is. Chrome accepts **1280x800** or
**640x400**, PNG or JPEG, and rejects anything else.

Capture them from the actual unpacked extension build, not the local FastAPI
frontend (the local transport intentionally hides extension-only CEP routes):

    cd secure-gateway-studio/extension
    npm ci && npm run build
    # Load extension/dist as an unpacked extension at chrome://extensions

Open the extension, set the browser window so the page renders at 1280x800,
and capture only data from a dedicated pilot tenant:

| # | Screen | How to reach it | Shows |
|---|---|---|---|
| 1 | User-data disclosure | First extension launch before accepting | The handled data, Google API destination, local retention, Limited Use, privacy link, and affirmative consent |
| 2 | Easy PoC for Chrome Enterprise Premium | Accept the disclosure, then top-level "Easy PoC" | OU picker, presets, and policy modules |
| 3 | DLP rules and actions | Same page, scroll to "Rules and what each one does" | Per-rule off / warn / block controls and the country selector |
| 4 | Execution trace | Same page, after an apply | Applied and skipped lists with reasons |
| 5 | Secure Gateway setup or Evidence | Open the Secure Gateway menu, then "New setup" or "Evidence" | The hash-bound deployment workflow or tamper-evident export |

Screens 1, 2, 3 and the setup variant of 5 render without Google credentials;
the CEP pickers will remain disconnected until authorization. Screen 4 and the
Evidence variant of 5 need a pilot run.

Required image files supplied by this repository:

- **Store/manifest icon:** `extension/icons/icon-128.png`, with a 96x96 product
  mark and 16 transparent pixels on every side.
- **Small promo tile:** `extension/docs/promo-440x280.png`. This 440x280 PNG is
  mandatory; it is a full-bleed, text-free brand image suitable for every
  supported locale.
- **Screenshot:** `extension/docs/screenshot-1280x800.png`. Re-capture this from
  the final unpacked `dist/` whenever the UI or disclosure text changes.

Do not paste the Admin Console into a screenshot: those frames belong in the
OAuth demo video, and a store screenshot showing another product's UI tends to
attract review questions.

---

## 6. Distribution

| Field | Suggested value | Why |
|---|---|---|
| Visibility | **Unlisted** for the first release | The tool changes an enterprise's Chrome policies. Unlisted keeps it reachable by link for pilot administrators while the OAuth verification settles, without appearing in search. Switch to Public once verified. |
| Regions | All | No region-specific behaviour. |
| Pricing | Free | |

---

## 7. Review notes (the free-text box)

    This extension is an independent open-source project. It is not an official
    Google product and is not affiliated with or endorsed by Google. The
    listing states this in the first section of the description, and the name
    does not imply otherwise.

    It is an administrator tool. It has no backend: it calls Google's public
    REST APIs directly. Workspace, Chrome, and Cloud Identity calls use the
    installing administrator's OAuth authority. The explicitly confirmed first
    bootstrap uses that administrator authority to create and pin the deployer,
    custom role, and minimum IAM bindings. Subsequent Google Cloud project
    mutations use short-lived tokens for the dedicated product-scoped deployer
    service account and never fall back to administrator authority. All writes
    target only that administrator's own deployment project, an explicitly
    selected upstream VPC project for which its administrator manually granted
    the exact documented role, and the administrator's Workspace tenant. The
    bootstrap itself never creates that cross-project role or grant.

    It requests no content scripts, no tabs, no webRequest and no cookies
    access, and never reads or modifies a web page. Its CSP is
    default-src 'none'; script-src 'self', and it executes no remote code.

    Full source: https://github.com/dymzd/Google/tree/main/secure-gateway-studio
    The uploaded ZIP is byte-reproducible from that source. Build with:
      cd secure-gateway-studio/extension && npm ci && npm run package
    The printed SHA-256 matches the uploaded artefact.

    Reviewing without a Workspace tenant: the extension first presents its
    user-data disclosure and affirmative-consent action. Before acceptance the
    service worker reads only non-sensitive consent metadata and does not start
    migration or resume. After acceptance it renders the non-tenant portions of each screen without credentials;
    API-backed actions report an authentication error rather than failing
    silently. A demo tenant can be provided on request.
