# Chrome Web Store submission

Copy-paste material for the Developer Dashboard, plus the OAuth verification
that runs separately in Google Cloud Console. Every justification here states
what the extension actually does; a reviewer who reads the source should find
nothing claimed that the code does not do.

Verified against `manifest.json` at version 0.2.0.

---

## 1. Before uploading

The store listing is not the blocker. These are.

- [ ] **Register the three added OAuth scopes on client `414812060045-…`** in
      Google Cloud Console, under APIs & Services then Credentials. Publishing
      the extension does not enable them. Without this, `getAuthToken` fails at
      the consent screen and every user is locked out.
      - `https://www.googleapis.com/auth/admin.directory.orgunit` (replaces the
        `.readonly` variant)
      - `https://www.googleapis.com/auth/admin.directory.customer.readonly`
      - `https://www.googleapis.com/auth/cloud-identity.policies`
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

    Plan, apply, and verify Chrome Enterprise Premium and Secure Gateway deployments in your own Google Cloud project.

### Category

    Developer Tools

### Language

    English (a complete Japanese UI is included)

### Detailed description (max 16,000)

    Secure Gateway Studio is an administrator tool for planning, applying, and
    verifying Chrome Enterprise Premium deployments against your own Google
    Cloud project and Google Workspace tenant.

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
    the developer, and no data sent anywhere except to Google's own APIs using
    your own administrator credentials.

    WHAT IT DOES

    - Secure Gateway deployments. Designs and applies BeyondCorp Private
      Security Gateway architectures for private HTTPS applications: direct
      private HTTPS, Nginx HTTPS-to-HTTP offload, or a regional internal
      Application Load Balancer. Every deployment is planned first, approved
      explicitly, and applied as a single reviewed unit.

    - Chrome Enterprise Premium evaluation. Applies a CEP baseline to one
      organizational unit: threat-protection policies, forced Endpoint
      Verification, content-inspection connectors, a Context-Aware Access
      level, data-boundary policies, and starter DLP rules. Each policy is
      checked against your tenant's live Chrome Policy schema before it is
      written, so a policy your tenant does not support is reported as skipped
      with the reason rather than failing silently.

    - Rollback. Returns every policy it applied to the parent organizational
      unit, and deletes only the resources it created. Anything you selected
      rather than created is left alone.

    - Evidence. A SHA-256 audit chain of what was planned, approved, applied,
      and verified, exportable as JSON.

    - Least privilege by construction. Mutations to Google Cloud run as a
      dedicated deployer service account the tool creates, not as your own
      administrator authority.

    HOW IT WORKS

    Everything runs locally in the extension. The service worker calls Google's
    public REST APIs directly with a token obtained through chrome.identity
    from the administrator who is signed in. Plans, approvals, run checkpoints,
    and the audit chain are stored in the browser profile's IndexedDB and never
    leave it.

    REQUIREMENTS

    - Chrome 142 or newer
    - A Google Workspace administrator account with Chrome management rights
    - A billing-enabled Google Cloud project
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
    Google Cloud project and Google Workspace tenant, and records verifiable
    evidence of what it changed.

### Permission justifications

Paste each verbatim into the matching box.

**identity**

    Obtains an OAuth token for the signed-in Google Workspace administrator so
    the extension can call Google's management APIs as that administrator.
    This is the only authentication path; without it the extension cannot
    function.

**identity.email**

    Reads the signed-in administrator's email address to record who approved
    and applied a deployment in the audit chain, and to grant that
    administrator Token Creator on the deployer service account during
    bootstrap.

**storage**

    Stores the deployer service account reference and the deployment
    specification for an approved run, so an apply that outlives a service
    worker restart can resume. No credentials are written to storage.

**alarms**

    Google's long-running operations outlast a Manifest V3 service worker. An
    alarm wakes the worker to continue polling an apply that is already in
    progress, so a partially applied deployment is never left unreconciled.

**downloads**

    Saves two files the administrator explicitly requests: the public root
    certificate of a locally generated proof-of-concept CA, for upload to
    Chrome Root Store, and a JSON evidence export. Both are generated inside
    the extension and passed as data: URLs. Nothing is downloaded from a
    remote server.

### Host permission justification

    Every host is a documented public Google API endpoint that the extension
    calls directly to read or change configuration in the administrator's own
    project and Workspace tenant. There is no wildcard host permission and no
    non-Google host. The extension never reads or modifies any web page: it
    requests no content scripts, no tabs, no webRequest, and no cookies access.

      iamcredentials.googleapis.com        impersonate the least-privilege deployer service account
      cloudresourcemanager.googleapis.com  project and organization lookup, IAM policy read and write
      serviceusage.googleapis.com          enable only the APIs the selected path needs
      iam.googleapis.com                   create the deployer service account and the custom roles
      beyondcorp.googleapis.com            security gateway, application matchers, upstream bindings
      accesscontextmanager.googleapis.com  read and create Context-Aware Access levels
      chromepolicy.googleapis.com          read policy schemas and apply Chrome policies to the target OU
      chromemanagement.googleapis.com      managed browser and profile signals used by preflight
      admin.googleapis.com                 organizational unit and group pickers; create the CEP sub OUs
      cloudidentity.googleapis.com         create and delete the Chrome DLP rules and detectors
      licensing.googleapis.com             confirm Chrome Enterprise Premium licence availability
      compute.googleapis.com               network, subnet, firewall, load balancer, instance group
      dns.googleapis.com                   private DNS record for the deployed application
      secretmanager.googleapis.com         TLS bundle storage and alias promotion
      privateca.googleapis.com             certificate issuance from a CSR generated in the extension
      cloudbilling.googleapis.com          confirm the project is billing-enabled before planning
      logging.googleapis.com               sanitized post-deployment log views
      oauth2.googleapis.com                resolve the signed-in administrator's identity
      www.googleapis.com                   Google API discovery and shared endpoints

### Remote code

Answer: **No, I am not using remote code.**

    The extension executes no remotely hosted code. Its content security policy
    is "default-src 'none'; script-src 'self'", which Chrome enforces, and the
    build is a plain esbuild bundle of the published source with no CDN, no
    eval, and no dynamically fetched script.

### Data usage

Declare **no data collected**. Supporting statement for the review notes:

    The extension collects no user data. It transmits nothing to the developer
    or to any third party. All network traffic goes to Google's own APIs,
    authorized by the administrator's own OAuth token, and every response is
    used only to render the current screen or to write the local audit record.

    Configuration, plans, approvals, run state, and the audit chain are stored
    in the browser profile's IndexedDB and in chrome.storage.local. They stay
    on the device. Access tokens are held in memory only and are never written
    to storage, logs, audit events, or the evidence export; a redaction pass
    strips anything token-shaped before serialization.

Certifications to tick:

- [x] I do not sell or transfer user data to third parties, outside of the approved use cases
- [x] I do not use or transfer user data for purposes that are unrelated to my item's single purpose
- [x] I do not use or transfer user data to determine creditworthiness or for lending purposes

---

## 4. OAuth verification (Google Cloud Console, separate from the store)

Scope-by-scope justification. The three marked **new in 0.2.0** are what makes
this a re-verification rather than a formality.

| Scope | Sensitivity | Justification |
|---|---|---|
| `userinfo.email` | basic | Identifies the administrator in the audit chain and for the Token Creator binding. |
| `admin.directory.group.readonly` | sensitive | Populates the group picker used to choose who may reach a deployed application. Read only. |
| `admin.directory.orgunit` **new in 0.2.0** | sensitive | Creates the `CEP Users` and `CEP Browsers` sub organizational units beneath the pilot OU the administrator selects, so user-scoped and browser-scoped policies are separated. Replaces the previous `.readonly` variant, which cannot create them. Creation is opt-in through a checkbox and reuses an existing OU of the same name. |
| `admin.directory.customer.readonly` **new in 0.2.0** | sensitive | Reads the tenant's primary domain, which the data-boundary policies are written from. A policy built from anything else silently fails to match. Read only. |
| `cloud-identity.policies` **new in 0.2.0** | sensitive | Creates, lists, and deletes the Chrome DLP rules and detectors the evaluation is made of, and is what lets rollback remove them again. Scoped to the customer the administrator already administers. |
| `cloud-platform` | sensitive | Creates and reconciles infrastructure across Compute Engine, IAM, Cloud DNS, Secret Manager, CA Service, BeyondCorp, and Access Context Manager. Google publishes no narrower scope spanning them. Mitigated by executing every mutation as an impersonated least-privilege deployer service account holding a project custom role, rather than as the administrator. |
| `chrome.management.policy` | sensitive | Reads Chrome policy schemas and applies policies to the target organizational unit. This is the core of the product. |
| `chrome.management.profiles.readonly` | sensitive | Preflight signals: managed profile counts and last policy sync, shown before a plan is approved. Read only. |
| `apps.licensing` | sensitive | Confirms Chrome Enterprise Premium licence availability before planning a deployment that requires it. |

### Scope justification

The console caps this box at **1000 characters**, so this is the version
that fits. Paste it as-is; the per-scope table above stays as the working
reference, not as submission text.

#### Single box (1000 characters, the cap is 1000)

    Secure Gateway Studio configures Chrome Enterprise Premium and BeyondCorp Security Gateway in the administrator's own Workspace tenant and Cloud project. No backend; nothing reaches the developer.

    Use: directory scopes fill the OU and group pickers, read the primary domain that domain-based policies are built from, and create the "CEP Users"/"CEP Browsers" sub-OUs those policies target. chrome.management.policy reads live schemas and applies policies to the chosen OU. cloud-identity.policies creates, lists and deletes the Chrome DLP rules, which also lets rollback remove them. cloud-platform builds the supporting infrastructure.

    Narrower scopes: read-only variants are used wherever we only read. orgunit.readonly cannot create the sub-OUs; policies.readonly cannot create or delete rules; chrome.management.policy has no writable narrower form. Nothing narrower than cloud-platform spans the services used, so Cloud mutations instead run as an impersonated least-privilege service account.

#### If the form asks per scope

Some consent-screen flows ask once per scope instead. Each of these is
independently under the limit.

**`admin.directory.orgunit`** (599 characters)

    Creates the two organizational units "CEP Users" and "CEP Browsers" beneath the pilot OU the administrator picks, so user-scoped and browser-scoped Chrome policies land in separate units. Also reads the OU tree to populate the picker. Creation is opt-in via a checkbox and reuses an existing OU of the same name.

    This extension requested admin.directory.orgunit.readonly until this version. That is no longer sufficient, because creating an OU is a write. Google publishes no scope that permits creating an organizational unit without other directory writes, and we make none of those other writes.

**`admin.directory.customer.readonly`** (392 characters)

    Reads the tenant's primary domain. The data-boundary policies this tool writes are domain patterns (for example restricting secondary sign-in to *@example.com), and a policy built from anything other than the real primary domain silently matches nothing.

    This is already the read-only variant. We deliberately do not request admin.directory.customer, which would permit writes we never make.

**`cloud-identity.policies`** (419 characters)

    Creates, lists and deletes the Chrome DLP rules and detectors that make up a Chrome Enterprise Premium evaluation. Listing is what makes the tool idempotent instead of duplicating rules on a second run; delete is what lets its rollback remove everything it created.

    cloud-identity.policies.readonly is not sufficient: it permits neither the create nor the delete. Google publishes no scope limited to DLP policy types.

**`cloud-platform`** (733 characters)

    Creates and reconciles the infrastructure a Secure Gateway deployment needs, across Compute Engine, IAM, Cloud DNS, Secret Manager, Certificate Authority Service, BeyondCorp, Access Context Manager and Service Usage.

    No narrower scope exists: Google publishes none covering a subset of those services. Rather than accept that breadth, the extension cuts it below the OAuth layer. It creates a dedicated deployer service account holding a project-scoped custom role, and every Cloud mutation executes as that account through short-lived impersonated tokens, never with the administrator's own authority. The admin token is used only to mint those tokens and to call the Workspace APIs, which do not accept service-account identities.

**`chrome.management.policy`** (467 characters)

    Reads the tenant's live Chrome policy schemas and applies policies to the organizational unit the administrator selects. This is the core function of the product.

    Reading the schema first is deliberate: a policy written into a field the tenant does not advertise does nothing, silently, so the tool refuses and reports it rather than appearing to succeed.

    There is no read-only variant that still permits applying a policy, and applying policy is the whole purpose.

**`chrome.management.profiles.readonly`** (215 characters)

    Reads managed profile counts and the last policy sync time, shown to the administrator during preflight so a plan can be reviewed against the tenant's real state before it is approved. Already the read-only variant.

**`admin.directory.group.readonly`** (143 characters)

    Populates the group picker used to choose who may reach a deployed application. Already the read-only variant; the tool never modifies a group.

**`apps.licensing`** (210 characters)

    Confirms Chrome Enterprise Premium licence availability before planning a deployment that requires it, so the administrator is told up front rather than at apply time. No read-only variant of this scope exists.

### Demo video

Verification requires a recording that shows each sensitive scope in use.
Cover, in order:

1. Sign in as a Workspace administrator, showing the consent screen with the
   scopes listed.
2. The setup screen reading the OU and group pickers
   (`admin.directory.*.readonly`).
3. The CEP PoC Deployer tab: select a pilot OU, enable sub-OU creation, apply.
   Show the created `CEP Users` and `CEP Browsers` OUs in Admin Console
   (`admin.directory.orgunit`).
4. The applied Chrome policies in Admin Console (`chrome.management.policy`).
5. The created DLP rules in Admin Console, under Data protection
   (`cloud-identity.policies`).
6. Rollback returning the OU to inherited and removing the rules.

### URLs

| Field | Value |
|---|---|
| Application homepage | `https://dymzd.github.io/Google/` |
| Privacy policy | `https://dymzd.github.io/Google/privacy.html` |
| Terms of service | optional; the MIT licence covers use |

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

The way through is GitHub Pages: `dymzd.github.io` is a domain whose content
you control, so Search Console can verify it, and `github.io` is on the Public
Suffix List, which makes `dymzd.github.io` a registrable domain in its own
right rather than a subdomain of somebody else's.

If the console refuses `dymzd.github.io` in the Authorized domains field, the
fallback is a domain you own outright, pointed at the same Pages site. Nothing
else about this page changes.

### Enabling the pages

`docs/index.md` and `docs/privacy.md` are already in the repository. To publish
them:

1. Repository **Settings → Pages**.
2. Source: **Deploy from a branch**, branch `main`, folder **`/docs`**.
3. Wait for the build, then confirm both load in a private window with no
   sign-in:
   - `https://dymzd.github.io/Google/`
   - `https://dymzd.github.io/Google/privacy.html`

### Verifying the domain

1. Open Search Console and add a **URL prefix** property for
   `https://dymzd.github.io/Google/`.
2. Choose the **HTML file** method, commit the verification file it gives you
   to `docs/`, wait for Pages to redeploy, then click Verify. The HTML tag
   method also works if you would rather add it to `docs/index.md` front matter.
3. Once verified, the same Google account can enter the domain under Authorized
   domains.

Verify with the **same Google account that owns the Cloud project**. A property
verified by another account does not count.

### Field by field

| Field | Value |
|---|---|
| App name | `Secure Gateway Studio` |
| User support email | a monitored address — see the warning below |
| App logo | `extension/icons/oauth-logo-120.png` (120x120, PNG, 7.8 KB) |
| Application home page | `https://dymzd.github.io/Google/` |
| Application privacy policy link | `https://dymzd.github.io/Google/privacy.html` |
| Application terms of service link | leave empty; the MIT licence covers use |
| Authorized domains | `dymzd.github.io` |
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

These could not be captured automatically here, so capture them by hand:

    cd secure-gateway-studio/frontend && npm run dev

Open the printed URL, set the browser window so the page renders at 1280x800,
and capture:

| # | Screen | How to reach it | Shows |
|---|---|---|---|
| 1 | CEP PoC Deployer | Left nav, bottom item | The feature this release is about: OU picker, presets, policy modules |
| 2 | DLP rules and actions | Same page, scroll to "Rules and what each one does" | Per-rule audit / warn / block, and the country selector |
| 3 | Execution trace | Same page, after an apply | Applied and skipped lists with reasons, which is the honesty story |
| 4 | New setup wizard | Left nav, "New setup" | The Secure Gateway half of the product |
| 5 | Evidence | Left nav, "Evidence" | The audit chain and export |

Screens 1, 2 and 4 render without any credentials. Screen 3 needs a run, so
capture it during the demo-video session against the pilot tenant. Screen 5
needs at least one recorded run.

Optional but recommended:

- **Small promo tile, 440x280 PNG.** Listings without one look unfinished in
  search results. The 128x128 icon on the product's navy background is enough.

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
    REST APIs directly, authorized by the OAuth token of the Google Workspace
    administrator who installs it, and writes only to that administrator's own
    Google Cloud project and Workspace tenant.

    It requests no content scripts, no tabs, no webRequest and no cookies
    access, and never reads or modifies a web page. Its CSP is
    default-src 'none'; script-src 'self', and it executes no remote code.

    Full source: https://github.com/dymzd/Google/tree/main/secure-gateway-studio
    The uploaded ZIP is byte-reproducible from that source. Build with:
      cd secure-gateway-studio/extension && npm ci && npm run package
    The printed SHA-256 matches the uploaded artefact.

    Reviewing without a Workspace tenant: the extension loads and renders every
    screen without credentials; API-backed actions report an authentication
    error rather than failing silently. A demo tenant can be provided on
    request.
