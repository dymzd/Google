---
layout: default
title: Privacy Policy
description: >-
  Privacy policy for the Secure Gateway Studio Chrome extension.
  The extension handles administrator and tenant data locally and through Google
  APIs, but sends no tenant data to its developer.
---

# Privacy Policy — Secure Gateway Studio

**Last updated: 24 August 2026**

**Applies to: the Secure Gateway Studio Chrome extension, version 0.2.1 and later**

## Summary

Secure Gateway Studio handles administrator identity, including the verified
email address and immutable OpenID Connect account identifier,
authentication information, Workspace tenant configuration, Google Cloud
resource metadata, and selected diagnostic activity. It talks directly to
Google APIs using administrator OAuth authority for Workspace, Chrome, Cloud
Identity, read-only preflight, and an explicitly confirmed initial deployer
bootstrap. That bootstrap creates and pins the service account, its custom
role, and the minimum IAM bindings needed to impersonate it. After bootstrap,
Google Cloud project mutations use a short-lived token for that dedicated
scoped deployer service account and never fall back to administrator authority.
Working state is stored
in the Chrome profile on the device. The developer receives no
tenant data and operates no server, analytics, advertising, or telemetry
service for the extension.

On first use, the extension shows a prominent summary of these practices and
requires an affirmative action before it requests Google authorization or
accesses tenant data.

## Not an official Google product

Secure Gateway Studio is an independent open-source project. It is **not built,
endorsed, or supported by Google**, and it is not affiliated with Google LLC.
"Google", "Google Workspace", "Google Cloud", "Chrome", and "Chrome Enterprise
Premium" are trademarks of Google LLC.

It is provided as is, with no warranty and no support commitment. You are
responsible for what it changes in your tenant.

## Who operates this extension

Secure Gateway Studio is published as open source at
<https://github.com/dymzd/Google>. There is no hosted service behind it and no
account to create. The developer operates no infrastructure that the extension
contacts.

## What the extension accesses

To do its job, the extension reads and writes configuration in **your own**
Google Cloud deployment project, an optional explicitly selected upstream VPC
project, and Google Workspace tenant. It starts with an OAuth token obtained
through `chrome.identity` from the administrator who is signed in to Chrome;
post-bootstrap Cloud mutations use the pinned deployer described above.

It handles:

- **Your Google Workspace directory** — organizational units, groups, and the
  tenant's primary domain, plus the users in the explicitly selected pilot OU
  when you choose per-user licence assignment.
- **Your Chrome policy configuration** — policy schemas and the policies set on
  the organizational unit you select.
- **Your Chrome DLP rules** — supported rules are listed and created through the
  Cloud Identity policy API using built-in detector references. CEP cleanup
  reports and retains them for manual ownership review; it does not delete them.
- **Your Google Cloud projects** — networking, IAM, DNS, certificates, logging,
  and BeyondCorp resources in the deployment project, plus VPC discovery/use
  and the managed `upstreamAccess` IAM binding in an optional upstream project,
  as required by the deployment you plan and approve. Bootstrap changes only
  the deployment project. A cross-project upstream requires its administrator
  to grant the documented exact custom role manually before validation.
- **Your administrator identity** — the verified email address is recorded in
  the local audit trail so the evidence export shows who approved and applied
  each change. The immutable Google OpenID Connect account identifier (`sub`)
  is stored locally with the deployer identity binding so that approvals,
  resumes, teardown, and other privileged actions cannot be inherited by a
  different signed-in Google account, even if an email address is later reused.
- **Administrator and gateway activity metadata** — approval/apply events and
  sanitized Cloud Logging diagnostics that you explicitly open or export. A
  diagnostic record is limited to timestamps, severity, Google service/method,
  status, monitored-resource fields, and request identifiers. The extension's
  partial-response request excludes URL paths and query strings, free-form log
  payloads, caller IP addresses, and principal identifiers.
- **Secure Gateway connection logging** — when you approve creation of a
  Security Gateway, the extension enables full Secure Gateway connection
  records in Cloud Logging in the selected Google Cloud project by sending the
  documented empty `logging` enablement marker. The records' contents,
  retention, and access are governed by the customer's Google Cloud
  configuration. The developer receives none of these records. When you open
  the log view, the extension first verifies the marker and then requests only
  its strict sanitized diagnostic field mask; it excludes URL paths, query
  strings, IP addresses, principals, and free-form payloads.
- **Authentication information** — short-lived Google OAuth and impersonated
  access tokens used to call the APIs. These tokens are never persisted.
- **An existing public-certificate secret, when you select one** — the exact
  numeric Secret Manager version containing its certificate and TLS private
  key. The extension reads that version only to validate the certificate/key
  match, requested DNS names, expiry, and digest before configuring the
  approved endpoint. The existing private key is held in memory only during
  that validation; it is never persisted, logged, saved as a file, passed to
  `chrome.downloads`, retransmitted, included in evidence, or made available
  to the developer. The approved VM
  later reads the pinned version directly from the same Secret Manager.

The extension does not read, modify, or observe any web page. It requests no
content scripts, no `tabs`, no `webRequest`, and no cookie access.

## What leaves your device

The extension sends requests only to Google's public API endpoints, listed in
full in
[`docs/PERMISSIONS.md`](https://github.com/dymzd/Google/blob/main/secure-gateway-studio/extension/docs/PERMISSIONS.md), authorized either by your administrator OAuth authority or by the
short-lived scoped deployer token described above. Google receives the identifiers, configuration, and request bodies
needed to read or change resources in your own Workspace tenant and explicitly
selected Cloud projects. A generated TLS bundle is sent only to the Secret
Manager resource you selected in the deployment project. If you select an existing public-certificate secret,
its pinned numeric SecretVersion arrives over HTTPS from your own Secret
Manager for in-memory validation. Its TLS private key is not sent onwards by
the extension; the approved VM later reads that same pinned version directly
from Secret Manager.

**Nothing is sent to the developer or to a developer-operated third party.**
There is no analytics, telemetry, crash reporting, advertising, profiling, or
usage measurement of any kind. The extension's content security policy
restricts API network access to `https://*.googleapis.com`, and Chrome enforces
it.

## Limited Use

Use of information received from Google APIs adheres to the Chrome Web Store
User Data Policy, including the Limited Use requirements. The extension uses
data only to provide its disclosed administrator-facing deployment,
verification, evidence, and cleanup features. It does not sell data, use or
transfer data for advertising, determine creditworthiness or lending, permit
human review by the developer, or use data for an unrelated purpose.

## What is stored, and where

The extension's durable local working state stays in your Chrome profile on
your device:

| Data | Storage | Why |
|---|---|---|
| Deployment drafts, plans, approvals | AES-256-GCM encrypted IndexedDB | So a configuration survives closing the tab without remaining cleartext at rest |
| Run checkpoints, rollback before-images, and operation records | AES-256-GCM encrypted IndexedDB | So an apply interrupted by a service-worker restart can resume |
| SHA-256 audit chain and acceptance evidence | AES-256-GCM encrypted IndexedDB | Evidence of what was planned, approved, applied, and verified |
| Administrator email and immutable Google account identifier; deployer reference and ownership pins | AES-256-GCM encrypted IndexedDB | Bind approvals and privileged actions to the same signed-in administrator and deployer across restarts |
| Public certificate material and operation intent | AES-256-GCM encrypted IndexedDB | Restart-safe certificate handoff and recovery without storing a private key |
| Generated TLS private key during an active run | `chrome.storage.session` | Session-only handoff to your Secret Manager; cleared when the run terminates |
| Existing selected-secret TLS private key | Memory only during discovery and Apply validation | Validate the pinned numeric SecretVersion without persisting, logging, saving as a file, passing to `chrome.downloads`, retransmitting, or exporting the private key |
| UI language (`en` or `ja`) | Unencrypted page `localStorage` | Remember only the display language; this value contains no tenant, authentication, configuration, or audit data |

The extension requests `unlimitedStorage` solely to exempt this encrypted
IndexedDB safety ledger from automatic quota eviction. Losing a plan,
checkpoint, before-image, or ownership record while Google resources still
exist would make safe resume, rollback, and teardown impossible. The permission
is not used to retain unrelated data, collect browsing data, or transmit
additional data off-device.

**Access tokens are held in memory only.** They are never written to storage,
never logged, and never placed in an audit event or an evidence export. A
redaction pass strips token-shaped values before serialization. Durable values
are encrypted with AES-GCM using a randomly generated, non-extractable
`CryptoKey` persisted by IndexedDB structured clone. Ciphertext is bound to its
schema, store, and hashed record key as authenticated data; a missing key,
wrong key, or modified ciphertext fails closed. This protects data at rest but
does not replace Chrome-profile and operating-system access control, because
the installed extension can decrypt its own state while you use it.

On an upgrade from 0.2.0, the extension does not read old IndexedDB,
`chrome.storage.local`, setup, or workflow values until you affirm the 0.2.1
in-product disclosure. It then encrypts them, clears the legacy unencrypted
setup and workflow records, and only afterwards enables startup/resume
processing. The non-sensitive UI language remains. Audit event hashes and their
semantic payloads are not rewritten by that encryption step.

## Retention and deletion

The developer retains nothing, because the developer receives nothing.

Local data lives as long as the extension is installed in that Chrome profile.
To delete all of it, remove the extension; Chrome discards the profile's
IndexedDB, including its non-extractable encryption key. Deleting the Chrome
profile has the same effect.

Data the extension wrote into your Google Cloud projects or Workspace tenant is
yours and is unaffected by uninstalling. Secure Gateway teardown restores or
deletes only resources whose durable ownership and managed-after state still
match; drift and shared resources are retained. CEP cleanup is read-only and
reports Chrome Policy, OU, access-level, and DLP candidates for manual review.
The Google Admin Console and Cloud Console remain the authority over all tenant
and project data.

## Your data rights

Because no tenant or personal data reaches the developer, the developer has no
copy to access, correct, export, or erase. The configuration and audit records
the extension creates are under your control in your own Google tenant and on
your own device, and are exportable as JSON from the Evidence screen.

## Children

This is an enterprise administration tool. It is not directed at children and
is not intended for use by anyone under 18.

## Changes to this policy

Material changes will be published in this file with a new date, in the same
repository, before a version depending on them is released. The revision history
is public in the repository's Git history.

## Verifying these claims

Every statement here is checkable against the published source. The packaged
extension is byte-reproducible from it:

```bash
cd secure-gateway-studio/extension && npm ci && npm run package
```

The printed SHA-256 matches the artefact on the Web Store for the same version.
See [`docs/VERIFYING_THE_BUILD.md`](https://github.com/dymzd/Google/blob/main/secure-gateway-studio/extension/docs/VERIFYING_THE_BUILD.md).

## Contact

**About this extension** — open an issue at
<https://github.com/dymzd/Google/issues>. This is a best-effort channel with no
response time commitment, and it is the only channel for the extension.

**About Chrome Enterprise Premium, Secure Gateway, licensing, or anything else
that is a Google product** — contact your Google account team, meaning your
Field Sales Representative or Customer Success Manager. Google supports its own
products; it does not support this extension, and questions about the extension
sent to Google will not reach the developer.

**About data this extension handles** — the developer receives none of it, so
the developer has no tenant-data copy on which to perform a data subject
request. Everything handled persistently is on your device or in your own
Google tenant/projects, all under your control.
