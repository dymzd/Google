---
title: Privacy Policy
description: >-
  Privacy policy for the Chrome Enterprise Premium PoC Deployer Chrome extension.
  The extension collects no user data and sends nothing to its developer.
---

# Privacy Policy — Chrome Enterprise Premium PoC Deployer

**Last updated: 19 August 2026**
**Applies to: the Chrome Enterprise Premium PoC Deployer Chrome extension (including Secure Gateway Studio), version 0.2.0 and later**

## Summary

Chrome Enterprise Premium PoC Deployer collects no personal data, transmits nothing to its
developer, and has no server. It is an administrator tool that talks directly
to Google's APIs using the credentials of the administrator who is signed in,
and stores its working state in the browser profile on the device.

## Not an official Google product

Chrome Enterprise Premium PoC Deployer is an independent open-source project. It is **not built,
endorsed, or supported by Google**, and it is not affiliated with Google LLC.
"Google", "Google Workspace", "Google Cloud", "Chrome", and "Chrome Enterprise
Premium" are trademarks of Google LLC.

It is provided as is, with no warranty and no support commitment. You are
responsible for what it changes in your tenant.

## Who operates this extension

Chrome Enterprise Premium PoC Deployer is published as open source at
<https://github.com/dymzd/Google>. There is no hosted service behind it and no
account to create. The developer operates no infrastructure that the extension
contacts.

## What the extension accesses

To do its job, the extension reads and writes configuration in **your own**
Google Cloud project and Google Workspace tenant, using an OAuth token obtained
through `chrome.identity` from the administrator who is signed in to Chrome.

It accesses:

- **Your Google Workspace directory** — organizational units, groups, and the
  tenant's primary domain, to let you choose where policies apply and to build
  domain-based policies correctly.
- **Your Chrome policy configuration** — policy schemas and the policies set on
  the organizational unit you select.
- **Your Chrome DLP rules and detectors** — created, listed, and deleted through
  the Cloud Identity policy API.
- **Your Google Cloud project** — networking, IAM, DNS, certificates, logging,
  and BeyondCorp resources, as required by the deployment you plan and approve.
- **Your administrator email address** — recorded in the local audit trail so
  the evidence export shows who approved and applied each change.

The extension does not read, modify, or observe any web page. It requests no
content scripts, no `tabs`, no `webRequest`, and no cookie access.

## What leaves your device

Only requests to Google's own public API endpoints, listed in full in
[`docs/PERMISSIONS.md`](https://github.com/dymzd/Google/blob/main/secure-gateway-studio/extension/docs/PERMISSIONS.md), each authorized by your own OAuth
token.

**Nothing is sent to the developer or to any third party.** There is no
analytics, telemetry, crash reporting, advertising, or usage measurement of any
kind. The extension's content security policy restricts network access to
`https://*.googleapis.com`, and Chrome enforces it.

## What is stored, and where

All of it stays in your Chrome profile on your device:

| Data | Storage | Why |
|---|---|---|
| Deployment drafts, plans, approvals | IndexedDB | So a configuration survives closing the tab |
| Run checkpoints and operation records | IndexedDB | So an apply interrupted by a service-worker restart can resume |
| SHA-256 audit chain of what changed | IndexedDB | Evidence of what was planned, approved, and applied |
| Deployer service account reference | `chrome.storage.local` | So later operations know which account to impersonate |

**Access tokens are held in memory only.** They are never written to storage,
never logged, and never placed in an audit event or an evidence export. A
redaction pass strips anything token-shaped before any object is serialized.

## Retention and deletion

The developer retains nothing, because the developer receives nothing.

Local data lives as long as the extension is installed in that Chrome profile.
To delete all of it, remove the extension; Chrome discards the profile's
IndexedDB and `chrome.storage.local` for it. Deleting the Chrome profile has the
same effect.

Data the extension wrote into your Google Cloud project or Workspace tenant is
yours and is unaffected by uninstalling. The extension's rollback and teardown
features remove what it created, and the Google Admin Console and Cloud Console
remain the authority over it.

## Your data rights

Because no personal data reaches the developer, there is nothing held about you
to access, correct, export, or erase. The configuration and audit records the
extension creates are under your control in your own Google tenant and on your
own device, and are exportable as JSON at any time from the Evidence screen.

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

**About data this extension holds on you** — there is none. The developer
receives nothing, so there is no data subject request to make. Everything the
extension stores is on your device and in your own Google tenant, both under
your control.
