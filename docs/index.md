---
title: Secure Gateway Studio
description: >-
  Secure Gateway Studio is a Chrome extension for Google Workspace
  administrators. It plans, applies, and verifies Chrome Enterprise Premium and
  BeyondCorp Security Gateway configurations in your own Google Cloud project
  and Workspace tenant.
---

**Secure Gateway Studio is a Chrome extension for Google Workspace
administrators.** It plans, applies, and verifies Chrome Enterprise Premium and
BeyondCorp Security Gateway configurations in **your own** Google Cloud project
and Google Workspace tenant, and records a verifiable record of every change it
makes.

It is the application that appears as *Secure Gateway Studio* on the Google
OAuth consent screen and in the Chrome Web Store.

## What it is for

A Workspace administrator evaluating Chrome Enterprise Premium has to configure
several Google services in a specific order, confirm the result, and be able to
undo it. Doing that by hand across the Admin Console and the Cloud Console is
slow and easy to get wrong. This extension does it as one reviewed operation:

1. **Plan.** It reads the current state of your tenant and project and shows
   exactly what it would change, before anything is written.
2. **Approve.** Nothing is applied until you approve that specific plan.
3. **Apply.** It writes the configuration through Google's public APIs, using
   your own administrator credentials.
4. **Verify.** It checks the result and records a SHA-256 audit chain of what
   was planned, approved, applied, and confirmed.
5. **Roll back.** It returns every policy it set to the parent organizational
   unit and deletes only the resources it created.

## What it configures

- **Chrome Enterprise Premium evaluation.** Threat-protection policies, forced
  Endpoint Verification, content-inspection connectors, a Context-Aware Access
  level, data-boundary policies, and starter DLP rules, applied to one pilot
  organizational unit.
- **BeyondCorp Secure Gateway deployments.** Private HTTPS application access
  for managed Chrome, in one of three architectures: direct private HTTPS, an
  Nginx HTTPS-to-HTTP offload tier, or a regional internal Application Load
  Balancer.
- **Least-privilege roles.** A dedicated deployer service account and two custom
  IAM roles, so the evaluation does not run on anyone's administrator authority.

## Not an official Google product

This is an independent open-source project. It is **not built, endorsed, or
supported by Google**, and it is not affiliated with Google LLC. "Google",
"Google Workspace", "Google Cloud", "Chrome", and "Chrome Enterprise Premium"
are trademarks of Google LLC.

It is provided as is, with no warranty and no support commitment. It changes
Chrome policy and cloud infrastructure in your own tenant, so evaluate it in a
non-production organizational unit first and review every plan before approving
it.

## Privacy

The extension has no backend. It calls Google's APIs directly with the
signed-in administrator's own token, and sends nothing to the developer or to
any third party. Configuration and audit records stay in your browser profile
and in your own Google tenant.

Full detail: [privacy policy](privacy.html).

## Source and verification

Source code: [github.com/dymzd/Google](https://github.com/dymzd/Google), under
`secure-gateway-studio/`.

The packaged extension is byte-reproducible from that source, so you can
confirm the artefact you install matches the code published here:

```bash
cd secure-gateway-studio/extension && npm ci && npm run package
```

The printed SHA-256 matches the published artefact for the same version.

## Support

For questions about Chrome Enterprise Premium, Secure Gateway, or licensing,
contact your Google account team — your Field Sales Representative or Customer
Success Manager. Google supports its own products; this is not one of them.

For problems with this tool, open an
[issue](https://github.com/dymzd/Google/issues). Best effort, with no response
time commitment.
