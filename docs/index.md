---
title: Secure Gateway Studio
---

# Secure Gateway Studio

An administrator tool for planning, applying, and verifying Chrome Enterprise
Premium and BeyondCorp Security Gateway deployments against **your own** Google
Cloud project and Google Workspace tenant.

## Not an official Google product

This is an independent open-source project. It is **not built, endorsed, or
supported by Google**, and it is not affiliated with Google LLC. "Google",
"Google Workspace", "Google Cloud", "Chrome", and "Chrome Enterprise Premium"
are trademarks of Google LLC.

It is provided as is, with no warranty and no support commitment. It changes
Chrome policy and cloud infrastructure in your own tenant, so evaluate it in a
non-production organizational unit first and review every plan before approving
it.

## What it does

- **Secure Gateway deployments.** Plans and applies BeyondCorp Private Security
  Gateway architectures for private HTTPS applications, with an explicit
  approval step between the plan and the change.
- **Chrome Enterprise Premium evaluation.** Applies a CEP baseline to one
  organizational unit: threat-protection policies, forced Endpoint
  Verification, content-inspection connectors, a Context-Aware Access level,
  data-boundary policies, and starter DLP rules.
- **Rollback.** Returns every policy it applied to the parent organizational
  unit, and deletes only what it created.
- **Evidence.** A SHA-256 audit chain of what was planned, approved, applied,
  and verified, exportable as JSON.

## Privacy

The extension has no backend. It calls Google's APIs directly with the
signed-in administrator's own token, and sends nothing to the developer. See
the [privacy policy](privacy.html).

## Source and verification

Source: [github.com/dymzd/Google](https://github.com/dymzd/Google) under
`secure-gateway-studio/`.

The packaged extension is byte-reproducible from that source:

```bash
cd secure-gateway-studio/extension && npm ci && npm run package
```

The printed SHA-256 matches the published artefact for the same version.

## Support

For questions about Chrome Enterprise Premium, Secure Gateway, or licensing,
contact your Google account team — your Field Sales Representative or Customer
Success Manager. Google supports its own products; this is not one of them.

For problems with this tool, open an
[issue](https://github.com/dymzd/Google/issues). Best effort, no response time
commitment.
