# Google Workspace, Chrome Enterprise, and BeyondCorp tooling

Independent open-source tooling for Google Workspace, Google Admin Console,
Chrome Enterprise, and BeyondCorp Security Gateway. The repository holds two
unrelated bodies of work — a set of single-purpose administration scripts, and
one full application — plus the source of the published project site.

## Layout

| Path | What it is |
| --- | --- |
| [`workspace-scripts/`](workspace-scripts/) | Standalone Google Workspace and Admin Console scripts. Each runs on its own. |
| [`secure-gateway-studio/`](secure-gateway-studio/) | The Secure Gateway Studio application: backend, frontend, Chrome extension, and IAM definitions. |
| [`docs/`](docs/) | Source of the published GitHub Pages site. Not developer documentation. |
| [`docs-internal/`](docs-internal/) | Design and reference material that is not published: the implementation plans and the deployment PDF. |
| [`design/`](design/) | Concept and screenshot images. |

## Standalone scripts

Each script is independent. Read
[`workspace-scripts/ConfigGuide.md`](workspace-scripts/ConfigGuide.md) first —
it covers the service account, customer ID, and admin credentials that every
script needs.

| Script | Purpose | Notes |
| --- | --- | --- |
| [`MassAddWifiSettings.gas`](workspace-scripts/MassAddWifiSettings.gas) | Bulk-manage WiFi settings for organizational units from a Google Sheet. | [docs](workspace-scripts/MassAddWifiSettings.md) |
| [`MassAddOUs.gas`](workspace-scripts/MassAddOUs.gas) | Bulk-create and modify organizational units from a Google Sheet. | [docs](workspace-scripts/MassAddOUs.md) |
| [`MoveMultipleBrowsers.py`](workspace-scripts/MoveMultipleBrowsers.py) | Move many Chrome browser devices between organizational units. | [docs](workspace-scripts/MoveMultipleBrowsers.md) |
| [`BlockExtensionBasedOnRiskScore.py`](workspace-scripts/BlockExtensionBasedOnRiskScore.py) | Block Chrome extensions whose Crxcavator or Spin.ai risk score exceeds a threshold. | [docs](workspace-scripts/BlockExtensionBasedOnRiskScore.md) |
| [`ManagedBookmarks.py`](workspace-scripts/ManagedBookmarks.py) | Push managed bookmarks to an organizational unit via the Chrome Policy API. | [docs](workspace-scripts/ManagedBookmarks.md) |
| [`ReleaseScraper.py`](workspace-scripts/ReleaseScraper.py) | Watch Chrome Enterprise release notes and post structured updates to Slack. | — |

## Secure Gateway Studio

A local administration tool and Chrome extension for planning, approving, and
applying BeyondCorp private Security Gateway architectures, giving managed
Chrome devices zero-trust private HTTPS access.

Start at [`secure-gateway-studio/README.md`](secure-gateway-studio/README.md)
for supported architectures, prerequisites, and how to run it. Continuous
integration is defined in
[`.github/workflows/secure-gateway-studio-ci.yml`](.github/workflows/secure-gateway-studio-ci.yml).

## Disclaimer

These scripts and tools are an independent open-source project. They are **not
built, endorsed, or supported by Google**, and are not affiliated with Google
LLC. "Google", "Google Workspace", "Google Cloud", "Chrome", and "Chrome
Enterprise Premium" are trademarks of Google LLC.

Everything here is provided as is, with no warranty and no support commitment.
Several of these tools change configuration in a live Google Workspace tenant or
Google Cloud project. Test in a non-production organizational unit first. The
author accepts no responsibility for problems arising from their use.

## Support

For questions about Google Workspace, Chrome Enterprise Premium, Secure Gateway,
or licensing, contact your Google account team — your Field Sales Representative
or Customer Success Manager. Google supports its own products; these tools are
not among them.

For problems with the tools in this repository, open a GitHub issue. Best effort
only, with no response time commitment.

## License

This repository is licensed under the Apache License 2.0. See [LICENSE](LICENSE)
for the complete terms. Distributed artefacts also include the notices required
for bundled third-party software.
