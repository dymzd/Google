# Verifying the published extension

This extension holds an administrator's Google authorization and can create,
change, and delete infrastructure in their project. You should not have to take
our word for what it does.

Everything it runs is in this repository, and the build is reproducible: the
same commit produces the same bytes on your machine as on ours. This page is
how you check that for yourself.

## What verification proves, and what it does not

It proves that **the extension you installed was built from the source you can
read**. Nothing was inserted between the repository and the artefact.

It does not prove the source is free of flaws, and it does not protect you if
the repository itself is compromised. For that, read the code — the parts that
touch Google are deliberately small and unminified for exactly this reason:

| File | What to read it for |
|---|---|
| `src/background/service-worker.ts` | The only context holding a token. Every Google call originates here. |
| `src/auth/tokens.ts` | How authorization is obtained and where it is (and is not) stored. |
| `src/providers/executor.ts` | Every mutation the extension can perform. |
| `docs/PERMISSIONS.md` | Why each permission and host is requested. |

## Reproducing the build

Requires Node 22 and Python 3.12.

```bash
git clone https://github.com/dymzd/Google.git
cd Google/secure-gateway-studio/extension
git checkout <the tag matching the version you installed>
npm ci
node build.mjs
python package.py
```

`build.mjs` prints a SHA-256 for every file it produces, and writes the same
digests to `dist/SHA256SUMS.json`. `package.py` prints the SHA-256 of
`secure-gateway-studio-<manifest version>.zip`.

Compare those against the digests published on the release tag. If they match,
the artefact came from this source.

The build has no timestamps, no build IDs, and no absolute paths in its output,
so two runs on different machines produce identical bytes. If yours differ,
that is worth reporting.

## Comparing against the installed extension

Chrome unpacks extensions on disk. Locate the installed version:

- **Windows** — `%LOCALAPPDATA%\Google\Chrome\User Data\<profile>\Extensions\<id>\<version>`
- **macOS** — `~/Library/Application Support/Google/Chrome/<profile>/Extensions/<id>/<version>`
- **Linux** — `~/.config/google-chrome/<profile>/Extensions/<id>/<version>`

Compare that directory against your `dist/`. Chrome adds `_metadata/` and may
rewrite `manifest.json` key ordering during install, so compare the code files
directly:

Use `dist/SHA256SUMS.json` to compare every emitted file. The two primary
JavaScript entry bundles can also be spot-checked directly:

```bash
sha256sum dist/src/background/service-worker.js dist/src/ui/app.js
```

The complete extension also includes markup, styling, the manifest, and static
assets, so verification must ultimately cover the full checksum manifest.

## Verifying the domain logic instead of trusting it

The extension is a port of the Python implementation in this same repository,
and the two are held to byte-level agreement by generated golden sets rather
than by review. You can run those checks yourself:

```bash
cd secure-gateway-studio/extension
npm run verify
```

That runs TypeScript checking plus 25 offline parity/behaviour scripts. None
needs a network or a Google project:

| Check | What it pins |
|---|---|
| routes | Every declared UI API route has a service-worker handler and unsupported methods fail predictably |
| UI capabilities | Extension-only routes are hidden from the local app and the extension requires the user-data disclosure before tenant access |
| coldstart | Durable state can be reconstructed after a fresh MV3 worker start, browser startup, or extension update |
| Google response | Non-object, malformed, or unexpectedly empty Google REST bodies fail closed without retaining raw response text |
| canonical | Both implementations serialise and hash identically, including non-ASCII |
| spec | Specifications round-trip to the same `configuration_hash` approvals bind to |
| auth | Mutations run as the pinned product-scoped deployer account, not the administrator |
| storage safety | OAuth tokens and private keys never enter durable extension storage; persisted identifiers and evidence are AES-GCM ciphertext |
| IndexedDB migration | v3/0.2.0 rows are untouched before consent, then encrypt without semantic audit rewrites; raw storage, tamper/wrong-key failure, and non-extractable-key restart are exercised |
| lifecycle durability | Apply, rollback, finalization, policy updates, and teardown share atomic global slots |
| audit | The audit chain matches Python's, and tampering is detected |
| planner | Both produce the same plan, gates, and required permissions |
| executor | Both issue the same Google API requests in order; the extension additionally removes the obsolete top-level `Router.fingerprint` from Compute v1 Router PATCH bodies |
| execution safety | Request identity, before-images, terminal cleanup, unsafe reset rejection, immutable deployer ownership pins, sole-operator 0.2.0 migration, explicitly audited deleted-deployer recreation (including etag-bound soft-deleted-role recovery), and bounded Gateway-application pagination stay fail-closed |
| discovery | Both probe the same resources and assemble the same snapshot |
| catalog | Cloud catalog reads use the bootstrapped deployer and select only an Access Policy applicable to the project number or an ancestor folder; missing or ambiguous access fails closed |
| resume | Apply completes exactly once even when the worker is killed mid-operation |
| certificates | RSA certificate/CSR generation, Secret Manager payloads, and public-root export stay valid |
| acceptance | T01–T09 evidence is derived from real probes and cannot be asserted without proof |
| evidence | Exported evidence is schema-bound, operation-bound, and tamper-evident |
| IAM policy | Version 3 conditions, unrelated bindings, members, and etags are preserved |
| teardown | Only exact, durably owned resources are destroyed and shared artifacts are retained |
| observability | Logging partial responses and parsers exclude URL paths, query strings, free-form payloads, IP addresses, and principals |
| CEP | Chrome Policy, Cloud Identity DLP, OU, licensing, read-only ownership-safe cleanup inspection, and the Admin-console role boundary match the selected controls |

The Python side enforces the same fixtures:

```bash
cd secure-gateway-studio/backend
uv sync --locked --extra dev
uv run pytest
```

A change that passes only one side fails the other, so neither implementation
can drift alone.

## Distribution artefact

Version 0.2.24 produces one versioned ZIP for upload to the Chrome Web Store:
`secure-gateway-studio-0.2.24.zip`. This repository does not produce or publish
a CRX. Rebuild the ZIP with `npm run package` and compare the printed SHA-256
before uploading it.

See `docs/PERMISSIONS.md` for what to review in a new version, and the
migration plan for how releases are sequenced.
