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
`dist.zip`.

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

```bash
sha256sum dist/src/background/service-worker.js dist/src/ui/app.js
```

Those two files are the entire program. Everything else is markup, styling, and
an icon.

## Verifying the domain logic instead of trusting it

The extension is a port of the Python implementation in this same repository,
and the two are held to byte-level agreement by generated golden sets rather
than by review. You can run those checks yourself:

```bash
cd secure-gateway-studio/extension
npm run verify
```

That runs eight checks, none of which need a network or a Google project:

| Check | What it pins |
|---|---|
| canonical | Both implementations serialise and hash identically, including non-ASCII |
| spec | Specifications round-trip to the same `configuration_hash` approvals bind to |
| auth | Mutations run as the least-privilege deployer account, not the administrator |
| audit | The audit chain matches Python's, and tampering is detected |
| planner | Both produce the same plan, gates, and required permissions |
| executor | Both issue the same Google API requests, in order, with the same bodies |
| discovery | Both probe the same resources and assemble the same snapshot |
| resume | Apply completes exactly once even when the worker is killed mid-operation |

The Python side enforces the same fixtures:

```bash
cd secure-gateway-studio/backend
uv sync --locked --extra dev
uv run pytest
```

A change that passes only one side fails the other, so neither implementation
can drift alone.

## Self-hosted distribution

Enterprises that would rather control when updates arrive can serve the CRX
themselves and point managed Chrome at it by policy, instead of taking updates
from the Web Store. In that arrangement you decide when a new version reaches
your fleet, and you can verify each one by the procedure above before it does.

See `docs/PERMISSIONS.md` for what to review in a new version, and the
migration plan for how releases are sequenced.
