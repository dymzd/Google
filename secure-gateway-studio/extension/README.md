# Secure Gateway Studio — Chrome extension

The Manifest V3 runtime distributed through the Chrome Web Store. The loopback
FastAPI runtime remains available and has a different capability boundary. See
[docs/CHROME_EXTENSION_IMPLEMENTATION_PLAN.md](../../docs/CHROME_EXTENSION_IMPLEMENTATION_PLAN.md)
for the historical migration design. This file describes the current extension
capability boundary for version 0.2.24.

The detailed Japanese cumulative release history is in
[`docs/PATCH_NOTES_0.2.24_JA.md`](docs/PATCH_NOTES_0.2.24_JA.md).

## Status

The Manifest V3 port is a PoC release candidate. Planning, short-lived
approvals, resumable execution, ownership-bounded teardown, certificate
handling, CEP provisioning, acceptance evidence, and audit export are wired
through the service worker. Promotion still requires the live staging gates in
[`../docs/ENTERPRISE_READINESS.md`](../docs/ENTERPRISE_READINESS.md); offline
verification does not certify a real tenant or managed-Chrome path.

Version 0.2.24 supports direct private HTTPS, Nginx HTTPS-to-HTTP offload, and
the PoC-only regional Internal Application Load Balancer path. It also recovers
an unfinished Apply or rollback—including legacy `failed` and
`rollback_unavailable` runs—before allowing a replacement preflight, so
run-owned residual resources are reconciled instead of being mistaken for a new
deployment. An explicit retry can bind a pre-identity-binding run to the
currently live-attested deployer only when the consumed approval, configuration
hash, operator email, project, and every executable checkpoint still match
exactly. Easy PoC for Chrome Enterprise Premium is extension-only.

The explicit legacy recovery path also recognizes the 0.2.0 attribution bug
that stored the deployer service-account email as `approvedBy`. It preserves
that historical value, records a separate audited human binding, and accepts it
only when the live Google email and immutable subject match the operator pinned
to the exact deployer identity. Recovery may cross from the historical
`secure-gateway-deployer` account name to the current
`secure-gateway-studio-deployer` name, but only for those two exact product
identities in the same deployment project.

If an administrator deliberately deletes the pinned deployer in Google Cloud,
0.2.24 offers a separate explicit recreation confirmation. It retires the old
immutable identity only after proving that the exact service account is absent,
the custom role is absent or soft-deleted with the exact managed definition,
and neither project IAM nor Access Policy IAM retains the old email, numeric
identity, or role. Active Apply, teardown, and CEP operations block retirement.
The retired pin is retained as a bounded local tombstone. A soft-deleted custom
role is restored with its etag because Google reserves deleted role IDs for up
to 44 days; otherwise a fresh role is created before granting the new deployer.

Rollback recovery now classifies every residual step before constructing the
Google executor. If any step lacks durable ownership/restore evidence, no
provider mutation starts: the run becomes permanently `rollback_unavailable`,
the UI lists every failed operation and every possible residual resource, and
the retry action disappears. Approval, run, and step records share one lifecycle
schema version; legacy records are either validated and upgraded once or sealed
for manual cleanup. Checkpoint-less IAM remains fail-closed without a parent-404
exception.

An installed update immediately enters the same consent-gated cold-start
reconciliation as browser startup. If an active Apply/rollback run survived in
encrypted IndexedDB but its alarm did not, top-level `runtime.onInstalled`
recreates the alarm without waiting for the UI, a browser restart, or a new
message. Before the 0.2.1 disclosure is accepted this wake reads only the
consent metadata and does not inspect durable product records.

Direct CEP licence assignment is limited to a non-production pilot OU with at
most 10 unique direct members; descendants are excluded. The complete list
must finish within four Directory pages before the first assignment, otherwise
no licence mutation is started. Each Directory and Licensing request has a
five-second deadline; deployer identity verification has a ten-second route deadline.
After assignment starts, a lost POST response is reconciled by exact
product/SKU/user GET; an unconfirmed outcome retains the durable tenant/OU lease
for exact-request recovery, so partial results are possible but never guessed.

## Persistent-state encryption

Version 0.2.1 encrypts every disk-backed deployment, tenant, identity, and audit
value with AES-256-GCM before writing IndexedDB. The randomly generated data key
is non-extractable and survives MV3 worker restarts through IndexedDB structured
clone. Only hashed record/index keys, lifecycle status, cryptographic metadata,
and the non-sensitive UI locale preference (`en` or `ja`) remain clear. The
locale is kept in page `localStorage`; it contains no tenant, authentication,
configuration, or audit data. Schema/store/record binding is authenticated as
AAD. A missing or substituted key and any ciphertext/metadata tamper fail
closed.

An upgraded 0.2.0 profile is not inspected during `onupgradeneeded` or worker
startup. The first-screen disclosure must be accepted before the extension
encrypts old IndexedDB, `chrome.storage.local`, setup, and workflow values. It
clears the legacy unencrypted setup and workflow records before marking consent
complete and allowing recovery/resume; the non-sensitive locale remains.

## Canonicalisation parity

Approvals bind to `plan_hash`, runs to `configuration_hash`, and the audit
trail is a SHA-256 chain. Every one of those digests is the hash of a canonical
JSON string, so this port and the Python reference implementation must produce
byte-identical output. They are verified against one shared golden set.

Run the check locally (no dependencies required — Node 22 strips the types):

```bash
node --experimental-strip-types extension/scripts/verify-canonical.ts
```

Regenerate the golden set only when the canonical rules change deliberately:

```bash
python backend/tests/fixtures/canonical/generate.py
```

A changed golden digest changes every approval binding and audit chain the
product has ever issued. Both `backend/tests/test_canonical.py` and the parity
job in CI verify against the same file, so a one-sided change fails rather than
diverging quietly.

## Rules the two implementations share

- object keys sorted by Unicode code point, not UTF-16 code unit;
- no insignificant whitespace;
- non-ASCII emitted raw, never `\uXXXX`;
- integers only within ±(2^53−1);
- floats only when neither whole-numbered nor exponential. `offload_cpu_target`
  is the only float the product hashes, and its `ge=0.1, le=0.9` bound keeps it
  clear of both hazards.
