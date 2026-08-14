# Secure Gateway Studio — Chrome extension

The Manifest V3 extension that replaces the local FastAPI agent. See
[docs/CHROME_EXTENSION_IMPLEMENTATION_PLAN.md](../../docs/CHROME_EXTENSION_IMPLEMENTATION_PLAN.md)
for the migration plan and phase order.

## Status

Phase 2 in progress. `src/domain/canonical.ts` is the first ported module and
the gate the rest of the port depends on.

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
