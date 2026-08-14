/**
 * Canonical JSON serialisation. Port of `backend/src/sgstudio/domain/canonical.py`.
 *
 * Approvals are bound to `plan_hash`, runs to `configuration_hash`, and the
 * audit trail is a SHA-256 chain. Every one of those digests is the hash of a
 * canonical JSON string, so this file and its Python counterpart must agree
 * byte for byte. `tests/canonical.test.ts` verifies both against the shared
 * golden set at `backend/tests/fixtures/canonical/golden.json`.
 *
 * The rules:
 *
 * - object keys sorted by Unicode code point;
 * - no insignificant whitespace;
 * - non-ASCII emitted raw, never `\uXXXX`;
 * - integers only, within +/-(2**53-1).
 *
 * `JSON.stringify` cannot be used for objects: it emits keys in insertion
 * order, and sorting them with the default comparator would order by UTF-16
 * code unit rather than code point. It *is* used for strings, where its escape
 * rules match Python's `ensure_ascii=False` exactly: only `"`, `\`, and
 * U+0000..U+001F are escaped, with the same short forms and the same lowercase
 * hex.
 */

import { sha256HexOfString } from "./sha256.ts";

const MAX_SAFE = Number.MAX_SAFE_INTEGER;

export class CanonicalisationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalisationError";
  }
}

/**
 * Compare by Unicode code point.
 *
 * `Array.prototype.sort()` compares UTF-16 code units, which places astral
 * characters (encoded as surrogate pairs beginning U+D800) below U+E000..U+FFFF
 * even though their code points are higher. Python's `sorted()` compares code
 * points. Iterating with `Array.from` yields whole code points.
 */
export function compareCodePoints(left: string, right: string): number {
  const a = Array.from(left);
  const b = Array.from(right);
  const shared = Math.min(a.length, b.length);
  for (let index = 0; index < shared; index += 1) {
    const x = a[index].codePointAt(0)!;
    const y = b[index].codePointAt(0)!;
    if (x !== y) return x < y ? -1 : 1;
  }
  if (a.length === b.length) return 0;
  return a.length < b.length ? -1 : 1;
}

function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (Number.isNaN(next) || next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function serialise(value: unknown, path: string): string {
  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";

    case "number": {
      if (!Number.isFinite(value)) {
        throw new CanonicalisationError(`Non-finite number at ${path}`);
      }
      if (Number.isInteger(value)) {
        // JavaScript cannot distinguish the integer 1 from the float 1.0, so
        // the Python side rejects whole-number floats outright. Anything
        // integral reaching here is therefore an integer on both sides.
        if (Math.abs(value) > MAX_SAFE) {
          throw new CanonicalisationError(
            `Integer at ${path} exceeds 2**53-1 and cannot survive a ` +
              "JavaScript round trip. Carry it as a string.",
          );
        }
        return String(value);
      }
      const rendered = String(value);
      if (rendered.includes("e") || rendered.includes("E")) {
        throw new CanonicalisationError(
          `Float at ${path} renders in exponential notation, where Python and ` +
            "JavaScript differ in both threshold and format. Scale the value " +
            "or carry it as a string.",
        );
      }
      return rendered;
    }

    case "string": {
      // Python raises when encoding a lone surrogate to UTF-8; JSON.stringify
      // would quietly escape it. Fail the same way rather than diverge.
      if (hasLoneSurrogate(value)) {
        throw new CanonicalisationError(
          `Lone surrogate at ${path} is not representable in UTF-8.`,
        );
      }
      return JSON.stringify(value);
    }

    case "object": {
      if (Array.isArray(value)) {
        const items = value.map((item, index) => serialise(item, `${path}[${index}]`));
        return `[${items.join(",")}]`;
      }
      const record = value as Record<string, unknown>;
      const keys = Object.keys(record).sort(compareCodePoints);
      const entries = keys.map((key) => {
        if (hasLoneSurrogate(key)) {
          throw new CanonicalisationError(
            `Lone surrogate in key at ${path} is not representable in UTF-8.`,
          );
        }
        return `${JSON.stringify(key)}:${serialise(record[key], `${path}.${key}`)}`;
      });
      return `{${entries.join(",")}}`;
    }

    default:
      throw new CanonicalisationError(`Unsupported type ${typeof value} at ${path}`);
  }
}

/** Serialise `payload` to the canonical string form. */
export function canonicalJson(payload: unknown): string {
  return serialise(payload, "$");
}

/** Return the SHA-256 hex digest of the canonical form of `payload`. */
export async function canonicalDigest(payload: unknown): Promise<string> {
  const encoded = new TextEncoder().encode(canonicalJson(payload));
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Same digest, computed without awaiting.
 *
 * Required inside IndexedDB transactions: awaiting a non-IndexedDB promise
 * lets the transaction auto-commit, and the audit chain must read the previous
 * hash and write the next one atomically. `verify-canonical.ts` asserts this
 * agrees with `canonicalDigest` on every golden case, so the two are one
 * definition with two call styles rather than two implementations.
 */
export function canonicalDigestSync(payload: unknown): string {
  return sha256HexOfString(canonicalJson(payload));
}
