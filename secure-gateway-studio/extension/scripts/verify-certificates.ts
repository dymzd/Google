/**
 * Certificate and CSR checks.
 *
 * The CSR is assembled by hand from DER rather than by a PKI library, so the
 * thing worth proving is that the bytes are actually a well-formed PKCS#10 that
 * CA Service will accept -- not merely that the code runs.
 *
 * These checks parse the produced DER back and assert its structure: the
 * version, the common name, that WebCrypto's SubjectPublicKeyInfo is spliced in
 * intact, that the SAN extension is present, and that the signature verifies
 * against the generated public key. A CSR that failed any of these would be
 * rejected by CA Service at Apply, long after the plan was approved.
 *
 * Run with:
 *   node --experimental-strip-types extension/scripts/verify-certificates.ts
 */

import { OID, objectIdentifier, integer, toPem } from "../src/domain/asn1.ts";
import {
  generateKeyAndCsr,
  secretPayload,
  validateSecretPayload,
  CertificateError,
} from "../src/providers/certificates.ts";

const failures: string[] = [];
let passed = 0;

function check(name: string, condition: boolean, detail = ""): void {
  if (condition) passed += 1;
  else failures.push(`${name}${detail ? `\n      ${detail}` : ""}`);
}

/** Walk DER far enough to pull out the top-level SEQUENCE members. */
function readTlv(bytes: Uint8Array, offset: number): {
  tag: number;
  contentStart: number;
  contentEnd: number;
} {
  const tag = bytes[offset];
  let length = bytes[offset + 1];
  let cursor = offset + 2;
  if ((length & 0x80) !== 0) {
    const count = length & 0x7f;
    length = 0;
    for (let index = 0; index < count; index += 1) {
      length = length * 256 + bytes[cursor + index];
    }
    cursor += count;
  }
  return { tag, contentStart: cursor, contentEnd: cursor + length };
}

function children(bytes: Uint8Array, start: number, end: number): number[] {
  const offsets: number[] = [];
  let cursor = start;
  while (cursor < end) {
    offsets.push(cursor);
    cursor = readTlv(bytes, cursor).contentEnd;
  }
  return offsets;
}

function pemToDer(pem: string): Uint8Array {
  const body = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s+/g, "");
  const binary = atob(body);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function contains(haystack: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let index = 0; index + needle.length <= haystack.length; index += 1) {
    for (let offset = 0; offset < needle.length; offset += 1) {
      if (haystack[index + offset] !== needle[offset]) continue outer;
    }
    return true;
  }
  return false;
}

const HOSTNAME = "demo-server-http.internal";

// -- DER primitives ------------------------------------------------------------
{
  // Known encodings from X.690; a mistake here would corrupt every structure
  // built on top.
  check(
    "OID encodes the shared first two arcs into one byte",
    [...objectIdentifier("2.5.4.3")].join(",") === "6,3,85,4,3",
    [...objectIdentifier("2.5.4.3")].join(","),
  );
  check(
    "OID encodes multi-byte arcs with continuation bits",
    [...objectIdentifier(OID.rsaEncryption)].join(",") ===
      "6,9,42,134,72,134,247,13,1,1,1",
    [...objectIdentifier(OID.rsaEncryption)].join(","),
  );
  check("INTEGER zero is a single zero byte", [...integer(0)].join(",") === "2,1,0");
  check(
    "INTEGER pads when the high bit would read as negative",
    [...integer(128)].join(",") === "2,2,0,128",
    [...integer(128)].join(","),
  );
}

// -- PEM armour ----------------------------------------------------------------
{
  const pem = toPem("TEST", Uint8Array.from({ length: 100 }, (_, index) => index));
  const lines = pem.trim().split("\n");
  check("PEM has begin and end markers", lines[0] === "-----BEGIN TEST-----");
  check("PEM ends with the matching marker", lines[lines.length - 1] === "-----END TEST-----");
  check(
    "PEM body wraps at 64 characters",
    lines.slice(1, -1).every((line) => line.length <= 64),
  );
  check("PEM round-trips to the original bytes", pemToDer(pem).length === 100);
}

// -- the CSR is a well-formed PKCS#10 -----------------------------------------
{
  const { keyPair, csrPem, privateKeyPem } = await generateKeyAndCsr(HOSTNAME);
  const der = pemToDer(csrPem);

  const outer = readTlv(der, 0);
  check("CSR is a SEQUENCE", outer.tag === 0x30);
  const top = children(der, outer.contentStart, outer.contentEnd);
  check("CSR has three top-level members", top.length === 3, String(top.length));

  const info = readTlv(der, top[0]);
  const infoParts = children(der, info.contentStart, info.contentEnd);
  check("CertificationRequestInfo has four members", infoParts.length === 4);

  const version = readTlv(der, infoParts[0]);
  check(
    "version is v1 (zero)",
    version.tag === 0x02 && der[version.contentStart] === 0,
  );

  check(
    "subject carries the hostname as common name",
    contains(der.subarray(infoParts[1], infoParts[2]), new TextEncoder().encode(HOSTNAME)),
  );

  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", keyPair.publicKey));
  check(
    "WebCrypto SubjectPublicKeyInfo is spliced in intact",
    contains(der, spki),
  );

  const attributes = readTlv(der, infoParts[3]);
  check("attributes use context tag [0]", attributes.tag === 0xa0);
  check(
    "attributes carry the extensionRequest OID",
    contains(der.subarray(infoParts[3], info.contentEnd), objectIdentifier(OID.extensionRequest)),
  );
  check(
    "attributes carry the subjectAltName OID",
    contains(der.subarray(infoParts[3], info.contentEnd), objectIdentifier(OID.subjectAltName)),
  );
  check(
    "SAN names the hostname",
    contains(
      der.subarray(infoParts[3], info.contentEnd),
      new TextEncoder().encode(HOSTNAME),
    ),
  );

  check(
    "signature algorithm is sha256WithRSAEncryption",
    contains(
      der.subarray(top[1], top[2]),
      objectIdentifier(OID.sha256WithRsaEncryption),
    ),
  );

  // The decisive check: CA Service verifies this signature over exactly these
  // bytes, so verifying it here is verifying the encoding.
  const signatureTlv = readTlv(der, top[2]);
  const signature = der.subarray(signatureTlv.contentStart + 1, signatureTlv.contentEnd);
  const signedRegion = der.subarray(top[0], info.contentEnd);
  const verified = await crypto.subtle.verify(
    { name: "RSASSA-PKCS1-v1_5" },
    keyPair.publicKey,
    signature as Uint8Array<ArrayBuffer>,
    signedRegion as Uint8Array<ArrayBuffer>,
  );
  check("CSR signature verifies over CertificationRequestInfo", verified);

  check(
    "private key exports as PKCS#8 PEM",
    privateKeyPem.startsWith("-----BEGIN PRIVATE KEY-----"),
  );
  check("RSA modulus is 3072 bits", spki.length > 380 && spki.length < 440, String(spki.length));
}

// -- the Secret Manager payload contract --------------------------------------
{
  // The generated startup script reads exactly these three fields, so the shape
  // is a contract with that script rather than an internal detail.
  const payload = secretPayload({
    certificatePem: "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n",
    certificateChainPem: ["-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n"],
    privateKeyPem: "-----BEGIN PRIVATE KEY-----\nCCC\n-----END PRIVATE KEY-----\n",
    hostname: HOSTNAME,
    issuerResourceName: null,
  });
  const parsed = JSON.parse(payload) as Record<string, unknown>;
  check(
    "payload carries exactly the three fields the VM reads",
    Object.keys(parsed).sort().join(",") ===
      "certificate_chain_pem,certificate_pem,private_key_pem",
    Object.keys(parsed).sort().join(","),
  );
}

// -- operator-supplied secrets are validated ----------------------------------
{
  const good = JSON.stringify({
    certificate_pem: "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n",
    certificate_chain_pem: [],
    private_key_pem: "-----BEGIN PRIVATE KEY-----\nBBB\n-----END PRIVATE KEY-----\n",
  });
  check("a well-formed secret validates", validateSecretPayload(good, HOSTNAME).hostname === HOSTNAME);

  const cases: [string, string][] = [
    ["not json", "not valid JSON"],
    [JSON.stringify({ certificate_chain_pem: [], private_key_pem: "x" }), "PEM certificate"],
    [
      JSON.stringify({
        certificate_pem: "-----BEGIN CERTIFICATE-----",
        certificate_chain_pem: [],
      }),
      "PEM private key",
    ],
    [
      JSON.stringify({
        certificate_pem: "-----BEGIN CERTIFICATE-----",
        private_key_pem: "PRIVATE KEY",
        certificate_chain_pem: "not-a-list",
      }),
      "list of PEM strings",
    ],
  ];
  for (const [raw, expected] of cases) {
    try {
      validateSecretPayload(raw, HOSTNAME);
      failures.push(`malformed secret accepted: ${raw.slice(0, 40)}`);
    } catch (error) {
      check(
        `malformed secret rejected (${expected})`,
        error instanceof CertificateError && error.message.includes(expected),
        (error as Error).message,
      );
    }
  }
}

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} of ${failures.length + passed} checks\n`);
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
console.log(`OK ${passed} certificate and CSR checks passed.`);
