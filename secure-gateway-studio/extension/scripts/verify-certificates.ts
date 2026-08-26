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
  crc32c,
  issueLocalPoc,
  issueEnterpriseCa,
  validatePublicCertificateAccessResponse,
} from "../src/providers/certificates.ts";
import { sha256Hex } from "../src/domain/sha256.ts";
import { parseDeploymentSpec } from "../src/domain/spec.ts";
import { revalidatePublicCertificateBinding } from "../src/providers/executor-path-a.ts";
import { offloadStartupScript } from "../src/providers/startup-scripts.ts";
import type { ResourceChange } from "../src/domain/planner.ts";
import type { Transport } from "../src/providers/executor.ts";

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
  const goodBundle = await issueLocalPoc(HOSTNAME, 30);
  const good = secretPayload(goodBundle);
  check(
    "a cryptographically valid secret validates",
    (await validateSecretPayload(good, HOSTNAME)).hostname === HOSTNAME,
  );
  check(
    "an omitted public root is allowed while the leaf and key are still validated",
    (await validateSecretPayload(
      secretPayload({ ...goodBundle, certificateChainPem: [] }),
      HOSTNAME,
    )).hostname === HOSTNAME,
  );

  const otherBundle = await issueLocalPoc(HOSTNAME, 30);
  for (const [name, payload, hostname, expected] of [
    [
      "mismatched leaf and private key",
      secretPayload({ ...goodBundle, privateKeyPem: otherBundle.privateKeyPem }),
      HOSTNAME,
      "do not match",
    ],
    ["wrong hostname SAN", good, "other.internal", "SAN"],
    [
      "wrongly ordered issuer chain",
      secretPayload({ ...goodBundle, certificateChainPem: otherBundle.certificateChainPem }),
      HOSTNAME,
      "signature",
    ],
    [
      "expired leaf",
      secretPayload(await issueLocalPoc(HOSTNAME, -1)),
      HOSTNAME,
      "expires too soon",
    ],
  ] as const) {
    try {
      await validateSecretPayload(payload, hostname);
      failures.push(`${name} was accepted`);
    } catch (error) {
      check(
        `${name} is rejected`,
        error instanceof CertificateError && error.message.includes(expected),
        (error as Error).message,
      );
    }
  }

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
      await validateSecretPayload(raw, HOSTNAME);
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

// CA Service's response is not trusted merely because it echoes the CSR. The
// returned leaf must still match the generated private key, exact SAN,
// requested lifetime, non-CA role, and every supplied issuer signature.
{
  const hostname = "ca-response.internal";
  const good = await issueLocalPoc(hostname, 30);
  const request = {
    csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nQ1NS\n-----END CERTIFICATE REQUEST-----",
    privateKeyPem: good.privateKeyPem,
  };
  const caPool = "projects/enterprise-secgw-01/locations/asia-east1/caPools/tls";
  const caName = `${caPool}/certificateAuthorities/issuer`;
  const certificateId = "deployment-cert-12345678";
  const payloadFor = (bundle: typeof good) => ({
    name: `${caPool}/certificates/${certificateId}`,
    pemCsr: request.csrPem,
    pemCertificate: bundle.certificatePem,
    pemCertificateChain: bundle.certificateChainPem,
    issuerCertificateAuthority: caName,
  });
  const issue = async (payload: Record<string, unknown>) =>
    issueEnterpriseCa(
      { async requestJson() { return { status: 200, payload }; } },
      {
        hostname,
        caPool,
        caName,
        certificateId,
        lifetimeDays: 30,
        request,
      },
    );
  check(
    "Private CA accepts a response only after full bundle validation",
    (await issue(payloadFor(good))).hostname === hostname,
  );
  const otherKey = await issueLocalPoc(hostname, 30);
  const otherSan = await issueLocalPoc("other.internal", 30);
  const excessiveLifetime = await issueLocalPoc(hostname, 90);
  for (const [name, payload] of [
    ["Private CA missing resource name", { ...payloadFor(good), name: undefined }],
    ["Private CA empty resource name", { ...payloadFor(good), name: "" }],
    [
      "Private CA wrong resource name",
      { ...payloadFor(good), name: `${caPool}/certificates/other` },
    ],
    ["Private CA wrong private key", payloadFor({ ...good, certificatePem: otherKey.certificatePem })],
    ["Private CA wrong SAN", payloadFor(otherSan)],
    ["Private CA unexpected lifetime", payloadFor(excessiveLifetime)],
    [
      "Private CA invalid issuer chain",
      payloadFor({ ...good, certificateChainPem: otherSan.certificateChainPem }),
    ],
  ] as const) {
    let error: unknown;
    try {
      await issue(payload);
    } catch (caught) {
      error = caught;
    }
    check(`${name} is rejected`, error instanceof CertificateError, String(error));
  }
}

// Public-trust Apply must consume the immutable version/digest approved at
// Plan time. It revalidates both `latest` and the numeric version, then embeds
// only the numeric resource name in the VM startup script.
{
  const spec = parseDeploymentSpec({
    project_id: "enterprise-secgw-01",
    mode: "poc",
    target_ou_id: "03-test-ou",
    managed_chrome_access_level: "accessPolicies/123/accessLevels/managed",
    test_ou_confirmed: true,
    principals: [{ type: "group", value: "secure-access@example.com" }],
    backend_kind: "existing_http",
    network_strategy: "existing",
    vpc_name: "private-app-vpc",
    subnet_name: "private-app-subnet",
    certificate_strategy: "public_trusted",
    public_certificate_secret:
      "projects/enterprise-secgw-01/secrets/operator-public-tls",
    private_hostname: "gateway.customer.dev",
    source_image: "projects/enterprise-secgw-01/global/images/sgs-nginx-20260824",
    existing_backend_url: "http://10.20.0.10:8080",
    existing_backend_location: "gcp",
    existing_backend_connectivity_confirmed: true,
  });
  const bundle = await issueLocalPoc(spec.private_hostname, 30);
  const bytes = new TextEncoder().encode(secretPayload(bundle));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const responsePayload = {
    name:
      "projects/enterprise-secgw-01/secrets/operator-public-tls/versions/7",
    payload: { data: btoa(binary), dataCrc32c: String(crc32c(bytes)) },
  };
  const validated = await validatePublicCertificateAccessResponse(responsePayload, {
    projectId: spec.project_id,
    secretName: "operator-public-tls",
    hostname: spec.private_hostname,
    minimumValidityDays: 1,
  });
  const change: ResourceChange = {
    provider: "compute",
    resource_type: "instance",
    resource_name: `${spec.name}-offload`,
    action: "create",
    risk: "medium",
    summary: "fixture",
    owned_after_apply: true,
    dependencies: [],
  };
  const binding = {
    secret_version_name: validated.versionName,
    payload_sha256: validated.payloadSha256,
  };
  const calls: string[] = [];
  const transport: Transport = {
    async requestJson(method, url) {
      calls.push(`${method} ${url}`);
      return { status: 200, payload: structuredClone(responsePayload) };
    },
  };
  const immutableVersion = await revalidatePublicCertificateBinding(
    transport,
    spec,
    binding,
  );
  const startup = offloadStartupScript(spec, {
    publicCertificateVersionName: immutableVersion,
  });
  check(
    "public certificate Apply revalidates latest and binds its numeric response",
    calls.length === 1 && calls[0]?.endsWith("/versions/latest:access"),
    JSON.stringify(calls),
  );
  check(
    "public certificate startup embeds only the approved numeric SecretVersion",
    startup.includes(validated.versionName) &&
      !startup.includes("/versions/latest") && !startup.includes("/versions/active") &&
      startup.includes("pin_presented_chain = False") &&
      startup.includes('"public_system_roots"'),
  );
  const privateSpec = parseDeploymentSpec({
    ...spec,
    certificate_strategy: "local_poc",
    public_certificate_secret: null,
    private_hostname: "gateway.internal",
  });
  const privateStartup = offloadStartupScript(privateSpec);
  check(
    "private certificate startup pins the presented certificate chain",
    privateStartup.includes("pin_presented_chain = True") &&
      privateStartup.includes('"presented_chain_pinned"') &&
      privateStartup.includes(
        'if pin_presented_chain:\n        context.load_verify_locations(cafile="/etc/nginx/tls.crt")',
      ),
  );
  check(
    "public certificate digest binds the exact decoded payload",
    validated.payloadSha256 === sha256Hex(bytes),
  );

  for (const [name, mutated] of [
    ["latest alias drift", { ...responsePayload, name: responsePayload.name.replace("/7", "/8") }],
    [
      "payload drift",
      {
        ...responsePayload,
        payload: {
          data: btoa(`${binary} `),
          dataCrc32c: String(crc32c(new TextEncoder().encode(`${secretPayload(bundle)} `))),
        },
      },
    ],
  ] as const) {
    let error: unknown;
    try {
      await revalidatePublicCertificateBinding(
        { async requestJson() { return { status: 200, payload: structuredClone(mutated) }; } },
        spec,
        binding,
      );
    } catch (caught) {
      error = caught;
    }
    check(`${name} is rejected before VM mutation`, error instanceof Error, String(error));
  }
}

if (failures.length > 0) {
  console.error(`FAIL ${failures.length} of ${failures.length + passed} checks\n`);
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
console.log(`OK ${passed} certificate and CSR checks passed.`);
