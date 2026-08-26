/**
 * Certificate issuance. Port of `providers/certificates.py`.
 *
 * CA Service receives only the CSR, never the private key. The enterprise and
 * PoC offload flows must nevertheless export the server key so the approved
 * Apply can write it to the operator's Secret Manager for the VM to read at
 * boot. The key is extractable only for that architectural handoff and remains
 * session-only in the extension until the run terminates.
 *
 * DER is assembled by `domain/asn1.ts` rather than a PKI library. See that file
 * for why.
 */

import {
  OID,
  bitString,
  bitStringWithUnusedBits,
  booleanValue,
  concat,
  contextConstructed,
  contextPrimitive,
  integer,
  objectIdentifier,
  octetString,
  sequence,
  set,
  toPem,
  utf8String,
  utcTime,
  nullValue,
} from "../domain/asn1.ts";
import type { Transport } from "./executor.ts";
import { sha256Hex } from "../domain/sha256.ts";

/** Matches the Python implementation's 3072-bit RSA with F4. */
const KEY_PARAMS: RsaHashedKeyGenParams = {
  name: "RSASSA-PKCS1-v1_5",
  modulusLength: 3072,
  publicExponent: Uint8Array.of(0x01, 0x00, 0x01),
  hash: "SHA-256",
};

export class CertificateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CertificateError";
  }
}

export interface CertificateBundle {
  certificatePem: string;
  certificateChainPem: string[];
  privateKeyPem: string;
  hostname: string;
  issuerResourceName: string | null;
}

export class CertificateIssuanceRejectedError extends CertificateError {
  constructor(message: string) {
    super(message);
    this.name = "CertificateIssuanceRejectedError";
  }
}

export interface EnterpriseCertificateRequest {
  csrPem: string;
  privateKeyPem: string;
}

export interface ValidatedPublicCertificateSecret {
  bundle: CertificateBundle;
  /** Immutable SecretVersion resource name, never the mutable `latest` alias. */
  versionName: string;
  /** SHA-256 of the exact decoded Secret Manager payload bytes. */
  payloadSha256: string;
}

function strictBase64Bytes(encoded: string): Uint8Array {
  if (
    encoded.length === 0 || encoded.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)
  ) {
    throw new CertificateError("Secret Manager payload is not valid base64");
  }
  try {
    const binary = atob(encoded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new CertificateError("Secret Manager payload is not valid base64");
  }
}

/** Unsigned Castagnoli CRC, matching Secret Manager payload.dataCrc32c. */
export function crc32c(payload: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of payload) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ ((crc & 1) !== 0 ? 0x82f63b78 : 0);
    }
  }
  return (~crc) >>> 0;
}

/**
 * Validate the real AccessSecretVersion response and bind it to a numeric,
 * immutable version. Callers may additionally require the Plan-bound version
 * and digest immediately before Apply.
 */
export async function validatePublicCertificateAccessResponse(
  response: Record<string, unknown>,
  options: {
    projectId: string;
    secretName: string;
    hostname: string;
    minimumValidityDays: number;
    expectedVersionName?: string;
    expectedPayloadSha256?: string;
  },
): Promise<ValidatedPublicCertificateSecret> {
  const versionName = response.name;
  const prefix = `projects/${options.projectId}/secrets/${options.secretName}/versions/`;
  if (
    typeof versionName !== "string" || !versionName.startsWith(prefix) ||
    !/^[1-9][0-9]*$/.test(versionName.slice(prefix.length))
  ) {
    throw new CertificateError("Secret Manager returned an invalid immutable version name");
  }
  if (
    options.expectedVersionName !== undefined &&
    versionName !== options.expectedVersionName
  ) {
    throw new CertificateError("The public certificate latest alias changed after approval");
  }
  const payload = response.payload;
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new CertificateError("Secret Manager response is missing payload");
  }
  const encoded = (payload as Record<string, unknown>).data;
  const expectedCrc = (payload as Record<string, unknown>).dataCrc32c;
  if (typeof encoded !== "string") {
    throw new CertificateError("Secret Manager response is missing payload.data");
  }
  if (
    (typeof expectedCrc !== "string" && typeof expectedCrc !== "number") ||
    String(expectedCrc) === ""
  ) {
    throw new CertificateError("Secret Manager response is missing payload.dataCrc32c");
  }
  const decoded = strictBase64Bytes(encoded);
  if (String(crc32c(decoded)) !== String(expectedCrc)) {
    throw new CertificateError("Secret Manager payload CRC32C does not match");
  }
  const payloadSha256 = sha256Hex(decoded);
  if (
    options.expectedPayloadSha256 !== undefined &&
    payloadSha256 !== options.expectedPayloadSha256
  ) {
    throw new CertificateError("The public certificate payload changed after approval");
  }
  let raw: string;
  try {
    raw = new TextDecoder("utf-8", { fatal: true }).decode(decoded);
  } catch {
    throw new CertificateError("Secret Manager payload is not valid UTF-8 JSON");
  }
  const bundle = await validateSecretPayload(
    raw,
    options.hostname,
    options.minimumValidityDays,
  );
  return { bundle, versionName, payloadSha256 };
}

/** A deterministic, run-scoped CA certificate ID suitable for exact retry. */
export function enterpriseCertificateId(deploymentName: string, runId: string): string {
  const suffix = runId.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 8);
  if (suffix.length !== 8) throw new CertificateError("run-id-invalid-for-certificate");
  const base = `${deploymentName}-cert`
    .slice(0, 63 - suffix.length - 1)
    .replace(/-+$/, "");
  return `${base}-${suffix}`;
}

/**
 * Serialise for direct transmission to Secret Manager.
 *
 * The offload VM's startup script reads exactly these three fields, so the
 * shape is a contract with the generated startup script rather than an
 * internal detail.
 */
export function secretPayload(bundle: CertificateBundle): string {
  return JSON.stringify({
    certificate_chain_pem: bundle.certificateChainPem,
    certificate_pem: bundle.certificatePem,
    private_key_pem: bundle.privateKeyPem,
  });
}

const RSA_ALGORITHM = sequence(objectIdentifier(OID.rsaEncryption), nullValue());

function subjectName(hostname: string): Uint8Array {
  return sequence(set(sequence(objectIdentifier(OID.commonName), utf8String(hostname))));
}

/**
 * The SAN extension, carried as a CSR attribute.
 *
 * A certificate with only a common name is rejected by every current browser;
 * the subject alternative name is what the TLS check in T03 actually validates.
 */
function extensionRequest(hostname: string): Uint8Array {
  const san = sequence(contextPrimitive(2, new TextEncoder().encode(hostname)));
  const extensions = sequence(
    sequence(objectIdentifier(OID.subjectAltName), octetString(san)),
  );
  return contextConstructed(
    0,
    sequence(objectIdentifier(OID.extensionRequest), set(extensions)),
  );
}

/**
 * Generate a key pair and a PKCS#10 CSR for `hostname`.
 *
 * `extractable` is required here: the private key has to reach Secret Manager
 * so the offload VM can serve TLS with it.
 */
export async function generateKeyAndCsr(
  hostname: string,
): Promise<{ keyPair: CryptoKeyPair; csrPem: string; privateKeyPem: string }> {
  const keyPair = (await crypto.subtle.generateKey(KEY_PARAMS, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", keyPair.publicKey));
  const certificationRequestInfo = sequence(
    integer(0), // version v1
    subjectName(hostname),
    // SubjectPublicKeyInfo is already DER from WebCrypto; splice it in whole.
    spki,
    extensionRequest(hostname),
  );

  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "RSASSA-PKCS1-v1_5" },
      keyPair.privateKey,
      // TypeScript models Uint8Array as generic over ArrayBufferLike; WebCrypto
      // wants a view over a plain ArrayBuffer, which this always is at runtime.
      certificationRequestInfo as Uint8Array<ArrayBuffer>,
    ),
  );

  const csr = sequence(
    certificationRequestInfo,
    sequence(objectIdentifier(OID.sha256WithRsaEncryption), nullValue()),
    bitString(signature),
  );

  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
  return {
    keyPair,
    csrPem: toPem("CERTIFICATE REQUEST", csr),
    privateKeyPem: toPem("PRIVATE KEY", pkcs8),
  };
}

/** Issue through Certificate Authority Service, sending only the CSR. */
export async function issueEnterpriseCa(
  transport: Transport,
  options: {
    hostname: string;
    caPool: string;
    caName: string;
    certificateId: string;
    lifetimeDays: number;
    requestId?: string;
    operationPollIntervalMs?: number;
    maxOperationPolls?: number;
    /**
     * Pre-generated material checkpointed before the remote mutation.
     * Retrying must reuse this exact CSR and key; generating a fresh pair for
     * an already-created certificate would make the returned leaf unusable.
     */
    request?: EnterpriseCertificateRequest;
  },
): Promise<CertificateBundle> {
  const request = options.request ?? await generateKeyAndCsr(options.hostname);
  const { csrPem, privateKeyPem } = request;
  const authorityId = options.caName.match(/\/certificateAuthorities\/([^/]+)$/)?.[1];
  if (authorityId === undefined || authorityId === "") {
    throw new CertificateError("Private CA authority resource name is invalid");
  }
  const collection = `https://privateca.googleapis.com/v1/${options.caPool}/certificates`;
  const exactUrl = `${collection}/${options.certificateId}`;

  const response = await transport.requestJson(
    "POST",
    collection,
    {
      params: {
        certificateId: options.certificateId,
        issuingCertificateAuthorityId: authorityId,
        ...(options.requestId ? { requestId: options.requestId } : {}),
      },
      jsonBody: {
        pemCsr: csrPem,
        lifetime: `${options.lifetimeDays * 86400}s`,
      },
      acceptedStatuses: [409],
    },
  );

  let certificatePayload = response.payload;
  if (response.status === 409) {
    const existing = await transport.requestJson("GET", exactUrl);
    if (
      existing.payload.name !== exactUrl.replace("https://privateca.googleapis.com/v1/", "") ||
      existing.payload.pemCsr !== csrPem ||
      existing.payload.issuerCertificateAuthority !== options.caName
    ) {
      throw new CertificateError("Private CA certificate reconciliation failed");
    }
    certificatePayload = existing.payload;
  } else {
    const operationName = certificatePayload.name;
    if (
      typeof operationName === "string" &&
      operationName.startsWith(`${options.caPool.split("/caPools/")[0]}/operations/`)
    ) {
      let operation = certificatePayload;
      const maxPolls = options.maxOperationPolls ?? 150;
      for (let poll = 0; operation.done !== true; poll += 1) {
        if (operation.error !== undefined) {
          throw new CertificateError("Private CA certificate operation failed");
        }
        if (poll >= maxPolls) {
          throw new CertificateError("Private CA certificate operation timed out");
        }
        const interval = options.operationPollIntervalMs ?? 2_000;
        if (interval > 0) {
          await new Promise((resolve) => setTimeout(resolve, interval));
        }
        operation = (
          await transport.requestJson(
            "GET",
            `https://privateca.googleapis.com/v1/${operationName}`,
          )
        ).payload;
      }
      if (operation.error !== undefined) {
        throw new CertificateIssuanceRejectedError(
          "Private CA certificate operation failed",
        );
      }
      const result = operation.response;
      if (typeof result !== "object" || result === null || Array.isArray(result)) {
        throw new CertificateError("Private CA operation returned no certificate response");
      }
      certificatePayload = result as Record<string, unknown>;
    }
  }

  if (certificatePayload.pemCsr !== csrPem) {
    throw new CertificateError("Private CA returned a certificate for an unexpected CSR");
  }

  const certificate = certificatePayload.pemCertificate;
  if (typeof certificate !== "string" || certificate === "") {
    throw new CertificateError("Private CA returned no certificate");
  }
  const chain = certificatePayload.pemCertificateChain;
  if (!Array.isArray(chain) || !chain.every((item) => typeof item === "string")) {
    throw new CertificateError("Private CA returned an invalid certificate chain");
  }
  const issuer = certificatePayload.name;
  if (certificatePayload.issuerCertificateAuthority !== options.caName) {
    throw new CertificateError("Private CA returned an unexpected issuing authority");
  }
  const expectedName = `${options.caPool}/certificates/${options.certificateId}`;
  if (issuer !== expectedName) {
    throw new CertificateError("Private CA returned an unexpected certificate resource");
  }

  const bundle: CertificateBundle = {
    certificatePem: certificate,
    certificateChainPem: chain as string[],
    privateKeyPem,
    hostname: options.hostname,
    issuerResourceName: expectedName,
  };
  // The CA response is external input. A matching CSR field alone does not
  // prove that its leaf uses our generated key, copied the approved SAN, has
  // the requested lifetime, or chains through the returned issuers.
  await validateSecretPayload(
    secretPayload(bundle),
    options.hostname,
    Math.max(0, options.lifetimeDays - 1),
  );
  const issuedLeaf = parseCertificate(certificate);
  if (
    issuedLeaf.dnsNames.length !== 1 ||
    issuedLeaf.dnsNames[0]?.toLowerCase() !== options.hostname.toLowerCase()
  ) {
    throw new CertificateError("Private CA returned an unexpected DNS SAN set");
  }
  const maximumNotAfter = Date.now() + (options.lifetimeDays + 1) * 86_400_000;
  if (issuedLeaf.notAfter.getTime() > maximumNotAfter) {
    throw new CertificateError("Private CA returned an unexpected certificate lifetime");
  }
  return bundle;
}

interface DerNode {
  tag: number;
  start: number;
  contentStart: number;
  end: number;
}

interface ParsedCertificate {
  der: Uint8Array;
  tbs: DerNode;
  signatureOid: string;
  signatureParameters: DerNode | null;
  signature: Uint8Array;
  issuer: Uint8Array;
  subject: Uint8Array;
  notBefore: Date;
  notAfter: Date;
  spki: Uint8Array;
  spkiOid: string;
  curveOid: string | null;
  dnsNames: string[];
  isCa: boolean;
}

const CERTIFICATE_OIDS = {
  rsaPss: "1.2.840.113549.1.1.10",
  sha1WithRsa: "1.2.840.113549.1.1.5",
  sha384WithRsa: "1.2.840.113549.1.1.12",
  sha512WithRsa: "1.2.840.113549.1.1.13",
  ecPublicKey: "1.2.840.10045.2.1",
  ecdsaSha256: "1.2.840.10045.4.3.2",
  ecdsaSha384: "1.2.840.10045.4.3.3",
  ecdsaSha512: "1.2.840.10045.4.3.4",
  p256: "1.2.840.10045.3.1.7",
  p384: "1.3.132.0.34",
  p521: "1.3.132.0.35",
  sha1: "1.3.14.3.2.26",
  sha256: "2.16.840.1.101.3.4.2.1",
  sha384: "2.16.840.1.101.3.4.2.2",
  sha512: "2.16.840.1.101.3.4.2.3",
  mgf1: "1.2.840.113549.1.1.8",
} as const;

function readDer(bytes: Uint8Array, start: number): DerNode {
  if (start < 0 || start + 2 > bytes.length) {
    throw new CertificateError("The TLS secret contains truncated DER");
  }
  const tag = bytes[start];
  let cursor = start + 1;
  let length = bytes[cursor++];
  if ((length & 0x80) !== 0) {
    const count = length & 0x7f;
    if (count === 0 || count > 4 || cursor + count > bytes.length) {
      throw new CertificateError("The TLS secret contains invalid DER length encoding");
    }
    length = 0;
    for (let index = 0; index < count; index += 1) {
      length = length * 256 + bytes[cursor++];
    }
  }
  const end = cursor + length;
  if (end > bytes.length) throw new CertificateError("The TLS secret contains truncated DER");
  return { tag, start, contentStart: cursor, end };
}

function derChildren(bytes: Uint8Array, parent: DerNode): DerNode[] {
  const output: DerNode[] = [];
  let cursor = parent.contentStart;
  while (cursor < parent.end) {
    const child = readDer(bytes, cursor);
    output.push(child);
    cursor = child.end;
  }
  if (cursor !== parent.end) throw new CertificateError("The TLS secret contains malformed DER");
  return output;
}

function requireTag(node: DerNode | undefined, tag: number, description: string): DerNode {
  if (node === undefined || node.tag !== tag) {
    throw new CertificateError(`The TLS secret has an invalid ${description}`);
  }
  return node;
}

function derSlice(bytes: Uint8Array, node: DerNode): Uint8Array {
  return bytes.slice(node.start, node.end);
}

function derValue(bytes: Uint8Array, node: DerNode): Uint8Array {
  return bytes.slice(node.contentStart, node.end);
}

function decodeOid(bytes: Uint8Array, node: DerNode): string {
  requireTag(node, 0x06, "object identifier");
  const value = derValue(bytes, node);
  if (value.length === 0) throw new CertificateError("The TLS secret has an empty object identifier");
  const first = value[0] < 40 ? 0 : value[0] < 80 ? 1 : 2;
  const arcs = [first, value[0] - first * 40];
  let current = 0;
  let continued = false;
  for (const byte of value.slice(1)) {
    current = current * 128 + (byte & 0x7f);
    continued = (byte & 0x80) !== 0;
    if (!continued) {
      arcs.push(current);
      current = 0;
    }
  }
  if (continued) throw new CertificateError("The TLS secret has a truncated object identifier");
  return arcs.join(".");
}

function pemDer(pem: string, label: string): Uint8Array {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = pem.trim().match(
    new RegExp(`^-----BEGIN ${escaped}-----\\s+([A-Za-z0-9+/=\\s]+)-----END ${escaped}-----$`),
  );
  if (match === null) throw new CertificateError(`The TLS secret contains an invalid ${label} PEM`);
  const encoded = match[1].replace(/\s+/g, "");
  if (encoded.length === 0 || encoded.length % 4 !== 0) {
    throw new CertificateError(`The TLS secret contains an invalid ${label} PEM`);
  }
  try {
    const binary = atob(encoded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new CertificateError(`The TLS secret contains an invalid ${label} PEM`);
  }
}

function parseCertificateTime(bytes: Uint8Array, node: DerNode): Date {
  if (node.tag !== 0x17 && node.tag !== 0x18) {
    throw new CertificateError("The TLS secret certificate has an invalid validity time");
  }
  const value = new TextDecoder("ascii", { fatal: true }).decode(derValue(bytes, node));
  const match = node.tag === 0x17
    ? value.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/)
    : value.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
  if (match === null) throw new CertificateError("The TLS secret certificate has an invalid validity time");
  let year = Number(match[1]);
  const offset = node.tag === 0x17 ? 0 : 2;
  if (node.tag === 0x17) year += year >= 50 ? 1900 : 2000;
  const parts = node.tag === 0x17 ? match.slice(2) : match.slice(2);
  const date = new Date(Date.UTC(
    year,
    Number(parts[0]) - 1,
    Number(parts[1]),
    Number(parts[2]),
    Number(parts[3]),
    Number(parts[4]),
  ));
  // `offset` is intentionally retained as a sanity marker for the two formats;
  // all captured components after the year occupy the same match positions.
  void offset;
  if (Number.isNaN(date.getTime())) {
    throw new CertificateError("The TLS secret certificate has an invalid validity time");
  }
  return date;
}

function parseCertificate(pem: string): ParsedCertificate {
  const der = pemDer(pem, "CERTIFICATE");
  const outer = requireTag(readDer(der, 0), 0x30, "certificate sequence");
  if (outer.end !== der.length) throw new CertificateError("The TLS secret certificate has trailing DER");
  const certificateParts = derChildren(der, outer);
  if (certificateParts.length !== 3) throw new CertificateError("The TLS secret certificate structure is invalid");
  const tbs = requireTag(certificateParts[0], 0x30, "TBSCertificate");
  const signatureAlgorithm = requireTag(certificateParts[1], 0x30, "signature algorithm");
  const signatureParts = derChildren(der, signatureAlgorithm);
  const signatureOid = decodeOid(der, requireTag(signatureParts[0], 0x06, "signature OID"));
  const signatureBitString = requireTag(certificateParts[2], 0x03, "certificate signature");
  const encodedSignature = derValue(der, signatureBitString);
  if (encodedSignature.length < 2 || encodedSignature[0] !== 0) {
    throw new CertificateError("The TLS secret certificate signature is invalid");
  }

  const fields = derChildren(der, tbs);
  const base = fields[0]?.tag === 0xa0 ? 1 : 0;
  if (fields.length < base + 6) throw new CertificateError("The TLS secret TBSCertificate is incomplete");
  const issuerNode = fields[base + 2];
  const validity = requireTag(fields[base + 3], 0x30, "certificate validity");
  const subjectNode = fields[base + 4];
  const spkiNode = requireTag(fields[base + 5], 0x30, "SubjectPublicKeyInfo");
  const validityParts = derChildren(der, validity);
  if (validityParts.length !== 2) throw new CertificateError("The TLS secret certificate validity is invalid");
  const spkiParts = derChildren(der, spkiNode);
  const spkiAlgorithm = requireTag(spkiParts[0], 0x30, "public-key algorithm");
  const spkiAlgorithmParts = derChildren(der, spkiAlgorithm);
  const spkiOid = decodeOid(der, requireTag(spkiAlgorithmParts[0], 0x06, "public-key OID"));
  const curveOid = spkiOid === CERTIFICATE_OIDS.ecPublicKey && spkiAlgorithmParts[1]?.tag === 0x06
    ? decodeOid(der, spkiAlgorithmParts[1])
    : null;

  const dnsNames: string[] = [];
  let isCa = false;
  const extensionsWrapper = fields.slice(base + 6).find((node) => node.tag === 0xa3);
  if (extensionsWrapper !== undefined) {
    const extensionSequence = requireTag(
      derChildren(der, extensionsWrapper)[0],
      0x30,
      "certificate extensions",
    );
    for (const extension of derChildren(der, extensionSequence)) {
      const parts = derChildren(der, requireTag(extension, 0x30, "certificate extension"));
      const oid = decodeOid(der, requireTag(parts[0], 0x06, "extension OID"));
      const valueNode = parts.find((node) => node.tag === 0x04);
      if (valueNode === undefined) throw new CertificateError("The TLS secret certificate extension has no value");
      const value = derValue(der, valueNode);
      const decoded = readDer(value, 0);
      if (decoded.end !== value.length) throw new CertificateError("The TLS secret certificate extension is malformed");
      if (oid === OID.subjectAltName) {
        for (const name of derChildren(value, requireTag(decoded, 0x30, "subjectAltName"))) {
          if (name.tag === 0x82) {
            dnsNames.push(new TextDecoder("ascii", { fatal: true }).decode(derValue(value, name)));
          }
        }
      }
      if (oid === OID.basicConstraints) {
        const constraints = derChildren(value, requireTag(decoded, 0x30, "Basic Constraints"));
        isCa = constraints[0]?.tag === 0x01 && derValue(value, constraints[0]).some((byte) => byte !== 0);
      }
    }
  }

  return {
    der,
    tbs,
    signatureOid,
    signatureParameters: signatureParts[1] ?? null,
    signature: encodedSignature.slice(1),
    issuer: derSlice(der, issuerNode),
    subject: derSlice(der, subjectNode),
    notBefore: parseCertificateTime(der, validityParts[0]),
    notAfter: parseCertificateTime(der, validityParts[1]),
    spki: derSlice(der, spkiNode),
    spkiOid,
    curveOid,
    dnsNames,
    isCa,
  };
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function curveName(oid: string | null): "P-256" | "P-384" | "P-521" {
  if (oid === CERTIFICATE_OIDS.p256) return "P-256";
  if (oid === CERTIFICATE_OIDS.p384) return "P-384";
  if (oid === CERTIFICATE_OIDS.p521) return "P-521";
  throw new CertificateError("The TLS secret uses an unsupported elliptic curve");
}

async function privateKeyMatches(certificate: ParsedCertificate, privateKeyPem: string): Promise<boolean> {
  const privateDer = pemDer(privateKeyPem, "PRIVATE KEY");
  try {
    if (certificate.spkiOid === OID.rsaEncryption) {
      const algorithm: RsaHashedImportParams = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
      const [privateKey, publicKey] = await Promise.all([
        crypto.subtle.importKey("pkcs8", privateDer as Uint8Array<ArrayBuffer>, algorithm, true, ["sign"]),
        crypto.subtle.importKey("spki", certificate.spki as Uint8Array<ArrayBuffer>, algorithm, true, ["verify"]),
      ]);
      const [privateJwk, publicJwk] = await Promise.all([
        crypto.subtle.exportKey("jwk", privateKey),
        crypto.subtle.exportKey("jwk", publicKey),
      ]);
      return privateJwk.n === publicJwk.n && privateJwk.e === publicJwk.e;
    }
    if (certificate.spkiOid === CERTIFICATE_OIDS.ecPublicKey) {
      const algorithm: EcKeyImportParams = { name: "ECDSA", namedCurve: curveName(certificate.curveOid) };
      const [privateKey, publicKey] = await Promise.all([
        crypto.subtle.importKey("pkcs8", privateDer as Uint8Array<ArrayBuffer>, algorithm, true, ["sign"]),
        crypto.subtle.importKey("spki", certificate.spki as Uint8Array<ArrayBuffer>, algorithm, true, ["verify"]),
      ]);
      const [privateJwk, publicJwk] = await Promise.all([
        crypto.subtle.exportKey("jwk", privateKey),
        crypto.subtle.exportKey("jwk", publicKey),
      ]);
      return privateJwk.crv === publicJwk.crv && privateJwk.x === publicJwk.x && privateJwk.y === publicJwk.y;
    }
  } catch (error) {
    throw new CertificateError(`The TLS secret private key cannot be imported: ${(error as Error).message}`);
  }
  throw new CertificateError("The TLS secret certificate uses an unsupported public-key algorithm");
}

function ecdsaDerToRaw(signature: Uint8Array, componentLength: number): Uint8Array {
  const sequenceNode = requireTag(readDer(signature, 0), 0x30, "ECDSA signature");
  const parts = derChildren(signature, sequenceNode);
  if (sequenceNode.end !== signature.length || parts.length !== 2) {
    throw new CertificateError("The TLS secret certificate has an invalid ECDSA signature");
  }
  const output = new Uint8Array(componentLength * 2);
  for (const [index, part] of parts.entries()) {
    let value = derValue(signature, requireTag(part, 0x02, "ECDSA integer"));
    while (value.length > componentLength && value[0] === 0) value = value.slice(1);
    if (value.length > componentLength) throw new CertificateError("The TLS secret ECDSA signature is too large");
    output.set(value, index * componentLength + componentLength - value.length);
  }
  return output;
}

type CertificateHash = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";

function rsaSignatureHash(oid: string): CertificateHash | null {
  if (oid === CERTIFICATE_OIDS.sha1WithRsa) return "SHA-1";
  if (oid === OID.sha256WithRsaEncryption) return "SHA-256";
  if (oid === CERTIFICATE_OIDS.sha384WithRsa) return "SHA-384";
  if (oid === CERTIFICATE_OIDS.sha512WithRsa) return "SHA-512";
  return null;
}

function digestName(oid: string): CertificateHash {
  if (oid === CERTIFICATE_OIDS.sha1) return "SHA-1";
  if (oid === CERTIFICATE_OIDS.sha256) return "SHA-256";
  if (oid === CERTIFICATE_OIDS.sha384) return "SHA-384";
  if (oid === CERTIFICATE_OIDS.sha512) return "SHA-512";
  throw new CertificateError("The TLS secret RSA-PSS certificate uses an unsupported hash");
}

function pssParameters(
  certificate: ParsedCertificate,
): { hash: CertificateHash; saltLength: number } {
  if (certificate.signatureParameters === null) return { hash: "SHA-1", saltLength: 20 };
  const parameters = derChildren(
    certificate.der,
    requireTag(certificate.signatureParameters, 0x30, "RSA-PSS parameters"),
  );
  let hash: CertificateHash = "SHA-1";
  let mgfHash: CertificateHash = "SHA-1";
  let saltLength = 20;
  for (const parameter of parameters) {
    const inner = derChildren(certificate.der, parameter)[0];
    if (parameter.tag === 0xa0) {
      const algorithm = derChildren(
        certificate.der,
        requireTag(inner, 0x30, "RSA-PSS hash algorithm"),
      );
      hash = digestName(decodeOid(
        certificate.der,
        requireTag(algorithm[0], 0x06, "RSA-PSS hash OID"),
      ));
    } else if (parameter.tag === 0xa1) {
      const algorithm = derChildren(
        certificate.der,
        requireTag(inner, 0x30, "RSA-PSS mask algorithm"),
      );
      if (decodeOid(
        certificate.der,
        requireTag(algorithm[0], 0x06, "RSA-PSS mask OID"),
      ) !== CERTIFICATE_OIDS.mgf1) {
        throw new CertificateError("The TLS secret RSA-PSS certificate uses an unsupported mask");
      }
      const maskHash = derChildren(
        certificate.der,
        requireTag(algorithm[1], 0x30, "RSA-PSS mask hash"),
      );
      mgfHash = digestName(decodeOid(
        certificate.der,
        requireTag(maskHash[0], 0x06, "RSA-PSS mask hash OID"),
      ));
    } else if (parameter.tag === 0xa2) {
      const value = derValue(
        certificate.der,
        requireTag(inner, 0x02, "RSA-PSS salt length"),
      );
      saltLength = value.reduce((total, byte) => total * 256 + byte, 0);
    } else if (parameter.tag === 0xa3) {
      const value = derValue(
        certificate.der,
        requireTag(inner, 0x02, "RSA-PSS trailer field"),
      ).reduce((total, byte) => total * 256 + byte, 0);
      if (value !== 1) {
        throw new CertificateError("The TLS secret RSA-PSS certificate uses an unsupported trailer");
      }
    }
  }
  if (mgfHash !== hash) {
    throw new CertificateError("The TLS secret RSA-PSS mask hash does not match its signature hash");
  }
  if (!Number.isSafeInteger(saltLength) || saltLength < 0 || saltLength > 1024) {
    throw new CertificateError("The TLS secret RSA-PSS salt length is invalid");
  }
  return { hash, saltLength };
}

async function certificateIssuedBy(child: ParsedCertificate, issuer: ParsedCertificate): Promise<boolean> {
  if (!equalBytes(child.issuer, issuer.subject)) return false;
  const rsaHash = rsaSignatureHash(child.signatureOid);
  if (rsaHash !== null) {
    if (issuer.spkiOid !== OID.rsaEncryption) return false;
    const key = await crypto.subtle.importKey(
      "spki",
      issuer.spki as Uint8Array<ArrayBuffer>,
      { name: "RSASSA-PKCS1-v1_5", hash: rsaHash },
      false,
      ["verify"],
    );
    return crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      key,
      child.signature as Uint8Array<ArrayBuffer>,
      derSlice(child.der, child.tbs) as Uint8Array<ArrayBuffer>,
    );
  }
  if (child.signatureOid === CERTIFICATE_OIDS.rsaPss) {
    if (issuer.spkiOid !== OID.rsaEncryption) return false;
    const { hash, saltLength } = pssParameters(child);
    const key = await crypto.subtle.importKey(
      "spki",
      issuer.spki as Uint8Array<ArrayBuffer>,
      { name: "RSA-PSS", hash },
      false,
      ["verify"],
    );
    return crypto.subtle.verify(
      { name: "RSA-PSS", saltLength },
      key,
      child.signature as Uint8Array<ArrayBuffer>,
      derSlice(child.der, child.tbs) as Uint8Array<ArrayBuffer>,
    );
  }
  const ecdsaHash = child.signatureOid === CERTIFICATE_OIDS.ecdsaSha256
    ? "SHA-256"
    : child.signatureOid === CERTIFICATE_OIDS.ecdsaSha384
      ? "SHA-384"
      : child.signatureOid === CERTIFICATE_OIDS.ecdsaSha512
        ? "SHA-512"
        : null;
  if (ecdsaHash !== null) {
    if (issuer.spkiOid !== CERTIFICATE_OIDS.ecPublicKey) return false;
    const curve = curveName(issuer.curveOid);
    const componentLength = curve === "P-256" ? 32 : curve === "P-384" ? 48 : 66;
    const key = await crypto.subtle.importKey(
      "spki",
      issuer.spki as Uint8Array<ArrayBuffer>,
      { name: "ECDSA", namedCurve: curve },
      false,
      ["verify"],
    );
    return crypto.subtle.verify(
      { name: "ECDSA", hash: ecdsaHash },
      key,
      ecdsaDerToRaw(child.signature, componentLength) as Uint8Array<ArrayBuffer>,
      derSlice(child.der, child.tbs) as Uint8Array<ArrayBuffer>,
    );
  }
  throw new CertificateError("The TLS secret certificate uses an unsupported signature algorithm");
}

function hostnameMatches(hostname: string, pattern: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  const name = pattern.toLowerCase().replace(/\.$/, "");
  if (host === name) return true;
  if (!name.startsWith("*.") || name.slice(1).includes("*")) return false;
  const suffix = name.slice(2);
  return suffix.length > 0 && host.endsWith(`.${suffix}`) && host.split(".").length === suffix.split(".").length + 1;
}

/**
 * Validate an operator-supplied Secret Manager payload, including the key and
 * each supplied issuer signature. WebCrypto cannot query Chrome's trust-anchor
 * store, so final public-root trust remains covered by the browser acceptance
 * test; no unverified supplied link is treated as a trust anchor here.
 */
export async function validateSecretPayload(
  raw: string,
  expectedHostname: string,
  minimumValidityDays = 1,
): Promise<CertificateBundle> {
  if (new TextEncoder().encode(raw).length > 256_000) {
    throw new CertificateError("The TLS secret payload exceeds the 256 KB safety limit");
  }
  let document: Record<string, unknown>;
  try {
    document = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    throw new CertificateError("The TLS secret payload is not valid JSON");
  }

  const certificate = document.certificate_pem;
  const key = document.private_key_pem;
  const chain = document.certificate_chain_pem;

  if (typeof certificate !== "string" || !certificate.includes("BEGIN CERTIFICATE")) {
    throw new CertificateError("The TLS secret is missing a PEM certificate");
  }
  if (typeof key !== "string" || !key.includes("PRIVATE KEY")) {
    throw new CertificateError("The TLS secret is missing a PEM private key");
  }
  if (!Array.isArray(chain) || !chain.every((item) => typeof item === "string")) {
    throw new CertificateError("The TLS secret chain must be a list of PEM strings");
  }

  const leaf = parseCertificate(certificate);
  const issuers = (chain as string[]).map(parseCertificate);
  const now = Date.now();
  if (leaf.notBefore.getTime() > now + 60_000) {
    throw new CertificateError("The TLS secret certificate is not yet valid");
  }
  if (leaf.notAfter.getTime() <= now + minimumValidityDays * 86_400_000) {
    throw new CertificateError("The TLS secret certificate expires too soon");
  }
  if (leaf.isCa) throw new CertificateError("The TLS secret leaf certificate must not be a CA");
  if (!leaf.dnsNames.some((name) => hostnameMatches(expectedHostname, name))) {
    throw new CertificateError("The TLS secret certificate SAN does not match the hostname");
  }
  if (!(await privateKeyMatches(leaf, key))) {
    throw new CertificateError("The TLS secret certificate and private key do not match");
  }

  let child = leaf;
  for (const issuer of issuers) {
    if (issuer.notBefore.getTime() > now + 60_000 || issuer.notAfter.getTime() <= now) {
      throw new CertificateError("The TLS secret certificate chain contains an invalid issuer lifetime");
    }
    if (!issuer.isCa) throw new CertificateError("The TLS secret certificate chain issuer is not a CA");
    if (!equalBytes(child.issuer, issuer.subject)) {
      throw new CertificateError("The TLS secret certificate chain is not in leaf-to-root order");
    }
    if (!(await certificateIssuedBy(child, issuer))) {
      throw new CertificateError("The TLS secret certificate chain signature is invalid");
    }
    child = issuer;
  }
  if (equalBytes(child.issuer, child.subject) && !(await certificateIssuedBy(child, child))) {
    throw new CertificateError("The TLS secret certificate chain root signature is invalid");
  }

  return {
    certificatePem: certificate,
    certificateChainPem: chain as string[],
    privateKeyPem: key,
    hostname: expectedHostname,
    issuerResourceName: null,
  };
}

/**
 * Issue a self-signed root CA and leaf certificate bundle for rapid local PoC deployments.
 */
export async function issueLocalPoc(
  hostname: string,
  lifetimeDays = 30,
): Promise<CertificateBundle> {
  const leafKeyPair = (await crypto.subtle.generateKey(KEY_PARAMS, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

  const rootKeyPair = (await crypto.subtle.generateKey(KEY_PARAMS, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

  const leafSpki = new Uint8Array(await crypto.subtle.exportKey("spki", leafKeyPair.publicKey));
  const rootSpki = new Uint8Array(await crypto.subtle.exportKey("spki", rootKeyPair.publicKey));

  const now = new Date(Date.now() - 5 * 60 * 1000);
  const expire = new Date(Date.now() + lifetimeDays * 86400 * 1000);

  const rootSubject = sequence(
    set(sequence(objectIdentifier(OID.organizationName), utf8String("Secure Gateway Studio PoC"))),
    set(sequence(objectIdentifier(OID.commonName), utf8String(`Secure Gateway Studio PoC Root - ${hostname}`))),
  );

  const leafSubject = sequence(
    set(sequence(objectIdentifier(OID.commonName), utf8String(hostname))),
  );

  // 1. Root Certificate
  // BasicConstraints: CA=True, pathLen=0
  const rootBc = sequence(
    objectIdentifier(OID.basicConstraints),
    booleanValue(true),
    octetString(sequence(booleanValue(true), integer(0))),
  );
  // KeyUsage: digitalSignature, keyCertSign, cRLSign (0x86)
  const rootKu = sequence(
    objectIdentifier(OID.keyUsage),
    booleanValue(true),
    octetString(bitStringWithUnusedBits(Uint8Array.of(0x86), 1)),
  );

  const rootTbs = sequence(
    contextConstructed(0, integer(2)), // v3
    integer(Math.floor(Math.random() * 1000000000) + 1),
    sequence(objectIdentifier(OID.sha256WithRsaEncryption), nullValue()),
    rootSubject,
    sequence(utcTime(now), utcTime(expire)),
    rootSubject,
    rootSpki,
    contextConstructed(3, sequence(rootBc, rootKu)),
  );

  const rootSig = new Uint8Array(
    await crypto.subtle.sign(
      { name: "RSASSA-PKCS1-v1_5" },
      rootKeyPair.privateKey,
      rootTbs as Uint8Array<ArrayBuffer>,
    ),
  );

  const rootCertDer = sequence(
    rootTbs,
    sequence(objectIdentifier(OID.sha256WithRsaEncryption), nullValue()),
    bitString(rootSig),
  );

  // 2. Leaf Certificate
  // SAN: dNSName = hostname
  const san = sequence(
    objectIdentifier(OID.subjectAltName),
    octetString(sequence(contextPrimitive(2, new TextEncoder().encode(hostname)))),
  );
  // BasicConstraints: CA=False
  const leafBc = sequence(
    objectIdentifier(OID.basicConstraints),
    booleanValue(true),
    octetString(sequence(booleanValue(false))),
  );
  // KeyUsage: digitalSignature, keyEncipherment (0xa0)
  const leafKu = sequence(
    objectIdentifier(OID.keyUsage),
    booleanValue(true),
    octetString(bitStringWithUnusedBits(Uint8Array.of(0xa0), 5)),
  );

  const leafTbs = sequence(
    contextConstructed(0, integer(2)), // v3
    integer(Math.floor(Math.random() * 1000000000) + 2),
    sequence(objectIdentifier(OID.sha256WithRsaEncryption), nullValue()),
    rootSubject, // Issuer is Root
    sequence(utcTime(now), utcTime(expire)),
    leafSubject,
    leafSpki,
    contextConstructed(3, sequence(san, leafBc, leafKu)),
  );

  const leafSig = new Uint8Array(
    await crypto.subtle.sign(
      { name: "RSASSA-PKCS1-v1_5" },
      rootKeyPair.privateKey, // Signed by Root Key
      leafTbs as Uint8Array<ArrayBuffer>,
    ),
  );

  const leafCertDer = sequence(
    leafTbs,
    sequence(objectIdentifier(OID.sha256WithRsaEncryption), nullValue()),
    bitString(leafSig),
  );

  const leafPkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", leafKeyPair.privateKey));

  const leafCertPem = toPem("CERTIFICATE", leafCertDer);
  const rootCertPem = toPem("CERTIFICATE", rootCertDer);
  const privateKeyPem = toPem("PRIVATE KEY", leafPkcs8);

  return {
    certificatePem: leafCertPem,
    certificateChainPem: [rootCertPem],
    privateKeyPem,
    hostname,
    issuerResourceName: null,
  };
}
