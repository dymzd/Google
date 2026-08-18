/**
 * Certificate issuance. Port of `providers/certificates.py`.
 *
 * The Python implementation generates an RSA key in process and sends only a
 * CSR to CA Service; the private key never leaves the machine. That property is
 * preserved and strengthened here: WebCrypto generates the key non-extractable
 * wherever the flow allows it, so the key material cannot be read back by any
 * script at all.
 *
 * The one place extractability is unavoidable is the enterprise and PoC flows,
 * which must write the private key into Secret Manager for the offload VM to
 * read at boot. That is inherent to the architecture -- the VM needs the key --
 * not a weakening introduced by the port.
 *
 * DER is assembled by `domain/asn1.ts` rather than a PKI library. See that file
 * for why.
 */

import {
  OID,
  bitString,
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
  nullValue,
} from "../domain/asn1.ts";
import type { Transport } from "./executor.ts";

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
  },
): Promise<CertificateBundle> {
  const { csrPem, privateKeyPem } = await generateKeyAndCsr(options.hostname);

  const response = await transport.requestJson(
    "POST",
    `https://privateca.googleapis.com/v1/${options.caPool}/certificates`,
    {
      params: { certificateId: options.certificateId },
      jsonBody: {
        pemCsr: csrPem,
        lifetime: `${options.lifetimeDays * 86400}s`,
        issuingCertificateAuthority: options.caName,
      },
    },
  );

  const certificate = response.payload.pemCertificate;
  if (typeof certificate !== "string" || certificate === "") {
    throw new CertificateError("Private CA returned no certificate");
  }
  const chain = response.payload.pemCertificateChain;
  if (!Array.isArray(chain) || !chain.every((item) => typeof item === "string")) {
    throw new CertificateError("Private CA returned an invalid certificate chain");
  }
  const issuer = response.payload.name;

  return {
    certificatePem: certificate,
    certificateChainPem: chain as string[],
    privateKeyPem,
    hostname: options.hostname,
    issuerResourceName:
      typeof issuer === "string" && issuer !== ""
        ? issuer
        : `${options.caPool}/certificates/${options.certificateId}`,
  };
}

/**
 * Validate an operator-supplied Secret Manager payload.
 *
 * Checks the contract the startup script depends on. It deliberately does not
 * verify the chain cryptographically -- that is the CA's job and the browser's
 * -- but a payload missing a field or naming the wrong host would leave the
 * offload VM serving a certificate no client accepts, and that is worth
 * catching before Apply rather than at T07.
 */
export function validateSecretPayload(
  raw: string,
  expectedHostname: string,
): CertificateBundle {
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

  return {
    certificatePem: certificate,
    certificateChainPem: chain as string[],
    privateKeyPem: key,
    hostname: expectedHostname,
    issuerResourceName: null,
  };
}
