/**
 * Minimal DER encoder, enough to build a PKCS#10 certificate signing request.
 *
 * WebCrypto generates keys and signs, but has no notion of X.509 or PKCS#10, so
 * something has to assemble the DER. The alternative was a PKI library; this is
 * roughly 120 lines against a dependency that a Web Store reviewer and a
 * customer auditing the published source would both have to take on trust.
 * Given the extension's whole security argument rests on being readable, the
 * dependency is the more expensive option.
 *
 * Scope is deliberately narrow: only the structures a CSR needs. It is not a
 * general ASN.1 implementation and should not grow into one.
 */

const encoder = new TextEncoder();

function encodeLength(length: number): Uint8Array {
  // Short form for < 128, long form otherwise: the leading byte carries the
  // count of length bytes with the high bit set.
  if (length < 0x80) return Uint8Array.of(length);
  const bytes: number[] = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>>= 8;
  }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function tlv(tag: number, ...contents: Uint8Array[]): Uint8Array {
  const body = concat(...contents);
  const length = encodeLength(body.length);
  const output = new Uint8Array(1 + length.length + body.length);
  output[0] = tag;
  output.set(length, 1);
  output.set(body, 1 + length.length);
  return output;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

export const sequence = (...contents: Uint8Array[]): Uint8Array => tlv(0x30, ...contents);
export const set = (...contents: Uint8Array[]): Uint8Array => tlv(0x31, ...contents);
export const octetString = (contents: Uint8Array): Uint8Array => tlv(0x04, contents);
export const utf8String = (value: string): Uint8Array => tlv(0x0c, encoder.encode(value));
export const nullValue = (): Uint8Array => Uint8Array.of(0x05, 0x00);

/** INTEGER, two's complement with a leading zero when the top bit is set. */
export function integer(value: number): Uint8Array {
  if (value === 0) return tlv(0x02, Uint8Array.of(0));
  const bytes: number[] = [];
  let remaining = value;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining = Math.floor(remaining / 256);
  }
  if ((bytes[0] & 0x80) !== 0) bytes.unshift(0);
  return tlv(0x02, Uint8Array.from(bytes));
}

/** BIT STRING with no unused trailing bits. */
export function bitString(contents: Uint8Array): Uint8Array {
  return tlv(0x03, Uint8Array.of(0x00), contents);
}

/** OBJECT IDENTIFIER from dotted decimal. */
export function objectIdentifier(dotted: string): Uint8Array {
  const parts = dotted.split(".").map(Number);
  // The first two arcs share one byte: 40 * first + second.
  const body: number[] = [40 * parts[0] + parts[1]];
  for (const arc of parts.slice(2)) {
    const chunk: number[] = [arc & 0x7f];
    let remaining = Math.floor(arc / 128);
    while (remaining > 0) {
      chunk.unshift((remaining & 0x7f) | 0x80);
      remaining = Math.floor(remaining / 128);
    }
    body.push(...chunk);
  }
  return tlv(0x06, Uint8Array.from(body));
}

/** Context-specific constructed tag, e.g. [0] on the CSR attributes. */
export function contextConstructed(number: number, ...contents: Uint8Array[]): Uint8Array {
  return tlv(0xa0 | number, ...contents);
}

/** Context-specific primitive tag, used for the dNSName in a SAN. */
export function contextPrimitive(number: number, contents: Uint8Array): Uint8Array {
  return tlv(0x80 | number, contents);
}

export const OID = {
  commonName: "2.5.4.3",
  rsaEncryption: "1.2.840.113549.1.1.1",
  sha256WithRsaEncryption: "1.2.840.113549.1.1.11",
  extensionRequest: "1.2.840.113549.1.9.14",
  subjectAltName: "2.5.29.17",
} as const;

/** PEM wrapper: base64 in 64-character lines with the usual armour. */
export function toPem(label: string, der: Uint8Array): string {
  let binary = "";
  for (const byte of der) binary += String.fromCharCode(byte);
  const body = btoa(binary).replace(/(.{64})/g, "$1\n").replace(/\n$/, "");
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}
