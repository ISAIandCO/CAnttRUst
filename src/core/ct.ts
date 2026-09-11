import { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
import { Certificate } from "@peculiar/asn1-x509";
import type { CtMode, CtVerdict, ValidSct } from "./types";

const SCT_OID = "1.3.6.1.4.1.11129.2.4.2";
const MAX_FUTURE_SKEW_MS = 24 * 60 * 60 * 1000;

type Sct = {
  raw: Uint8Array;
  logId: Uint8Array;
  timestamp: number;
  extensions: Uint8Array;
  hashAlgorithm: number;
  signatureAlgorithm: number;
  signature: Uint8Array;
};

export type CtLog = {
  operator: string;
  description: string;
  key: string;
  logId: string;
  startInclusive: number;
  endExclusive: number;
  state: { name: string; since: number };
};

// Our NUC policy: retired/read-only logs may attest earlier SCTs;
// rejected logs never count, including signatures issued before rejection.
export function isSctFromAcceptedState(log: CtLog, timestamp: number): boolean {
  if (!Number.isFinite(log.state?.since)) return false;
  switch (log.state.name) {
    case "usable": return timestamp >= log.state.since;
    case "readonly":
    case "retired": return timestamp < log.state.since;
    default: return false;
  }
}

function readU16(data: Uint8Array, offset: number): number {
  if (offset + 2 > data.length) throw new Error("truncated uint16");
  return (data[offset]! << 8) | data[offset + 1]!;
}

function readU64(data: Uint8Array, offset: number): number {
  if (offset + 8 > data.length) throw new Error("truncated uint64");
  let value = 0n;
  for (let i = 0; i < 8; i += 1) value = (value << 8n) | BigInt(data[offset + i]!);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("uint64 exceeds safe range");
  return Number(value);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

export function parseSctList(data: Uint8Array): Sct[] {
  const total = readU16(data, 0);
  if (total !== data.length - 2 || total === 0) throw new Error("invalid SCT list length");
  const result: Sct[] = [];
  let offset = 2;
  while (offset < data.length) {
    const length = readU16(data, offset);
    offset += 2;
    if (!length || offset + length > data.length) throw new Error("invalid SCT length");
    const raw = data.slice(offset, offset + length);
    offset += length;
    let cursor = 0;
    if (raw[cursor++] !== 0) throw new Error("unsupported SCT version");
    if (cursor + 32 > raw.length) throw new Error("truncated log id");
    const logId = raw.slice(cursor, cursor + 32);
    cursor += 32;
    const timestamp = readU64(raw, cursor);
    cursor += 8;
    const extensionsLength = readU16(raw, cursor);
    cursor += 2;
    if (cursor + extensionsLength + 4 > raw.length) throw new Error("truncated SCT extensions");
    const extensions = raw.slice(cursor, cursor + extensionsLength);
    cursor += extensionsLength;
    const hashAlgorithm = raw[cursor++]!;
    const signatureAlgorithm = raw[cursor++]!;
    const signatureLength = readU16(raw, cursor);
    cursor += 2;
    if (!signatureLength || cursor + signatureLength !== raw.length) throw new Error("invalid SCT signature length");
    const signature = raw.slice(cursor);
    if (result.some((item) => bytesEqual(item.raw, raw))) throw new Error("duplicate SCT");
    result.push({ raw, logId, timestamp, extensions, hashAlgorithm, signatureAlgorithm, signature });
  }
  return result;
}

function derLength(data: Uint8Array, offset: number): { length: number; bytes: number } {
  const first = data[offset];
  if (first === undefined) throw new Error("truncated DER length");
  if (first < 0x80) return { length: first, bytes: 1 };
  const count = first & 0x7f;
  if (count === 0 || count > 4 || offset + count >= data.length) throw new Error("invalid DER length");
  if (data[offset + 1] === 0) throw new Error("non-minimal DER length");
  let length = 0;
  for (let i = 1; i <= count; i += 1) length = (length << 8) | data[offset + i]!;
  if (length < 0x80) throw new Error("non-minimal DER length");
  return { length, bytes: count + 1 };
}

function unwrapDerOctetString(data: Uint8Array): Uint8Array {
  if (data[0] !== 0x04) throw new Error("SCT extension is not an OCTET STRING");
  const length = derLength(data, 1);
  const start = 1 + length.bytes;
  if (start + length.length !== data.length) throw new Error("invalid OCTET STRING length");
  return data.slice(start);
}

function trimPositiveInteger(integer: Uint8Array, width: number): Uint8Array {
  if (!integer.length || (integer[0]! & 0x80) !== 0) throw new Error("negative ECDSA integer");
  if (integer.length > 1 && integer[0] === 0 && (integer[1]! & 0x80) === 0) throw new Error("non-minimal ECDSA integer");
  const value = integer[0] === 0 ? integer.slice(1) : integer;
  if (value.length > width) throw new Error("oversized ECDSA integer");
  const result = new Uint8Array(width);
  result.set(value, width - value.length);
  return result;
}

export function ecdsaDerSignatureToRaw(der: Uint8Array, width = 32): Uint8Array {
  if (der[0] !== 0x30) throw new Error("ECDSA signature is not a sequence");
  const sequenceLength = derLength(der, 1);
  let offset = 1 + sequenceLength.bytes;
  if (offset + sequenceLength.length !== der.length || der[offset++] !== 0x02) throw new Error("invalid ECDSA sequence");
  const rLength = derLength(der, offset);
  offset += rLength.bytes;
  const r = der.slice(offset, offset + rLength.length);
  offset += rLength.length;
  if (offset >= der.length || der[offset++] !== 0x02) throw new Error("missing ECDSA s");
  const sLength = derLength(der, offset);
  offset += sLength.bytes;
  const s = der.slice(offset, offset + sLength.length);
  offset += sLength.length;
  if (offset !== der.length) throw new Error("trailing ECDSA data");
  const raw = new Uint8Array(width * 2);
  raw.set(trimPositiveInteger(r, width), 0);
  raw.set(trimPositiveInteger(s, width), width);
  return raw;
}

function encodeLength(value: number, bytes: number): Uint8Array {
  const result = new Uint8Array(bytes);
  for (let i = bytes - 1, current = value; i >= 0; i -= 1, current >>>= 8) result[i] = current & 0xff;
  if (value >= 2 ** (bytes * 8)) throw new Error("length overflow");
  return result;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function encodeU64(value: number): Uint8Array {
  let current = BigInt(value);
  const result = new Uint8Array(8);
  for (let i = 7; i >= 0; i -= 1) {
    result[i] = Number(current & 0xffn);
    current >>= 8n;
  }
  return result;
}

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function reconstructPrecertificate(leafDer: Uint8Array): { tbs: Uint8Array; sctList: Uint8Array; notAfter: number } {
  const certificate = AsnParser.parse(leafDer, Certificate);
  const extensions = certificate.tbsCertificate.extensions ?? [];
  const sctIndex = extensions.findIndex((extension) => extension.extnID === SCT_OID);
  if (sctIndex < 0) throw new Error("missing SCT extension");
  const [sct] = extensions.splice(sctIndex, 1);
  if (!sct) throw new Error("missing SCT extension");
  return {
    tbs: new Uint8Array(AsnSerializer.serialize(certificate.tbsCertificate)),
    sctList: unwrapDerOctetString(new Uint8Array(sct.extnValue.buffer)),
    notAfter: certificate.tbsCertificate.validity.notAfter.getTime().getTime()
  };
}

function issuerSpki(issuerDer: Uint8Array): Uint8Array {
  const certificate = AsnParser.parse(issuerDer, Certificate);
  return new Uint8Array(AsnSerializer.serialize(certificate.tbsCertificate.subjectPublicKeyInfo));
}

async function verifySct(sct: Sct, log: CtLog, tbs: Uint8Array, issuerHash: Uint8Array): Promise<boolean> {
  if (sct.hashAlgorithm !== 4 || sct.signatureAlgorithm !== 3) throw new Error("unsupported SCT signature algorithm");
  const input = concat(
    Uint8Array.of(0, 0),
    encodeU64(sct.timestamp),
    Uint8Array.of(0, 1),
    issuerHash,
    encodeLength(tbs.length, 3),
    tbs,
    encodeLength(sct.extensions.length, 2),
    sct.extensions
  );
  const key = await crypto.subtle.importKey("spki", Uint8Array.from(fromBase64(log.key)).buffer, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    Uint8Array.from(ecdsaDerSignatureToRaw(sct.signature)).buffer,
    Uint8Array.from(input).buffer
  );
}

export async function verifyEmbeddedScts(leafDer: Uint8Array, issuerDer: Uint8Array | undefined, logs: CtLog[], mode: CtMode): Promise<CtVerdict> {
  if (!issuerDer) return { status: "indeterminate", reason: "issuer_not_found" };
  try {
    const { tbs, sctList, notAfter } = reconstructPrecertificate(leafDer);
    const scts = parseSctList(sctList);
    const spki = issuerSpki(issuerDer);
    const issuerHash = new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(spki).buffer));
    const valid: ValidSct[] = [];
    let matchedLog = false;
    let outsideInterval = false;
    let untrustedState = false;
    let invalidSignature = false;
    let unsupportedAlgorithm = false;
    for (const sct of scts) {
      const log = logs.find((candidate) => bytesEqual(fromBase64(candidate.logId), sct.logId));
      if (!log) continue;
      matchedLog = true;
      if (!isSctFromAcceptedState(log, sct.timestamp)) {
        untrustedState = true;
        continue;
      }
      if (notAfter < log.startInclusive || notAfter >= log.endExclusive || sct.timestamp > notAfter || sct.timestamp > Date.now() + MAX_FUTURE_SKEW_MS) {
        outsideInterval = true;
        continue;
      }
      try {
        if (await verifySct(sct, log, tbs, issuerHash)) valid.push({ logId: log.logId, operator: log.operator, timestamp: sct.timestamp });
        else invalidSignature = true;
      } catch (error) {
        if (error instanceof Error && error.message.includes("unsupported")) unsupportedAlgorithm = true;
        else invalidSignature = true;
      }
    }
    if (unsupportedAlgorithm && !valid.length) return { status: "indeterminate", reason: "unsupported_signature_algorithm" };
    const operators = new Set(valid.map((item) => item.operator));
    const yandex = operators.has("Yandex");
    const satisfied = mode === "yandex-required" ? yandex && valid.length >= 1 : yandex && valid.length >= 2 && operators.size >= 2;
    if (satisfied) return { status: "valid", validScts: valid, policy: mode };
    const observedLogIds = scts.map((item) => base64(item.logId));
    if (!matchedLog) return { status: "invalid", reason: "no_trusted_log", observedLogIds };
    if (untrustedState && !valid.length) return { status: "invalid", reason: "log_not_accepted_at_sct_time", observedLogIds };
    if (outsideInterval && !valid.length) return { status: "invalid", reason: "sct_outside_log_interval", observedLogIds };
    if (invalidSignature && !valid.length) return { status: "invalid", reason: "invalid_sct_signature", observedLogIds };
    return { status: "invalid", reason: "policy_not_satisfied", observedLogIds };
  } catch (error) {
    if (error instanceof Error && error.message === "missing SCT extension") {
      return { status: "invalid", reason: "missing_embedded_sct", observedLogIds: [] };
    }
    return { status: "indeterminate", reason: "certificate_parse_error" };
  }
}
