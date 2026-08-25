import { normalizeSha256, sha256Hex } from "../../core/fingerprint";
import type { CertificateSnapshot } from "../../core/types";

function bytes(value: unknown): Uint8Array {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (Array.isArray(value)) return Uint8Array.from(value as number[]);
  throw new Error("Firefox did not return rawDER");
}

export type TlsInspection = {
  state: string;
  certificates: CertificateSnapshot[];
  firefoxCtStatus?: string;
  protocolVersion?: string;
  hsts?: boolean;
  usedEch?: boolean;
  usedOcsp?: boolean;
};

export async function inspectTls(requestId: string): Promise<TlsInspection> {
  const info = await browser.webRequest.getSecurityInfo(requestId, { certificateChain: true, rawDER: true });
  const certificates = await Promise.all((info.certificates ?? []).map(async (certificate) => {
    const rawDER = bytes(certificate.rawDER);
    const snapshot: CertificateSnapshot = {
      rawDER,
      derSha256: await sha256Hex(rawDER),
      subject: certificate.subject,
      issuer: certificate.issuer,
      isBuiltInRoot: certificate.isBuiltInRoot,
      validityStart: certificate.validity.start,
      validityEnd: certificate.validity.end
    };
    const firefoxSha256 = normalizeSha256(certificate.fingerprint.sha256);
    if (firefoxSha256) snapshot.firefoxSha256 = firefoxSha256;
    return snapshot;
  }));
  const result: TlsInspection = { state: info.state, certificates };
  if (info.certificateTransparencyStatus) result.firefoxCtStatus = info.certificateTransparencyStatus;
  if (info.protocolVersion) result.protocolVersion = info.protocolVersion;
  if (info.hsts !== undefined) result.hsts = info.hsts;
  if (info.usedEch !== undefined) result.usedEch = info.usedEch;
  if (info.usedOcsp !== undefined) result.usedOcsp = info.usedOcsp;
  return result;
}
