import { normalizeSha256 } from "./fingerprint";
import type { CertificateSnapshot, ProtectedCa, ProtectedCaMatch } from "./types";

export function matchProtectedCA(certificates: CertificateSnapshot[], policy: ProtectedCa[]): ProtectedCaMatch | null {
  for (let certificateIndex = 0; certificateIndex < certificates.length; certificateIndex += 1) {
    const certificate = certificates[certificateIndex];
    if (!certificate) continue;
    for (const ca of policy) {
      if (ca.rootDerSha256.some((value) => normalizeSha256(value) === certificate.derSha256)) {
        return { ca, certificate, certificateIndex };
      }
    }
  }
  return null;
}
