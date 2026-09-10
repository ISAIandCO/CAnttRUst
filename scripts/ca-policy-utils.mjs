import { createHash, X509Certificate } from "node:crypto";

export function inspectRootBundle(raw) {
  const text = raw.toString("utf8");
  const blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (!blocks?.length || blocks.length > 32 || text.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, "").trim()) {
    throw new Error("Expected a bounded PEM certificate bundle");
  }
  const roots = [];
  for (const pem of blocks) {
    const cert = new X509Certificate(pem);
    if (!cert.ca) throw new Error("Non-CA certificate in root source");
    if (cert.subject !== cert.issuer) continue; // The official bundle also contains intermediates.
    if (!cert.verify(cert.publicKey)) throw new Error("Invalid root self-signature");
    if (!cert.subject.split("\n").includes("CN=Russian Trusted Root CA")) throw new Error("Unexpected root identity; manual investigation required");
    roots.push({
      derSha256: createHash("sha256").update(cert.raw).digest("hex"),
      spkiSha256: createHash("sha256").update(cert.publicKey.export({ type: "spki", format: "der" })).digest("hex"),
      subject: cert.subject, notBefore: new Date(cert.validFrom).toISOString(), notAfter: new Date(cert.validTo).toISOString(),
      pem: cert.toString()
    });
  }
  if (!roots.length) throw new Error("No Russian Trusted Root CA in source");
  return roots;
}

export function addRootFingerprints(existing, roots) {
  // A disappeared/expired root remains restricted for users who still trust it.
  return [...new Set([...existing, ...roots.map((root) => root.derSha256)])].sort();
}
