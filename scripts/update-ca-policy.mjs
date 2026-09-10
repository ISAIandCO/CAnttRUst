import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { downloadPolicy } from "./download-policy.mjs";
import { addRootFingerprints, inspectRootBundle } from "./ca-policy-utils.mjs";

// Official bundle linked by https://developers.sber.ru/help/certificates/how-to
const source = "https://gu-st.ru/content/Other/doc/russiantrustedca.pem";
const policyPath = new URL("../src/policy/protected-cas.json", import.meta.url);
const policy = JSON.parse(await readFile(policyPath, "utf8"));
const ca = policy.cas.find((item) => item.id === "russian-trusted-root-ca");
if (!ca?.rootDerSha256?.length) throw new Error("Missing existing Russian root policy");
const raw = await downloadPolicy(source, 128 * 1024);
const roots = inspectRootBundle(raw);
const additions = roots.filter((root) => !ca.rootDerSha256.includes(root.derSha256));
if (!additions.length) {
  console.log("No new root fingerprints; existing restrictions preserved");
  process.exit(0);
}
for (const root of additions) {
  if (Date.parse(root.notBefore) > Date.now() + 86400000 || Date.parse(root.notAfter) <= Date.now()) throw new Error("New root is not currently valid; manual investigation required");
}
const evidenceDir = new URL("../src/policy/ca-evidence/", import.meta.url);
await mkdir(evidenceDir, { recursive: true });
for (const root of additions) {
  await writeFile(new URL(`${root.derSha256}.pem`, evidenceDir), root.pem);
  const { pem, ...metadata } = root;
  await writeFile(new URL(`${root.derSha256}.json`, evidenceDir), `${JSON.stringify({ ...metadata, source, sourceSha256: createHash("sha256").update(raw).digest("hex") }, null, 2)}\n`);
}
ca.rootDerSha256 = addRootFingerprints(ca.rootDerSha256, roots);
await writeFile(policyPath, `${JSON.stringify(policy, null, 2)}\n`);
console.log("Root restriction candidates added:", additions.map((root) => root.derSha256));
