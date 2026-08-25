import { readFile } from "node:fs/promises";
import { validateCtList } from "./policy-utils.mjs";

const cas = JSON.parse(await readFile(new URL("../src/policy/protected-cas.json", import.meta.url), "utf8"));
const logs = JSON.parse(await readFile(new URL("../src/policy/ct/yandex-nuc-log-list.json", import.meta.url), "utf8"));
const ids = new Set();

if (cas.schema !== 1 || !Array.isArray(cas.cas) || !cas.cas.length) throw new Error("Invalid CA policy");
for (const ca of cas.cas) {
  if (ids.has(ca.id)) throw new Error(`Duplicate CA id: ${ca.id}`);
  ids.add(ca.id);
  if (!ca.rootDerSha256.every((value) => /^[0-9a-f]{64}$/.test(value))) throw new Error(`Invalid fingerprint: ${ca.id}`);
  if (!ca.allowedDnsZones.every((zone) => /^(ru|su|xn--p1ai)$/.test(zone))) throw new Error(`Invalid zone: ${ca.id}`);
}
validateCtList(logs);
console.log(`Verified ${cas.cas.length} protected CA and ${logs.operators.flatMap((item) => item.logs).length} CT logs`);
