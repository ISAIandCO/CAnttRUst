import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { ACCEPTED_OPERATORS, hasCtPolicyChanged, normalizedCtList, validateCtUpdate } from "./policy-utils.mjs";
import { downloadPolicy } from "./download-policy.mjs";

const source = "https://browser-resources.s3.yandex.net/ctlog/ctlog.json";
const path = new URL("../src/policy/ct/yandex-nuc-log-list.json", import.meta.url);
const lockPath = new URL("../src/policy/ct/ct-policy-lock.json", import.meta.url);
const previous = JSON.parse(await readFile(path, "utf8"));
const raw = await downloadPolicy(source);
const next = normalizedCtList(JSON.parse(raw.toString("utf8")));
const changes = validateCtUpdate(previous, next);

if (!hasCtPolicyChanged(previous, next)) {
  console.log("No accepted CT policy changes");
  process.exit(0);
}

console.log("Added:", changes.added);
console.log("Removed:", changes.removed);

await writeFile(path, `${JSON.stringify(next, null, 2)}\n`);
await writeFile(lockPath, `${JSON.stringify({
  schema: 1,
  source,
  retrievedAt: new Date().toISOString(),
  sourceSha256: createHash("sha256").update(raw).digest("hex"),
  acceptedOperators: [...ACCEPTED_OPERATORS]
}, null, 2)}\n`);
