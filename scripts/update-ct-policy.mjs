import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { ACCEPTED_OPERATORS, hasCtPolicyChanged, normalizedCtList, validateCtList } from "./policy-utils.mjs";

const source = "https://browser-resources.s3.yandex.net/ctlog/ctlog.json";
const path = new URL("../src/policy/ct/yandex-nuc-log-list.json", import.meta.url);
const lockPath = new URL("../src/policy/ct/ct-policy-lock.json", import.meta.url);
const previous = JSON.parse(await readFile(path, "utf8"));
const response = await fetch(source);
if (!response.ok) throw new Error(`CT policy download failed: ${response.status}`);
const raw = Buffer.from(await response.arrayBuffer());
const next = normalizedCtList(JSON.parse(raw.toString("utf8")));
validateCtList(next);

if (!hasCtPolicyChanged(previous, next)) {
  console.log("No accepted CT policy changes");
  process.exit(0);
}

const oldIds = new Set(previous.operators.flatMap((operator) => operator.logs.map((log) => log.log_id)));
const newIds = new Set(next.operators.flatMap((operator) => operator.logs.map((log) => log.log_id)));
console.log("Added:", [...newIds].filter((id) => !oldIds.has(id)));
console.log("Removed:", [...oldIds].filter((id) => !newIds.has(id)));

await writeFile(path, `${JSON.stringify(next, null, 2)}\n`);
await writeFile(lockPath, `${JSON.stringify({
  schema: 1,
  source,
  retrievedAt: new Date().toISOString(),
  sourceSha256: createHash("sha256").update(raw).digest("hex"),
  acceptedOperators: [...ACCEPTED_OPERATORS]
}, null, 2)}\n`);
