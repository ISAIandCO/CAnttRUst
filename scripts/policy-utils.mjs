import { createHash, createPublicKey } from "node:crypto";

export const ACCEPTED_OPERATORS = new Set([
  "Yandex", "VK LLC", "The Ministry of Digital Development and Communications"
]);
const STATES = new Set(["pending", "qualified", "usable", "readonly", "retired", "rejected"]);
const timestamp = (value) => typeof value === "string" && /^\d{4}-\d\d-\d\dT.*Z$/.test(value) && Number.isFinite(Date.parse(value));

export function validateCtList(list) {
  if (!list || typeof list.version !== "string" || !/^\d+(\.\d+)*$/.test(list.version) || !timestamp(list.log_list_timestamp) || !Array.isArray(list.operators) || !list.operators.length) {
    throw new Error("Invalid CT list schema");
  }
  const ids = new Set();
  const operators = new Set();
  for (const operator of list.operators) {
    if (!ACCEPTED_OPERATORS.has(operator.name) || operators.has(operator.name) || !Array.isArray(operator.logs) || !operator.logs.length) {
      throw new Error(`Unexpected, empty or duplicate CT operator: ${operator?.name ?? "missing"}`);
    }
    operators.add(operator.name);
    if (operator.tiled_logs?.length) throw new Error("Tiled CT logs require explicit implementation review");
    for (const log of operator.logs) {
      if (typeof log.key !== "string" || typeof log.log_id !== "string") throw new Error("Missing CT key or log ID");
      const spki = Buffer.from(log.key, "base64");
      const id = createHash("sha256").update(spki).digest("base64");
      if (id !== log.log_id || spki.toString("base64") !== log.key) throw new Error(`log_id/key mismatch: ${log.description}`);
      if (ids.has(id)) throw new Error(`Duplicate log_id: ${id}`);
      ids.add(id);
      const key = createPublicKey({ key: spki, format: "der", type: "spki" });
      if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") throw new Error(`Unsupported log key: ${log.description}`);
      const interval = log.temporal_interval;
      if (!timestamp(interval?.start_inclusive) || !timestamp(interval?.end_exclusive) || Date.parse(interval.start_inclusive) >= Date.parse(interval.end_exclusive)) {
        throw new Error(`Invalid temporal interval: ${log.description}`);
      }
      const states = Object.keys(log.state ?? {});
      if (states.length !== 1 || !STATES.has(states[0]) || !timestamp(log.state[states[0]]?.timestamp)) throw new Error(`Invalid CT state: ${log.description}`);
    }
  }
  if (!operators.has("Yandex")) throw new Error("Required Yandex operator is missing");
  return ids;
}

export function normalizedCtList(list) {
  // This endpoint is the NUC list, not the global WebPKI list. New operators need review.
  validateCtList(list);
  return {
    version: list.version,
    log_list_timestamp: list.log_list_timestamp,
    operators: list.operators.map((operator) => ({
      name: operator.name,
      email: [...(operator.email ?? [])].sort(),
      logs: [...operator.logs].sort((a, b) => a.log_id.localeCompare(b.log_id)),
      tiled_logs: []
    })).sort((a, b) => a.name.localeCompare(b.name))
  };
}

export function effectiveCtPolicy(list) {
  return list.operators.flatMap((operator) => operator.logs.map((log) => ({
    operator: operator.name, logId: log.log_id, key: log.key,
    start: log.temporal_interval.start_inclusive, end: log.temporal_interval.end_exclusive,
    state: Object.keys(log.state)[0], stateSince: Object.values(log.state)[0].timestamp
  }))).sort((a, b) => a.logId.localeCompare(b.logId));
}

export function hasCtPolicyChanged(previous, next) {
  return JSON.stringify(effectiveCtPolicy(previous)) !== JSON.stringify(effectiveCtPolicy(next));
}

export function validateCtUpdate(previous, next, now = Date.now()) {
  const oldIds = validateCtList(previous);
  const newIds = validateCtList(next);
  if (Date.parse(next.log_list_timestamp) < Date.parse(previous.log_list_timestamp) || Date.parse(next.log_list_timestamp) > now + 86400000) throw new Error("CT source timestamp rollback or future timestamp");
  const before = previous.version.split(".").map(Number);
  const after = next.version.split(".").map(Number);
  for (let i = 0; i < Math.max(before.length, after.length); i++) {
    if ((after[i] ?? 0) < (before[i] ?? 0)) throw new Error("CT source version rollback");
    if ((after[i] ?? 0) > (before[i] ?? 0)) break;
  }
  const removed = [...oldIds].filter((id) => !newIds.has(id));
  if (removed.length > oldIds.size / 2) throw new Error("More than half of CT logs disappeared; manual investigation required");
  const yandex = next.operators.find((operator) => operator.name === "Yandex");
  if (!yandex.logs.some((log) => log.state.usable && Date.parse(log.state.usable.timestamp) <= now && Date.parse(log.temporal_interval.end_exclusive) > now)) throw new Error("No usable unexpired Yandex shard; manual investigation required");
  return { added: [...newIds].filter((id) => !oldIds.has(id)), removed };
}
