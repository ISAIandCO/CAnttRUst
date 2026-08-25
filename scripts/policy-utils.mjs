import { createHash, createPublicKey } from "node:crypto";

export const ACCEPTED_OPERATORS = new Set([
  "Yandex",
  "VK LLC",
  "The Ministry of Digital Development and Communications"
]);

export function validateCtList(list) {
  if (!list || typeof list.version !== "string" || !Array.isArray(list.operators)) {
    throw new Error("Invalid CT list schema");
  }
  const ids = new Set();
  for (const operator of list.operators) {
    if (!ACCEPTED_OPERATORS.has(operator.name) || !Array.isArray(operator.logs)) {
      throw new Error(`Unexpected CT operator: ${operator?.name ?? "missing"}`);
    }
    for (const log of operator.logs) {
      const spki = Buffer.from(log.key, "base64");
      const id = createHash("sha256").update(spki).digest("base64");
      if (id !== log.log_id) throw new Error(`log_id mismatch: ${log.description}`);
      if (ids.has(id)) throw new Error(`Duplicate log_id: ${id}`);
      ids.add(id);
      const key = createPublicKey({ key: spki, format: "der", type: "spki" });
      if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
        throw new Error(`Unsupported log key: ${log.description}`);
      }
      const start = Date.parse(log.temporal_interval?.start_inclusive);
      const end = Date.parse(log.temporal_interval?.end_exclusive);
      if (!Number.isFinite(start) || !Number.isFinite(end) || start >= end) {
        throw new Error(`Invalid temporal interval: ${log.description}`);
      }
    }
  }
  return ids;
}

export function normalizedCtList(list) {
  return {
    version: list.version,
    log_list_timestamp: list.log_list_timestamp,
    operators: list.operators
      .filter((operator) => ACCEPTED_OPERATORS.has(operator.name))
      .map((operator) => ({
        name: operator.name,
        email: [...(operator.email ?? [])].sort(),
        logs: [...operator.logs].sort((a, b) => a.log_id.localeCompare(b.log_id)),
        tiled_logs: []
      }))
      .sort((a, b) => a.name.localeCompare(b.name))
  };
}

export function hasCtPolicyChanged(previous, next) {
  return JSON.stringify([previous.version, previous.operators]) !==
    JSON.stringify([next.version, next.operators]);
}
