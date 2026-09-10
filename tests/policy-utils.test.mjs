import { describe, expect, it } from "vitest";
import ctList from "./fixtures/ct-log-list.json" with { type: "json" };
import { hasCtPolicyChanged, normalizedCtList, validateCtList, validateCtUpdate } from "../scripts/policy-utils.mjs";
const now = Date.parse("2026-09-10T00:00:00Z");

describe("CT policy monitoring", () => {
  it("ignores metadata, JSON key order and log/operator ordering", () => {
    const next = structuredClone(ctList);
    next.version = "999.1";
    next.log_list_timestamp = "2026-09-10T00:00:00Z";
    next.operators.reverse();
    for (const operator of next.operators) {
      operator.email = ["changed@example.test"];
      operator.logs.reverse();
      for (const log of operator.logs) { log.description = "different"; log.url += "other"; }
    }
    expect(hasCtPolicyChanged(ctList, next)).toBe(false);
  });
  it("detects states, intervals, keys and removals", () => {
    for (const edit of [
      (log) => { log.state = { rejected: { timestamp: "2026-09-01T00:00:00Z" } }; },
      (log) => { log.temporal_interval.end_exclusive = "2029-01-01T00:00:00Z"; },
      (log) => { log.key += "changed"; }
    ]) {
      const next = structuredClone(ctList); edit(next.operators[0].logs[0]);
      expect(hasCtPolicyChanged(ctList, next)).toBe(true);
    }
    const next = structuredClone(ctList); next.operators[0].logs.pop();
    expect(hasCtPolicyChanged(ctList, next)).toBe(true);
  });
  it("rejects incomplete, unknown, malformed or unsupported lists", () => {
    for (const edit of [
      (list) => { list.operators = []; },
      (list) => { list.operators = list.operators.filter((op) => op.name !== "Yandex"); },
      (list) => { list.operators[0].logs = []; },
      (list) => { list.operators[0].name = "New operator"; },
      (list) => { list.operators[0].logs[0].key = "AA=="; },
      (list) => { list.operators[0].logs[0].state = { surprise: { timestamp: "2026-01-01T00:00:00Z" } }; },
      (list) => { list.operators[0].logs[0].state = {}; },
      (list) => { list.operators[0].tiled_logs = [{}]; }
    ]) {
      const next = structuredClone(ctList); edit(next);
      expect(() => normalizedCtList(next)).toThrow();
    }
    expect(validateCtList(ctList).size).toBe(6);
  });
  it("rejects rollback and loss of usable Yandex coverage", () => {
    for (const edit of [
      (list) => { list.version = "1.1"; },
      (list) => { list.log_list_timestamp = "2025-01-01T00:00:00Z"; },
      (list) => { list.log_list_timestamp = "2099-01-01T00:00:00Z"; },
      (list) => { list.operators.find((op) => op.name === "Yandex").logs.forEach((log) => { log.state = { rejected: { timestamp: "2026-09-01T00:00:00Z" } }; }); }
    ]) {
      const next = structuredClone(ctList); edit(next);
      expect(() => validateCtUpdate(ctList, next, now)).toThrow();
    }
    expect(validateCtUpdate(ctList, structuredClone(ctList), now)).toEqual({ added: [], removed: [] });
  });
});
