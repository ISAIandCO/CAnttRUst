import { describe, expect, it } from "vitest";
import ctList from "../src/policy/ct/yandex-nuc-log-list.json" with { type: "json" };
import { hasCtPolicyChanged } from "../scripts/policy-utils.mjs";

describe("CT policy monitoring", () => {
  it("ignores source timestamps but detects accepted-log changes", () => {
    const timestampOnly = { ...ctList, log_list_timestamp: "2099-01-01T00:00:00Z" };
    expect(hasCtPolicyChanged(ctList, timestampOnly)).toBe(false);

    const changed = structuredClone(timestampOnly);
    changed.operators[0].logs[0].description += " changed";
    expect(hasCtPolicyChanged(ctList, changed)).toBe(true);
  });
});
