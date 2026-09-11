import { beforeEach, expect, it, vi } from "vitest";
let stored: any;
beforeEach(() => {
  vi.resetModules(); vi.useRealTimers(); stored = {};
  vi.stubGlobal("browser", { storage: { local: { get: async () => structuredClone(stored), set: vi.fn(async (value) => { stored = structuredClone(value); }) } } });
});
it("expires hour exceptions, isolates private mode, excludes session/private data from disk", async () => {
  const { addAllowedHost, getSettings, isAllowed } = await import("../src/state/settings");
  await addAllowedHost("a.test", "zone", "hour");
  await addAllowedHost("b.test", "ct", "session");
  await addAllowedHost("private.test", "all", "permanent", true);
  const settings = await getSettings();
  expect(stored.settings.allowlist).toHaveLength(1);
  expect(isAllowed(settings, "a.test", "zone")).toBe(true);
  expect(isAllowed(settings, "a.test", "ct")).toBe(false);
  expect(isAllowed(settings, "sub.a.test", "zone")).toBe(false);
  expect(isAllowed(settings, "private.test", "zone")).toBe(false);
  expect(isAllowed(settings, "private.test", "zone", true)).toBe(true);
  vi.useFakeTimers(); vi.setSystemTime(Date.now() + 3600_001);
  expect(isAllowed(settings, "a.test", "zone")).toBe(false);
  expect((await getSettings()).allowlist).toHaveLength(2);
  vi.useRealTimers();
});
it("loses session exceptions on restart but retains unexpired hour exceptions", async () => {
  const first = await import("../src/state/settings");
  await first.addAllowedHost("session.test", "all", "session");
  await first.addAllowedHost("hour.test", "ct", "hour");
  vi.resetModules();
  const next = await import("../src/state/settings");
  expect((await next.getSettings()).allowlist.map((item) => item.host)).toEqual(["hour.test"]);
});
it("serializes concurrent writes and does not activate an exception if persistence fails", async () => {
  const { addAllowedHost, getSettings } = await import("../src/state/settings");
  await Promise.all([addAllowedHost("a.test", "zone", "session"), addAllowedHost("b.test", "ct", "hour")]);
  expect((await getSettings()).allowlist).toHaveLength(2);
  vi.mocked(browser.storage.local.set).mockRejectedValueOnce(new Error("disk full"));
  await expect(addAllowedHost("c.test")).rejects.toThrow("disk full");
  expect((await getSettings()).allowlist).toHaveLength(2);
  await addAllowedHost("d.test");
  expect((await getSettings()).allowlist).toHaveLength(3);
});
it("rejects malformed scopes/expiry and migrates old permanent entries", async () => {
  const { parseSettings } = await import("../src/state/settings");
  const entry = { id: "a", type: "exact-host", host: "a.test" };
  expect(parseSettings({ allowlist: [entry] }).allowlist[0]).toMatchObject({ scope: "all", incognito: false });
  for (const patch of [{ scope: "oops" }, { expiresAt: "tomorrow" }, { expiresAt: 0 }, { sessionId: "other session" }]) {
    expect(parseSettings({ allowlist: [{ ...entry, ...patch }] }).allowlist).toHaveLength(0);
  }
});
