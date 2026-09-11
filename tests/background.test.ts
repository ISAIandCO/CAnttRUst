import { beforeEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { X509Certificate } from "node:crypto";
const tls = vi.hoisted(() => ({ inspect: vi.fn() }));
vi.mock("../src/adapters/firefox/tls-inspector", () => ({ inspectTls: tls.inspect }));
let headers: (details: any) => Promise<any>;
let before: (details: any) => void;
let message: (input: any, sender: any) => Promise<any>;
let stored: any;
const listener = () => ({ addListener: vi.fn() });
const details = (type = "main_frame", url = "https://bad.test/path", tabId = 1) => ({ type, url, tabId, requestId: crypto.randomUUID(), incognito: false });
const cert = (name: string) => {
  const rawDER = name.endsWith("pem") ? new X509Certificate(readFileSync(new URL(`fixtures/${name}`, import.meta.url))).raw : readFileSync(new URL(`fixtures/${name}`, import.meta.url));
  return { rawDER, derSha256: new X509Certificate(rawDER).fingerprint256.replaceAll(":", "").toLowerCase(), subject: "fixture", issuer: "fixture" };
};
const chain = [cert("check-russian-trusted-leaf.der"), cert("russian-trusted-sub-ca.der"), cert("russian-trusted-root-ca.pem")];
async function request(d = details()) { before(d); return headers(d); }
const sender = (page: string, tabId = 1) => ({ id: "test", url: `moz-extension://test/${page}.html`, tab: { id: tabId, incognito: false } });
beforeEach(async () => {
  vi.resetModules(); stored = {};
  tls.inspect.mockReset().mockResolvedValue({ state: "secure", certificates: chain });
  vi.stubGlobal("browser", {
    storage: { local: { get: async () => stored, set: vi.fn(async (value) => { stored = value; }) } },
    webRequest: { onHeadersReceived: { addListener: vi.fn((fn) => { headers = fn; }) }, onBeforeRequest: { addListener: vi.fn((fn) => { before = fn; }) }, onBeforeRedirect: listener(), onCompleted: listener(), onErrorOccurred: listener() },
    browserAction: { setBadgeText: vi.fn(async () => {}) },
    tabs: { onRemoved: listener(), onUpdated: listener(), query: async () => [{ id: 1, incognito: false }], reload: vi.fn(async () => {}) },
    runtime: { id: "test", getURL: (path: string) => `moz-extension://test/${path}`, onMessage: { addListener: (fn: any) => { message = fn; } } }
  });
  await import("../src/adapters/firefox/background");
});
describe("request integration", () => {
  it("registers every HTTPS resource type", () => {
    expect(browser.webRequest.onHeadersReceived.addListener).toHaveBeenCalledWith(expect.any(Function), { urls: ["https://*/*"] }, ["blocking"]);
  });
  it.each(["sub_frame", "script", "xmlhttprequest", "image", "stylesheet"])("cancels %s without redirecting it", async (type) => {
    expect(await request(details(type))).toEqual({ cancel: true });
    expect(await message({ type: "popup:get" }, sender("popup"))).toMatchObject({ blocked: 1, resources: [{ status: "blocked" }] });
  });
  it("redirects main frames and binds warning reads/actions to the originating tab", async () => {
    const result = await request();
    const eventId = new URLSearchParams(new URL(result.redirectUrl).hash.slice(1)).get("event");
    expect(await message({ type: "warning:get", eventId }, sender("warning", 2))).toBe(null);
    await expect(message({ type: "warning:continue", eventId }, sender("warning", 2))).rejects.toThrow();
    expect(await message({ type: "warning:get", eventId }, sender("warning"))).not.toHaveProperty("originalUrl");
    await message({ type: "warning:continue", eventId }, sender("warning"));
    expect(await request(details("script"))).toEqual({ cancel: true });
    expect(await request()).toEqual({});
    expect(await request()).toHaveProperty("redirectUrl");
  });
  it("does not accept pages whose names merely start with warning.html", async () => {
    await expect(message({ type: "warning:get" }, { ...sender("warning"), url: "moz-extension://test/warning.html.evil" })).rejects.toThrow();
  });
  it("shows TLS API failure and empty chains as unavailable", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    tls.inspect.mockRejectedValueOnce(new Error("API failed"));
    expect(await request()).toEqual({});
    expect(await message({ type: "popup:get" }, sender("popup"))).toMatchObject({ unavailable: 1, main: { status: "unavailable" } });
    tls.inspect.mockResolvedValueOnce({ certificates: [] });
    await request();
    expect(await message({ type: "popup:get" }, sender("popup"))).toMatchObject({ main: { status: "unavailable" } });
    vi.restoreAllMocks();
  });
  it("zone and CT exceptions do not disable the other rule", async () => {
    const { addAllowedHost } = await import("../src/state/settings");
    await addAllowedHost("bad.test", "ct", "session");
    expect(await request()).toHaveProperty("redirectUrl");
    await addAllowedHost("bad.test", "zone", "session");
    expect(await request()).toEqual({});
    await addAllowedHost("zone.test", "zone", "session");
    tls.inspect.mockResolvedValue({ certificates: [chain[2], chain[2]] });
    expect(await request(details("script", "https://zone.test/a"))).toEqual({ cancel: true });
  });
  it("ignores diagnostics from an old navigation finishing after a new one", async () => {
    let resolve: (value: unknown) => void = () => {};
    tls.inspect.mockReturnValueOnce(new Promise((done) => { resolve = done; }));
    const first = request();
    await vi.waitFor(() => expect(tls.inspect).toHaveBeenCalled());
    before(details("main_frame", "http://new.test/"));
    resolve({ certificates: chain }); await first;
    expect(await message({ type: "popup:get" }, sender("popup"))).toMatchObject({ blocked: 0, resources: [] });
  });
  it("keeps diagnostics bounded without losing block counts", async () => {
    for (let i = 0; i < 30; i++) await request(details("script", `https://host${i}.test/`));
    const state = await message({ type: "popup:get" }, sender("popup"));
    expect(state.blocked).toBe(30); expect(state.resources).toHaveLength(20);
  });
});


describe("simple popup exceptions", () => {
  it("adds selected blocked hosts atomically and reloads once", async () => {
    await request(details("script", "https://one.test/a"));
    await request(details("script", "https://two.test/b"));
    await message({ type: "popup:allow", tabId: 1, hosts: ["one.test", "two.test"], scope: "all", duration: "permanent" }, sender("popup"));
    expect(stored.settings.allowlist.map((entry: any) => entry.host)).toEqual(["one.test", "two.test"]);
    expect(browser.tabs.reload).toHaveBeenCalledTimes(1);
  });
  it("rejects a stale tab or unobserved domain without adding any exception", async () => {
    await request(details("script", "https://one.test/a"));
    const input = { type: "popup:allow", tabId: 1, hosts: ["one.test", "unobserved.test"], scope: "all", duration: "permanent" };
    await expect(message(input, sender("popup"))).rejects.toThrow();
    await expect(message({ ...input, tabId: 2, hosts: ["one.test"] }, sender("popup"))).rejects.toThrow();
    expect(stored.settings).toBeUndefined();
    expect(browser.tabs.reload).not.toHaveBeenCalled();
  });
  it("retains bulk candidates beyond the 20 diagnostic entries and excludes ordinary CA resources", async () => {
    for (let i = 0; i < 30; i++) await request(details("script", `https://host${i}.test/a`));
    tls.inspect.mockResolvedValue({ certificates: [chain[0]] });
    for (let i = 0; i < 30; i++) await request(details("script", `https://ordinary${i}.test/a`));
    const state = await message({ type: "popup:get" }, sender("popup"));
    expect(state.blockedHosts).toHaveLength(30);
    expect(state.resources).toHaveLength(20);
    expect(state.resources.every((item: any) => item.status === "blocked")).toBe(true);
  });
  it("caps the badge at 99+ while retaining the exact count", async () => {
    for (let i = 0; i < 100; i++) {
      await request(details("script"));
      if ([0, 98, 99].includes(i)) expect(browser.browserAction.setBadgeText).toHaveBeenLastCalledWith({ tabId: 1, text: i === 99 ? "99+" : String(i + 1) });
    }
    expect(await message({ type: "popup:get" }, sender("popup"))).toMatchObject({ blocked: 100 });
  });
});
