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
