// Bundled only by scripts/test-firefox.mjs into a disposable test extension.
import "../../src/adapters/firefox/background";
import { addAllowedHost, getSettings, removeAllowedHost } from "../../src/state/settings";
import { getTabStatus } from "../../src/state/tab-status";
declare const TEST_CONFIG: { http: string; https: string; other: string };
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const assert = (condition: unknown, label: string): void => { if (!condition) throw new Error(label); };
async function until(check: () => Promise<boolean> | boolean, label: string): Promise<void> {
  for (let i = 0; i < 100; i++) { if (await check()) return; await sleep(100); }
  throw new Error(`Timeout: ${label}`);
}
async function main(): Promise<void> {
  const passed: string[] = [];
  let tab = await browser.tabs.create({ url: `${TEST_CONFIG.https}/page` });
  const id = tab.id!;
  await until(async () => (await browser.tabs.get(id)).url?.startsWith(browser.runtime.getURL("warning.html")) === true, "main warning");
  assert(getTabStatus(id).main?.status === "blocked", "main CT block"); passed.push("main-frame warning with real TLS chain");
  await addAllowedHost("a.test", "zone", "session");
  await browser.tabs.update(id, { url: `${TEST_CONFIG.https}/page?zone` });
  await until(async () => (await browser.tabs.get(id)).url?.startsWith(browser.runtime.getURL("warning.html")) === true, "zone exception retains CT");
  passed.push("zone exception retains CT enforcement");
  await addAllowedHost("a.test", "ct", "session");
  await browser.tabs.update(id, { url: `${TEST_CONFIG.https}/page?ct` });
  await until(() => getTabStatus(id).main?.status === "exception", "CT exception");
  passed.push("scoped CT exception permits response");
  for (const entry of (await getSettings()).allowlist) await removeAllowedHost(entry.id);
  await browser.tabs.update(id, { url: `${TEST_CONFIG.http}/resources` });
  await until(() => getTabStatus(id).blocked >= 3, "iframe/script/fetch blocks");
  const state = getTabStatus(id);
  for (const type of ["script", "sub_frame", "xmlhttprequest"]) assert(state.resources.some((item) => item.type === type && item.status === "blocked"), `blocked ${type}`);
  await until(async () => (await browser.tabs.executeScript(id, { code: "document.documentElement.dataset.fetchBlocked === 'yes'" }))[0] === true, "fetch rejection delivered");
  const [result] = await browser.tabs.executeScript(id, { code: "({ executed: document.documentElement.dataset.executed === 'yes', fetchBlocked: document.documentElement.dataset.fetchBlocked === 'yes' })" });
  assert(!result.executed && result.fetchBlocked, "blocked content not delivered");
  passed.push("iframe, script and fetch canceled; script not executed");
  await browser.tabs.update(id, { url: `${TEST_CONFIG.other}/page` });
  await until(() => getTabStatus(id).main?.status === "other_ca", "ordinary CA");
  passed.push("unprotected TLS chain unaffected");
  await browser.tabs.update(id, { url: `${TEST_CONFIG.http}/redirect` });
  await until(async () => (await browser.tabs.get(id)).url?.startsWith(browser.runtime.getURL("warning.html")) === true, "redirect recheck");
  passed.push("HTTP redirect to protected TLS checked");
  // Populate the browser cache with an explicit exception, revoke it, then reload.
  await addAllowedHost("a.test", "all", "session");
  await browser.tabs.update(id, { url: `${TEST_CONFIG.http}/resources` });
  await until(async () => {
    try { return (await browser.tabs.executeScript(id, { code: "document.documentElement.dataset.executed === 'yes'" }))[0] === true; } catch { return false; }
  }, "cache population");
  for (const entry of (await getSettings()).allowlist) await removeAllowedHost(entry.id);
  const beforeCache = await (await fetch(`${TEST_CONFIG.http}/stats`)).json();
  await browser.tabs.reload(id);
  await until(() => getTabStatus(id).blocked >= 3, "cached resources rechecked");
  assert(!(await browser.tabs.executeScript(id, { code: "document.documentElement.dataset.executed === 'yes'" }))[0], "cached script not executed");
  const afterCache = await (await fetch(`${TEST_CONFIG.http}/stats`)).json();
  assert(beforeCache.scriptRequests === afterCache.scriptRequests, "script served from cache without server hit");
  passed.push("cached resource rechecked after exception removal");
  // Inject an API failure only in this disposable test bundle.
  const original = browser.webRequest.getSecurityInfo;
  browser.webRequest.getSecurityInfo = async () => { throw new Error("Injected E2E TLS API failure"); };
  await browser.tabs.update(id, { url: `${TEST_CONFIG.other}/page?failure` });
  await until(() => getTabStatus(id).main?.status === "unavailable", "API failure diagnostics");
  browser.webRequest.getSecurityInfo = original;
  passed.push("TLS API failure displayed as unavailable");
  await browser.tabs.update(id, { url: `${TEST_CONFIG.https}/page?ui` });
  await until(async () => (await browser.tabs.get(id)).url?.startsWith(browser.runtime.getURL("warning.html")) === true, "warning UI ready");
  await fetch(`${TEST_CONFIG.http}/result`, { method: "POST", body: JSON.stringify({ passed }) });
}
void main().catch(async (error) => {
  await fetch(`${TEST_CONFIG.http}/result`, { method: "POST", body: JSON.stringify({ error: String(error), stack: error.stack, tabs: (await browser.tabs.query({})).map((tab) => ({ url: tab.url, state: getTabStatus(tab.id!) })) }) });
});
