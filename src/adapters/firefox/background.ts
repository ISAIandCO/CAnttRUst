import caPolicyJson from "../../policy/protected-cas.json";
import ctListJson from "../../policy/ct/yandex-nuc-log-list.json";
import { matchProtectedCA } from "../../core/ca";
import { verifyEmbeddedScts, type CtLog } from "../../core/ct";
import { isHostInAllowedZones, normalizeHostname } from "../../core/hostname";
import type { CtMode, ExceptionScope, ExceptionDuration, ProtectedCa, SecurityEvent } from "../../core/types";
import { clearTabBypasses, consumeBypass, createBypass } from "../../state/bypass";
import { addEvent, clearTabEvents, getEvent, publicEvent } from "../../state/events";
import { addAllowedHost, addAllowedHosts, clearPrivateExceptions, getSettings, importSettings, isAllowed, removeAllowedHost, updateSettings } from "../../state/settings";
import { badgeText, forgetTab, getTabStatus, recordStatus, resetTab, tabEpoch, type RequestStatus } from "../../state/tab-status";
import { inspectTls } from "./tls-inspector";

const protectedCas = caPolicyJson.cas as ProtectedCa[];
const ctLogs: CtLog[] = ctListJson.operators.flatMap((operator) => operator.logs.map((log) => ({
  operator: operator.name,
  description: log.description,
  key: log.key,
  logId: log.log_id,
  startInclusive: Date.parse(log.temporal_interval.start_inclusive),
  endExclusive: Date.parse(log.temporal_interval.end_exclusive),
  state: { name: Object.keys(log.state)[0]!, since: Date.parse(Object.values(log.state)[0]!.timestamp) }
})));

function warningRedirect(event: SecurityEvent): browser.webRequest.BlockingResponse {
  return { redirectUrl: `${browser.runtime.getURL("warning.html")}#event=${encodeURIComponent(event.id)}` };
}

async function onHeadersReceived(details: browser.webRequest._OnHeadersReceivedDetails): Promise<browser.webRequest.BlockingResponse> {
  const host = normalizeHostname(details.url);
  if (host.kind === "invalid") return {};
  const epoch = requestEpochs.get(details.requestId) ?? tabEpoch(details.tabId);
  const report = (result: Omit<RequestStatus, "host" | "type">): void => {
    const state = recordStatus(details.tabId, epoch, { host: host.ascii, type: details.type, ...result });
    if (state) void browser.browserAction.setBadgeText({ tabId: details.tabId,
      text: badgeText(state) }).catch(() => undefined);
  };
  const block = (event: Omit<SecurityEvent, "id" | "timestamp">): browser.webRequest.BlockingResponse => {
    report({ status: "blocked", reason: event.ctSummary?.status ?? event.reason, ca: event.matchedCaId });
    return details.type === "main_frame" ? warningRedirect(addEvent(event)) : { cancel: true };
  };
  let matched = false;
  let inspection: Awaited<ReturnType<typeof inspectTls>> | undefined;
  let match: ReturnType<typeof matchProtectedCA> = null;
  try {
    const settings = await getSettings();
    if (!settings.enabled) { report({ status: "disabled", reason: "disabled" }); return {}; }
    const bypassInput = { tabId: details.tabId, incognito: Boolean(details.incognito), host: host.ascii, originalUrl: details.url };
    if (details.type === "main_frame" && consumeBypass(bypassInput)) { report({ status: "exception", reason: "one_time" }); return {}; }

    inspection = await inspectTls(details.requestId);
    if (!inspection.certificates.length) throw new Error("TLS certificate chain unavailable");
    match = matchProtectedCA(inspection.certificates, protectedCas);
    if (!match) { report({ status: "other_ca", reason: "other_ca", ca: inspection.certificates.at(-1)!.subject }); return {}; }
    matched = true;
    const zoneAllowed = isAllowed(settings, host.ascii, "zone", Boolean(details.incognito));
    const ctAllowed = isAllowed(settings, host.ascii, "ct", Boolean(details.incognito));

    const leaf = inspection.certificates[0];
    if (!leaf) throw new Error("missing leaf certificate");
    const baseEvent = {
      tabId: details.tabId,
      incognito: Boolean(details.incognito),
      host: host.ascii,
      originalUrl: details.url,
      leafSha256: leaf.derSha256,
      matchedCaSha256: match.certificate.derSha256,
      leafSubject: leaf.subject,
      leafIssuer: leaf.issuer,
      matchedCaId: match.ca.id
    };

    if (!zoneAllowed && (host.kind !== "dns" || !isHostInAllowedZones(host.ascii, match.ca.allowedDnsZones))) {
      return block({ ...baseEvent, reason: "protected_ca_outside_zone" });
    }

    if (ctAllowed) { report({ status: "exception", reason: "ct_exception", ca: match.ca.id }); return {}; }
    const verdict = await verifyEmbeddedScts(leaf.rawDER, inspection.certificates[1]?.rawDER, ctLogs, settings.ctMode);
    if (verdict.status === "valid") {
      report({ status: zoneAllowed ? "exception" : "valid", reason: zoneAllowed ? "zone_exception_ct_valid" : "ct_valid", ca: match.ca.id, operators: [...new Set(verdict.validScts.map((sct) => sct.operator))] });
      return {};
    }
    return block({
      ...baseEvent,
      reason: verdict.status === "indeterminate" ? "ct_indeterminate" : "ct_invalid",
      ctSummary: { status: verdict.reason, validOperators: [] }
    });
  } catch (error) {
    console.error("CAnttRUst request check failed", error);
    if (!matched || !inspection?.certificates[0] || !match) { report({ status: "unavailable", reason: "tls_unavailable" }); return {}; }
    const leaf = inspection.certificates[0];
    return block({
      tabId: details.tabId,
      incognito: Boolean(details.incognito),
      host: host.ascii,
      originalUrl: details.url,
      reason: "ct_indeterminate",
      leafSha256: leaf.derSha256,
      matchedCaSha256: match.certificate.derSha256,
      leafSubject: leaf.subject,
      leafIssuer: leaf.issuer,
      matchedCaId: match.ca.id,
      ctSummary: { status: "internal_error", validOperators: [] }
    });
  }
}

const requestEpochs = new Map<string, number>();
browser.webRequest.onBeforeRequest.addListener((details) => {
  if (details.type === "main_frame") {
    resetTab(details.tabId);
    if (details.tabId >= 0) void browser.browserAction.setBadgeText({ tabId: details.tabId, text: "" }).catch(() => undefined);
  }
  requestEpochs.set(details.requestId, tabEpoch(details.tabId));
}, { urls: ["http://*/*", "https://*/*"] });
const releaseRequest = (details: { requestId: string }): void => { requestEpochs.delete(details.requestId); };
browser.webRequest.onBeforeRedirect.addListener(releaseRequest, { urls: ["http://*/*", "https://*/*"] });
browser.webRequest.onCompleted.addListener(releaseRequest, { urls: ["http://*/*", "https://*/*"] });
browser.webRequest.onErrorOccurred.addListener(releaseRequest, { urls: ["http://*/*", "https://*/*"] });
browser.tabs.onRemoved.addListener(async (tabId) => {
  forgetTab(tabId);
  clearTabEvents(tabId);
  clearTabBypasses(tabId);
  if (!(await browser.tabs.query({})).some((tab) => tab.incognito)) await clearPrivateExceptions();
});

browser.tabs.onUpdated.addListener((tabId, change) => {
  if (change.url && !/^https?:/.test(change.url) && change.url.split(/[?#]/)[0] !== browser.runtime.getURL("warning.html")) {
    resetTab(tabId);
    void browser.browserAction.setBadgeText({ tabId, text: "" }).catch(() => undefined);
  }
});

browser.webRequest.onHeadersReceived.addListener(
  onHeadersReceived,
  { urls: ["https://*/*"] },
  ["blocking"]
);


function ownPage(sender: browser.runtime.MessageSender, page: "warning" | "options" | "popup"): boolean {
  return sender.id === browser.runtime.id && sender.url?.split(/[?#]/)[0] === browser.runtime.getURL(`${page}.html`);
}

browser.runtime.onMessage.addListener(async (message: unknown, sender): Promise<unknown> => {
  if (!message || typeof message !== "object") throw new Error("Invalid message");
  const input = message as Record<string, unknown>;
  if (input.type === "warning:allow" || input.type === "popup:allow") {
    if (!["zone", "ct", "all"].includes(String(input.scope)) || !["session", "hour", "permanent"].includes(String(input.duration))) throw new Error("Некорректное исключение");
  }
  if (input.type === "warning:get" && ownPage(sender, "warning")) {
    const event = getEvent(String(input.eventId));
    return event && sender.tab?.id === event.tabId && Boolean(sender.tab.incognito) === event.incognito ? publicEvent(event) : null;
  }
  if ((input.type === "warning:continue" || input.type === "warning:allow") && ownPage(sender, "warning")) {
    const event = getEvent(String(input.eventId));
    if (!event || sender.tab?.id !== event.tabId || Boolean(sender.tab.incognito) !== event.incognito) throw new Error("Expired warning event");
    if (input.type === "warning:allow") await addAllowedHost(event.host, input.scope as ExceptionScope, input.duration as ExceptionDuration, event.incognito);
    else createBypass({ tabId: event.tabId, incognito: event.incognito, host: event.host, originalUrl: event.originalUrl });
    return { originalUrl: event.originalUrl };
  }
  if (ownPage(sender, "popup")) {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (tab?.id === undefined) throw new Error("Вкладка недоступна");
    const state = getTabStatus(tab.id);
    if (input.type === "popup:get") return { ...state, tabId: tab.id, enabled: (await getSettings()).enabled };
    if (input.type === "popup:allow") {
      if (input.tabId !== tab.id || !Array.isArray(input.hosts) || !input.hosts.length || input.hosts.length > 1000
        || !input.hosts.every((host) => typeof host === "string" && state.blockedHosts.includes(host))) throw new Error("Список блокировок изменился. Откройте меню заново.");
      await addAllowedHosts(input.hosts as string[], input.scope as ExceptionScope, input.duration as ExceptionDuration, Boolean(tab.incognito));
      await browser.tabs.reload(tab.id);
      return true;
    }
  }
  if (ownPage(sender, "options")) {
    if (input.type === "options:get") return getSettings();
    if (input.type === "options:update") return updateSettings({ enabled: input.enabled === true, ctMode: input.ctMode as CtMode });
    if (input.type === "options:remove") return removeAllowedHost(String(input.id));
    if (input.type === "options:import") return importSettings(input.settings);
  }
  throw new Error("Unauthorized message");
});
