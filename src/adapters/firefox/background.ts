import caPolicyJson from "../../policy/protected-cas.json";
import ctListJson from "../../policy/ct/yandex-nuc-log-list.json";
import { matchProtectedCA } from "../../core/ca";
import { verifyEmbeddedScts, type CtLog } from "../../core/ct";
import { isHostInAllowedZones, normalizeHostname } from "../../core/hostname";
import type { CtMode, ProtectedCa, SecurityEvent } from "../../core/types";
import { consumeBypass, createBypass } from "../../state/bypass";
import { addEvent, getEvent, publicEvent } from "../../state/events";
import { addAllowedHost, getSettings, importSettings, isAllowed, removeAllowedHost, updateSettings } from "../../state/settings";
import { inspectTls } from "./tls-inspector";

const protectedCas = caPolicyJson.cas as ProtectedCa[];
const ctLogs: CtLog[] = ctListJson.operators.flatMap((operator) => operator.logs.map((log) => ({
  operator: operator.name,
  description: log.description,
  key: log.key,
  logId: log.log_id,
  startInclusive: Date.parse(log.temporal_interval.start_inclusive),
  endExclusive: Date.parse(log.temporal_interval.end_exclusive)
})));

function warningRedirect(event: SecurityEvent): browser.webRequest.BlockingResponse {
  return { redirectUrl: `${browser.runtime.getURL("warning.html")}#event=${encodeURIComponent(event.id)}` };
}

async function onHeadersReceived(details: browser.webRequest._OnHeadersReceivedDetails): Promise<browser.webRequest.BlockingResponse> {
  const host = normalizeHostname(details.url);
  if (host.kind === "invalid") return {};
  let matched = false;
  let inspection: Awaited<ReturnType<typeof inspectTls>> | undefined;
  let match: ReturnType<typeof matchProtectedCA> = null;
  try {
    const settings = await getSettings();
    if (!settings.enabled) return {};
    const bypassInput = { tabId: details.tabId, incognito: Boolean(details.incognito), host: host.ascii, originalUrl: details.url };
    if (consumeBypass(bypassInput)) return {};

    inspection = await inspectTls(details.requestId);
    match = matchProtectedCA(inspection.certificates, protectedCas);
    if (!match) return {};
    matched = true;
    if (isAllowed(settings, host.ascii)) return {};

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

    if (host.kind !== "dns" || !isHostInAllowedZones(host.ascii, match.ca.allowedDnsZones)) {
      return warningRedirect(addEvent({ ...baseEvent, reason: "protected_ca_outside_zone" }));
    }

    const verdict = await verifyEmbeddedScts(leaf.rawDER, inspection.certificates[1]?.rawDER, ctLogs, settings.ctMode);
    if (verdict.status === "valid") return {};
    return warningRedirect(addEvent({
      ...baseEvent,
      reason: verdict.status === "indeterminate" ? "ct_indeterminate" : "ct_invalid",
      ctSummary: { status: verdict.reason, validOperators: [] }
    }));
  } catch (error) {
    console.error("CAnttRUst navigation check failed", error);
    if (!matched || !inspection?.certificates[0] || !match) return {};
    const leaf = inspection.certificates[0];
    return warningRedirect(addEvent({
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
    }));
  }
}

browser.webRequest.onHeadersReceived.addListener(
  onHeadersReceived,
  { urls: ["https://*/*"], types: ["main_frame"] },
  ["blocking"]
);

browser.browserAction.onClicked.addListener(() => browser.runtime.openOptionsPage());

function ownPage(sender: browser.runtime.MessageSender, page: "warning" | "options"): boolean {
  return Boolean(sender.url?.startsWith(browser.runtime.getURL(`${page}.html`)));
}

browser.runtime.onMessage.addListener(async (message: unknown, sender): Promise<unknown> => {
  if (!message || typeof message !== "object") throw new Error("Invalid message");
  const input = message as Record<string, unknown>;
  if (input.type === "warning:get" && ownPage(sender, "warning")) {
    const event = getEvent(String(input.eventId));
    return event ? publicEvent(event) : null;
  }
  if ((input.type === "warning:continue" || input.type === "warning:allow") && ownPage(sender, "warning")) {
    const event = getEvent(String(input.eventId));
    if (!event || sender.tab?.id !== event.tabId || Boolean(sender.tab.incognito) !== event.incognito) throw new Error("Expired warning event");
    if (input.type === "warning:allow") await addAllowedHost(event.host);
    else createBypass({ tabId: event.tabId, incognito: event.incognito, host: event.host, originalUrl: event.originalUrl });
    return { originalUrl: event.originalUrl };
  }
  if (ownPage(sender, "options")) {
    if (input.type === "options:get") return getSettings();
    if (input.type === "options:update") return updateSettings({ enabled: input.enabled === true, ctMode: input.ctMode as CtMode });
    if (input.type === "options:remove") return removeAllowedHost(String(input.id));
    if (input.type === "options:import") return importSettings(input.settings);
  }
  throw new Error("Unauthorized message");
});
