import { reasonText } from "../status-text";
import { normalizeHostname } from "../../core/hostname";
import type { PublicSecurityEvent } from "../../core/types";

const byId = (id: string): HTMLElement => {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing element ${id}`);
  return element;
};
const eventId = new URLSearchParams(location.hash.slice(1)).get("event") ?? "";
let event: PublicSecurityEvent | null = null;

function setText(id: string, value: string): void {
  byId(id).textContent = value;
}

function setBusy(value: boolean): void {
  for (const id of ["continue", "allow"]) (byId(id) as HTMLButtonElement).disabled = value;
}

async function navigate(type: "warning:continue" | "warning:allow"): Promise<void> {
  setBusy(true);
  try {
    const response = await browser.runtime.sendMessage({ type, eventId, scope: (byId("scope") as HTMLSelectElement).value, duration: (byId("duration") as HTMLSelectElement).value }) as { originalUrl: string };
    location.replace(response.originalUrl);
  } catch (error) {
    setText("error", error instanceof Error ? error.message : "Действие не удалось");
    byId("error").hidden = false;
    setBusy(false);
  }
}

byId("back").addEventListener("click", () => {
  if (history.length > 1) history.back();
  else window.close();
});
byId("continue").addEventListener("click", () => void navigate("warning:continue"));
byId("allow").addEventListener("click", () => {
  if (event) void navigate("warning:allow");
});

void browser.runtime.sendMessage({ type: "warning:get", eventId }).then((response: PublicSecurityEvent | null) => {
  event = response;
  if (!event) throw new Error("Сведения о блокировке истекли. Вернитесь назад и повторите переход.");
  setText("host", event.host);
  setText("leaf", event.leafSha256);
  setText("root", event.matchedCaSha256);
  setText("subject", event.leafSubject);
  setText("issuer", event.leafIssuer);
  setText("ct", event.ctSummary ? reasonText(event.ctSummary.status) : "не применялся");
  setText("reason", event.reason === "protected_ca_outside_zone"
    ? "Firefox построил TLS-соединение через защищаемый российский CA вне разрешённых зон .ru, .su и .рф. Ответ сайта не был передан странице."
    : "Сертификат построен через защищаемый российский CA, но проверка SCT не пройдена: подписи, статус лога или время SCT не соответствуют принятой политике.");
  byId("details").hidden = false;
  if (normalizeHostname(`https://${event.host}`).kind !== "dns") byId("allow").hidden = true;
}).catch((error: unknown) => {
  setText("reason", "Не удалось получить сведения о заблокированном соединении.");
  setText("error", error instanceof Error ? error.message : "Неизвестная ошибка");
  byId("error").hidden = false;
  byId("continue").hidden = true;
  byId("allow").hidden = true;
});
