import { normalizeHostname } from "../../core/hostname";
import type { TabStatus } from "../../state/tab-status";
import { reasonText } from "../status-text";
const byId = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;
byId("options").addEventListener("click", () => void browser.runtime.openOptionsPage());
const fail = (error: unknown): void => { byId("error").textContent = error instanceof Error ? error.message : "Действие не удалось"; };
byId<HTMLButtonElement>("allow").addEventListener("click", async () => {
  const button = byId<HTMLButtonElement>("allow");
  button.disabled = true;
  try {
    await browser.runtime.sendMessage({ type: "popup:allow", host: byId<HTMLSelectElement>("host").value,
      scope: byId<HTMLSelectElement>("scope").value, duration: byId<HTMLSelectElement>("duration").value });
    window.close();
  } catch (error) { fail(error); button.disabled = false; }
});
void browser.runtime.sendMessage({ type: "popup:get" }).then((state: TabStatus & { enabled: boolean }) => {
  byId("summary").textContent = !state.enabled ? "Защита отключена. Для новой проверки включите её и перезагрузите вкладку."
    : `Блокировок: ${state.blocked}. Проверок недоступно: ${state.unavailable}. ${state.main ? "" : "Нет результата для страницы: перезагрузите HTTPS-вкладку. HTTP и внутренние страницы не проверяются."}`;
  const items = [state.main, ...state.resources].filter((item) => item !== undefined);
  for (const item of items) {
    const row = document.createElement("section");
    const title = document.createElement("strong");
    title.textContent = `${item.host} · ${item.type === "main_frame" ? "страница" : item.type}`;
    const text = document.createElement("p");
    text.textContent = `${reasonText(item.reason)}${item.ca ? ` · CA: ${item.ca}` : ""}${item.operators?.length ? ` · Операторы: ${item.operators.join(", ")}` : ""}`;
    row.append(title, text); byId("requests").append(row);
  }
  const hosts = [...new Set(items.filter((item) => item.status === "blocked" && normalizeHostname(`https://${item.host}`).kind === "dns").map((item) => item.host))];
  for (const host of hosts) { const option = document.createElement("option"); option.value = host; option.textContent = host; byId("host").append(option); }
  byId("exception").hidden = !state.enabled || !hosts.length;
}).catch(fail);
