import { normalizeHostname } from "../../core/hostname";
import type { TabStatus } from "../../state/tab-status";
import { reasonText } from "../status-text";
const byId = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;
let tabId: number;
const choices: HTMLInputElement[] = [];
byId("options").addEventListener("click", () => void browser.runtime.openOptionsPage());
const fail = (error: unknown): void => { byId("error").textContent = error instanceof Error ? error.message : "Действие не удалось"; };
function updateSelection(): void {
  const count = choices.filter((input) => input.checked).length;
  const button = byId<HTMLButtonElement>("allow");
  button.disabled = count === 0;
  button.textContent = count ? `Разрешить выбранные (${count}) и перезагрузить` : "Выберите домены";
  const all = byId<HTMLInputElement>("select-all");
  all.checked = count > 0 && count === choices.length;
  all.indeterminate = count > 0 && count < choices.length;
}
byId<HTMLInputElement>("select-all").addEventListener("change", (event) => {
  for (const input of choices) input.checked = (event.currentTarget as HTMLInputElement).checked;
  updateSelection();
});
byId("exceptions").addEventListener("submit", async (event) => {
  event.preventDefault();
  const hosts = choices.filter((input) => input.checked).map((input) => input.value);
  if (!hosts.length) return;
  byId<HTMLButtonElement>("allow").disabled = true;
  try {
    await browser.runtime.sendMessage({ type: "popup:allow", tabId, hosts,
      scope: byId<HTMLSelectElement>("scope").value, duration: byId<HTMLSelectElement>("duration").value });
    window.close();
  } catch (error) { fail(error); updateSelection(); }
});
void browser.runtime.sendMessage({ type: "popup:get" }).then((state: TabStatus & { enabled: boolean; tabId: number }) => {
  tabId = state.tabId;
  const items = [state.main, ...state.resources].filter((item) => item !== undefined).filter((item) => item.ca && item.status !== "other_ca");
  const blocked = new Set(state.blockedHosts);
  const hosts = [...new Set([...blocked, ...items.map((item) => item.host)])];
  byId("summary").textContent = !state.enabled ? "Защита отключена. Включите её в настройках и перезагрузите вкладку."
    : hosts.length ? `Соединения через отслеживаемый CA Минцифры. Заблокировано: ${state.blocked}.`
    : "Соединений через отслеживаемый CA Минцифры не обнаружено. Если страница была открыта до установки расширения, перезагрузите её.";
  if (state.enabled && state.unavailable) byId("summary").textContent += ` Не удалось проверить соединений: ${state.unavailable}.`;
  for (const host of hosts) {
    const row = document.createElement("section");
    const label = document.createElement("label");
    label.className = "host-choice";
    const title = document.createElement("strong"); title.textContent = host;
    if (state.enabled && blocked.has(host) && normalizeHostname(`https://${host}`).kind === "dns") {
      const input = document.createElement("input"); input.type = "checkbox"; input.value = host;
      input.addEventListener("change", updateSelection); choices.push(input); label.append(input);
    }
    label.append(title); row.append(label);
    const matches = items.filter((item) => item.host === host);
    const text = document.createElement("p");
    const reasons = [...new Set(matches.map((item) => reasonText(item.reason)))];
    const operators = [...new Set(matches.flatMap((item) => item.operators ?? []))];
    if (operators.length) reasons.push(`Операторы CT: ${operators.join(", ")}`);
    text.textContent = reasons.join(" · ") || "Соединение заблокировано";
    row.append(text); byId("requests").append(row);
  }
  byId("exception").hidden = !choices.length;
  byId("selection").hidden = !choices.length;
  if (choices.length === 1) choices[0]!.checked = true;
  updateSelection();
}).catch(fail);
