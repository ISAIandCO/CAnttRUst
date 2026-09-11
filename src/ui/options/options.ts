import caPolicy from "../../policy/protected-cas.json";
import ctLock from "../../policy/ct/ct-policy-lock.json";
import type { Settings } from "../../core/types";

const byId = <T extends HTMLElement>(id: string): T => {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing element ${id}`);
  return element as T;
};
let settings: Settings;

function status(message: string): void {
  byId("status").textContent = message;
}

function render(next: Settings): void {
  settings = next;
  byId<HTMLInputElement>("enabled").checked = settings.enabled;
  byId<HTMLSelectElement>("ct-mode").value = settings.ctMode;
  const list = byId<HTMLUListElement>("allowlist");
  list.replaceChildren(...settings.allowlist.map((entry) => {
    const item = document.createElement("li");
    const host = document.createElement("span");
    host.textContent = `${entry.host} · ${{ zone: "зона", ct: "CT", all: "зона и CT" }[entry.scope ?? "all"]} · ${entry.expiresAt ? `до ${new Date(entry.expiresAt).toLocaleString()}` : entry.sessionId ? "сессия" : "постоянно"}${entry.incognito ? " · приватно" : ""}`;
    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = "Удалить";
    remove.addEventListener("click", () => void browser.runtime.sendMessage({ type: "options:remove", id: entry.id }).then((value: Settings) => {
      render(value);
      status(`Удалено: ${entry.host}`);
    }));
    item.append(host, remove);
    return item;
  }));
  byId("empty").hidden = settings.allowlist.length > 0;
}

async function save(): Promise<void> {
  const next = await browser.runtime.sendMessage({
    type: "options:update",
    enabled: byId<HTMLInputElement>("enabled").checked,
    ctMode: byId<HTMLSelectElement>("ct-mode").value
  }) as Settings;
  render(next);
  status("Настройки сохранены.");
}

byId("enabled").addEventListener("change", () => void save());
byId("ct-mode").addEventListener("change", () => void save());
byId("export").addEventListener("click", () => {
  const url = URL.createObjectURL(new Blob([`${JSON.stringify({ ...settings, allowlist: settings.allowlist.filter((entry) => !entry.sessionId && !entry.incognito) }, null, 2)}\n`], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "canttrust-settings.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
});
byId<HTMLInputElement>("import").addEventListener("change", async (input) => {
  try {
    const file = (input.currentTarget as HTMLInputElement).files?.[0];
    if (!file || file.size > 256 * 1024) throw new Error("Файл отсутствует или превышает 256 KiB");
    render(await browser.runtime.sendMessage({ type: "options:import", settings: JSON.parse(await file.text()) }) as Settings);
    status("Настройки импортированы.");
  } catch (error) {
    status(error instanceof Error ? error.message : "Импорт не удался");
  }
});

byId("version").textContent = browser.runtime.getManifest().version;
byId("fingerprint").textContent = caPolicy.cas[0]?.rootDerSha256.join(", ") ?? "—";
byId("snapshot").textContent = `${ctLock.retrievedAt} / ${ctLock.sourceSha256}`;
void browser.runtime.sendMessage({ type: "options:get" }).then((value: Settings) => render(value));
