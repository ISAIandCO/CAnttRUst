import { normalizeHostname } from "../core/hostname";
import type { AllowlistEntry, CtMode, Settings } from "../core/types";

const STORAGE_KEY = "settings";
export const DEFAULT_SETTINGS: Settings = { schema: 1, enabled: true, ctMode: "yandex-required", allowlist: [] };

function normalizeAllowlistHost(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 253 || /[\s/@:?#]/.test(value)) return null;
  const host = normalizeHostname(`https://${value}`);
  return host.kind === "dns" ? host.ascii : null;
}

function validateEntry(value: unknown): AllowlistEntry | null {
  if (!value || typeof value !== "object") return null;
  const candidate = value as Partial<AllowlistEntry>;
  const host = normalizeAllowlistHost(candidate.host);
  if (!host || candidate.type !== "exact-host") return null;
  const createdAt = typeof candidate.createdAt === "string" && Number.isFinite(Date.parse(candidate.createdAt))
    ? candidate.createdAt
    : new Date().toISOString();
  const entry: AllowlistEntry = {
    id: typeof candidate.id === "string" && candidate.id.length <= 100 ? candidate.id : crypto.randomUUID(),
    type: "exact-host",
    host,
    createdAt
  };
  if (typeof candidate.note === "string" && candidate.note.length <= 256) entry.note = candidate.note;
  return entry;
}

export function parseSettings(value: unknown): Settings {
  if (!value || typeof value !== "object") return structuredClone(DEFAULT_SETTINGS);
  const candidate = value as Partial<Settings>;
  const mode: CtMode = candidate.ctMode === "hardened" ? "hardened" : "yandex-required";
  const unique = new Map<string, AllowlistEntry>();
  if (Array.isArray(candidate.allowlist)) {
    for (const value of candidate.allowlist.slice(0, 1000)) {
      const entry = validateEntry(value);
      if (entry) unique.set(entry.host, entry);
    }
  }
  return { schema: 1, enabled: candidate.enabled !== false, ctMode: mode, allowlist: [...unique.values()] };
}

let current = structuredClone(DEFAULT_SETTINGS);
let ready: Promise<Settings> | undefined;

export function getSettings(): Promise<Settings> {
  ready ??= browser.storage.local.get(STORAGE_KEY).then((stored) => {
    current = parseSettings(stored[STORAGE_KEY]);
    return current;
  });
  return ready.then(() => structuredClone(current));
}

async function save(next: Settings): Promise<Settings> {
  current = parseSettings(next);
  ready = Promise.resolve(current);
  await browser.storage.local.set({ [STORAGE_KEY]: current });
  return structuredClone(current);
}

export async function updateSettings(patch: { enabled?: boolean; ctMode?: CtMode }): Promise<Settings> {
  await getSettings();
  return save({ ...current, ...patch });
}

export async function addAllowedHost(host: string): Promise<Settings> {
  await getSettings();
  const normalized = normalizeAllowlistHost(host);
  if (!normalized) throw new Error("Разрешены только DNS-имена");
  if (current.allowlist.some((entry) => entry.host === normalized)) return structuredClone(current);
  return save({ ...current, allowlist: [...current.allowlist, { id: crypto.randomUUID(), type: "exact-host", host: normalized, createdAt: new Date().toISOString() }] });
}

export async function removeAllowedHost(id: string): Promise<Settings> {
  await getSettings();
  return save({ ...current, allowlist: current.allowlist.filter((entry) => entry.id !== id) });
}

export async function importSettings(value: unknown): Promise<Settings> {
  const serialized = JSON.stringify(value);
  if (serialized.length > 256 * 1024) throw new Error("Файл настроек слишком большой");
  return save(parseSettings(value));
}

export function isAllowed(settings: Settings, host: string): boolean {
  return settings.allowlist.some((entry) => entry.host === host);
}
