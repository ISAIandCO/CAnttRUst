import { normalizeHostname } from "../core/hostname";
import type { AllowlistEntry, CtMode, ExceptionScope, ExceptionDuration, Settings } from "../core/types";

const SESSION_ID = crypto.randomUUID();
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
  if (candidate.scope !== undefined && !["zone", "ct", "all"].includes(candidate.scope)) return null;
  if (candidate.expiresAt !== undefined && (!Number.isFinite(candidate.expiresAt) || candidate.expiresAt <= Date.now())) return null;
  if (candidate.sessionId !== undefined && candidate.sessionId !== SESSION_ID) return null;
  const createdAt = typeof candidate.createdAt === "string" && Number.isFinite(Date.parse(candidate.createdAt))
    ? candidate.createdAt
    : new Date().toISOString();
  const entry: AllowlistEntry = {
    id: typeof candidate.id === "string" && candidate.id.length <= 100 ? candidate.id : crypto.randomUUID(),
    type: "exact-host",
    host,
    createdAt,
    scope: candidate.scope ?? "all",
    incognito: candidate.incognito === true
  };
  if (candidate.expiresAt !== undefined) entry.expiresAt = candidate.expiresAt;
  if (candidate.sessionId !== undefined) entry.sessionId = candidate.sessionId;
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
      if (entry) unique.set(`${entry.host}:${entry.scope}:${entry.incognito}`, entry);
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
  return ready.then(() => parseSettings(current));
}

let writes: Promise<unknown> = Promise.resolve();
function mutate(change: (settings: Settings) => Settings): Promise<Settings> {
  const operation = writes.then(async () => {
    const next = parseSettings(change(await getSettings()));
    await browser.storage.local.set({ [STORAGE_KEY]: { ...next,
      allowlist: next.allowlist.filter((entry) => !entry.sessionId && !entry.incognito)
    } });
    current = next;
    return structuredClone(next);
  });
  writes = operation.catch(() => undefined);
  return operation;
}

export function updateSettings(patch: { enabled?: boolean; ctMode?: CtMode }): Promise<Settings> {
  return mutate((settings) => ({ ...settings, ...patch }));
}

export function addAllowedHost(host: string, scope: ExceptionScope = "all", duration: ExceptionDuration = "permanent", incognito = false): Promise<Settings> {
  const normalized = normalizeAllowlistHost(host);
  if (!normalized) throw new Error("Разрешены только DNS-имена");
  if (!["zone", "ct", "all"].includes(scope) || !["session", "hour", "permanent"].includes(duration)) throw new Error("Некорректное исключение");
  const entry: AllowlistEntry = { id: crypto.randomUUID(), type: "exact-host", host: normalized,
    createdAt: new Date().toISOString(), scope, incognito };
  if (duration === "hour") entry.expiresAt = Date.now() + 3600_000;
  if (duration === "session" || incognito) entry.sessionId = SESSION_ID;
  return mutate((settings) => {
    const remaining = settings.allowlist.filter((item) =>
      !(item.host === normalized && item.scope === scope && Boolean(item.incognito) === incognito));
    if (remaining.length >= 1000) throw new Error("Достигнут предел в 1000 исключений");
    return { ...settings, allowlist: [...remaining, entry] };
  });
}

export function removeAllowedHost(id: string): Promise<Settings> {
  return mutate((settings) => ({ ...settings, allowlist: settings.allowlist.filter((entry) => entry.id !== id) }));
}

export function clearPrivateExceptions(): Promise<Settings> {
  return mutate((settings) => ({ ...settings, allowlist: settings.allowlist.filter((entry) => !entry.incognito) }));
}

export function importSettings(value: unknown): Promise<Settings> {
  const serialized = JSON.stringify(value);
  if (!serialized || serialized.length > 256 * 1024) throw new Error("Файл настроек слишком большой");
  const parsed = parseSettings(value);
  parsed.allowlist = parsed.allowlist.filter((entry) => !entry.sessionId && !entry.incognito);
  return mutate(() => parsed);
}

export function isAllowed(settings: Settings, host: string, scope: "zone" | "ct", incognito = false): boolean {
  return settings.allowlist.some((entry) => entry.host === host && Boolean(entry.incognito) === incognito
    && (entry.scope === undefined || entry.scope === "all" || entry.scope === scope)
    && (entry.expiresAt === undefined || entry.expiresAt > Date.now())
    && (entry.sessionId === undefined || entry.sessionId === SESSION_ID));
}
