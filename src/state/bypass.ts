type Bypass = {
  id: string;
  tabId: number;
  incognito: boolean;
  host: string;
  originalUrl: string;
  expiresAt: number;
};

const entries = new Map<string, Bypass>();

function prune(): void {
  const now = Date.now();
  for (const [id, entry] of entries) if (entry.expiresAt <= now) entries.delete(id);
}

export function createBypass(input: Omit<Bypass, "id" | "expiresAt">): void {
  prune();
  const entry = { ...input, id: crypto.randomUUID(), expiresAt: Date.now() + 60_000 };
  entries.set(entry.id, entry);
}

export function consumeBypass(input: Omit<Bypass, "id" | "expiresAt">): boolean {
  prune();
  for (const [id, entry] of entries) {
    if (entry.tabId === input.tabId && entry.incognito === input.incognito && entry.host === input.host && entry.originalUrl === input.originalUrl) {
      entries.delete(id);
      return true;
    }
  }
  return false;
}
