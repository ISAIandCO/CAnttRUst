import type { PublicSecurityEvent, SecurityEvent } from "../core/types";

const events = new Map<string, SecurityEvent>();
const TTL_MS = 10 * 60_000;
const MAX_EVENTS = 20;

function prune(): void {
  const cutoff = Date.now() - TTL_MS;
  for (const [id, event] of events) if (Date.parse(event.timestamp) < cutoff) events.delete(id);
}

export function addEvent(event: Omit<SecurityEvent, "id" | "timestamp">): SecurityEvent {
  prune();
  while (events.size >= MAX_EVENTS) events.delete(events.keys().next().value as string);
  const stored = { ...event, id: crypto.randomUUID(), timestamp: new Date().toISOString() };
  events.set(stored.id, stored);
  return stored;
}

export function getEvent(id: string): SecurityEvent | undefined {
  prune();
  return events.get(id);
}

export function publicEvent(event: SecurityEvent): PublicSecurityEvent {
  const { originalUrl: _originalUrl, ...safe } = event;
  return safe;
}

export function clearTabEvents(tabId: number): void {
  for (const [id, event] of events) if (event.tabId === tabId) events.delete(id);
}
