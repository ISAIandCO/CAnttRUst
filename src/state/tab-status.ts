export type RequestStatus = {
  host: string;
  type: string;
  status: "valid" | "other_ca" | "blocked" | "unavailable" | "exception" | "disabled";
  reason: string;
  ca?: string;
  operators?: string[];
};
export type TabStatus = { main?: RequestStatus; resources: RequestStatus[]; blockedHosts: string[]; blocked: number; unavailable: number };
const tabs = new Map<number, TabStatus>();
const epochs = new Map<number, number>();
let nextEpoch = 0;
export function resetTab(tabId: number): void {
  tabs.delete(tabId);
  epochs.set(tabId, ++nextEpoch);
}
export function forgetTab(tabId: number): void { tabs.delete(tabId); epochs.delete(tabId); }
export function tabEpoch(tabId: number): number { return epochs.get(tabId) ?? 0; }
export function getTabStatus(tabId: number): TabStatus {
  return structuredClone(tabs.get(tabId) ?? { resources: [], blockedHosts: [], blocked: 0, unavailable: 0 });
}
export function recordStatus(tabId: number, epoch: number, result: RequestStatus): TabStatus | undefined {
  if (tabId < 0 || epoch !== tabEpoch(tabId)) return;
  const state = tabs.get(tabId) ?? { resources: [], blockedHosts: [], blocked: 0, unavailable: 0 };
  if (result.type === "main_frame") state.main = result;
  else if (result.ca && result.status !== "other_ca") {
    const index = state.resources.findIndex((item) => item.host === result.host && item.type === result.type && item.status === result.status && item.reason === result.reason);
    if (index >= 0) state.resources.splice(index, 1);
    state.resources.unshift(result);
    state.resources.length = Math.min(state.resources.length, 20);
  }
  if (result.status === "blocked") {
    state.blocked++;
    if (!state.blockedHosts.includes(result.host) && state.blockedHosts.length < 1000) state.blockedHosts.push(result.host);
  }
  if (result.status === "unavailable") state.unavailable++;
  tabs.set(tabId, state);
  return state;
}

export function badgeText(state: TabStatus): string {
  return state.blocked > 99 ? "99+" : state.blocked ? String(state.blocked)
    : state.unavailable ? "?" : state.main?.status === "valid" ? "CT" : "";
}
