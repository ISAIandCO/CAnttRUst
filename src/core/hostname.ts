import type { NormalizedHost } from "./types";

function zone(host: string): NormalizedHost["protectedZone"] {
  if (host === "ru" || host.endsWith(".ru")) return "ru";
  if (host === "su" || host.endsWith(".su")) return "su";
  if (host === "xn--p1ai" || host.endsWith(".xn--p1ai")) return "rf";
  return null;
}

function isIpv4(host: string): boolean {
  const parts = host.split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

export function normalizeHostname(input: string): NormalizedHost {
  try {
    const url = new URL(input);
    let host = url.hostname.toLowerCase().replace(/\.$/, "");
    if (!host) throw new Error("missing hostname");
    if (host.startsWith("[") && host.endsWith("]")) {
      host = host.slice(1, -1);
      return { ascii: host, display: host, kind: "ipv6", protectedZone: null };
    }
    if (isIpv4(host)) return { ascii: host, display: host, kind: "ipv4", protectedZone: null };
    if (host === "localhost") return { ascii: host, display: host, kind: "localhost", protectedZone: null };
    return { ascii: host, display: host, kind: "dns", protectedZone: zone(host) };
  } catch {
    return { ascii: "", display: "", kind: "invalid", protectedZone: null };
  }
}

export function isHostInAllowedZones(host: string, zones: string[]): boolean {
  return zones.some((allowed) => host === allowed || host.endsWith(`.${allowed}`));
}
