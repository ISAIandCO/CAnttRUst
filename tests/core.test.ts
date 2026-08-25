import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import ctList from "../src/policy/ct/yandex-nuc-log-list.json";
import { matchProtectedCA } from "../src/core/ca";
import { ecdsaDerSignatureToRaw, parseSctList, verifyEmbeddedScts, type CtLog } from "../src/core/ct";
import { normalizeSha256, sha256Hex } from "../src/core/fingerprint";
import { isHostInAllowedZones, normalizeHostname } from "../src/core/hostname";
import { consumeBypass, createBypass } from "../src/state/bypass";
import { parseSettings } from "../src/state/settings";
import type { CertificateSnapshot, ProtectedCa } from "../src/core/types";

describe("hostname policy", () => {
  it("normalizes Russian DNS zones without suffix confusion", () => {
    expect(normalizeHostname("https://ПРИМЕР.РФ./")).toMatchObject({ ascii: "xn--e1afmkfd.xn--p1ai", kind: "dns", protectedZone: "rf" });
    expect(isHostInAllowedZones("a.example.ru", ["ru", "su", "xn--p1ai"])).toBe(true);
    expect(isHostInAllowedZones("example.ru.evil.test", ["ru"])).toBe(false);
    expect(normalizeHostname("https://127.0.0.1/").kind).toBe("ipv4");
    expect(normalizeHostname("https://[::1]/").kind).toBe("ipv6");
  });
});

describe("certificate matching", () => {
  it("matches the DER hash anywhere in the returned chain", async () => {
    const der = Uint8Array.of(1, 2, 3);
    const hash = await sha256Hex(der);
    const certificate = (bytes: Uint8Array, derSha256: string): CertificateSnapshot => ({
      rawDER: bytes,
      derSha256,
      subject: "subject",
      issuer: "issuer",
      isBuiltInRoot: false,
      validityStart: 0,
      validityEnd: 1
    });
    const policy: ProtectedCa[] = [{ id: "test", name: "test", rootDerSha256: [hash.toUpperCase()], allowedDnsZones: ["ru"], allowIp: false, ctPolicy: "test" }];
    expect(normalizeSha256(`aa:${"00:".repeat(29)}bb`)).toBe(null);
    expect(matchProtectedCA([certificate(Uint8Array.of(0), "0".repeat(64)), certificate(der, hash)], policy)?.certificateIndex).toBe(1);
  });
});

describe("SCT parser", () => {
  it("parses one bounded SCT and rejects malformed lengths", () => {
    const signature = Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02);
    const raw = Uint8Array.of(0, ...new Uint8Array(32), ...new Uint8Array(8), 0, 0, 4, 3, 0, signature.length, ...signature);
    const list = Uint8Array.of((raw.length + 2) >> 8, (raw.length + 2) & 0xff, raw.length >> 8, raw.length & 0xff, ...raw);
    expect(parseSctList(list)).toHaveLength(1);
    expect(ecdsaDerSignatureToRaw(signature)).toEqual(Uint8Array.of(...new Uint8Array(31), 1, ...new Uint8Array(31), 2));
    expect(() => parseSctList(list.slice(0, -1))).toThrow("invalid SCT list length");
  });

  it("verifies real embedded SCT signatures from three Russian operators", async () => {
    const leaf = new Uint8Array(readFileSync(new URL("fixtures/check-russian-trusted-leaf.der", import.meta.url)));
    const issuer = new Uint8Array(readFileSync(new URL("fixtures/russian-trusted-sub-ca.der", import.meta.url)));
    const logs: CtLog[] = ctList.operators.flatMap((operator) => operator.logs.map((log) => ({
      operator: operator.name,
      description: log.description,
      key: log.key,
      logId: log.log_id,
      startInclusive: Date.parse(log.temporal_interval.start_inclusive),
      endExclusive: Date.parse(log.temporal_interval.end_exclusive)
    })));
    const verdict = await verifyEmbeddedScts(leaf, issuer, logs, "hardened");
    expect(verdict).toMatchObject({ status: "valid", policy: "hardened" });
    if (verdict.status === "valid") expect(new Set(verdict.validScts.map((sct) => sct.operator))).toEqual(new Set([
      "Yandex",
      "VK LLC",
      "The Ministry of Digital Development and Communications"
    ]));
  });
});

describe("settings import", () => {
  it("keeps exact DNS hosts, removes duplicates and rejects IP entries", () => {
    const parsed = parseSettings({ enabled: false, ctMode: "hardened", allowlist: [
      { id: "1", type: "exact-host", host: "пример.рф", createdAt: "2026-01-01T00:00:00Z" },
      { id: "2", type: "exact-host", host: "xn--e1afmkfd.xn--p1ai", createdAt: "2026-01-02T00:00:00Z" },
      { id: "3", type: "exact-host", host: "127.0.0.1", createdAt: "2026-01-03T00:00:00Z" }
    ] });
    expect(parsed).toMatchObject({ enabled: false, ctMode: "hardened" });
    expect(parsed.allowlist).toHaveLength(1);
    expect(parsed.allowlist[0]?.host).toBe("xn--e1afmkfd.xn--p1ai");
  });
});

describe("one-shot bypass", () => {
  it("is exact and consumed once", () => {
    const input = { tabId: 7, incognito: true, host: "example.test", originalUrl: "https://example.test/path" };
    createBypass(input);
    expect(consumeBypass({ ...input, originalUrl: "https://example.test/other" })).toBe(false);
    expect(consumeBypass(input)).toBe(true);
    expect(consumeBypass(input)).toBe(false);
  });
});
