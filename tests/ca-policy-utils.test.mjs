import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { addRootFingerprints, inspectRootBundle } from "../scripts/ca-policy-utils.mjs";
const root = readFileSync(new URL("fixtures/russian-trusted-root-ca.pem", import.meta.url));

describe("root source monitoring", () => {
  it("computes the existing root DER fingerprint and verifies its self-signature", () => {
    expect(inspectRootBundle(root)[0].derSha256).toBe("d26d2d0231b7c39f92cc738512ba54103519e4405d68b5bd703e9788ca8ecf31");
    expect(inspectRootBundle(Buffer.from(`\n${root}\n`))[0].derSha256).toBe(inspectRootBundle(root)[0].derSha256);
  });
  it("preserves old restrictions and deduplicates new roots", () => {
    const roots = [{ derSha256: "new" }, { derSha256: "new" }];
    expect(addRootFingerprints(["old"], roots)).toEqual(["new", "old"]);
    expect(addRootFingerprints(["old"], [])).toEqual(["old"]);
  });
  it("rejects an HTML/error response or corrupted certificate", () => {
    for (const input of ["", "<html>maintenance</html>", `garbage\n${root}`, root.toString().replace("MI", "!!")]) {
      expect(() => inspectRootBundle(Buffer.from(input))).toThrow();
    }
  });
});
