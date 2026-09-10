import { afterEach, describe, expect, it } from "vitest";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const source = fileURLToPath(new URL("../", import.meta.url));
const dirs = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });
function setup() {
  const dir = mkdtempSync(join(tmpdir(), "canttrust-update-")); dirs.push(dir);
  for (const path of ["scripts", "src/policy", "package.json", "package-lock.json", "manifest.firefox.json"]) cpSync(join(source, path), join(dir, path), { recursive: true });
  const git = (...args) => execFileSync("git", args, { cwd: dir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  git("init", "-q"); git("add", "."); git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "baseline");
  const mock = join(dir, "mock.mjs");
  writeFileSync(mock, `import {readFileSync} from 'node:fs';
globalThis.fetch = async (url) => {
  if (String(url).includes('addons.mozilla.org')) return new Response(process.env.AMO_BODY || '', {status:Number(process.env.AMO_HTTP || 200)});
  if (String(url).includes('gu-st.ru')) return new Response(readFileSync(process.env.ROOT_FILE), {status:Number(process.env.ROOT_HTTP || 200)});
  return new Response(readFileSync(process.env.CT_FILE));
};`);
  const ctPath = join(dir, "source.json");
  const ct = JSON.parse(readFileSync(join(dir, "src/policy/ct/yandex-nuc-log-list.json"), "utf8"));
  const env = { ...process.env, NODE_OPTIONS: `--import=${mock}`, CT_FILE: ctPath,
    ROOT_FILE: join(source, "tests/fixtures/russian-trusted-root-ca.pem"),
    GITHUB_OUTPUT: join(dir, "output"), GITHUB_STEP_SUMMARY: join(dir, "summary") };
  const run = (script, extra = {}) => spawnSync(process.execPath, [`scripts/${script}`], { cwd: dir, env: { ...env, ...extra }, encoding: "utf8", timeout: 10000 });
  return { dir, git, ct, run, save: () => writeFileSync(ctPath, JSON.stringify(ct)), read: (path) => readFileSync(join(dir, path), "utf8") };
}

describe("policy update pipeline", () => {
  it("does not bump the version or rewrite snapshots for source metadata", () => {
    const t = setup(); const version = JSON.parse(t.read("package.json")).version;
    t.ct.version = "999.0"; t.ct.operators[0].email = ["new@example.test"]; t.save();
    const result = t.run("prepare-policy-update.mjs");
    expect(result.status, result.stderr).toBe(0);
    expect(t.read("output")).toContain("changed=false");
    expect(JSON.parse(t.read("package.json")).version).toBe(version);
    expect(t.git("diff", "--stat")).toBe("");
  });
  it("bumps all versions once and reuses the same pending policy on a later check", () => {
    const t = setup(); const base = t.git("rev-parse", "HEAD").trim();
    const version = JSON.parse(t.read("package.json")).version.split(".").map(Number); version[2]++;
    t.ct.operators[0].logs[0].state = { retired: { timestamp: "2026-09-01T00:00:00Z" } }; t.save();
    let result = t.run("prepare-policy-update.mjs"); expect(result.status, result.stderr).toBe(0);
    for (const path of ["package.json", "package-lock.json", "manifest.firefox.json"]) expect(JSON.parse(t.read(path)).version).toBe(version.join("."));
    t.git("add", "src/policy", "package.json", "package-lock.json", "manifest.firefox.json");
    t.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "candidate");
    const candidate = t.git("rev-parse", "HEAD").trim();
    t.git("update-ref", "refs/remotes/origin/bot/security-policy", candidate);
    t.git("reset", "--hard", base);
    t.ct.version = "999.0"; t.ct.operators[0].email = ["metadata-only@example.test"]; t.save();
    result = t.run("prepare-policy-update.mjs"); expect(result.status, result.stderr).toBe(0);
    expect(t.git("diff", candidate, "--", "src/policy", "package.json", "package-lock.json", "manifest.firefox.json")).toBe("");
  });
  it("reports a root-source failure without losing a valid CT candidate", () => {
    const t = setup(); t.ct.operators[0].logs[0].state = { retired: { timestamp: "2026-09-01T00:00:00Z" } }; t.save();
    const result = t.run("prepare-policy-update.mjs", { ROOT_HTTP: "503" });
    expect(result.status, result.stderr).toBe(0); // Workflow consumes errors=true and marks the run failed.
    expect(t.read("output")).toContain("changed=true\nerrors=true");
    expect(t.read("artifacts/policy-errors.md")).toContain("503");
    expect(t.git("diff", "--", "src/policy/protected-cas.json")).toBe("");
  });
});

describe("AMO preflight and status", () => {
  it.each(["public", "unreviewed", "disabled"])("recognizes an existing %s version instead of resubmitting it", (status) => {
    const t = setup(); const version = JSON.parse(t.read("package.json")).version;
    const result = t.run("amo-status.mjs", { WEB_EXT_API_KEY: "test", WEB_EXT_API_SECRET: "test",
      AMO_BODY: JSON.stringify({ version, channel: "listed", file: { status } }) });
    expect(result.status, result.stderr).toBe(status === "disabled" ? 1 : 0);
    expect(t.read("output")).toContain(`status=${status}`);
  });
  it("allows submission only for a missing version; API failures and channel conflicts stop it", () => {
    const t = setup(); const version = JSON.parse(t.read("package.json")).version;
    const secrets = { WEB_EXT_API_KEY: "test", WEB_EXT_API_SECRET: "test" };
    expect(t.run("amo-status.mjs", { ...secrets, AMO_HTTP: "404" }).status).toBe(0);
    expect(t.read("output")).toContain("status=not-submitted");
    expect(t.run("amo-status.mjs", { ...secrets, AMO_HTTP: "503" }).status).toBe(1);
    expect(t.run("amo-status.mjs", { ...secrets, AMO_BODY: JSON.stringify({ version, channel: "unlisted", file: { status: "public" } }) }).status).toBe(1);
  });
});
