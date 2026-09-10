import { createHash, createHmac, randomUUID } from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

import { versionForChannel } from "./release-version.mjs";

const manifest = JSON.parse(readFileSync(new URL("../manifest.firefox.json", import.meta.url), "utf8"));
const channel = process.argv[2] ?? "listed";
const version = versionForChannel(manifest.version, channel);
const addon = encodeURIComponent(manifest.browser_specific_settings.gecko.id);
const issuer = process.env.WEB_EXT_API_KEY;
const secret = process.env.WEB_EXT_API_SECRET;
if (!issuer || !secret) throw new Error("Configure AMO_JWT_ISSUER and AMO_JWT_SECRET repository secrets");
const now = Math.floor(Date.now() / 1000);
const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const payload = `${encode({ alg: "HS256", typ: "JWT" })}.${encode({ iss: issuer, jti: randomUUID(), iat: now, exp: now + 60 })}`;
const jwt = `${payload}.${createHmac("sha256", secret).update(payload).digest("base64url")}`;
const response = await fetch(`https://addons.mozilla.org/api/v5/addons/addon/${addon}/versions/${encodeURIComponent(version)}/`, {
  headers: { Authorization: `JWT ${jwt}` }, signal: AbortSignal.timeout(30000), redirect: "error"
});
let status;
let data;
if (response.status === 404) status = "not-submitted";
else {
  if (!response.ok) throw new Error(`AMO status check failed: HTTP ${response.status}`);
  data = await response.json();
  if (data.version !== version || data.channel !== channel) throw new Error("AMO version/channel conflict; review the version in Developer Hub");
  status = data.is_disabled ? "disabled" : data.file?.status;
  if (!["public", "unreviewed", "disabled"].includes(status)) throw new Error("Unknown AMO version status; inspect Developer Hub");
}
if (channel === "unlisted" && status === "public" && process.argv.includes("--download")) {
  const url = new URL(data.file.url);
  if (url.origin !== "https://addons.mozilla.org" || !/^sha256:[0-9a-f]{64}$/.test(data.file.hash)) throw new Error("Unexpected signed download URL/hash");
  const file = await fetch(url, { headers: { Authorization: `JWT ${jwt}` }, signal: AbortSignal.timeout(60000) });
  if (!file.ok) throw new Error(`Signed XPI download failed: HTTP ${file.status}`);
  const chunks = []; let size = 0;
  for await (const chunk of file.body) {
    size += chunk.length;
    if (size > 16 * 1024 * 1024) throw new Error("Signed XPI exceeds size limit");
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks);
  if (`sha256:${createHash("sha256").update(bytes).digest("hex")}` !== data.file.hash) throw new Error("Signed XPI checksum mismatch");
  mkdirSync("artifacts/signed", { recursive: true });
  writeFileSync("artifacts/signed/canttrust-unlisted.xpi", bytes);
}
const descriptions = {
  "not-submitted": "Версия пока не найдена в AMO.",
  public: "Версия одобрена AMO.",
  unreviewed: "Версия отправлена и ожидает проверки Mozilla.",
  disabled: "Версия отключена, отклонена или требует действий в Developer Hub."
};
mkdirSync("artifacts/amo", { recursive: true });
writeFileSync("artifacts/amo/status.json", `${JSON.stringify({ version, channel, status, checkedAt: new Date().toISOString() }, null, 2)}\n`);
const summary = `CAnttRUst ${version} (${channel}): ${descriptions[status]}`;
console.log(summary);
if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `status=${status}\nversion=${version}\n`);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${summary}\n\n`);
if (status === "disabled") process.exitCode = 1;
