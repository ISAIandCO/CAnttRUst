import { execFileSync } from "node:child_process";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

import { effectiveCtPolicy } from "./policy-utils.mjs";

const errors = [];
const checks = [];
for (const [name, script] of [["CT-логи", "update-ct-policy.mjs"], ["Корневые сертификаты", "update-ca-policy.mjs"]]) {
  try {
    const output = execFileSync(process.execPath, [`scripts/${script}`], { encoding: "utf8", timeout: 60000 });
    checks.push(`${name}: проверено.\n${output.trim()}`);
  } catch (error) {
    errors.push(`${name}: ${String(error.stderr || error.message).slice(0, 4000)}`);
  }
}
const changed = Boolean(execFileSync("git", ["status", "--porcelain", "--", "src/policy"], { encoding: "utf8" }).trim());
if (changed) {
  execFileSync(process.execPath, ["scripts/bump-version.mjs"], { stdio: "inherit" });
  // Reuse the pending snapshot when only upstream metadata changed since the PR.
  // This avoids a new bot commit every day while the same policy awaits review.
  const read = (path) => JSON.parse(readFileSync(path, "utf8"));
  try {
    const pending = (path) => JSON.parse(execFileSync("git", ["show", `origin/bot/security-policy:${path}`], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }));
    const ctPath = "src/policy/ct/yandex-nuc-log-list.json";
    const caPath = "src/policy/protected-cas.json";
    if (pending("package.json").version === read("package.json").version &&
        JSON.stringify(effectiveCtPolicy(pending(ctPath))) === JSON.stringify(effectiveCtPolicy(read(ctPath))) &&
        JSON.stringify(pending(caPath)) === JSON.stringify(read(caPath))) {
      // Restore only data/version paths owned by the bot, never workflow or source code.
      execFileSync("git", ["restore", "--source=origin/bot/security-policy", "--worktree", "--", "src/policy", "package.json", "package-lock.json", "manifest.firefox.json"]);
    }
  } catch { /* No pending branch: create the first candidate. */ }
}
mkdirSync("artifacts", { recursive: true });
const report = [
  "Обновление локальной политики CAnttRUst.",
  "Изменения вступят в силу после слияния этого PR и выпуска версии. Слияние запускает отправку в AMO; решение о публикации принимает Mozilla.",
  "Проверьте новые ключи, статусы CT-логов и DER-отпечатки корней в diff. Автоматического слияния нет. Хеш скачанного файла и самоподпись корня не подтверждают подлинность источника.",
  ...checks.map((line) => `\`\`\`text\n${line}\n\`\`\``),
  ...(errors.length ? ["Не все источники проверены — успешные проверки обработаны независимо:", ...errors.map((line) => `\`\`\`text\n${line}\n\`\`\``)] : [])
].join("\n\n");
writeFileSync("artifacts/policy-update.md", `${report}\n`);
writeFileSync("artifacts/policy-errors.md", errors.join("\n\n") || "Все источники проверены.");
if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `changed=${changed}\nerrors=${errors.length > 0}\n`);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${report}\n`);
console.log(report);
