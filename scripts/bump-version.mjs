import { readFile, writeFile } from "node:fs/promises";
const paths = ["package.json", "package-lock.json", "manifest.firefox.json"];
const files = await Promise.all(paths.map(async (path) => JSON.parse(await readFile(new URL(`../${path}`, import.meta.url), "utf8"))));
const current = files[0].version;
if (!/^\d+\.\d+\.\d+$/.test(current) || files.some((file) => file.version !== current) || files[1].packages[""].version !== current) throw new Error("Expected synchronized three-part versions");
const parts = current.split(".").map(Number);
parts[2]++;
if (parts.some((part) => !Number.isSafeInteger(part) || part > 65535)) throw new Error("Version exceeds Firefox limits");
const next = parts.join(".");
for (const [index, path] of paths.entries()) {
  files[index].version = next;
  if (path === "package-lock.json") files[index].packages[""].version = next;
  await writeFile(new URL(`../${path}`, import.meta.url), `${JSON.stringify(files[index], null, 2)}\n`);
}
console.log(`Version: ${current} -> ${next}`);
