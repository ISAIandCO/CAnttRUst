import { readdir, readFile } from "node:fs/promises";

const root = new URL("../dist/firefox/", import.meta.url);
const forbidden = [
  [/\beval\s*\(/, "eval"],
  [/\bnew\s+Function\s*\(/, "new Function"],
  [/<script\b[^>]*\bsrc=["']https?:\/\//i, "remote script"],
  [/\bimport\s*\(\s*["']https?:\/\//, "remote import"]
];

async function files(directory) {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const url = new URL(entry.name, directory);
    if (entry.isDirectory()) result.push(...await files(new URL(`${entry.name}/`, directory)));
    else if (/\.(?:html|js|mjs|css)$/.test(entry.name)) result.push(url);
  }
  return result;
}

for (const file of await files(root)) {
  const source = await readFile(file, "utf8");
  for (const [pattern, label] of forbidden) {
    if (pattern.test(source)) throw new Error(`${label} found in ${file.pathname}`);
  }
}

console.log("Bundle scan passed: no dynamic code or remote scripts");

