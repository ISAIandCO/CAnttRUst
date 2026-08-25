import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";

const root = new URL("../dist/firefox/", import.meta.url);

async function snapshot(directory) {
  const entries = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) entries.push(...await snapshot(new URL(`${entry.name}/`, directory)));
    else {
      const file = new URL(entry.name, directory);
      const relative = decodeURIComponent(file.pathname.slice(root.pathname.length));
      entries.push([relative, createHash("sha256").update(await readFile(file)).digest("hex")]);
    }
  }
  return entries.sort(([a], [b]) => a.localeCompare(b));
}

function build() {
  const result = spawnSync(process.execPath, [new URL("build.mjs", import.meta.url).pathname], { stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

build();
const first = JSON.stringify(await snapshot(root));
build();
const second = JSON.stringify(await snapshot(root));
if (first !== second) throw new Error("Two consecutive builds differ");
console.log("Reproducibility check passed");

