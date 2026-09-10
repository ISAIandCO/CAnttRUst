import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { build } from "esbuild";
import { versionForChannel } from "./release-version.mjs";

const dist = new URL("../dist/firefox/", import.meta.url);
const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const manifest = JSON.parse(await readFile(new URL("../manifest.firefox.json", import.meta.url), "utf8"));
const channel = process.argv[2] ?? "amo";

if (!new Set(["amo", "self-hosted"]).has(channel)) {
  throw new Error(`Unknown build channel: ${channel}`);
}
if (channel === "self-hosted") {
  manifest.browser_specific_settings.gecko.update_url =
    "https://github.com/ISAIandCO/CAnttRUst/releases/latest/download/updates.json";
}

if (pkg.version !== manifest.version) {
  throw new Error(`Version mismatch: package ${pkg.version}, manifest ${manifest.version}`);
}

manifest.version = versionForChannel(pkg.version, channel === "self-hosted" ? "unlisted" : "listed");

await rm(dist, { recursive: true, force: true });
await mkdir(new URL("icons/", dist), { recursive: true });
await mkdir(new URL("policy/ct/", dist), { recursive: true });

await build({
  absWorkingDir: new URL("..", import.meta.url).pathname,
  entryPoints: {
    background: "src/adapters/firefox/background.ts",
    warning: "src/ui/warning/warning.ts",
    options: "src/ui/options/options.ts"
  },
  outdir: dist.pathname,
  bundle: true,
  format: "iife",
  platform: "browser",
  target: "firefox142",
  sourcemap: false,
  minify: false,
  legalComments: "inline"
});

await writeFile(new URL("manifest.json", dist), `${JSON.stringify(manifest, null, 2)}\n`);
for (const name of ["warning.html", "warning.css", "options.html", "options.css"]) {
  const area = name.startsWith("warning") ? "warning" : "options";
  await cp(new URL(`../src/ui/${area}/${name}`, import.meta.url), new URL(name, dist));
}
for (const size of [48, 96, 128]) {
  await cp(new URL(`../src/ui/icons/icon-${size}.png`, import.meta.url), new URL(`icons/icon-${size}.png`, dist));
}
await cp(new URL("../src/policy/protected-cas.json", import.meta.url), new URL("policy/protected-cas.json", dist));
await cp(new URL("../src/policy/ct/yandex-nuc-log-list.json", import.meta.url), new URL("policy/ct/yandex-nuc-log-list.json", dist));
await cp(new URL("../src/policy/ct/ct-policy-lock.json", import.meta.url), new URL("policy/ct/ct-policy-lock.json", dist));

console.log(`Built ${pkg.name} ${manifest.version} (${channel}) in ${dist.pathname}`);
