import { mkdtemp, readFile, writeFile, cp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn, execFileSync } from "node:child_process";
import { createServer as httpServer } from "node:http";
import { createServer as httpsServer } from "node:https";
import { X509Certificate, createHash } from "node:crypto";
import { build } from "esbuild";
const root = new URL("../", import.meta.url).pathname;
const temp = await mkdtemp(join(tmpdir(), "canttrust-firefox-"));
let driver, session;
let driverLog = "";
const servers = [];
const webdriver = process.env.GECKODRIVER ?? "geckodriver";
const firefox = process.env.FIREFOX_BINARY;
const portServer = httpServer();
await new Promise((done) => portServer.listen(0, "127.0.0.1", done));
const driverPort = portServer.address().port;
await new Promise((done) => portServer.close(done));
async function api(path, body, method = "POST") {
  const response = await fetch(`http://127.0.0.1:${driverPort}${path}`, { method, ...(body === undefined ? {} : { body: JSON.stringify(body), headers: { "Content-Type": "application/json" } }), signal: AbortSignal.timeout(60_000) });
  const data = await response.json();
  if (!response.ok) throw new Error(JSON.stringify(data));
  return data.value;
}
async function listen(server) {
  servers.push(server);
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  return server.address().port;
}
try {
  async function certificate(name) {
    const key = join(temp, `${name}.key`), cert = join(temp, `${name}.pem`);
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-keyout", key, "-out", cert, "-subj", `/CN=${name}`, "-addext", "subjectAltName=DNS:a.test"], { stdio: "ignore" });
    const leafKey = join(temp, `${name}-leaf.key`), leafCert = join(temp, `${name}-leaf.pem`), csr = join(temp, `${name}.csr`), ext = join(temp, `${name}.ext`);
    execFileSync("openssl", ["req", "-newkey", "rsa:2048", "-nodes", "-keyout", leafKey, "-out", csr, "-subj", "/CN=a.test"], { stdio: "ignore" });
    await writeFile(ext, "subjectAltName=DNS:a.test\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n");
    execFileSync("openssl", ["x509", "-req", "-in", csr, "-CA", cert, "-CAkey", key, "-CAcreateserial", "-out", leafCert, "-days", "2", "-extfile", ext], { stdio: "ignore" });
    return { key: leafKey, cert: leafCert, root: cert };
  }
  const cert = await certificate("protected-test"), otherCert = await certificate("ordinary-test");
  let scriptRequests = 0;
  function tlsResponse(req, res) {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Cache-Control", "public, max-age=3600");
    if (req.url.startsWith("/script")) { scriptRequests++; res.setHeader("Content-Type", "application/javascript"); res.end("document.documentElement.dataset.executed = 'yes';"); }
    else { res.setHeader("Content-Type", "text/html"); res.end("<!doctype html><title>TLS fixture</title><p>fixture</p>"); }
  }
  const tlsPort = await listen(httpsServer({ key: await readFile(cert.key), cert: await readFile(cert.cert) }, tlsResponse));
  const otherPort = await listen(httpsServer({ key: await readFile(otherCert.key), cert: await readFile(otherCert.cert) }, tlsResponse));
  const https = `https://a.test:${tlsPort}`, other = `https://a.test:${otherPort}`;
  let finish;
  const result = new Promise((done) => { finish = done; });
  const httpPort = await listen(httpServer((req, res) => {
    if (req.url === "/stats") { res.setHeader("Content-Type", "application/json"); res.end(JSON.stringify({ scriptRequests })); }
    else if (req.url === "/result") {
      let body = ""; req.on("data", (chunk) => { body += chunk; });
      req.on("end", () => { finish(JSON.parse(body)); res.end("ok"); });
    } else if (req.url === "/redirect") { res.writeHead(302, { Location: `${https}/page?redirect` }); res.end(); }
    else {
      res.setHeader("Content-Type", "text/html"); res.setHeader("Cache-Control", "no-store");
      res.end(`<!doctype html><title>Resource fixture</title><script src="${https}/script"></script><iframe src="${https}/frame"></iframe><script>fetch('${https}/fetch').then(()=>document.documentElement.dataset.fetchBlocked='no').catch(()=>document.documentElement.dataset.fetchBlocked='yes')</script>`);
    }
  }));
  const extension = join(temp, "extension");
  await cp(join(root, "dist/firefox"), extension, { recursive: true });
  const hash = createHash("sha256").update(new X509Certificate(await readFile(cert.root)).raw).digest("hex");
  await build({ absWorkingDir: root, entryPoints: ["tests/firefox/runner.ts"], outfile: join(extension, "background.js"), bundle: true, format: "iife", platform: "browser", target: "firefox142",
    define: { TEST_CONFIG: JSON.stringify({ http: `http://127.0.0.1:${httpPort}`, https, other }) },
    plugins: [{ name: "test-ca-only", setup(plugin) { plugin.onLoad({ filter: /protected-cas\.json$/ }, () => ({ loader: "json", contents: JSON.stringify({ cas: [{ id: "test-root", name: "test-root", rootDerSha256: [hash], allowedDnsZones: ["test"], allowIp: false, ctPolicy: "test" }] }) })); } }] });
  const xpi = join(temp, "test.xpi");
  execFileSync("python3", ["-c", "import sys,zipfile,pathlib; root=pathlib.Path(sys.argv[1]); z=zipfile.ZipFile(sys.argv[2],'w'); [z.write(p,p.relative_to(root)) for p in root.rglob('*') if p.is_file()]; z.close()", extension, xpi]);
  driver = spawn(webdriver, ["--port", String(driverPort)], { stdio: ["ignore", "pipe", "pipe"] });
  driver.on("error", (error) => { driverLog += String(error); });
  driver.stdout.on("data", (data) => { driverLog += data; }); driver.stderr.on("data", (data) => { driverLog += data; });
  let started = false;
  for (let i = 0; i < 100; i++) { try { await api("/status", undefined, "GET"); started = true; break; } catch { await new Promise((done) => setTimeout(done, 100)); } }
  if (!started) throw new Error(`geckodriver failed: ${driverLog}`);
  const created = await api("/session", { capabilities: { alwaysMatch: { browserName: "firefox", acceptInsecureCerts: false,
    "moz:firefoxOptions": { ...(firefox ? { binary: resolve(firefox) } : {}), args: ["-headless", "-remote-allow-system-access"], prefs: { "network.dns.localDomains": "a.test", "network.proxy.type": 0, "network.trr.mode": 5 } } } } });
  session = created.sessionId;
  await api(`/session/${session}/moz/context`, { context: "chrome" });
  for (const path of [cert.root, otherCert.root]) {
    const base64 = new X509Certificate(await readFile(path)).raw.toString("base64");
    await api(`/session/${session}/execute/sync`, { script: "Cc['@mozilla.org/security/x509certdb;1'].getService(Ci.nsIX509CertDB).addCertFromBase64(arguments[0], 'CT,C,C');", args: [base64] });
  }
  await api(`/session/${session}/moz/context`, { context: "content" });
  console.log(`Firefox ${created.capabilities.browserVersion}: local TLS integration tests`);
  await api(`/session/${session}/moz/addon/install`, { path: xpi, temporary: true });
  let timeout;
  const outcome = await Promise.race([result, new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error(`Browser tests timed out\n${driverLog.slice(-5000)}`)), 90_000); })]).finally(() => clearTimeout(timeout));
  if (outcome.error) throw new Error(JSON.stringify(outcome));
  const handles = await api(`/session/${session}/window/handles`, undefined, "GET");
  await api(`/session/${session}/window`, { handle: handles.at(-1) });
  let ui;
  for (let i = 0; i < 50; i++) {
    ui = await api(`/session/${session}/execute/sync`, { script: "return {ready: document.getElementById('details')?.hidden === false, error: document.getElementById('error')?.textContent, scope: document.getElementById('scope')?.value, duration: document.getElementById('duration')?.value};", args: [] });
    if (ui.ready) break;
    await new Promise((done) => setTimeout(done, 100));
  }
  if (!ui.ready || ui.error || ui.scope !== "all" || ui.duration !== "permanent") throw new Error(`Warning UI failed: ${JSON.stringify(ui)}`);
  outcome.passed.push("warning UI receives bound event and defaults to a full exception");
  await api(`/session/${session}/execute/sync`, { script: "document.getElementById('continue').click();", args: [] });
  let currentUrl;
  for (let i = 0; i < 50; i++) {
    currentUrl = await api(`/session/${session}/url`, undefined, "GET");
    if (currentUrl.startsWith(https)) break;
    await new Promise((done) => setTimeout(done, 100));
  }
  if (!currentUrl.startsWith(https)) throw new Error("Warning continue button did not navigate");
  outcome.passed.push("warning one-time continue button navigates successfully");
  for (const test of outcome.passed) console.log(`PASS ${test}`);
} catch (error) {
  console.error(driverLog.slice(-6000));
  throw error;
} finally {
  if (session) await api(`/session/${session}`, undefined, "DELETE").catch(() => {});
  driver?.kill();
  for (const server of servers) { server.closeAllConnections(); server.close(); }
  await rm(temp, { recursive: true, force: true });
}
