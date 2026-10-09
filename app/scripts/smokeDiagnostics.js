"use strict";
// Run with Electron, not node. Uses the production renderer/preload/IPC and real local probes.
const { app, clipboard, ipcMain, dialog } = require("electron");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const zlib = require("node:zlib");
const { once } = require("node:events");
const { createMainWindow, hardenSession } = require("../src/main/bootstrap/createMainWindow");
const { registerCoreIpc } = require("../src/main/ipc/registerCoreIpc");
const { DiagnosticsService } = require("../src/main/diagnostics/diagnosticsService");
const { ConfigStore } = require("../src/main/config/configStore");
const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-diagnostics-ui-"));
app.setPath("userData", root);
let window, server, diagnostics;
const errors = [];
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(source, timeout = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeout) { if (await window.webContents.executeJavaScript(source)) return; await wait(50); }
  throw new Error("UI condition timed out: " + source);
}
async function run() {
  await app.whenReady();
  server = http.createServer((req, res) => {
    const body = Buffer.from("Local diagnostics UI smoke ".repeat(30));
    const encoder = { gzip: zlib.gzipSync, br: zlib.brotliCompressSync, deflate: zlib.deflateSync, zstd: zlib.zstdCompressSync }[req.headers["accept-encoding"]];
    res.setHeader("content-type", "text/plain");
    if (encoder) { res.setHeader("content-encoding", req.headers["accept-encoding"]); res.end(encoder(body)); } else res.end(body);
  });
  server.on("clientError", (_error, socket) => socket.destroy());
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  diagnostics = new DiagnosticsService({ storageRoot: root });
  const configStore = new ConfigStore(root); configStore.load(); configStore.update({ updates: { autoCheck: false } });
  hardenSession(); window = createMainWindow();
  window.webContents.on("console-message", (event) => { if (event.level === "error") { errors.push(event.message); console.error(event.message); } });
  // Unrelated services stay offline in this test. All diagnostics use production implementations.
  registerCoreIpc({ ipcMain, app, clipboard, dialog, configStore, diagnosticsService: diagnostics,
    pluginService: { getState: () => ({ installed: [], catalog: [], windows: [] }) }, pluginRuntime: { notifyLanguageChanged() {} },
    vaultStore: { status: () => ({ unlocked: true }) }, profileService: { list: () => [] },
    updateService: { getState: () => ({ currentVersion: "0.0.1", status: "idle", releases: [] }) }, getMainWindow: () => window });
  diagnostics.on("progress", (value) => window.webContents.send("diagnostics:progress", value));
  await until('Boolean(document.querySelector(".diag-toolbar"))');
  assert.deepEqual(await window.webContents.executeJavaScript('Array.from(document.querySelectorAll(".sidebar [data-view], #hashToolButton")).map(n => n.dataset.view || "hash").filter(n => ["plugins","diagnostics","hash"].includes(n))'), ["plugins", "diagnostics", "hash"]);
  await window.webContents.executeJavaScript(`document.querySelector('[data-view="diagnostics"]').click(); document.querySelector('.diag-toolbar input').value = 'http://127.0.0.1:${server.address().port}/'; document.querySelector('#diag-panel-http .primary').click();`);
  await until('diagnosticsView.state.report?.status === "completed"');
  const result = await window.webContents.executeJavaScript('diagnosticsView.state.report');
  assert.equal(result.results.http[0].comparisons[0].samples[0].negotiated, "1.1");
  assert.equal(result.results.http[0].comparisons[0].samples[0].downloadedBytes, 810);
  assert.equal(result.results.http[0].comparisons[2].samples[0].status, "unavailable");
  assert.equal(await window.webContents.executeJavaScript('typeof window.require'), "undefined");
  for (const language of ["de", "en", "cs"]) await window.webContents.executeJavaScript(`applyLanguage('${language}'); document.querySelector('#diag-tab-http').click();`);
  await window.webContents.executeJavaScript('document.querySelector(".diag-controls select:last-of-type"); diagnosticsView.refreshLanguage();');
  // Exercise both themes, narrow window, real compression and persistent history.
  for (const theme of ["dark", "light"]) {
    await window.webContents.executeJavaScript(`{ const themeSelect = Array.from(document.querySelectorAll('.diag-controls select')).at(-1); themeSelect.value = '${theme}'; themeSelect.dispatchEvent(new Event('change')); }`);
    await wait(100);
    assert.equal(await window.webContents.executeJavaScript('document.querySelector("#diagnosticsView").dataset.theme'), theme);
  }
  await window.webContents.executeJavaScript('Array.from(document.querySelectorAll("#diag-panel-http .primary"))[1].click()');
  await until('diagnosticsView.state.report?.results.compression && diagnosticsView.state.report.status === "completed"');
  assert.equal(await window.webContents.executeJavaScript('diagnosticsView.state.report.results.compression[0].results.find(r=>r.encoding==="br").status'), "success");
  const history = diagnostics.history.list(); assert.equal(history.length, 2);
  assert.equal(new (require("../src/main/diagnostics/historyStore").DiagnosticsHistory)(root).list().length, 2);
  window.setSize(960, 720);
  await wait(100);
  assert.equal(await window.webContents.executeJavaScript("document.documentElement.scrollWidth <= window.innerWidth"), true);
  await window.webContents.executeJavaScript('document.querySelector("#diag-tab-history").click()'); await wait(100);
  assert.equal(await window.webContents.executeJavaScript('document.querySelectorAll("#diag-panel-history tbody tr").length'), 2);
  const preferences = window.webContents.getLastWebPreferences(); assert.equal(preferences.contextIsolation, true); assert.equal(preferences.sandbox, true); assert.equal(preferences.nodeIntegration, false);
  const artifacts = process.env.CHJ_DIAGNOSTICS_SMOKE_ARTIFACT_DIR;
  if (artifacts) { fs.mkdirSync(artifacts, { recursive: true }); await window.webContents.executeJavaScript('document.querySelector("#diag-tab-http").click()'); await wait(100); fs.writeFileSync(path.join(artifacts, "diagnostics-light.png"), (await Promise.race([window.webContents.capturePage(), wait(5000).then(() => { throw new Error("Screenshot capture timed out"); })])).toPNG()); }
  assert.deepEqual(errors, []);
  console.log("CHJ_DIAGNOSTICS_UI_OK: real HTTP/1.1, protocol failures, Brotli, history, CZ/DE/EN, light/dark, sandbox");
}
run().then(() => finish(0), (error) => { console.error(error); finish(1); });
let finishing = false;
function finish(code) { if (finishing) return; finishing = true; diagnostics?.stopAll(); window?.destroy(); server?.close(); try { fs.rmSync(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 }); } catch (error) { console.error("Temporary Chromium cache cleanup:", error.code); } app.exit(code); }
setTimeout(() => { console.error("Diagnostics UI smoke exceeded 30s"); finish(1); }, 30000).unref();
