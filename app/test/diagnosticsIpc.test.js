"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { EventEmitter } = require("node:events");
const { registerCoreIpc } = require("../src/main/ipc/registerCoreIpc");
const { DiagnosticsService } = require("../src/main/diagnostics/diagnosticsService");
const { tcpProbe } = require("../src/main/diagnostics/socketDiagnostics");
const { catalogs } = require("../src/renderer/diagnosticsI18n");
test("diagnostics IPC checks sender, returns structured failures and confines copy/export to measured reports", async () => {
  const handlers = new Map(), copies = [], service = new DiagnosticsService();
  registerCoreIpc({ ipcMain: { handle: (channel, fn) => handlers.set(channel, fn), on() {} }, clipboard: { writeText: (text) => copies.push(text) }, diagnosticsService: service, getMainWindow: () => ({ isDestroyed: () => false, webContents: { id: 42 } }) });
  const trusted = { sender: { id: 42 } }, start = handlers.get("diagnostics:start");
  await assert.rejects(start({ sender: { id: 13 } }, { target: "127.0.0.1" }), { code: "UNTRUSTED_IPC_SENDER" });
  assert.deepEqual(await start(trusted, { target: "https://user:pass@localhost" }), { ok: false, error: { code: "URL_AUTH_OR_SCHEME_FORBIDDEN", message: "URL_AUTH_OR_SCHEME_FORBIDDEN" } });
  const result = await start(trusted, { target: "127.0.0.1", tools: ["dns"] }); assert.equal(result.ok, true); service.cancel(result.value.id);
  const copied = await handlers.get("diagnostics:copy")(trusted, { id: result.value.id }); assert.equal(copied.ok, true); assert.match(copies[0], /127.0.0.1/);
  const invalidExport = await handlers.get("diagnostics:export")(trusted, { id: result.value.id, format: "../../secret" }); assert.equal(invalidExport.ok, false); assert.equal(invalidExport.error.code, "INVALID_EXPORT_FORMAT");
});
test("preload exposes a frozen, narrow diagnostics API with disposable progress subscriptions", async () => {
  let exposed; const calls = [], listeners = new Map();
  const ipcRenderer = { invoke: async (...args) => { calls.push(args); }, on: (name, fn) => listeners.set(name, fn), removeListener: (name) => listeners.delete(name) };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../src/preload/corePreload.js"), "utf8"), { process: { platform: "linux" }, require: (name) => { assert.equal(name, "electron"); return { contextBridge: { exposeInMainWorld: (_name, value) => { exposed = value; } }, ipcRenderer }; } });
  assert.ok(Object.isFrozen(exposed.diagnostics)); assert.equal(exposed.diagnostics.exec, undefined);
  await exposed.diagnostics.start({ target: "localhost" }); assert.equal(calls[0][0], "diagnostics:start");
  let received; const dispose = exposed.diagnostics.onProgress((value) => { received = value; }); listeners.get("diagnostics:progress")({}, { kind: "complete" }); assert.equal(received.kind, "complete"); dispose(); assert.equal(listeners.size, 0);
});
test("TCP timeout and cancellation destroy their socket and preserve distinct statuses", async () => {
  let destroyed = 0;
  const connect = () => { const socket = new EventEmitter(); socket.destroy = () => { destroyed++; }; return socket; };
  const result = await tcpProbe("127.0.0.1", 443, { timeoutMs: 20 }, new AbortController().signal, connect); assert.equal(result.status, "timeout"); assert.equal(result.connectionMs, null);
  const controller = new AbortController(), request = tcpProbe("127.0.0.1", 443, { timeoutMs: 500 }, controller.signal, connect); controller.abort(); await assert.rejects(request, { code: "CANCELLED" }); assert.equal(destroyed, 2);
});
test("diagnostics navigation, translation catalogs and renderer isolation remain integrated", () => {
  const html = fs.readFileSync(path.join(__dirname, "../src/renderer/index.html"), "utf8");
  assert.ok(html.indexOf('data-view="plugins"') < html.indexOf('data-view="diagnostics"')); assert.ok(html.indexOf('data-view="diagnostics"') < html.indexOf('id="hashToolButton"'));
  assert.ok(html.indexOf('src="diagnostics.js"') < html.indexOf('src="app.js"'));
  for (const lang of ["cs", "de", "en"]) { assert.deepEqual(Object.keys(catalogs[lang]), Object.keys(catalogs.en)); assert.ok(catalogs[lang]["Run Diagnostics"]); assert.ok(catalogs[lang]["HTTP/3 testing unavailable"]); }
  const bootstrap = fs.readFileSync(path.join(__dirname, "../src/main/bootstrap/createMainWindow.js"), "utf8");
  assert.match(bootstrap, /contextIsolation: true/); assert.match(bootstrap, /nodeIntegration: false/); assert.match(bootstrap, /sandbox: true/);
  const renderer = fs.readFileSync(path.join(__dirname, "../src/renderer/diagnostics.js"), "utf8"); assert.ok(!/innerHTML|require\(|fetch\(/.test(renderer));
});
