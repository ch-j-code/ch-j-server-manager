"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { EventEmitter } = require("node:events");
const { PluginRegistry, PLUGIN_API_VERSION, supportsPluginApi, validateManifest } = require("../src/main/plugins/pluginRegistry");
const { PLUGIN_CSP, PluginRuntime } = require("../src/main/plugins/pluginRuntime");

const pluginRoot = path.join(__dirname, "..", "src", "main", "firstPartyPlugins");
const manifestPath = path.join(pluginRoot, "chj.hash-checksum", "0.0.1", "manifest.json");

test("Hash & Checksum is a bundled first-party plugin on Plugin API 1.2", (t) => {
  const storage = fs.mkdtempSync(path.join(os.tmpdir(), "chj-hash-registry-")); t.after(() => fs.rmSync(storage, { recursive: true, force: true }));
  const manifest = validateManifest(JSON.parse(fs.readFileSync(manifestPath, "utf8")));
  assert.equal(PLUGIN_API_VERSION, "1.2.0"); assert.equal(manifest.pluginApi, "^1.2.0"); assert.deepEqual(manifest.permissions, ["local.hash"]);
  assert.equal(supportsPluginApi("^1.0.0"), true); assert.equal(supportsPluginApi("^1.1.0"), true); assert.equal(supportsPluginApi("^1.2.0"), true);
  const registry = new PluginRegistry(storage, null, { bundledRoot: pluginRoot }); const installed = registry.getInstalled("chj.hash-checksum");
  assert.equal(installed.bundled, true); assert.equal(registry.resolveEntry(installed.id).entryPath.endsWith(path.join("ui", "index.html")), true);
});

test("plugin UI is network-isolated and contains no Node, remote-session, or path-based access", () => {
  const preload = fs.readFileSync(path.join(__dirname, "..", "src", "preload", "pluginPreload.js"), "utf8");
  const ui = fs.readFileSync(path.join(pluginRoot, "chj.hash-checksum", "0.0.1", "ui", "index.js"), "utf8");
  assert.match(PLUGIN_CSP, /connect-src 'none'/); assert.match(preload, /plugin:hashing:selectFiles/); assert.doesNotMatch(preload, /require\(["']node:fs/);
  assert.doesNotMatch(ui, /\brequire\s*\(/); assert.doesNotMatch(ui, /\b(?:ssh|sftp|scp|remote\.exec)\b/i); assert.doesNotMatch(ui, /filePath|localPath|absolutePath/);
});

test("hash IPC enforces local.hash, scopes calls and progress to the owning plugin, and cleans up on close", async () => {
  const handlers = new Map(); const calls = []; const events = []; const hashing = new EventEmitter();
  hashing.getAlgorithms = () => [{ id: "sha256" }];
  hashing.start = (pluginId, payload) => { calls.push(["start", pluginId, payload.selectionId]); return { jobId: "job_owner" }; };
  hashing.status = (pluginId, jobId) => { calls.push(["status", pluginId, jobId]); if (pluginId !== "owner") throw Object.assign(new Error("Unknown job"), { code: "HASH_INVALID_JOB" }); return { jobId }; };
  hashing.cancel = async (pluginId, jobId) => { calls.push(["cancel", pluginId, jobId]); return { state: "cancelled" }; };
  hashing.selectFiles = async () => ({}); hashing.selectDirectory = async () => ({}); hashing.selectManifest = async () => ({}); hashing.selectManifestDestination = async () => ({});
  hashing.verify = () => ({}); hashing.compare = () => ({}); hashing.generateManifest = () => ({}); hashing.verifyManifest = () => ({}); hashing.exportResults = () => ({}); hashing.copyResult = () => ({});
  hashing.cleanupPlugin = (pluginId) => calls.push(["cleanup", pluginId]);
  const runtime = new PluginRuntime({ BrowserWindow: class {}, registry: {}, sessionManager: {}, localHashService: hashing, isVaultUnlocked: () => true });
  runtime.registerIpc({ handle: (channel, handler) => handlers.set(channel, handler) });
  const makeWindow = (id) => ({ isDestroyed: () => false, close: () => {}, webContents: { id, send: (channel, payload) => events.push([id, channel, payload.jobId]) } });
  const ownerWindow = makeWindow(10); const deniedWindow = makeWindow(11); const otherWindow = makeWindow(12);
  runtime.contexts.set(10, { manifest: { id: "owner", permissions: ["local.hash"] }, window: ownerWindow });
  runtime.contexts.set(11, { manifest: { id: "denied", permissions: [] }, window: deniedWindow });
  runtime.contexts.set(12, { manifest: { id: "other", permissions: ["local.hash"] }, window: otherWindow });
  runtime.windows.set("owner", ownerWindow); runtime.windows.set("other", otherWindow);
  assert.deepEqual(await handlers.get("plugin:hashing:start")({ sender: { id: 10 } }, { selectionId: "opaque" }), { jobId: "job_owner" });
  await assert.rejects(() => handlers.get("plugin:hashing:start")({ sender: { id: 11 } }, { selectionId: "opaque" }), { code: "PLUGIN_PERMISSION_DENIED" });
  await assert.rejects(() => handlers.get("plugin:hashing:status")({ sender: { id: 12 } }, { jobId: "job_owner" }), { code: "HASH_INVALID_JOB" });
  hashing.emit("progress", { pluginId: "owner", job: { jobId: "job_owner" } }); assert.deepEqual(events, [[10, "plugin:hashing:progress", "job_owner"]]);
  ownerWindow.webContents = { id: 10, send: () => {} }; runtime.contexts.set(10, { manifest: { id: "owner", permissions: ["local.hash"] }, window: ownerWindow });
  hashing.cleanupPlugin("owner"); assert.ok(calls.some((call) => call[0] === "cleanup" && call[1] === "owner"));
});

test("plugin language IPC uses the app language and broadcasts updates to open windows", async () => {
  const handlers = new Map();
  const events = [];
  const runtime = new PluginRuntime({ BrowserWindow: class {}, registry: {}, getLanguage: () => "cs", isVaultUnlocked: () => true });
  runtime.registerIpc({ handle: (channel, handler) => handlers.set(channel, handler) });
  const window = { isDestroyed: () => false, webContents: { send: (channel, payload) => events.push([channel, payload]) } };
  runtime.contexts.set(21, { manifest: { id: "chj.hash-checksum", permissions: ["local.hash"] }, window });
  runtime.windows.set("chj.hash-checksum", window);
  runtime.windows.set("closed", { isDestroyed: () => true });
  assert.equal(await handlers.get("plugin:ui:getLanguage")({ sender: { id: 21 } }), "cs");
  await assert.rejects(() => handlers.get("plugin:ui:getLanguage")({ sender: { id: 999 } }));
  runtime.notifyLanguageChanged("de");
  assert.deepEqual(events, [["plugin:ui:languageChanged", "de"]]);
});

test("hash errors retain their code in the IPC message for localized renderer errors", async () => {
  const handlers = new Map();
  const runtime = new PluginRuntime({ BrowserWindow: class {}, registry: {}, isVaultUnlocked: () => true, localHashService: {
    on: () => {},
    start: () => { throw Object.assign(new Error("Invalid key"), { code: "HASH_INVALID_KEY" }); }
  } });
  runtime.registerIpc({ handle: (channel, handler) => handlers.set(channel, handler) });
  runtime.contexts.set(22, { manifest: { id: "chj.hash-checksum", permissions: ["local.hash"] }, window: { isDestroyed: () => false } });
  await assert.rejects(() => handlers.get("plugin:hashing:start")({ sender: { id: 22 } }), { code: "HASH_INVALID_KEY", message: "HASH_INVALID_KEY: Invalid key" });
});
