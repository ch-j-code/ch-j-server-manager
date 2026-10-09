"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { PluginRuntime } = require("../src/main/plugins/pluginRuntime");

class FakeWindow extends EventEmitter {
  constructor() {
    super();
    let protocolHandler = null;
    this.protocolRegistrations = 0;
    this.webContents = new EventEmitter();
    this.webContents.id = 42;
    this.webContents.session = {
      protocol: {
        isProtocolHandled: () => Boolean(protocolHandler),
        handle: (scheme, handler) => {
          assert.equal(scheme, "chj-plugin");
          protocolHandler = handler;
          this.protocolRegistrations += 1;
        }
      },
      setPermissionRequestHandler: () => {},
      setPermissionCheckHandler: () => {}
    };
    this.webContents.setWindowOpenHandler = () => {};
    this.destroyed = false;
    this.visible = false;
    this.loadedUrl = null;
  }

  isDestroyed() { return this.destroyed; }
  isMinimized() { return false; }
  show() { this.visible = true; }
  hide() { this.visible = false; }
  focus() { this.focused = true; }
  loadURL(url) { this.loadedUrl = url; return Promise.resolve(); }
  close() { this.destroyed = true; this.emit("closed"); }
}

test("Core chrome CSS is available to strict self-only plugin CSP without exposing other Core files", async () => {
  const runtime = new PluginRuntime({ registry: { resolveEntry: () => ({ manifest: { entry: "ui/index.html" }, root: "/missing-plugin" }) } });
  const response = await runtime.handleRequest({ url: "chj-plugin://chj.key-generator/__chj_core__/window-chrome.css" });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Content-Type"), "text/css; charset=utf-8");
  assert.match(await response.text(), /#chj-chrome-collapse/);
  const denied = await runtime.handleRequest({ url: "chj-plugin://chj.key-generator/__chj_core__/windowChrome.js" });
  assert.equal(denied.status, 404);
});

test("plugin runtime registers the custom protocol in the isolated plugin session", () => {
  let pluginWindow;
  let pluginWindowOptions;
  const windowStates = [];
  const managerWindow = Object.assign(new EventEmitter(), { destroyed: false, minimized: false, shown: false, focused: false, isDestroyed() { return this.destroyed; }, isMinimized() { return this.minimized; }, restore() { this.minimized = false; }, show() { this.shown = true; }, focus() { this.focused = true; } });
  const manifest = {
    id: "chj.system-monitor",
    name: "System Monitor",
    version: "0.0.1",
    entry: "ui/index.html",
    permissions: ["session.read", "system.metrics.read"]
  };
  const runtime = new PluginRuntime({
    BrowserWindow: class extends FakeWindow { constructor(options) { super(); pluginWindow = this; pluginWindowOptions = options; } },
    registry: { resolveEntry: () => ({ manifest, root: "/plugin", entryPath: "/plugin/ui/index.html" }) },
    sessionManager: {},
    getMainWindow: () => managerWindow,
    onWindowState: (windows) => windowStates.push(windows),
    isVaultUnlocked: () => true,
    preload: "/pluginPreload.js"
  });

  runtime.open(manifest.id);
  assert.equal(pluginWindow.protocolRegistrations, 1);
  assert.equal(pluginWindow.loadedUrl, "chj-plugin://chj.system-monitor/ui/index.html");
  assert.equal(pluginWindowOptions.parent, managerWindow);
  assert.equal(pluginWindowOptions.modal, false);
  pluginWindow.emit("ready-to-show");
  pluginWindow.emit("minimize");
  assert.equal(pluginWindow.visible, false);
  assert.equal(managerWindow.focused, true);
  assert.equal(windowStates.at(-1)[0].minimized, true);
  runtime.open(manifest.id);
  assert.equal(pluginWindow.protocolRegistrations, 1);
  assert.equal(pluginWindow.visible, true);
  assert.equal(runtime.listWindows()[0].minimized, false);
  managerWindow.minimized = true;
  managerWindow.focused = false;
  managerWindow.emit("minimize");
  assert.equal(pluginWindow.visible, false);
  assert.equal(managerWindow.minimized, true);
  assert.equal(managerWindow.focused, false);
  assert.equal(runtime.listWindows()[0].minimized, true);
  pluginWindow.close();
  assert.equal(managerWindow.listenerCount("minimize"), 0);
});

test("plugin collapse IPC docks only the sender's window and restores it on reopen", async () => {
  const handlers = new Map();
  let pluginWindow;
  const manifest = { id: "chj.hash-checksum", name: "Hash & Checksum", entry: "ui/index.html", permissions: [] };
  const runtime = new PluginRuntime({
    BrowserWindow: class extends FakeWindow { constructor() { super(); pluginWindow = this; } },
    registry: { resolveEntry: () => ({ manifest, root: "/plugin" }) },
    isVaultUnlocked: () => true
  });
  runtime.registerIpc({ handle: (channel, handler) => handlers.set(channel, handler) });
  runtime.open(manifest.id);
  pluginWindow.emit("ready-to-show");
  const collapse = handlers.get("plugin:window:minimize");
  await assert.rejects(() => collapse({ sender: { id: 999 } }), { code: "UNTRUSTED_PLUGIN_SENDER" });
  await collapse({ sender: { id: pluginWindow.webContents.id } });
  assert.equal(pluginWindow.visible, false);
  assert.equal(runtime.listWindows()[0].minimized, true);
  runtime.open(manifest.id);
  assert.equal(pluginWindow.visible, true);
  assert.equal(runtime.listWindows()[0].minimized, false);
});

test("plugin runtime routes user capabilities by sender identity and manifest permission", async () => {
  const handlers = new Map();
  const calls = [];
  const runtime = new PluginRuntime({
    BrowserWindow: FakeWindow,
    registry: {},
    sessionManager: {
      readUsers: async (sessionId) => { calls.push(["read", sessionId]); return [{ username: "test" }]; },
      manageUser: async (sessionId, payload) => { calls.push(["manage", sessionId, payload.action]); return { action: payload.action }; }
    },
    logService: { readTail: async () => ({ text: "forbidden" }) },
    keyGeneratorService: {},
    isVaultUnlocked: () => true
  });
  runtime.registerIpc({ handle: (channel, handler) => handlers.set(channel, handler) });
  const window = { isDestroyed: () => false, close: () => {} };
  runtime.contexts.set(77, { manifest: { permissions: ["users.read", "users.manage"] }, window });
  const event = { sender: { id: 77 } };
  assert.deepEqual(await handlers.get("plugin:users:list")(event, { sessionId: "terminal-users" }), [{ username: "test" }]);
  assert.deepEqual(await handlers.get("plugin:users:manage")(event, { sessionId: "terminal-users", action: "lock", username: "bob" }), { action: "lock" });
  assert.deepEqual(calls, [["read", "terminal-users"], ["manage", "terminal-users", "lock"]]);
  await assert.rejects(() => handlers.get("plugin:logs:read")(event, {}), { code: "PLUGIN_PERMISSION_DENIED" });
});

test("plugin runtime routes file capabilities and keeps permissions separate", async () => {
  const handlers = new Map();
  const calls = [];
  const remoteFileService = {
    list: async (sessionId, path) => { calls.push(["list", sessionId, path]); return [{ name: "a.txt" }]; },
    readText: async (sessionId, path) => { calls.push(["readText", sessionId, path]); return { text: "ahoj" }; },
    writeText: async (sessionId, path, text) => { calls.push(["writeText", sessionId, path, text]); return { size: 4 }; },
    createFile: async () => ({}), mkdir: async () => ({}), rename: async () => ({}), remove: async () => ({}), removeMany: async () => ({}),
    upload: async () => ({}), download: async () => ({}), downloadMany: async () => ({}), downloadArchive: async () => ({})
  };
  const runtime = new PluginRuntime({ BrowserWindow: FakeWindow, registry: {}, sessionManager: {}, remoteFileService, isVaultUnlocked: () => true });
  runtime.registerIpc({ handle: (channel, handler) => handlers.set(channel, handler) });
  const window = { isDestroyed: () => false, close: () => {} };
  runtime.contexts.set(88, { manifest: { permissions: ["files.read"] }, window });
  const event = { sender: { id: 88 } };

  assert.deepEqual(await handlers.get("plugin:files:list")(event, { sessionId: "sftp-1", path: "/home/test" }), [{ name: "a.txt" }]);
  assert.deepEqual(await handlers.get("plugin:files:readText")(event, { sessionId: "sftp-1", path: "/home/test/a.txt" }), { text: "ahoj" });
  await assert.rejects(() => handlers.get("plugin:files:writeText")(event, { sessionId: "sftp-1", path: "/home/test/a.txt", text: "nově" }), { code: "PLUGIN_PERMISSION_DENIED" });
  await assert.rejects(() => handlers.get("plugin:files:download")(event, { sessionId: "sftp-1", path: "/home/test/a.txt" }), { code: "PLUGIN_PERMISSION_DENIED" });
  for (const capability of ["saveText", "cleanupRecovery"]) {
    await assert.rejects(() => handlers.get(`plugin:files:${capability}`)(event, { sessionId: "sftp-1" }), { code: "PLUGIN_PERMISSION_DENIED" });
  }
  assert.deepEqual(calls, [["list", "sftp-1", "/home/test"], ["readText", "sftp-1", "/home/test/a.txt"]]);
});

test("editor IPC forwards structured options, owns document handles and protects recovery reads", async () => {
  const handlers = new Map(), calls = [];
  const remoteFileService = {};
  for (const method of ["readText", "saveText", "listRecovery", "readRecovery", "cleanupRecovery", "closeText"]) {
    remoteFileService[method] = (...args) => { calls.push([method, ...args]); return { ok: true }; };
  }
  const runtime = new PluginRuntime({ BrowserWindow: FakeWindow, registry: {}, remoteFileService, isVaultUnlocked: () => true });
  runtime.registerIpc({ handle: (channel, handler) => handlers.set(channel, handler) });
  const window = { isDestroyed: () => false };
  runtime.contexts.set(91, { manifest: { id: "editor", permissions: ["files.read", "files.write"] }, window });
  runtime.contexts.set(92, { manifest: { id: "other", permissions: [] }, window });
  const options = { editId: "opaque", sudo: true, sudoPassword: "secret" };
  await handlers.get("plugin:files:saveText")({ sender: { id: 91 } }, { sessionId: "s", path: "/etc/config", text: "content", options });
  assert.deepEqual(calls[0], ["saveText", "s", "/etc/config", "content", options, "editor"]);
  await handlers.get("plugin:files:closeText")({ sender: { id: 91 } }, { editId: "opaque" });
  assert.deepEqual(calls[1], ["closeText", "opaque", "editor"]);
  for (const method of ["listRecovery", "readRecovery", "closeText"]) {
    await assert.rejects(() => handlers.get(`plugin:files:${method}`)({ sender: { id: 92 } }), { code: "PLUGIN_PERMISSION_DENIED" });
  }
});

test("plugin runtime separates NGINX read and manage capabilities", async () => {
  const handlers = new Map();
  const calls = [];
  const sessionManager = {
    inspectNginx: async (sessionId) => { calls.push(["inspect", sessionId]); return { installed: true }; },
    readNginxConfig: async () => ({}), dumpNginxConfig: async () => ({}), testNginxConfig: async () => ({ ok: true }),
    saveNginxConfig: async (sessionId, payload) => { calls.push(["save", sessionId, payload.path]); return { path: payload.path }; },
    reloadNginx: async () => ({ ok: true })
  };
  const runtime = new PluginRuntime({ BrowserWindow: FakeWindow, registry: {}, sessionManager, isVaultUnlocked: () => true });
  runtime.registerIpc({ handle: (channel, handler) => handlers.set(channel, handler) });
  const window = { isDestroyed: () => false, close: () => {} };
  const event = { sender: { id: 99 } };
  runtime.contexts.set(99, { manifest: { permissions: ["nginx.read"] }, window });
  assert.deepEqual(await handlers.get("plugin:nginx:inspect")(event, { sessionId: "nginx-1" }), { installed: true });
  await assert.rejects(() => handlers.get("plugin:nginx:saveConfig")(event, { sessionId: "nginx-1", path: "/etc/nginx/nginx.conf" }), { code: "PLUGIN_PERMISSION_DENIED" });
  runtime.contexts.set(99, { manifest: { permissions: ["nginx.read", "nginx.manage"] }, window });
  assert.deepEqual(await handlers.get("plugin:nginx:saveConfig")(event, { sessionId: "nginx-1", path: "/etc/nginx/nginx.conf" }), { path: "/etc/nginx/nginx.conf" });
  assert.deepEqual(calls, [["inspect", "nginx-1"], ["save", "nginx-1", "/etc/nginx/nginx.conf"]]);
});

test("closing a destroyed plugin window releases its context without reading webContents", () => {
  let pluginWindow;
  const cleanup = [];
  const manifest = { id: "chj.hash-checksum", name: "Hash & Checksum", version: "0.0.1", entry: "ui/index.html", permissions: ["local.hash"] };
  const runtime = new PluginRuntime({
    BrowserWindow: class extends FakeWindow { constructor() { super(); pluginWindow = this; } },
    registry: { resolveEntry: () => ({ manifest, root: "/plugin" }) },
    localHashService: { on: () => {}, cleanupPlugin: (id) => cleanup.push(id) },
    isVaultUnlocked: () => true
  });
  runtime.open(manifest.id);
  const senderId = pluginWindow.webContents.id;
  Object.defineProperty(pluginWindow, "webContents", { get() { throw new Error("Object has been destroyed"); } });
  pluginWindow.destroyed = true;
  assert.doesNotThrow(() => pluginWindow.emit("closed"));
  assert.equal(runtime.contexts.has(senderId), false);
  assert.equal(runtime.windows.has(manifest.id), false);
  assert.deepEqual(cleanup, [manifest.id]);
});
