"use strict";

const fs = require("node:fs");
const path = require("node:path");

const MIME_TYPES = Object.freeze({
  ".css": "text/css; charset=utf-8",
  ".gif": "image/gif",
  ".html": "text/html; charset=utf-8",
  ".jpeg": "image/jpeg",
  ".jpg": "image/jpeg",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".webp": "image/webp",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf"
});
const PLUGIN_CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; worker-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'";

class PluginRuntime {
  constructor(options) {
    this.BrowserWindow = options.BrowserWindow;
    this.registry = options.registry;
    this.sessionManager = options.sessionManager;
    this.keyGeneratorService = options.keyGeneratorService;
    this.logService = options.logService;
    this.remoteFileService = options.remoteFileService;
    this.localHashService = options.localHashService;
    this.getLanguage = options.getLanguage || (() => "en");
    this.getMainWindow = options.getMainWindow;
    this.isVaultUnlocked = options.isVaultUnlocked;
    this.preload = options.preload;
    this.icon = options.icon;
    this.onWindowState = options.onWindowState;
    this.logger = options.logger;
    this.contexts = new Map();
    this.windows = new Map();
    this.localHashService?.on("progress", ({ pluginId, job }) => {
      const window = this.windows.get(pluginId);
      if (window && !window.isDestroyed()) window.webContents.send("plugin:hashing:progress", job);
    });
  }

  registerIpc(ipcMain) {
    const handle = (channel, permission, action) => {
      ipcMain.handle(channel, async (event, payload = {}) => {
        const context = this._context(event.sender.id);
        if (permission && !context.manifest.permissions.includes(permission)) {
          const error = new Error(`Plugin permission denied: ${permission}`);
          error.code = "PLUGIN_PERMISSION_DENIED";
          throw error;
        }
        try {
          return await action(context, payload);
        } catch (error) {
          // Electron serializes the message, but drops custom error properties.
          if (error?.code?.startsWith("HASH_") && !error.message.startsWith(`${error.code}:`)) error.message = `${error.code}: ${error.message}`;
          throw error;
        }
      });
    };
    handle("plugin:getInfo", null, (context) => context.manifest);
    handle("plugin:ui:getLanguage", null, () => this.getLanguage());
    handle("plugin:close", null, (context) => { context.window.close(); return { ok: true }; });
    handle("plugin:sessions:list", "session.read", () => this.sessionManager.list());
    handle("plugin:system:metrics", "system.metrics.read", (_context, payload) => this.sessionManager.readSystemMetrics(payload.sessionId));
    handle("plugin:keys:generate", "keys.generate", (_context, payload) => this.keyGeneratorService.generate(payload));
    handle("plugin:keys:save", "keys.generate", (_context, payload) => this.keyGeneratorService.save(payload.generationId));
    handle("plugin:logs:read", "logs.read", (_context, payload) => this.logService.readTail(payload));
    handle("plugin:users:list", "users.read", (_context, payload) => this.sessionManager.readUsers(payload.sessionId));
    handle("plugin:users:manage", "users.manage", (_context, payload) => this.sessionManager.manageUser(payload.sessionId, payload));
    handle("plugin:nginx:inspect", "nginx.read", (_context, payload) => this.sessionManager.inspectNginx(payload.sessionId));
    handle("plugin:nginx:readConfig", "nginx.read", (_context, payload) => this.sessionManager.readNginxConfig(payload.sessionId, payload));
    handle("plugin:nginx:dumpConfig", "nginx.read", (_context, payload) => this.sessionManager.dumpNginxConfig(payload.sessionId, payload));
    handle("plugin:nginx:testConfig", "nginx.read", (_context, payload) => this.sessionManager.testNginxConfig(payload.sessionId, payload));
    handle("plugin:nginx:saveConfig", "nginx.manage", (_context, payload) => this.sessionManager.saveNginxConfig(payload.sessionId, payload));
    handle("plugin:nginx:reload", "nginx.manage", (_context, payload) => this.sessionManager.reloadNginx(payload.sessionId, payload));
    handle("plugin:files:list", "files.read", (_context, payload) => this.remoteFileService.list(payload.sessionId, payload.path));
    handle("plugin:files:readText", "files.read", (_context, payload) => this.remoteFileService.readText(payload.sessionId, payload.path));
    handle("plugin:files:writeText", "files.write", (_context, payload) => this.remoteFileService.writeText(payload.sessionId, payload.path, payload.text));
    handle("plugin:files:createFile", "files.write", (_context, payload) => this.remoteFileService.createFile(payload.sessionId, payload.path));
    handle("plugin:files:mkdir", "files.write", (_context, payload) => this.remoteFileService.mkdir(payload.sessionId, payload.path));
    handle("plugin:files:rename", "files.write", (_context, payload) => this.remoteFileService.rename(payload.sessionId, payload.from, payload.to));
    handle("plugin:files:remove", "files.write", (_context, payload) => this.remoteFileService.remove(payload.sessionId, payload.path));
    handle("plugin:files:removeMany", "files.write", (_context, payload) => this.remoteFileService.removeMany(payload.sessionId, payload.paths, payload.recursive));
    handle("plugin:files:upload", "files.transfer", (_context, payload) => this.remoteFileService.upload(payload.sessionId, payload.directory));
    handle("plugin:files:download", "files.transfer", (_context, payload) => this.remoteFileService.download(payload.sessionId, payload.path));
    handle("plugin:files:downloadMany", "files.transfer", (_context, payload) => this.remoteFileService.downloadMany(payload.sessionId, payload.paths));
    handle("plugin:files:downloadArchive", "files.transfer", (_context, payload) => this.remoteFileService.downloadArchive(payload.sessionId, payload.paths, payload.format));
    handle("plugin:hashing:algorithms", "local.hash", () => this.localHashService.getAlgorithms());
    handle("plugin:hashing:selectFiles", "local.hash", (context, payload) => this.localHashService.selectFiles(context.manifest.id, payload));
    handle("plugin:hashing:selectDirectory", "local.hash", (context) => this.localHashService.selectDirectory(context.manifest.id));
    handle("plugin:hashing:selectManifest", "local.hash", (context) => this.localHashService.selectManifest(context.manifest.id));
    handle("plugin:hashing:selectManifestDestination", "local.hash", (context, payload) => this.localHashService.selectManifestDestination(context.manifest.id, payload));
    handle("plugin:hashing:start", "local.hash", (context, payload) => this.localHashService.start(context.manifest.id, payload));
    handle("plugin:hashing:verify", "local.hash", (context, payload) => this.localHashService.verify(context.manifest.id, payload));
    handle("plugin:hashing:compare", "local.hash", (context, payload) => this.localHashService.compare(context.manifest.id, payload));
    handle("plugin:hashing:generateManifest", "local.hash", (context, payload) => this.localHashService.generateManifest(context.manifest.id, payload));
    handle("plugin:hashing:verifyManifest", "local.hash", (context, payload) => this.localHashService.verifyManifest(context.manifest.id, payload));
    handle("plugin:hashing:exportResults", "local.hash", (context, payload) => this.localHashService.exportResults(context.manifest.id, payload));
    handle("plugin:hashing:copyResult", "local.hash", (context, payload) => this.localHashService.copyResult(context.manifest.id, payload));
    handle("plugin:hashing:status", "local.hash", (context, payload) => this.localHashService.status(context.manifest.id, payload.jobId));
    handle("plugin:hashing:cancel", "local.hash", (context, payload) => this.localHashService.cancel(context.manifest.id, payload.jobId));
  }

  notifyLanguageChanged(language) {
    for (const window of this.windows.values()) {
      if (!window.isDestroyed()) window.webContents.send("plugin:ui:languageChanged", language);
    }
  }

  async handleRequest(request) {
    try {
      const url = new URL(request.url);
      const pluginId = url.hostname;
      const resolved = this.registry.resolveEntry(pluginId);
      const requested = decodeURIComponent(url.pathname.replace(/^\/+/, "") || resolved.manifest.entry).replace(/\\/g, "/");
      if (!requested || requested.startsWith(".") || requested.split("/").some((segment) => !segment || segment === ".." || segment.startsWith("."))) {
        return new Response("Not found", { status: 404 });
      }
      const filePath = path.join(resolved.root, ...requested.split("/"));
      const relative = path.relative(resolved.root, filePath);
      if (relative.startsWith("..") || path.isAbsolute(relative)) return new Response("Not found", { status: 404 });
      const stat = await fs.promises.stat(filePath);
      if (!stat.isFile() || stat.size > 10 * 1024 * 1024) return new Response("Not found", { status: 404 });
      const data = await fs.promises.readFile(filePath);
      return new Response(data, {
        status: 200,
        headers: {
          "Content-Type": MIME_TYPES[path.extname(filePath).toLowerCase()] || "application/octet-stream",
          "Content-Security-Policy": PLUGIN_CSP,
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff"
        }
      });
    } catch (error) {
      this.logger?.warn("Plugin resource request rejected.", { url: request.url, message: error?.message || String(error) });
      return new Response("Not found", { status: 404 });
    }
  }

  open(pluginId) {
    if (!this.isVaultUnlocked()) throw new Error("Unlock the vault before opening a plugin.");
    const resolved = this.registry.resolveEntry(pluginId);
    const existing = this.windows.get(resolved.manifest.id);
    if (existing && !existing.isDestroyed()) {
      if (existing.isMinimized()) existing.restore();
      const context = this.contexts.get(existing.webContents.id);
      if (context) context.minimized = false;
      existing.show();
      existing.focus();
      this._emitWindowState();
      return resolved.manifest;
    }
    const window = new this.BrowserWindow({
      title: `${resolved.manifest.name} · CH-J Server Manager`,
      width: 980,
      height: 700,
      minWidth: 760,
      minHeight: 520,
      backgroundColor: "#07111f",
      icon: this.icon,
      show: false,
      webPreferences: {
        preload: this.preload,
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
        webSecurity: true,
        allowRunningInsecureContent: false,
        spellcheck: false,
        partition: `plugin-${resolved.manifest.id}`
      }
    });
    const pluginSession = window.webContents.session;
    if (!pluginSession.protocol.isProtocolHandled("chj-plugin")) {
      pluginSession.protocol.handle("chj-plugin", (request) => this.handleRequest(request));
    }
    pluginSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
    pluginSession.setPermissionCheckHandler(() => false);
    window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
    window.webContents.on("will-navigate", (event, url) => {
      if (!url.startsWith(`chj-plugin://${resolved.manifest.id}/`)) event.preventDefault();
    });
    const context = { manifest: resolved.manifest, window, minimized: false };
    const webContentsId = window.webContents.id;
    this.contexts.set(webContentsId, context);
    this.windows.set(resolved.manifest.id, window);
    window.once("ready-to-show", () => {
      window.show();
      this._emitWindowState();
    });
    window.on("minimize", (event) => {
      event.preventDefault();
      context.minimized = true;
      window.hide();
      const manager = this.getMainWindow?.();
      if (manager && !manager.isDestroyed()) {
        if (manager.isMinimized()) manager.restore();
        manager.show();
        manager.focus();
      }
      this._emitWindowState();
      this.logger?.info("Plugin window minimized to the Core taskbar.", { pluginId: resolved.manifest.id });
    });
    window.on("closed", () => {
      this.localHashService?.cleanupPlugin(resolved.manifest.id);
      this.contexts.delete(webContentsId);
      this.windows.delete(resolved.manifest.id);
      this._emitWindowState();
    });
    const pluginUrl = `chj-plugin://${resolved.manifest.id}/${resolved.manifest.entry}`;
    void window.loadURL(pluginUrl).catch((error) => {
      this.logger?.error("Plugin window failed to load.", {
        pluginId: resolved.manifest.id,
        url: pluginUrl,
        message: error?.message || String(error)
      });
    });
    this.logger?.info("Plugin window opened.", { pluginId: resolved.manifest.id, version: resolved.manifest.version });
    return resolved.manifest;
  }

  closeAll() {
    for (const window of this.windows.values()) {
      if (!window.isDestroyed()) window.close();
    }
  }

  close(pluginId) {
    const window = this.windows.get(String(pluginId || ""));
    if (window && !window.isDestroyed()) window.close();
  }

  listWindows() {
    const result = [];
    for (const [pluginId, window] of this.windows) {
      if (window.isDestroyed()) continue;
      const context = this.contexts.get(window.webContents.id);
      if (!context) continue;
      result.push({
        pluginId,
        name: context.manifest.name,
        version: context.manifest.version,
        minimized: context.minimized === true
      });
    }
    return result;
  }

  _emitWindowState() {
    try { this.onWindowState?.(this.listWindows()); }
    catch (error) { this.logger?.warn("Plugin window state could not be delivered.", { message: error?.message || String(error) }); }
  }

  _context(webContentsId) {
    const context = this.contexts.get(webContentsId);
    if (!context || context.window.isDestroyed()) {
      const error = new Error("Untrusted plugin IPC sender.");
      error.code = "UNTRUSTED_PLUGIN_SENDER";
      throw error;
    }
    return context;
  }
}

module.exports = { MIME_TYPES, PLUGIN_CSP, PluginRuntime };
