"use strict";

const { contextBridge, ipcRenderer } = require("electron");

function subscribe(channel, callback) {
  if (typeof callback !== "function") return () => {};
  const listener = (_event, payload) => callback(payload);
  ipcRenderer.on(channel, listener);
  return () => ipcRenderer.removeListener(channel, listener);
}

contextBridge.exposeInMainWorld("chjCore", Object.freeze({
  platform: process.platform,
  getInfo: () => ipcRenderer.invoke("core:getInfo"),
  openLegalDocument: (document) => ipcRenderer.invoke("legal:open", { document }),
  getConfig: () => ipcRenderer.invoke("config:get"),
  updateConfig: (payload) => ipcRenderer.invoke("config:update", payload),
  listPlugins: () => ipcRenderer.invoke("plugins:list"),
  getPluginState: () => ipcRenderer.invoke("plugins:getState"),
  checkPluginCatalog: () => ipcRenderer.invoke("plugins:checkCatalog"),
  installPlugin: (releaseId) => ipcRenderer.invoke("plugins:install", { releaseId }),
  uninstallPlugin: (pluginId) => ipcRenderer.invoke("plugins:uninstall", { pluginId }),
  openPlugin: (pluginId) => ipcRenderer.invoke("plugins:open", { pluginId }),
  onPluginWindowState: (callback) => subscribe("core:pluginWindowState", callback),
  getVaultStatus: () => ipcRenderer.invoke("vault:status"),
  createVault: (password) => ipcRenderer.invoke("vault:create", { password }),
  unlockVault: (password) => ipcRenderer.invoke("vault:unlock", { password }),
  lockVault: () => ipcRenderer.invoke("vault:lock"),
  resetVault: (confirmation) => ipcRenderer.invoke("vault:reset", { confirmation }),
  listProfiles: () => ipcRenderer.invoke("profiles:list"),
  saveProfile: (payload) => ipcRenderer.invoke("profiles:save", payload),
  deleteProfile: (id) => ipcRenderer.invoke("profiles:delete", { id }),
  selectPrivateKey: () => ipcRenderer.invoke("profiles:selectPrivateKey"),
  listSshSessions: () => ipcRenderer.invoke("ssh:list"),
  connectSsh: (payload) => ipcRenderer.invoke("ssh:connect", payload),
  trustSshHostKey: (payload) => ipcRenderer.invoke("ssh:trustHostKey", payload),
  disconnectSsh: (sessionId) => ipcRenderer.invoke("ssh:disconnect", { sessionId }),
  sendTerminalInput: (sessionId, data) => ipcRenderer.send("ssh:input", { sessionId, data }),
  resizeTerminal: (sessionId, cols, rows) => ipcRenderer.invoke("ssh:resize", { sessionId, cols, rows }),
  getUpdateState: () => ipcRenderer.invoke("updates:getState"),
  checkForUpdates: () => ipcRenderer.invoke("updates:check"),
  selectUpdateRelease: (id) => ipcRenderer.invoke("updates:select", { id }),
  downloadUpdate: () => ipcRenderer.invoke("updates:download"),
  installUpdate: () => ipcRenderer.invoke("updates:install"),
  revealUpdate: () => ipcRenderer.invoke("updates:reveal"),
  onUpdateState: (callback) => subscribe("core:updateState", callback),
  onSshData: (callback) => subscribe("ssh:data", callback),
  onSshState: (callback) => subscribe("ssh:state", callback),
  onSshError: (callback) => subscribe("ssh:error", callback)
}));
