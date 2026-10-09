"use strict";

const { contextBridge, ipcRenderer } = require("electron");

function subscribe(channel, callback) {
  if (typeof callback !== "function") return () => {};
  const listener = (_event, payload) => callback(payload);
  ipcRenderer.on(channel, listener);
  return () => ipcRenderer.removeListener(channel, listener);
}

async function biometricRequest(channel) {
  const result = await ipcRenderer.invoke(channel);
  if (!result.ok) throw Object.assign(new Error(result.error.message), { code: result.error.code });
  return result.value;
}

contextBridge.exposeInMainWorld("chjCore", Object.freeze({
  platform: process.platform,
  diagnostics: Object.freeze({
    resolve: (options) => ipcRenderer.invoke("diagnostics:resolve", options),
    start: (options) => ipcRenderer.invoke("diagnostics:start", options),
    cancel: (id, tool) => ipcRenderer.invoke("diagnostics:cancel", { id, tool }),
    get: (id) => ipcRenderer.invoke("diagnostics:get", { id }),
    history: () => ipcRenderer.invoke("diagnostics:history"),
    removeHistory: (id) => ipcRenderer.invoke("diagnostics:removeHistory", { id }),
    export: (id, format) => ipcRenderer.invoke("diagnostics:export", { id, format }),
    copy: (id, format = "txt") => ipcRenderer.invoke("diagnostics:copy", { id, format }),
    import: () => ipcRenderer.invoke("diagnostics:import"),
    onProgress: (callback) => subscribe("diagnostics:progress", callback)
  }),
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
  getBiometricStatus: () => biometricRequest("biometrics:status"),
  enableBiometrics: () => biometricRequest("biometrics:enable"),
  disableBiometrics: () => biometricRequest("biometrics:disable"),
  unlockVaultWithBiometrics: () => biometricRequest("biometrics:unlock"),
  authenticateSensitiveAction: () => biometricRequest("biometrics:authenticate"),
  onVaultLocked: (callback) => subscribe("vault:locked", callback),
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
