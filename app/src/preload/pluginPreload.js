"use strict";

const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("chjPlugin", Object.freeze({
  getInfo: () => ipcRenderer.invoke("plugin:getInfo"),
  close: () => ipcRenderer.invoke("plugin:close"),
  sessions: Object.freeze({
    list: () => ipcRenderer.invoke("plugin:sessions:list")
  }),
  system: Object.freeze({
    readMetrics: (sessionId) => ipcRenderer.invoke("plugin:system:metrics", { sessionId })
  }),
  keys: Object.freeze({
    generate: (payload) => ipcRenderer.invoke("plugin:keys:generate", payload),
    save: (generationId) => ipcRenderer.invoke("plugin:keys:save", { generationId })
  }),
  logs: Object.freeze({
    read: (options) => ipcRenderer.invoke("plugin:logs:read", options)
  }),
  users: Object.freeze({
    list: (sessionId) => ipcRenderer.invoke("plugin:users:list", { sessionId }),
    manage: (sessionId, payload) => ipcRenderer.invoke("plugin:users:manage", { ...payload, sessionId })
  }),
  nginx: Object.freeze({
    inspect: (sessionId) => ipcRenderer.invoke("plugin:nginx:inspect", { sessionId }),
    readConfig: (sessionId, payload) => ipcRenderer.invoke("plugin:nginx:readConfig", { ...payload, sessionId }),
    dumpConfig: (sessionId, sudoPassword) => ipcRenderer.invoke("plugin:nginx:dumpConfig", { sessionId, sudoPassword }),
    testConfig: (sessionId, sudoPassword) => ipcRenderer.invoke("plugin:nginx:testConfig", { sessionId, sudoPassword }),
    saveConfig: (sessionId, payload) => ipcRenderer.invoke("plugin:nginx:saveConfig", { ...payload, sessionId }),
    reload: (sessionId, sudoPassword, confirm = false) => ipcRenderer.invoke("plugin:nginx:reload", { sessionId, sudoPassword, confirm })
  }),
  files: Object.freeze({
    list: (sessionId, path) => ipcRenderer.invoke("plugin:files:list", { sessionId, path }),
    readText: (sessionId, path) => ipcRenderer.invoke("plugin:files:readText", { sessionId, path }),
    writeText: (sessionId, path, text) => ipcRenderer.invoke("plugin:files:writeText", { sessionId, path, text }),
    createFile: (sessionId, path) => ipcRenderer.invoke("plugin:files:createFile", { sessionId, path }),
    mkdir: (sessionId, path) => ipcRenderer.invoke("plugin:files:mkdir", { sessionId, path }),
    rename: (sessionId, from, to) => ipcRenderer.invoke("plugin:files:rename", { sessionId, from, to }),
    remove: (sessionId, path) => ipcRenderer.invoke("plugin:files:remove", { sessionId, path }),
    removeMany: (sessionId, paths, recursive = false) => ipcRenderer.invoke("plugin:files:removeMany", { sessionId, paths, recursive }),
    upload: (sessionId, directory) => ipcRenderer.invoke("plugin:files:upload", { sessionId, directory }),
    download: (sessionId, path) => ipcRenderer.invoke("plugin:files:download", { sessionId, path }),
    downloadMany: (sessionId, paths) => ipcRenderer.invoke("plugin:files:downloadMany", { sessionId, paths }),
    downloadArchive: (sessionId, paths, format) => ipcRenderer.invoke("plugin:files:downloadArchive", { sessionId, paths, format })
  }),
  hashing: Object.freeze({
    getAlgorithms: () => ipcRenderer.invoke("plugin:hashing:algorithms"),
    selectFiles: (multiple = false) => ipcRenderer.invoke("plugin:hashing:selectFiles", { multiple }),
    selectDirectory: () => ipcRenderer.invoke("plugin:hashing:selectDirectory"),
    selectManifest: () => ipcRenderer.invoke("plugin:hashing:selectManifest"),
    selectManifestDestination: (suggestedName) => ipcRenderer.invoke("plugin:hashing:selectManifestDestination", { suggestedName }),
    start: (payload) => ipcRenderer.invoke("plugin:hashing:start", payload),
    verify: (payload) => ipcRenderer.invoke("plugin:hashing:verify", payload),
    compare: (payload) => ipcRenderer.invoke("plugin:hashing:compare", payload),
    generateManifest: (payload) => ipcRenderer.invoke("plugin:hashing:generateManifest", payload),
    verifyManifest: (payload) => ipcRenderer.invoke("plugin:hashing:verifyManifest", payload),
    exportResults: (payload) => ipcRenderer.invoke("plugin:hashing:exportResults", payload),
    copyResult: (payload) => ipcRenderer.invoke("plugin:hashing:copyResult", payload),
    status: (jobId) => ipcRenderer.invoke("plugin:hashing:status", { jobId }),
    cancel: (jobId) => ipcRenderer.invoke("plugin:hashing:cancel", { jobId }),
    onProgress: (callback) => {
      if (typeof callback !== "function") throw new TypeError("Progress callback must be a function.");
      const listener = (_event, job) => callback(job);
      ipcRenderer.on("plugin:hashing:progress", listener);
      return () => ipcRenderer.removeListener("plugin:hashing:progress", listener);
    }
  })
}));
