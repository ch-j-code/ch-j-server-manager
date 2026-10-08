"use strict";

const { contextBridge, ipcRenderer } = require("electron");

// Core provides the same chrome to bundled and already installed plugins.
// Shadow DOM keeps plugin styles out of the title bar; the plugin remains sandboxed.
window.addEventListener("DOMContentLoaded", () => {
  const styleUrl = new URL("/__chj_core__/window-chrome.css", window.location.href).href;
  const host = document.createElement("chj-plugin-chrome");
  host.id = "chj-plugin-window-chrome";
  const shadow = host.attachShadow({ mode: "open" });
  let loadedStyles = 0;
  const stylesheet = () => {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = styleUrl;
    link.addEventListener("load", () => {
      if (++loadedStyles === 2) host.dataset.ready = "true";
    });
    return link;
  };
  document.head.append(stylesheet());
  const header = document.createElement("header");
  header.id = "chj-chrome-header";
  if (process.platform === "win32" || process.platform === "linux") header.className = "native-controls";
  const mark = document.createElement("span");
  mark.id = "chj-chrome-mark";
  mark.textContent = "CH-J";
  const title = document.createElement("span");
  title.id = "chj-chrome-title";
  title.textContent = document.title || "CH-J Server Manager";
  const collapse = document.createElement("button");
  collapse.type = "button";
  collapse.id = "chj-chrome-collapse";
  const copy = {
    cs: ["Sbalit", "Sbalit do spodní lišty aplikace"],
    de: ["Einklappen", "In die untere Leiste der Anwendung einklappen"],
    en: ["Collapse", "Collapse into the application's bottom bar"]
  };
  const translate = (language) => {
    const [label, description] = copy[language] || copy.en;
    collapse.textContent = label;
    collapse.title = description;
    collapse.setAttribute("aria-label", description);
  };
  translate("en");
  collapse.addEventListener("click", () => {
    void ipcRenderer.invoke("plugin:window:minimize").catch((error) => console.error("Plugin collapse failed.", error));
  });
  ipcRenderer.on("plugin:ui:languageChanged", (_event, language) => translate(language));
  void ipcRenderer.invoke("plugin:ui:getLanguage").then(translate).catch(() => {});
  void ipcRenderer.invoke("plugin:getInfo").then((manifest) => { title.textContent = manifest.name; }).catch(() => {});
  header.append(mark, title, collapse);
  shadow.append(stylesheet(), header);
  document.body.prepend(host);
});

contextBridge.exposeInMainWorld("chjPlugin", Object.freeze({
  getInfo: () => ipcRenderer.invoke("plugin:getInfo"),
  ui: Object.freeze({
    getLanguage: () => ipcRenderer.invoke("plugin:ui:getLanguage"),
    onLanguageChanged: (callback) => {
      if (typeof callback !== "function") throw new TypeError("Language callback must be a function.");
      const listener = (_event, language) => callback(language);
      ipcRenderer.on("plugin:ui:languageChanged", listener);
      return () => ipcRenderer.removeListener("plugin:ui:languageChanged", listener);
    }
  }),
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
