"use strict";

const path = require("node:path");
const { BrowserWindow, session, shell } = require("electron");

function isAllowedExternalUrl(value) {
  try {
    const url = new URL(String(value || ""));
    return url.protocol === "https:" && ["ch-j.de"].includes(url.hostname);
  } catch {
    return false;
  }
}

function hardenSession(logger) {
  session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        "X-Content-Type-Options": ["nosniff"],
        "Referrer-Policy": ["no-referrer"],
        "Permissions-Policy": ["camera=(), microphone=(), geolocation=(), usb=(), serial=()"]
      }
    });
  });
  logger?.info("Default Electron session hardened.");
}

function windowChromeOptions(platform = process.platform) {
  if (platform !== "win32") return {};
  return {
    titleBarStyle: "hidden",
    titleBarOverlay: {
      color: "#07111f",
      symbolColor: "#d9eaff",
      height: 40
    }
  };
}

function createMainWindow(options = {}) {
  const preload = path.join(__dirname, "..", "..", "preload", "corePreload.js");
  const renderer = path.join(__dirname, "..", "..", "renderer", "index.html");
  const window = new BrowserWindow({
    title: "CH-J Server Manager",
    width: 1240,
    height: 780,
    minWidth: 960,
    minHeight: 640,
    backgroundColor: "#07111f",
    icon: options.icon,
    show: false,
    ...windowChromeOptions(),
    webPreferences: {
      preload,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      spellcheck: false
    }
  });

  window.webContents.setWindowOpenHandler(({ url }) => {
    if (isAllowedExternalUrl(url)) void shell.openExternal(url);
    return { action: "deny" };
  });
  window.webContents.on("will-navigate", (event, url) => {
    if (url !== window.webContents.getURL()) event.preventDefault();
  });
  window.webContents.on("will-attach-webview", (event) => event.preventDefault());
  window.once("ready-to-show", () => window.show());
  window.loadFile(renderer);
  return window;
}

module.exports = {
  createMainWindow,
  hardenSession,
  isAllowedExternalUrl,
  windowChromeOptions
};
