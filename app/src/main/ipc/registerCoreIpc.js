"use strict";

const path = require("node:path");

const PRIVATE_KEY_DIALOG_COPY = Object.freeze({
  cs: { title: "Vybrat soukromý SSH klíč", keys: "Soukromé SSH klíče", all: "Všechny soubory" },
  de: { title: "Privaten SSH-Schlüssel auswählen", keys: "Private SSH-Schlüssel", all: "Alle Dateien" },
  en: { title: "Select an SSH private key", keys: "SSH private keys", all: "All files" }
});

function registerCoreIpc(options) {
  const {
    ipcMain, shell, dialog, app, configStore, pluginRegistry, pluginService, pluginRuntime, profileService,
    sessionManager, vaultStore, updateService, updateInstallerLauncher, getMainWindow, logger
  } = options;

  function assertTrustedSender(event) {
    const mainWindow = getMainWindow();
    if (!mainWindow || mainWindow.isDestroyed() || event.sender.id !== mainWindow.webContents.id) {
      const error = new Error("Untrusted IPC sender.");
      error.code = "UNTRUSTED_IPC_SENDER";
      throw error;
    }
  }

  function handle(channel, handler) {
    ipcMain.handle(channel, async (event, payload) => {
      assertTrustedSender(event);
      try {
        return await handler(payload);
      } catch (error) {
        logger?.error("IPC operation failed.", { channel, message: error?.message || String(error), code: error?.code });
        throw error;
      }
    });
  }

  function send(channel, handler) {
    ipcMain.on(channel, (event, payload) => {
      try {
        assertTrustedSender(event);
        handler(payload);
      } catch (error) {
        logger?.warn("IPC event was rejected.", { channel, message: error?.message || String(error), code: error?.code });
      }
    });
  }

  function sessionResult(action) {
    return async (payload) => {
      try {
        return { ok: true, value: await action(payload || {}) };
      } catch (error) {
        return {
          ok: false,
          error: typeof error?.toJSON === "function"
            ? error.toJSON()
            : { code: error?.code || "SSH_OPERATION_FAILED", message: error?.message || String(error) }
        };
      }
    };
  }

  handle("core:getInfo", async () => ({
    name: app.getName(),
    version: app.getVersion(),
    platform: process.platform,
    arch: process.arch,
    coreApi: "1.0.0",
    pluginApi: options.pluginApiVersion || require("../plugins/pluginRegistry").PLUGIN_API_VERSION,
    dataSchema: 1,
    license: "Apache-2.0",
    copyright: "Copyright 2026 Josef Chudy"
  }));
  handle("legal:open", async (payload = {}) => {
    const names = {
      application: "APPLICATION_LICENSE.txt",
      notice: "NOTICE.txt",
      thirdParty: "THIRD_PARTY_NOTICES.txt",
      thirdPartyBundle: "THIRD_PARTY_LICENSES.zip",
      electron: "ELECTRON_LICENSE.txt",
      chromium: "CHROMIUM_LICENSES.html"
    };
    const filename = names[String(payload.document || "")];
    if (!filename) throw new Error("Unknown legal document.");
    const root = app.isPackaged ? path.join(process.resourcesPath, "licenses") : app.getAppPath();
    const developmentFiles = {
      APPLICATION_LICENSE: "LICENSE",
      NOTICE: "NOTICE",
      THIRD_PARTY_NOTICES: "THIRD_PARTY_NOTICES.txt",
      THIRD_PARTY_LICENSES: "THIRD_PARTY_LICENSES.zip",
      ELECTRON_LICENSE: path.join("node_modules", "electron", "dist", "LICENSE"),
      CHROMIUM_LICENSES: path.join("node_modules", "electron", "dist", "LICENSES.chromium.html")
    };
    const stem = path.parse(filename).name;
    const filePath = app.isPackaged ? path.join(root, filename) : path.join(root, developmentFiles[stem]);
    const error = await shell.openPath(filePath);
    if (error) throw new Error(`The legal document could not be opened: ${error}`);
    return { ok: true };
  });
  handle("config:get", async () => configStore.get());
  handle("config:update", async (payload = {}) => configStore.update(payload));
  handle("plugins:list", async () => pluginRegistry.listInstalled());
  handle("plugins:getState", async () => pluginService.getState());
  handle("plugins:checkCatalog", async () => pluginService.checkCatalog());
  handle("plugins:install", async (payload = {}) => pluginService.install(payload.releaseId));
  handle("plugins:uninstall", async (payload = {}) => pluginService.uninstall(payload.pluginId));
  handle("plugins:open", async (payload = {}) => pluginService.open(payload.pluginId));
  handle("vault:status", async () => vaultStore.status());
  handle("vault:create", async (payload = {}) => vaultStore.create(payload.password));
  handle("vault:unlock", async (payload = {}) => vaultStore.unlock(payload.password));
  handle("vault:lock", async () => {
    pluginRuntime.closeAll();
    await sessionManager.disconnectAll("vault-lock");
    return vaultStore.lock();
  });
  handle("vault:reset", async (payload = {}) => {
    pluginRuntime.closeAll();
    await sessionManager.disconnectAll("vault-reset");
    const status = vaultStore.reset(payload.confirmation);
    logger?.warn("Encrypted user vault was reset by the user.");
    return status;
  });
  handle("profiles:list", async () => profileService.list());
  handle("profiles:save", async (payload = {}) => profileService.save(payload));
  handle("profiles:delete", async (payload = {}) => profileService.delete(String(payload.id || "")));
  handle("profiles:selectPrivateKey", async () => {
    const mainWindow = getMainWindow();
    const copy = PRIVATE_KEY_DIALOG_COPY[configStore.get().ui.language] || PRIVATE_KEY_DIALOG_COPY.cs;
    const result = await dialog.showOpenDialog(mainWindow, {
      title: copy.title,
      properties: ["openFile"],
      filters: [{ name: copy.keys, extensions: ["pem", "key", "ppk"] }, { name: copy.all, extensions: ["*"] }]
    });
    return { canceled: result.canceled, path: result.filePaths[0] || null };
  });
  handle("ssh:list", async () => sessionManager.list());
  handle("ssh:connect", sessionResult((payload) => sessionManager.connect(payload)));
  handle("ssh:trustHostKey", sessionResult((payload) => sessionManager.trustPending(payload)));
  handle("ssh:disconnect", sessionResult((payload) => sessionManager.disconnect(payload.sessionId, "user")));
  handle("ssh:resize", sessionResult((payload) => sessionManager.resize(payload.sessionId, payload.cols, payload.rows)));
  send("ssh:input", (payload = {}) => sessionManager.write(payload.sessionId, payload.data));
  handle("updates:getState", async () => updateService.getState());
  handle("updates:check", async () => updateService.check());
  handle("updates:select", async (payload = {}) => updateService.select(payload.id));
  handle("updates:download", async () => updateService.download());
  handle("updates:install", async () => {
    // The renderer supplies neither a path nor a verification flag. The main
    // process re-hashes and re-verifies its internally tracked artifact here.
    const filePath = await updateService.prepareInstallerLaunch();
    const result = await updateInstallerLauncher.install(filePath);
    updateService.markInstallerLaunched();
    if (result.restartApplication) {
      setTimeout(() => {
        app.relaunch();
        app.quit();
      }, 250).unref?.();
    }
    return { ok: true, installed: result.installed === true, restarting: result.restartApplication === true };
  });
  handle("updates:reveal", async () => {
    const filePath = updateService.getVerifiedDownloadPath();
    if (!filePath) throw new Error("No verified update has been downloaded.");
    shell.showItemInFolder(filePath);
    return { ok: true };
  });
}

module.exports = { registerCoreIpc };
