"use strict";

const path = require("node:path");

const PRIVATE_KEY_DIALOG_COPY = Object.freeze({
  cs: { title: "Vybrat soukromý SSH klíč", keys: "Soukromé SSH klíče", all: "Všechny soubory" },
  de: { title: "Privaten SSH-Schlüssel auswählen", keys: "Private SSH-Schlüssel", all: "Alle Dateien" },
  en: { title: "Select an SSH private key", keys: "SSH private keys", all: "All files" }
});

function registerCoreIpc(options) {
  const {
    ipcMain, shell, dialog, clipboard, app, configStore, pluginRegistry, pluginService, pluginRuntime, profileService,
    sessionManager, vaultStore, biometricService, vaultLockController, updateService, updateInstallerLauncher, diagnosticsService, getMainWindow, logger
  } = options;

  function assertTrustedSender(event) {
    const mainWindow = getMainWindow();
    if (!mainWindow || mainWindow.isDestroyed() || event.sender.id !== mainWindow.webContents.id ||
        (mainWindow.webContents.mainFrame && event.senderFrame !== mainWindow.webContents.mainFrame)) {
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
  handle("config:update", async (payload = {}) => {
    if (payload.security) {
      await vaultStore.verifyPassword(payload.masterPassword);
      if (payload.security.requireSystemAuthentication && !(await biometricService.getStatus()).available) {
        throw new Error("BIOMETRIC_UNAVAILABLE");
      }
    }
    const config = configStore.update(payload);
    pluginRuntime.notifyLanguageChanged(config.ui.language);
    return config;
  });
  handle("plugins:list", async () => pluginRegistry.listInstalled());
  handle("plugins:getState", async () => pluginService.getState());
  handle("plugins:checkCatalog", async () => pluginService.checkCatalog());
  handle("plugins:install", async (payload = {}) => { await biometricService?.requireSensitiveAction(); return pluginService.install(payload.releaseId); });
  handle("plugins:uninstall", async (payload = {}) => { await biometricService?.requireSensitiveAction(); return pluginService.uninstall(payload.pluginId); });
  handle("plugins:open", async (payload = {}) => pluginService.open(payload.pluginId));
  handle("vault:status", async () => vaultStore.status());
  handle("vault:create", async (payload = {}) => { const status = await vaultStore.create(payload.password); vaultLockController?.activity(); return status; });
  handle("vault:unlock", async (payload = {}) => { biometricService?.cancel(); const status = await vaultStore.unlock(payload.password); vaultLockController?.activity(); return status; });
  handle("biometrics:status", sessionResult(() => biometricService.getStatus()));
  handle("biometrics:enable", sessionResult(() => biometricService.enable()));
  handle("biometrics:disable", sessionResult(() => biometricService.disable()));
  handle("biometrics:unlock", sessionResult(async () => {
    const status = await biometricService.unlock(); vaultLockController?.activity(); return status;
  }));
  handle("biometrics:authenticate", sessionResult(() => biometricService.authenticateSensitiveAction()));
  handle("vault:lock", async () => {
    if (vaultLockController) return vaultLockController.lock();
    pluginRuntime.closeAll();
    await sessionManager.disconnectAll("vault-lock");
    return vaultStore.lock();
  });
  handle("vault:reset", async (payload = {}) => {
    if (payload.confirmation !== "SMAZAT") throw Object.assign(new Error("Vault reset confirmation is invalid."), { code: "VAULT_RESET_CONFIRMATION_REQUIRED" });
    if (vaultStore.status().unlocked) await biometricService?.requireSensitiveAction();
    await biometricService?.disable({ reset: true });
    pluginRuntime.closeAll();
    await sessionManager.disconnectAll("vault-reset");
    const status = vaultStore.reset(payload.confirmation);
    logger?.warn("Encrypted user vault was reset by the user.");
    return status;
  });
  handle("profiles:list", async () => profileService.list());
  handle("profiles:save", async (payload = {}) => profileService.save(payload));
  handle("profiles:delete", async (payload = {}) => { await biometricService?.requireSensitiveAction(); return profileService.delete(String(payload.id || "")); });
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
  const diagnosticsResult = (action) => async (payload = {}) => {
    try { return { ok: true, value: await action(payload) }; }
    catch (error) { return { ok: false, error: { code: error.code || "DIAGNOSTICS_ERROR", message: String(error.message || error).slice(0, 400) } }; }
  };
  handle("diagnostics:resolve", diagnosticsResult((payload) => diagnosticsService.resolve(payload)));
  handle("diagnostics:start", diagnosticsResult((payload) => diagnosticsService.start(payload)));
  handle("diagnostics:cancel", diagnosticsResult((payload) => diagnosticsService.cancel(payload.id, payload.tool)));
  handle("diagnostics:get", diagnosticsResult((payload) => diagnosticsService.get(payload.id)));
  handle("diagnostics:history", diagnosticsResult(() => diagnosticsService.history.list()));
  handle("diagnostics:removeHistory", diagnosticsResult((payload) => diagnosticsService.history.remove(payload.id)));
  handle("diagnostics:copy", diagnosticsResult((payload) => {
    clipboard.writeText(diagnosticsService.export(payload.id, payload.format || "txt"));
    return { copied: true };
  }));
  handle("diagnostics:export", diagnosticsResult(async (payload) => {
    const content = diagnosticsService.export(payload.id, payload.format);
    const result = await dialog.showSaveDialog(getMainWindow(), { defaultPath: `diagnostics.${payload.format}`, filters: [{ name: payload.format.toUpperCase(), extensions: [payload.format] }] });
    if (result.canceled || !result.filePath) return { canceled: true };
    await require("node:fs").promises.writeFile(result.filePath, content, { mode: 0o600 });
    return { canceled: false };
  }));
  handle("diagnostics:import", diagnosticsResult(async () => {
    const result = await dialog.showOpenDialog(getMainWindow(), { properties: ["openFile"], filters: [{ name: "Diagnostics JSON", extensions: ["json"] }] });
    if (result.canceled || !result.filePaths[0]) return { canceled: true };
    const fs = require("node:fs"); const stat = await fs.promises.lstat(result.filePaths[0]);
    if (!stat.isFile() || stat.size > 2 * 1024 * 1024) throw Object.assign(new Error("IMPORT_LIMIT"), { code: "IMPORT_LIMIT" });
    const id = diagnosticsService.history.import(await fs.promises.readFile(result.filePaths[0], "utf8"));
    return { id };
  }));
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
    await biometricService?.requireSensitiveAction();
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
