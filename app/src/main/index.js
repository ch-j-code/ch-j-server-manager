"use strict";

const path = require("node:path");
const { app, BrowserWindow, dialog, ipcMain, protocol, shell } = require("electron");
const { createMainWindow, hardenSession } = require("./bootstrap/createMainWindow");
const { ConfigStore } = require("./config/configStore");
const { registerCoreIpc } = require("./ipc/registerCoreIpc");
const { Logger } = require("./logging/logger");
const { LogService } = require("./logging/logService");
const { RemoteFileService } = require("./files/remoteFileService");
const { PLUGIN_API_VERSION, PluginRegistry } = require("./plugins/pluginRegistry");
const { PluginCatalogProvider } = require("./plugins/pluginCatalogProvider");
const { PluginInstaller } = require("./plugins/pluginInstaller");
const { PluginRuntime } = require("./plugins/pluginRuntime");
const { PluginService } = require("./plugins/pluginService");
const { KeyGeneratorService } = require("./keys/keyGeneratorService");
const { ProfileService } = require("./profiles/profileService");
const { createTestHttpsFetch } = require("./security/testHttpsFetch");
const { VaultStore } = require("./security/vaultStore");
const { SessionManager } = require("./sessions/sessionManager");
const { HashUrlProvider } = require("./updates/hashUrlProvider");
const { UpdateService } = require("./updates/updateService");
const buildInfo = require("../shared/buildInfo.json");

app.setName("CH-J Server Manager");
const buildSmokeUserData = process.env.CHJ_BUILD_SMOKE_USER_DATA_DIR;
if (buildSmokeUserData && path.isAbsolute(buildSmokeUserData)) app.setPath("userData", buildSmokeUserData);
if (process.platform === "win32") app.setAppUserModelId("de.ch-j.servermanager");
protocol.registerSchemesAsPrivileged([{ scheme: "chj-plugin", privileges: { standard: true, secure: true, supportFetchAPI: true } }]);

let mainWindow = null;
let logger = null;
let updateService = null;
let sessionManager = null;
let vaultStore = null;

const hasSingleInstanceLock = buildSmokeUserData ? true : app.requestSingleInstanceLock();
if (!hasSingleInstanceLock) app.quit();

function focusMainWindow() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
}

async function bootstrap() {
  const storageRoot = app.getPath("userData");
  const appIcon = path.join(__dirname, "..", "..", "build", "icon.png");
  logger = new Logger(storageRoot);
  const logService = new LogService(logger.logPath);
  const configStore = new ConfigStore(storageRoot);
  configStore.load();
  const testUpdateFetch = createTestHttpsFetch({
    allowedBaseUrls: configStore.get().updates.baseUrls,
    // Jen starý host používá dočasnou alfa výjimku. Kanonický www host
    // musí vždy projít standardním ověřením veřejného certifikátu.
    insecureBaseUrls: ["https://sm.ch-j.de/"]
  });
  const pluginRegistry = new PluginRegistry(storageRoot, logger);
  vaultStore = new VaultStore(storageRoot);
  const profileService = new ProfileService(vaultStore);
  sessionManager = new SessionManager({ profileService, logger });
  const keyGeneratorService = new KeyGeneratorService({
    selectSavePath: async (suggestedName) => {
      const result = await dialog.showSaveDialog(mainWindow, { title: "Uložit pár SSH klíčů", defaultPath: suggestedName });
      return { canceled: result.canceled, path: result.filePath || null };
    }
  });
  const remoteFileService = new RemoteFileService({
    sessionManager,
    selectUploadPath: async () => {
      const result = await dialog.showOpenDialog(mainWindow, { title: "Vybrat soubory nebo složky k nahrání", properties: ["openFile", "openDirectory", "multiSelections"] });
      return { canceled: result.canceled, paths: result.filePaths };
    },
    selectDownloadPath: async (suggestedName) => {
      const result = await dialog.showSaveDialog(mainWindow, { title: "Uložit stažený soubor", defaultPath: suggestedName });
      return { canceled: result.canceled, path: result.filePath || null };
    },
    selectDownloadDirectory: async () => {
      const result = await dialog.showOpenDialog(mainWindow, { title: "Vybrat složku pro stažení", properties: ["openDirectory", "createDirectory"] });
      return { canceled: result.canceled, path: result.filePaths[0] || null };
    },
    selectArchivePath: async (suggestedName, format) => {
      const extensions = format === "tar.gz" ? ["tar.gz", "tgz"] : [format];
      const result = await dialog.showSaveDialog(mainWindow, { title: "Uložit vzdálené položky jako archiv", defaultPath: suggestedName, filters: [{ name: format.toUpperCase(), extensions }] });
      return { canceled: result.canceled, path: result.filePath || null };
    },
    logger
  });
  const pluginInstaller = new PluginInstaller({ storageRoot, appVersion: app.getVersion(), pluginApiVersion: PLUGIN_API_VERSION, logger });
  const pluginRuntime = new PluginRuntime({
    BrowserWindow,
    registry: pluginRegistry,
    sessionManager,
    keyGeneratorService,
    logService,
    remoteFileService,
    getMainWindow: () => mainWindow,
    isVaultUnlocked: () => vaultStore.status().unlocked,
    preload: path.join(__dirname, "..", "preload", "pluginPreload.js"),
    icon: appIcon,
    onWindowState: (windows) => {
      if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send("core:pluginWindowState", windows);
    },
    logger
  });
  protocol.handle("chj-plugin", (request) => pluginRuntime.handleRequest(request));
  pluginRuntime.registerIpc(ipcMain);
  const pluginService = new PluginService({
    appVersion: app.getVersion(),
    pluginApiVersion: PLUGIN_API_VERSION,
    configStore,
    registry: pluginRegistry,
    installer: pluginInstaller,
    runtime: pluginRuntime,
    logger,
    providerFactory: (updateConfig) => new PluginCatalogProvider({
      baseUrls: updateConfig.baseUrls,
      downloadRoot: path.join(storageRoot, "plugins", ".downloads"),
      fetchImpl: testUpdateFetch,
      logger
    })
  });
  updateService = new UpdateService({
    appVersion: app.getVersion(),
    buildId: buildInfo.buildId,
    platform: process.platform,
    arch: process.arch,
    configStore,
    logger,
    providerFactory: (updateConfig) => new HashUrlProvider({
      baseUrls: updateConfig.baseUrls,
      downloadRoot: path.join(storageRoot, "updates", "downloads"),
      fetchImpl: testUpdateFetch,
      logger
    })
  });

  for (const [cache, service] of [["Core update", updateService], ["plugin package", pluginService]]) {
    try {
      const result = service.cleanupDownloads();
      if (result.cleaned) logger.info(`${cache} download cache cleaned on startup.`, { root: result.root });
    } catch (error) {
      logger.warn(`${cache} download cache cleanup failed.`, { message: error?.message || String(error) });
    }
  }

  hardenSession(logger);
  mainWindow = createMainWindow({ logger, icon: appIcon });
  registerCoreIpc({
    ipcMain,
    shell,
    dialog,
    app,
    configStore,
    pluginRegistry,
    pluginService,
    pluginRuntime,
    profileService,
    sessionManager,
    vaultStore,
    updateService,
    getMainWindow: () => mainWindow,
    logger
  });

  const sendToRenderer = (channel, payload) => {
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send(channel, payload);
  };
  sessionManager.on("data", (payload) => sendToRenderer("ssh:data", payload));
  sessionManager.on("state", (payload) => sendToRenderer("ssh:state", payload));
  sessionManager.on("sessionError", (payload) => sendToRenderer("ssh:error", payload));

  mainWindow.webContents.once("did-finish-load", () => {
    const config = configStore.get();
    if (!config.updates.autoCheck) return;
    updateService.check()
      .then((state) => {
        if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send("core:updateState", state);
      })
      .catch((error) => logger.warn("Automatic update check failed.", { message: error?.message || String(error) }));
  });

  logger.info("Core initialized.", {
    version: app.getVersion(),
    buildId: buildInfo.buildId,
    platform: process.platform,
    arch: process.arch,
    storageRoot
  });
  if (buildSmokeUserData) {
    console.log("CHJ_BUILD_SMOKE_READY");
    setTimeout(() => app.quit(), 50);
  }
}

app.on("second-instance", focusMainWindow);
app.whenReady().then(bootstrap).catch((error) => {
  logger?.error("Core bootstrap failed.", { message: error?.message || String(error), stack: error?.stack });
  app.quit();
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    mainWindow = createMainWindow({ logger });
  } else {
    focusMainWindow();
  }
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  void sessionManager?.disconnectAll("app-quit");
  vaultStore?.lock();
});

process.on("uncaughtException", (error) => {
  logger?.error("Uncaught exception.", { message: error?.message || String(error), stack: error?.stack });
});
process.on("unhandledRejection", (error) => {
  logger?.error("Unhandled rejection.", { message: error?.message || String(error), stack: error?.stack });
});
