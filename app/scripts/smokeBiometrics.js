"use strict";
// Isolated UI test. Only the OS adapter is mocked; no production authentication is bypassed.
const { app, ipcMain } = require("electron");
const assert = require("node:assert/strict"), fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const { createMainWindow, hardenSession } = require("../src/main/bootstrap/createMainWindow");
const { registerCoreIpc } = require("../src/main/ipc/registerCoreIpc");
const { VaultStore } = require("../src/main/security/vaultStore");
const { ConfigStore } = require("../src/main/config/configStore");
const { BiometricService } = require("../src/main/security/biometrics/biometricService");
const { VaultLockController } = require("../src/main/security/vaultLockController");
const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-biometric-ui-")); app.setPath("userData", root);
let window, lock, service; const errors = [], keys = new Map();
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(source) { for (let i = 0; i < 100; i++) { if (await window.webContents.executeJavaScript(source)) return; await wait(50); } throw new Error("UI timeout: " + source); }
async function run() {
  await app.whenReady(); const config = new ConfigStore(root); config.load();
  const vault = new VaultStore(root); await vault.create("test-password"); vault.lock();
  const adapter = { info: { provider: "touch-id", protection: "biometry-current-set" },
    getAvailability: async () => ({ available: true, code: "BIOMETRIC_AVAILABLE", ...adapter.info }), enroll: async () => {}, authenticate: async () => {},
    storeProtectedKey: async (id, key) => { keys.set(id, Buffer.from(key)); }, retrieveProtectedKey: async id => Buffer.from(keys.get(id)), removeEnrollment: async id => keys.delete(id) };
  service = new BiometricService({ storageRoot: root, vaultStore: vault, configStore: config, adapter });
  const pluginRuntime = { notifyLanguageChanged() {}, closeAll() {} }, sessionManager = { disconnectAll: async () => {} };
  lock = new VaultLockController({ vaultStore: vault, configStore: config, biometricService: service, pluginRuntime, sessionManager });
  hardenSession(); window = createMainWindow(); window.webContents.on("console-message", event => { if (event.level === "error") errors.push(event.message); });
  lock.on("locked", status => window.webContents.send("vault:locked", status));
  registerCoreIpc({ ipcMain, app, configStore: config, vaultStore: vault, biometricService: service, vaultLockController: lock, pluginRuntime, sessionManager,
    pluginService: { getState: () => ({ installed: [], catalog: [], windows: [] }) }, profileService: { list: () => [] },
    updateService: { getState: () => ({ currentVersion: "0.0.1", status: "idle", releases: [] }) }, getMainWindow: () => window });
  await until('state.vault && biometricStatus');
  assert.equal(await window.webContents.executeJavaScript('document.querySelector("#biometricUnlockButton").hidden'), true);
  await window.webContents.executeJavaScript('document.querySelector("#vaultPassword").value="test-password"; document.querySelector("#vaultForm").requestSubmit()');
  await until('state.vault.unlocked');
  await window.webContents.executeJavaScript('document.querySelector("[data-view=settings]").click(); document.querySelector("#enableBiometricsButton").click()');
  await until('biometricStatus.enabled'); assert.equal(keys.size, 1);
  await window.webContents.executeJavaScript('document.querySelector("#autoLockEnabled").click()');
  assert.equal(await window.webContents.executeJavaScript('document.querySelector("#autoLockMinutes").value'), "15");
  await window.webContents.executeJavaScript('document.querySelector("#securityMasterPassword").value="test-password";document.querySelector("#securityForm").requestSubmit()');
  await until('state.config.security.autoLockMinutes === 15');
  const artifacts = process.env.CHJ_BIOMETRIC_SMOKE_ARTIFACT_DIR;
  if (artifacts) { await window.webContents.executeJavaScript('document.querySelector("#securityForm").scrollIntoView()'); await wait(100); fs.mkdirSync(artifacts, { recursive: true }); fs.writeFileSync(path.join(artifacts, "security-settings.png"), (await window.webContents.capturePage()).toPNG()); }
  await lock.lock(); await until('!state.vault.unlocked && !document.querySelector("#biometricUnlockButton").hidden');
  for (const [language, label] of [["cs", "Odemknout pomocí Touch ID"], ["de", "Mit Touch ID entsperren"], ["en", "Unlock with Touch ID"]]) {
    await window.webContents.executeJavaScript(`applyLanguage(${JSON.stringify(language)})`);
    assert.equal(await window.webContents.executeJavaScript('document.querySelector("#biometricUnlockButton").textContent'), label);
  }
  await window.webContents.executeJavaScript('document.querySelector("#biometricUnlockButton").click()'); await until('state.vault.unlocked');
  assert.equal(await window.webContents.executeJavaScript('typeof window.require'), "undefined");
  await window.webContents.executeJavaScript('document.querySelector("#disableBiometricsButton").click()'); await until('!biometricStatus.enabled'); assert.equal(keys.size, 0);
  assert.deepEqual(errors, []); console.log("CHJ_BIOMETRICS_UI_OK: master password, enable, lock, biometric unlock, remove, default15, CZ/DE/EN, sandbox (mock OS adapter)");
}
let finished = false;
function finish(code) {
  if (finished) return; finished = true; lock?.dispose(); window?.destroy();
  for (const key of keys.values()) key.fill(0);
  try { fs.rmSync(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 }); }
  catch (error) { console.warn("Temporary Chromium cache cleanup:", error.code); }
  app.exit(code);
}
run().then(() => finish(0), error => { console.error(error); finish(1); }); setTimeout(() => { console.error("Biometric UI smoke timed out"); finish(1); }, 30000).unref();
