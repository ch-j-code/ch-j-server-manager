"use strict";

const api = window.chjCore;
const i18n = window.chjI18n;
const t = (key, values) => i18n.t(key, values);
const TERMINAL_SESSION_ID = "terminal-main";
const HASH_TOOL_ID = "chj.hash-checksum";
if (api?.platform) document.body.classList.add(`platform-${api.platform}`);
const state = {
  info: null,
  config: null,
  plugins: [],
  pluginState: null,
  pluginWindows: [],
  update: null,
  vault: null,
  profiles: [],
  selectedProfileId: "",
  terminalConnected: false,
  terminalStateKind: "disconnected"
};

const $ = (selector) => document.querySelector(selector);
const elements = {
  viewTitle: $("#viewTitle"), runtimeText: $("#runtimeText"), sidebarVersion: $("#sidebarVersion"),
  coreApiValue: $("#coreApiValue"), dataSchemaValue: $("#dataSchemaValue"), pluginCountValue: $("#pluginCountValue"),
  currentVersion: $("#currentVersion"), updateChannel: $("#updateChannel"), updateHeadline: $("#updateHeadline"),
  updateMessage: $("#updateMessage"), updateHash: $("#updateHash"), checkUpdateButton: $("#checkUpdateButton"),
  downloadUpdateButton: $("#downloadUpdateButton"), installUpdateButton: $("#installUpdateButton"), revealUpdateButton: $("#revealUpdateButton"),
  updateReleaseRows: $("#updateReleaseRows"), updateReleaseCount: $("#updateReleaseCount"), pluginRows: $("#pluginRows"),
  pluginCatalogRows: $("#pluginCatalogRows"), pluginCatalogSource: $("#pluginCatalogSource"), checkPluginCatalogButton: $("#checkPluginCatalogButton"),
  pluginTaskbar: $("#pluginTaskbar"), pluginTaskbarItems: $("#pluginTaskbarItems"),
  updateViewChannelSelect: $("#updateViewChannelSelect"), pluginViewChannelSelect: $("#pluginViewChannelSelect"),
  settingsForm: $("#settingsForm"), languageSelect: $("#languageSelect"), channelSelect: $("#channelSelect"), pluginChannelSelect: $("#pluginChannelSelect"), autoCheckInput: $("#autoCheckInput"),
  baseUrlsText: $("#baseUrlsText"), settingsStatus: $("#settingsStatus"), lockVaultButton: $("#lockVaultButton"),
  vaultOverlay: $("#vaultOverlay"), vaultForm: $("#vaultForm"), vaultLanguageSelect: $("#vaultLanguageSelect"), vaultModeText: $("#vaultModeText"), vaultTitle: $("#vaultTitle"),
  vaultDescription: $("#vaultDescription"), vaultPassword: $("#vaultPassword"), vaultConfirmLabel: $("#vaultConfirmLabel"),
  vaultPasswordConfirm: $("#vaultPasswordConfirm"), vaultMessage: $("#vaultMessage"), vaultSubmit: $("#vaultSubmit"),
  showVaultResetButton: $("#showVaultResetButton"), vaultResetPanel: $("#vaultResetPanel"),
  vaultResetConfirmation: $("#vaultResetConfirmation"), cancelVaultResetButton: $("#cancelVaultResetButton"),
  confirmVaultResetButton: $("#confirmVaultResetButton"),
  profileRows: $("#profileRows"), profileForm: $("#profileForm"), profileId: $("#profileId"), profileLabel: $("#profileLabel"),
  profileHost: $("#profileHost"), profilePort: $("#profilePort"), profileUsername: $("#profileUsername"),
  profileAuthMethod: $("#profileAuthMethod"), privateKeyField: $("#privateKeyField"), passwordStorageField: $("#passwordStorageField"),
  profileStorePassword: $("#profileStorePassword"), profileStoredPassword: $("#profileStoredPassword"),
  profilePrivateKeyPath: $("#profilePrivateKeyPath"), selectPrivateKeyButton: $("#selectPrivateKeyButton"),
  profileMessage: $("#profileMessage"), deleteProfileButton: $("#deleteProfileButton"), newProfileButton: $("#newProfileButton"),
  terminalProfileSelect: $("#terminalProfileSelect"), credentialLabelText: $("#credentialLabelText"), terminalCredential: $("#terminalCredential"),
  connectButton: $("#connectButton"), disconnectButton: $("#disconnectButton"), terminalState: $("#terminalState"),
  terminalHost: $("#terminalHost"), terminalElement: $("#terminal")
};

const titles = {
  overview: "nav.overview", terminal: "terminal.title", profiles: "nav.servers",
  updates: "nav.updates", plugins: "nav.plugins", diagnostics: "nav.diagnostics", settings: "nav.settings"
};

let diagnosticsView = null;
let terminal = null;
let fitAddon = null;

function errorText(error) {
  return error?.message || String(error || t("errors.unknown"));
}

function showView(name) {
  document.querySelectorAll("[data-view]").forEach((button) => button.classList.toggle("active", button.dataset.view === name));
  document.querySelectorAll("[data-view-panel]").forEach((panel) => panel.classList.toggle("active", panel.dataset.viewPanel === name));
  elements.viewTitle.textContent = titles[name] ? t(titles[name]) : "CH-J Server Manager";
  if (name === "terminal") requestAnimationFrame(fitTerminal);
}

function setBusy(button, busy, label) {
  button.disabled = busy;
  if (label) button.textContent = label;
}

function formatBytes(bytes) {
  const units = ["B", "KB", "MB", "GB"];
  let value = Number(bytes || 0);
  let index = 0;
  while (value >= 1024 && index < units.length - 1) { value /= 1024; index += 1; }
  return `${i18n.formatNumber(value, { maximumFractionDigits: 1 })} ${units[index]}`;
}

function applyLanguage(language) {
  const selected = i18n.setLanguage(language);
  document.documentElement.lang = selected;
  i18n.apply(document);
  elements.languageSelect.value = selected;
  elements.vaultLanguageSelect.value = selected;
  const activeView = document.querySelector("[data-view].active")?.dataset.view || "overview";
  showView(activeView);
  if (state.update) renderUpdate(state.update);
  if (state.config) elements.updateChannel.textContent = t("updates.channel", { channel: state.config.updates.channel });
  renderPlugins();
  renderProfiles();
  diagnosticsView?.refreshLanguage();
  renderTerminalProfileSelect();
  if (state.vault) configureVault(state.vault);
  const terminalStateKeys = { disconnected: "terminal.disconnected", connecting: "terminal.connecting", connected: "terminal.connected", error: "terminal.connectionError" };
  setTerminalState(state.terminalStateKind, t(terminalStateKeys[state.terminalStateKind] || "terminal.disconnected"));
  return selected;
}

function renderUpdate(updateState) {
  state.update = updateState;
  elements.currentVersion.textContent = `v${updateState.currentVersion || state.info?.version || "0.0.1"}`;
  const release = updateState.release;
  const currentReleaseSelected = updateState.releaseRelation === "sameVersionCurrentRelease";
  elements.downloadUpdateButton.hidden = currentReleaseSelected;
  elements.downloadUpdateButton.disabled = !release || currentReleaseSelected;
  renderReleaseCatalog(updateState);
  if (updateState.downloaded) {
    elements.updateHeadline.textContent = t("updates.downloaded", { version: release?.version || "?" });
    elements.updateMessage.textContent = `${updateState.downloaded.filename} · ${formatBytes(updateState.downloaded.size)} · ${t("updates.signatureVerified")}`;
    elements.updateHash.hidden = false;
    elements.updateHash.textContent = `SHA-512 ${updateState.downloaded.sha512}`;
    elements.revealUpdateButton.hidden = false;
    elements.installUpdateButton.hidden = false;
  } else if (release) {
    const relationKey = {
      newerVersion: "updates.newerVersion",
      sameVersionNewerRelease: "updates.sameVersionNewerRelease",
      sameVersionCurrentRelease: "updates.sameVersionCurrentRelease",
      sameVersionOlderRelease: "updates.sameVersionOlderRelease",
      olderVersion: "updates.olderVersion"
    }[updateState.releaseRelation] || "updates.selected";
    elements.updateHeadline.textContent = t(relationKey, { version: release.version });
    const published = t("updates.publishedAt", { date: formatReleaseDate(release.publishedAt) });
    elements.updateMessage.textContent = release.notes ? `${published} · ${release.notes}` : published;
    elements.updateHash.hidden = false;
    elements.updateHash.textContent = `SHA-512 ${release.sha512}`;
    elements.revealUpdateButton.hidden = true;
    elements.installUpdateButton.hidden = true;
  } else {
    elements.updateHeadline.textContent = t("updates.noneAvailable");
    elements.updateMessage.textContent = t("updates.noCompatible");
    elements.updateHash.hidden = true;
    elements.revealUpdateButton.hidden = true;
    elements.installUpdateButton.hidden = true;
  }
}

function formatReleaseDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value || "—");
  return new Intl.DateTimeFormat(i18n.getLocale(), { dateStyle: "medium", timeStyle: "medium" }).format(date);
}

function renderReleaseCatalog(updateState) {
  const releases = Array.isArray(updateState.releases) ? updateState.releases : [];
  elements.updateReleaseCount.textContent = String(releases.length);
  elements.updateReleaseRows.replaceChildren();
  if (!releases.length) {
    const empty = document.createElement("div");
    empty.className = "update-release-empty";
    empty.textContent = t(updateState.status === "idle" ? "updates.catalogBeforeCheck" : "updates.catalogEmpty");
    elements.updateReleaseRows.append(empty);
    return;
  }
  for (const release of releases) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = `update-release-row${release.id === updateState.selectedReleaseId ? " selected" : ""}`;
    const version = document.createElement("strong"); version.textContent = `v${release.version}`;
    const published = document.createElement("span"); published.textContent = formatReleaseDate(release.publishedAt);
    const file = document.createElement("span"); file.textContent = `${release.filename} · ${formatBytes(release.size)}`;
    const action = document.createElement("span"); action.className = "release-select-label"; action.textContent = t(release.id === updateState.selectedReleaseId ? "updates.selectedLabel" : "updates.selectLabel");
    row.append(version, published, file, action);
    row.addEventListener("click", async () => {
      try { renderUpdate(await api.selectUpdateRelease(release.id)); }
      catch (error) { elements.updateMessage.textContent = errorText(error); }
    });
    elements.updateReleaseRows.append(row);
  }
}

function renderPlugins() {
  const plugins = state.plugins.filter((plugin) => plugin.id !== HASH_TOOL_ID);
  elements.pluginCountValue.textContent = String(plugins.length);
  elements.pluginRows.replaceChildren();
  if (plugins.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    const strong = document.createElement("strong"); strong.textContent = t("plugins.none");
    const span = document.createElement("span"); span.textContent = t("plugins.first");
    empty.append(strong, span); elements.pluginRows.append(empty); renderPluginCatalog(); renderPluginTaskbar(); return;
  }
  for (const plugin of plugins) {
    const row = document.createElement("div"); row.className = "plugin-row plugin-table-row";
    const name = document.createElement("strong"); name.textContent = plugin.name;
    const version = document.createElement("span"); version.textContent = plugin.version;
    const permissions = document.createElement("span"); permissions.textContent = plugin.permissions.join(", ") || t("plugins.noPermissions");
    const actions = document.createElement("div"); actions.className = "plugin-actions";
    const open = document.createElement("button"); open.type = "button"; open.className = "button"; open.textContent = t("plugins.open");
    open.addEventListener("click", async () => { try { await api.openPlugin(plugin.id); } catch (error) { window.alert(errorText(error)); } });
    actions.append(open);
    if (plugin.bundled) {
      const bundled = document.createElement("span"); bundled.className = "release-select-label"; bundled.textContent = t("plugins.bundled"); actions.append(bundled);
    } else {
      const remove = document.createElement("button"); remove.type = "button"; remove.className = "button danger"; remove.textContent = t("plugins.remove");
      remove.addEventListener("click", async () => {
        if (!window.confirm(t("plugins.removeConfirm", { name: plugin.name }))) return;
        remove.disabled = true;
        try {
          state.pluginState = await api.uninstallPlugin(plugin.id);
          state.plugins = state.pluginState.installed;
          renderPlugins();
        } catch (error) { window.alert(errorText(error)); remove.disabled = false; }
      });
      actions.append(remove);
    }
    row.append(name, version, permissions, actions); elements.pluginRows.append(row);
  }
  renderPluginCatalog();
  renderPluginTaskbar();
}

function renderPluginTaskbar(windows = state.pluginWindows) {
  state.pluginWindows = Array.isArray(windows) ? windows : [];
  const minimized = state.pluginWindows.filter((item) => item.minimized);
  elements.pluginTaskbar.hidden = minimized.length === 0;
  elements.pluginTaskbarItems.replaceChildren();
  for (const plugin of minimized) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "plugin-taskbar-item";
    button.title = t("plugins.restore", { name: plugin.name });
    const icon = document.createElement("span");
    icon.className = "plugin-taskbar-icon";
    icon.textContent = String(plugin.name || plugin.pluginId).split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase();
    const name = document.createElement("strong");
    name.textContent = plugin.name;
    const action = document.createElement("small");
    action.textContent = t("plugins.restoreAction");
    button.append(icon, name, action);
    button.addEventListener("click", async () => {
      try { await api.openPlugin(plugin.pluginId); }
      catch (error) { window.alert(errorText(error)); }
    });
    elements.pluginTaskbarItems.append(button);
  }
}

function renderPluginCatalog() {
  if (!elements.pluginCatalogRows) return;
  const catalog = (state.pluginState?.catalog || []).filter((plugin) => plugin.id !== HASH_TOOL_ID);
  elements.pluginCatalogSource.textContent = state.pluginState?.sourceBaseUrl || "";
  elements.pluginCatalogRows.replaceChildren();
  if (!catalog.length) {
    const empty = document.createElement("div"); empty.className = "plugin-catalog-empty";
    empty.textContent = t(state.pluginState?.sourceBaseUrl ? "plugins.catalogEmpty" : "plugins.catalogBeforeCheck");
    elements.pluginCatalogRows.append(empty); return;
  }
  for (const plugin of catalog) {
    const row = document.createElement("div"); row.className = "plugin-row plugin-table-row";
    const name = document.createElement("div");
    const strong = document.createElement("strong"); strong.textContent = plugin.name;
    const notes = document.createElement("small"); notes.textContent = plugin.notes || plugin.id;
    name.append(strong, notes);
    const version = document.createElement("span"); version.textContent = `v${plugin.version} · ${plugin.channel}`;
    const permissions = document.createElement("span"); permissions.textContent = plugin.permissions.join(", ") || t("plugins.noPermissions");
    const install = document.createElement("button"); install.type = "button"; install.className = `button${plugin.installed ? "" : " primary"}`;
    install.disabled = plugin.installed;
    install.textContent = t(plugin.installed ? "plugins.installed" : plugin.updateAvailable ? "plugins.update" : "plugins.install");
    install.addEventListener("click", async () => {
      if (!window.confirm(t("plugins.installConfirm", { name: plugin.name, version: plugin.version, permissions: plugin.permissions.join(", ") || t("plugins.noPermissions") }))) return;
      install.disabled = true; install.textContent = t("plugins.installing");
      try {
        state.pluginState = await api.installPlugin(plugin.releaseId);
        state.plugins = state.pluginState.installed;
        renderPlugins();
      } catch (error) { window.alert(errorText(error)); install.disabled = false; install.textContent = t("plugins.install"); }
    });
    row.append(name, version, permissions, install); elements.pluginCatalogRows.append(row);
  }
}

function configureVault(status) {
  state.vault = status;
  elements.vaultOverlay.hidden = Boolean(status.unlocked);
  elements.vaultMessage.className = "form-message";
  elements.vaultMessage.textContent = "";
  elements.vaultPassword.value = "";
  elements.vaultPasswordConfirm.value = "";
  elements.vaultResetConfirmation.value = "";
  elements.vaultResetPanel.hidden = true;
  if (status.unlocked) return;
  if (status.damaged) {
    elements.vaultForm.dataset.mode = "damaged";
    elements.vaultModeText.textContent = t("vault.damagedMode");
    elements.vaultTitle.textContent = t("vault.damagedTitle");
    elements.vaultDescription.textContent = t("vault.damagedDescription");
    elements.vaultSubmit.disabled = true;
    elements.vaultConfirmLabel.hidden = true;
    elements.showVaultResetButton.hidden = false;
    return;
  }
  const setup = status.needsSetup;
  elements.vaultForm.dataset.mode = setup ? "setup" : "unlock";
  elements.vaultModeText.textContent = t(setup ? "vault.setupMode" : "vault.lockedMode");
  elements.vaultSubmit.disabled = false;
  elements.vaultConfirmLabel.hidden = !setup;
  elements.showVaultResetButton.hidden = setup;
  elements.vaultPassword.autocomplete = setup ? "new-password" : "current-password";
  elements.vaultTitle.textContent = t(setup ? "vault.setupTitle" : "vault.unlockTitle");
  elements.vaultDescription.textContent = t(setup ? "vault.setupDescription" : "vault.lockedDescription");
  elements.vaultSubmit.textContent = t(setup ? "vault.create" : "vault.unlock");
  setTimeout(() => elements.vaultPassword.focus(), 20);
}

function clearProtectedUi() {
  state.profiles = [];
  state.selectedProfileId = "";
  state.terminalConnected = false;
  renderProfiles();
  diagnosticsView?.refreshLanguage();
  renderTerminalProfileSelect();
  setTerminalState("disconnected", t("terminal.disconnected"));
  terminal?.reset();
}

async function loadProfiles(selectId = state.selectedProfileId) {
  state.profiles = await api.listProfiles();
  if (!state.profiles.some((profile) => profile.id === selectId)) selectId = state.profiles[0]?.id || "";
  state.selectedProfileId = selectId;
  renderProfiles();
  diagnosticsView?.refreshLanguage();
  renderTerminalProfileSelect();
  if (selectId) fillProfileForm(state.profiles.find((profile) => profile.id === selectId));
  else resetProfileForm();
}

function renderProfiles() {
  elements.profileRows.replaceChildren();
  if (!state.profiles.length) {
    const empty = document.createElement("div"); empty.className = "profile-empty";
    empty.textContent = t("profiles.none"); elements.profileRows.append(empty); return;
  }
  for (const profile of state.profiles) {
    const row = document.createElement("button"); row.type = "button";
    row.className = `profile-row${profile.id === state.selectedProfileId ? " active" : ""}`;
    const name = document.createElement("strong"); name.textContent = profile.label;
    const address = document.createElement("span"); address.textContent = `${profile.username}@${profile.host}:${profile.port}`;
    const auth = document.createElement("span"); auth.className = "profile-auth"; auth.textContent = t(profile.authMethod === "privateKey" ? "profiles.key" : "profiles.password");
    row.append(name, address, auth);
    row.addEventListener("click", () => { state.selectedProfileId = profile.id; renderProfiles(); fillProfileForm(profile); });
    elements.profileRows.append(row);
  }
}

function renderTerminalProfileSelect() {
  const previous = elements.terminalProfileSelect.value || state.selectedProfileId;
  elements.terminalProfileSelect.replaceChildren(new Option(t("terminal.selectServer"), ""));
  for (const profile of state.profiles) elements.terminalProfileSelect.add(new Option(`${profile.label} — ${profile.host}`, profile.id));
  elements.terminalProfileSelect.value = state.profiles.some((profile) => profile.id === previous) ? previous : (state.profiles[0]?.id || "");
  updateTerminalProfile();
}

function resetProfileForm() {
  elements.profileForm.reset();
  elements.profileId.value = "";
  elements.profilePort.value = "22";
  elements.profileAuthMethod.value = "password";
  elements.profilePrivateKeyPath.value = "";
  elements.profileStorePassword.checked = false;
  elements.profileStoredPassword.value = "";
  elements.profileStoredPassword.placeholder = t("profiles.storePasswordPlaceholder");
  elements.deleteProfileButton.hidden = true;
  elements.profileMessage.textContent = "";
  updatePrivateKeyField();
}

function fillProfileForm(profile) {
  if (!profile) { resetProfileForm(); return; }
  elements.profileId.value = profile.id;
  elements.profileLabel.value = profile.label;
  elements.profileHost.value = profile.host;
  elements.profilePort.value = String(profile.port);
  elements.profileUsername.value = profile.username;
  elements.profileAuthMethod.value = profile.authMethod;
  elements.profilePrivateKeyPath.value = profile.privateKeyPath || "";
  elements.profileStorePassword.checked = Boolean(profile.hasStoredPassword);
  elements.profileStoredPassword.value = "";
  elements.profileStoredPassword.placeholder = t(profile.hasStoredPassword ? "profiles.passwordStoredPlaceholder" : "profiles.storePasswordPlaceholder");
  elements.deleteProfileButton.hidden = false;
  elements.profileMessage.textContent = "";
  updatePrivateKeyField();
}

function updatePrivateKeyField() {
  const privateKey = elements.profileAuthMethod.value === "privateKey";
  elements.privateKeyField.hidden = !privateKey;
  elements.passwordStorageField.hidden = privateKey;
  elements.profileStoredPassword.disabled = privateKey || !elements.profileStorePassword.checked;
}

function updateTerminalProfile() {
  const profile = state.profiles.find((item) => item.id === elements.terminalProfileSelect.value);
  if (!profile) {
    elements.terminalHost.textContent = t("terminal.noProfile");
    elements.credentialLabelText.textContent = t("terminal.password");
    elements.terminalCredential.placeholder = t("terminal.sshPassword");
    return;
  }
  elements.terminalHost.textContent = `${profile.username}@${profile.host}:${profile.port} · ${profile.authMethod === "privateKey" ? profile.privateKeyPath : t("terminal.passwordAuth")}`;
  elements.credentialLabelText.textContent = t(profile.authMethod === "privateKey" ? "terminal.passphrase" : "terminal.password");
  elements.terminalCredential.placeholder = t(profile.authMethod === "privateKey" ? "terminal.keyPassphrase" : profile.hasStoredPassword ? "terminal.savedPasswordHint" : "terminal.sshPassword");
}

function initTerminal() {
  if (!window.Terminal || !window.FitAddon?.FitAddon) {
    elements.terminalHost.textContent = t("terminal.libraryMissing");
    return;
  }
  terminal = new window.Terminal({
    cursorBlink: true,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
    fontSize: 13,
    scrollback: 8000,
    theme: { background: "#050b12", foreground: "#d8e7f5", cursor: "#43d6a0", selectionBackground: "#264c6d" }
  });
  fitAddon = new window.FitAddon.FitAddon();
  terminal.loadAddon(fitAddon);
  terminal.open(elements.terminalElement);
  terminal.writeln("\x1b[36mCH-J Server Manager Core\x1b[0m");
  terminal.writeln(`${t("terminal.welcome")}\r\n`);
  terminal.onData((data) => { if (state.terminalConnected) api.sendTerminalInput(TERMINAL_SESSION_ID, data); });
  new ResizeObserver(() => fitTerminal()).observe(elements.terminalElement);
  fitTerminal();
}

function fitTerminal() {
  if (!terminal || !fitAddon || elements.terminalElement.offsetParent === null) return;
  try {
    fitAddon.fit();
    if (state.terminalConnected) void api.resizeTerminal(TERMINAL_SESSION_ID, terminal.cols, terminal.rows);
  } catch {}
}

function setTerminalState(kind, text) {
  state.terminalStateKind = kind;
  elements.terminalState.className = `connection-badge ${kind}`;
  elements.terminalState.textContent = text;
  if (kind !== "connected") state.terminalLatency = null;
  renderTerminalLatency();
  elements.connectButton.disabled = kind === "connecting" || kind === "connected";
  elements.disconnectButton.disabled = kind !== "connected" && kind !== "connecting";
  elements.terminalProfileSelect.disabled = kind === "connecting" || kind === "connected";
}

function renderTerminalLatency() {
  const element = $("#terminalLatency");
  element.hidden = state.terminalStateKind !== "connected";
  const format = (value) => typeof value === "number" && Number.isFinite(value) && value > 0
    ? (value < 0.1 ? "<0.1 ms" : `${value.toFixed(1)} ms`) : `— (${t("terminal.latencyUnavailable")})`;
  element.textContent = `${t("terminal.ping")}: ${format(state.terminalLatency?.pingMs)} · ${t("terminal.sshRtt")}: ${format(state.terminalLatency?.sshRttMs)}`;
  element.title = t("terminal.latencyMeaning");
}

async function connectTerminal(retry = false) {
  const profile = state.profiles.find((item) => item.id === elements.terminalProfileSelect.value);
  if (!profile) { showView("profiles"); elements.profileMessage.textContent = t("terminal.noProfile"); return; }
  fitTerminal();
  if (!retry) {
    terminal?.clear();
    terminal?.writeln(`\x1b[33m${t("terminal.connectingTo", { target: `${profile.username}@${profile.host}:${profile.port}` })}\x1b[0m`);
  }
  setTerminalState("connecting", t("terminal.connecting"));
  const credential = elements.terminalCredential.value;
  const result = await api.connectSsh({
    sessionId: TERMINAL_SESSION_ID,
    profileId: profile.id,
    password: profile.authMethod === "password" ? credential : undefined,
    passphrase: profile.authMethod === "privateKey" ? credential : undefined,
    cols: terminal?.cols || 100,
    rows: terminal?.rows || 30
  });
  if (result.ok) {
    state.terminalConnected = true;
    elements.terminalCredential.value = "";
    setTerminalState("connected", t("terminal.connected"));
    terminal?.focus();
    return;
  }
  const issue = result.error || { code: "SSH_CONNECTION_FAILED", message: t("ssh.failed") };
  if (issue.code === "HOST_KEY_UNKNOWN") {
    const accepted = window.confirm(t("ssh.unknownHost", issue));
    if (accepted) {
      const trusted = await api.trustSshHostKey({ sessionId: TERMINAL_SESSION_ID, profileId: profile.id, fingerprint: issue.fingerprint });
      if (trusted.ok) { await connectTerminal(true); return; }
      terminal?.writeln(`\r\n\x1b[31m${trusted.error?.message || t("ssh.trustFailed")}\x1b[0m`);
    }
  } else if (issue.code === "HOST_KEY_MISMATCH") {
    terminal?.writeln(`\r\n\x1b[31m${t("ssh.keyChanged")}\x1b[0m`);
    terminal?.writeln(`${t("ssh.knownKey")}: ${issue.knownFingerprint}\r\n${t("ssh.newKey")}:  ${issue.fingerprint}`);
    const accepted = window.confirm(t("ssh.changedHostConfirm", issue));
    if (accepted) {
      const trusted = await api.trustSshHostKey({
        sessionId: TERMINAL_SESSION_ID,
        profileId: profile.id,
        fingerprint: issue.fingerprint,
        knownFingerprint: issue.knownFingerprint,
        replaceKnown: true
      });
      if (trusted.ok) { await connectTerminal(true); return; }
      terminal?.writeln(`\r\n\x1b[31m${trusted.error?.message || t("ssh.trustFailed")}\x1b[0m`);
    }
  } else {
    terminal?.writeln(`\r\n\x1b[31m${issue.message}\x1b[0m`);
  }
  state.terminalConnected = false;
  setTerminalState("error", t("terminal.connectionError"));
}

async function checkUpdates() {
  setBusy(elements.checkUpdateButton, true, t("updates.checking"));
  elements.updateHeadline.textContent = t("updates.checkingServer");
  elements.updateMessage.textContent = t("updates.tryingEndpoints");
  try { renderUpdate(await api.checkForUpdates()); }
  catch (error) { elements.updateHeadline.textContent = t("updates.checkFailed"); elements.updateMessage.textContent = errorText(error); }
  finally { setBusy(elements.checkUpdateButton, false, t("updates.check")); }
}

async function initialize() {
  if (!api || !i18n) throw new Error("Core preload or i18n API is unavailable.");
  [state.info, state.config, state.pluginState, state.update, state.vault] = await Promise.all([
    api.getInfo(), api.getConfig(), api.getPluginState(), api.getUpdateState(), api.getVaultStatus()
  ]);
  state.plugins = state.pluginState.installed;
  state.pluginWindows = state.pluginState.windows || [];
  i18n.setLanguage(state.config.ui.language);
  document.documentElement.lang = i18n.getLanguage();
  i18n.apply(document);
  elements.runtimeText.textContent = `${state.info.platform} / ${state.info.arch}`;
  elements.sidebarVersion.textContent = `v${state.info.version}`;
  elements.coreApiValue.textContent = state.info.coreApi;
  elements.dataSchemaValue.textContent = String(state.info.dataSchema);
  elements.currentVersion.textContent = `v${state.info.version}`;
  elements.languageSelect.value = state.config.ui.language;
  elements.vaultLanguageSelect.value = state.config.ui.language;
  elements.vaultLanguageSelect.disabled = false;
  elements.channelSelect.value = state.config.updates.channel;
  elements.updateViewChannelSelect.value = state.config.updates.channel;
  elements.pluginChannelSelect.value = state.config.plugins.channel;
  elements.pluginViewChannelSelect.value = state.config.plugins.channel;
  elements.autoCheckInput.checked = state.config.updates.autoCheck;
  elements.baseUrlsText.textContent = state.config.updates.baseUrls.join("\n");
  elements.updateChannel.textContent = t("updates.channel", { channel: state.config.updates.channel });
  diagnosticsView = window.CHJ_DIAGNOSTICS.mount($("#diagnosticsView"), {
    api: api.diagnostics, language: () => i18n.getLanguage(), getTheme: () => state.config.ui.theme,
    setTheme: async (theme) => { state.config = await api.updateConfig({ ui: { theme } }); }
  });
  renderPlugins(); renderUpdate(state.update); initTerminal(); configureVault(state.vault);
  if (state.vault.unlocked) await loadProfiles();
}

document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => showView(button.dataset.view)));
$("#hashToolButton").addEventListener("click", async () => {
  try { await api.openPlugin(HASH_TOOL_ID); }
  catch (error) { window.alert(errorText(error)); }
});
elements.vaultForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = elements.vaultPassword.value;
  const passwordLength = Array.from(password).length;
  if (passwordLength < 4 || passwordLength > 64) { elements.vaultMessage.textContent = t("vault.passwordLength"); return; }
  if (state.vault.needsSetup && password !== elements.vaultPasswordConfirm.value) { elements.vaultMessage.textContent = t("vault.passwordMismatch"); return; }
  setBusy(elements.vaultSubmit, true, t(state.vault.needsSetup ? "vault.creating" : "vault.unlocking"));
  try {
    const status = state.vault.needsSetup ? await api.createVault(password) : await api.unlockVault(password);
    configureVault(status);
    await loadProfiles();
  } catch (error) { elements.vaultMessage.className = "form-message"; elements.vaultMessage.textContent = errorText(error); }
  finally { if (!state.vault.unlocked) setBusy(elements.vaultSubmit, false, t(state.vault.needsSetup ? "vault.create" : "vault.unlock")); }
});
elements.lockVaultButton.addEventListener("click", async () => {
  configureVault(await api.lockVault());
  clearProtectedUi();
  terminal?.writeln(`${t("terminal.vaultLocked")}\r\n`);
});
elements.showVaultResetButton.addEventListener("click", () => {
  elements.vaultResetPanel.hidden = false;
  elements.showVaultResetButton.hidden = true;
  elements.vaultResetConfirmation.focus();
});
elements.cancelVaultResetButton.addEventListener("click", () => {
  elements.vaultResetPanel.hidden = true;
  elements.showVaultResetButton.hidden = false;
  elements.vaultResetConfirmation.value = "";
});
elements.confirmVaultResetButton.addEventListener("click", async () => {
  if (elements.vaultResetConfirmation.value !== "SMAZAT") {
    elements.vaultMessage.textContent = t("vault.typeDelete");
    return;
  }
  if (!window.confirm(t("vault.finalResetConfirm"))) return;
  setBusy(elements.confirmVaultResetButton, true, t("vault.deleting"));
  try {
    const status = await api.resetVault("SMAZAT");
    clearProtectedUi();
    configureVault(status);
    elements.vaultMessage.className = "form-message success";
    elements.vaultMessage.textContent = t("vault.resetDone");
  } catch (error) {
    elements.vaultMessage.className = "form-message";
    elements.vaultMessage.textContent = errorText(error);
  } finally {
    setBusy(elements.confirmVaultResetButton, false, t("vault.resetAction"));
  }
});
elements.newProfileButton.addEventListener("click", () => { state.selectedProfileId = ""; renderProfiles(); resetProfileForm(); elements.profileLabel.focus(); });
elements.profileAuthMethod.addEventListener("change", updatePrivateKeyField);
elements.profileStorePassword.addEventListener("change", updatePrivateKeyField);
elements.selectPrivateKeyButton.addEventListener("click", async () => {
  const result = await api.selectPrivateKey();
  if (!result.canceled) elements.profilePrivateKeyPath.value = result.path;
});
elements.profileForm.addEventListener("submit", async (event) => {
  event.preventDefault(); elements.profileMessage.className = "form-message"; elements.profileMessage.textContent = "";
  try {
    const saved = await api.saveProfile({
      id: elements.profileId.value || undefined, label: elements.profileLabel.value, host: elements.profileHost.value,
      port: Number(elements.profilePort.value), username: elements.profileUsername.value,
      authMethod: elements.profileAuthMethod.value, privateKeyPath: elements.profilePrivateKeyPath.value,
      storePassword: elements.profileAuthMethod.value === "password" && elements.profileStorePassword.checked,
      password: elements.profileStoredPassword.value
    });
    await loadProfiles(saved.id); elements.profileMessage.className = "form-message success"; elements.profileMessage.textContent = t("profiles.saved");
  } catch (error) { elements.profileMessage.textContent = errorText(error); }
});
elements.deleteProfileButton.addEventListener("click", async () => {
  const id = elements.profileId.value;
  if (!id || !window.confirm(t("profiles.deleteConfirm"))) return;
  await api.deleteProfile(id); state.selectedProfileId = ""; await loadProfiles("");
});
elements.terminalProfileSelect.addEventListener("change", () => { elements.terminalCredential.value = ""; updateTerminalProfile(); });
elements.connectButton.addEventListener("click", () => connectTerminal().catch((error) => { setTerminalState("error", t("terminal.error")); terminal?.writeln(`\r\n\x1b[31m${errorText(error)}\x1b[0m`); }));
elements.disconnectButton.addEventListener("click", async () => { await api.disconnectSsh(TERMINAL_SESSION_ID); });
elements.checkUpdateButton.addEventListener("click", checkUpdates);
elements.downloadUpdateButton.addEventListener("click", async () => {
  setBusy(elements.downloadUpdateButton, true, t("updates.downloadingAndVerifying"));
  elements.updateHeadline.textContent = t("updates.verifyingSignature");
  try { renderUpdate(await api.downloadUpdate()); }
  catch (_error) {
    elements.updateHeadline.textContent = t("updates.downloadRejected");
    elements.updateMessage.textContent = t("updates.signatureFailure");
    elements.installUpdateButton.hidden = true;
    elements.revealUpdateButton.hidden = true;
  }
  finally { setBusy(elements.downloadUpdateButton, false, t("updates.download")); }
});
elements.installUpdateButton.addEventListener("click", async () => {
  const release = state.update?.release;
  if (!release || !window.confirm(t("updates.installConfirm", { version: release.version, date: formatReleaseDate(release.publishedAt) }))) return;
  setBusy(elements.installUpdateButton, true, t("updates.verifyingSignature"));
  try { await api.installUpdate(); }
  catch (_error) {
    try { renderUpdate(await api.getUpdateState()); } catch {}
    elements.updateHeadline.textContent = t("updates.installFailed");
    elements.updateMessage.textContent = t("updates.installFailure");
    elements.installUpdateButton.hidden = true;
  } finally { setBusy(elements.installUpdateButton, false, t("updates.install")); }
});
elements.revealUpdateButton.addEventListener("click", () => api.revealUpdate());
elements.updateViewChannelSelect.addEventListener("change", async () => {
  state.config = await api.updateConfig({ updates: { channel: elements.updateViewChannelSelect.value } });
  elements.channelSelect.value = state.config.updates.channel;
  elements.updateChannel.textContent = t("updates.channel", { channel: state.config.updates.channel });
  await checkUpdates();
});
elements.pluginViewChannelSelect.addEventListener("change", async () => {
  state.config = await api.updateConfig({ plugins: { channel: elements.pluginViewChannelSelect.value } });
  elements.pluginChannelSelect.value = state.config.plugins.channel;
  elements.checkPluginCatalogButton.click();
});
elements.checkPluginCatalogButton.addEventListener("click", async () => {
  setBusy(elements.checkPluginCatalogButton, true, t("plugins.checking"));
  try { state.pluginState = await api.checkPluginCatalog(); state.plugins = state.pluginState.installed; renderPlugins(); }
  catch (error) { window.alert(errorText(error)); }
  finally { setBusy(elements.checkPluginCatalogButton, false, t("plugins.checkCatalog")); }
});
elements.settingsForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  state.config = await api.updateConfig({
    ui: { language: elements.languageSelect.value },
    updates: { channel: elements.channelSelect.value, autoCheck: elements.autoCheckInput.checked },
    plugins: { channel: elements.pluginChannelSelect.value }
  });
  elements.updateViewChannelSelect.value = state.config.updates.channel;
  elements.pluginViewChannelSelect.value = state.config.plugins.channel;
  applyLanguage(state.config.ui.language);
  elements.updateChannel.textContent = t("updates.channel", { channel: state.config.updates.channel });
  elements.settingsStatus.textContent = t("settings.saved"); setTimeout(() => { elements.settingsStatus.textContent = ""; }, 1800);
});
elements.languageSelect.addEventListener("change", () => applyLanguage(elements.languageSelect.value));
document.querySelectorAll("[data-legal-document]").forEach((button) => {
  button.addEventListener("click", async () => {
    try { await api.openLegalDocument(button.dataset.legalDocument); }
    catch (error) { window.alert(errorText(error)); }
  });
});
elements.vaultLanguageSelect.addEventListener("change", async () => {
  const language = applyLanguage(elements.vaultLanguageSelect.value);
  state.config = await api.updateConfig({ ui: { language } });
});

api?.onUpdateState((payload) => renderUpdate(payload));
api?.onPluginWindowState((windows) => renderPluginTaskbar(windows));
api?.onSshData((payload) => { if (payload.sessionId === TERMINAL_SESSION_ID) terminal?.write(payload.data); });
api?.onSshState((payload) => {
  if (payload.sessionId !== TERMINAL_SESSION_ID) return;
  state.terminalConnected = payload.state === "connected";
  state.terminalLatency = payload.latency;
  if (payload.state === "connecting") setTerminalState("connecting", t("terminal.connecting"));
  else if (payload.state === "connected") setTerminalState("connected", t("terminal.connected"));
  else setTerminalState("disconnected", t("terminal.disconnected"));
});
api?.onSshError((payload) => { if (payload.sessionId === TERMINAL_SESSION_ID) terminal?.writeln(`\r\n\x1b[31m${payload.message}\x1b[0m`); });

initialize().catch((error) => {
  elements.runtimeText.textContent = t("errors.initialization");
  elements.updateMessage.textContent = errorText(error);
});
