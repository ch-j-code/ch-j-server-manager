"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { atomicWriteJson } = require("../storage/atomicFile");

const SUPPORTED_LANGUAGES = Object.freeze(["cs", "de", "en"]);
const CATALOG_CHANNELS = Object.freeze(["alpha", "beta", "stable", "all"]);

const DEFAULT_CONFIG = Object.freeze({
  schemaVersion: 1,
  ui: {
    language: "cs",
    theme: "system"
  },
  updates: {
    channel: "alpha",
    autoCheck: true,
    lastLaunchedRelease: null,
    baseUrls: [
      "https://www.sm.ch-j.de/",
      "https://sm.ch-j.de/"
    ]
  },
  plugins: {
    channel: "alpha"
  },
  security: { autoLockMinutes: 0, lockOnBlur: false, requireSystemAuthentication: false }
});

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function normalizeReleaseMarker(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const id = String(value.id || "").trim();
  const version = String(value.version || "").trim();
  const publishedAt = String(value.publishedAt || "").trim();
  const sha512 = String(value.sha512 || "").trim().toLowerCase();
  if (!id || !version || Number.isNaN(Date.parse(publishedAt)) || !/^[a-f0-9]{128}$/.test(sha512)) return null;
  return { id, version, publishedAt, sha512 };
}

function normalizeConfig(input = {}) {
  const source = input && typeof input === "object" && !Array.isArray(input) ? input : {};
  const channel = CATALOG_CHANNELS.includes(source.updates?.channel)
    ? source.updates.channel
    : DEFAULT_CONFIG.updates.channel;
  const pluginChannel = CATALOG_CHANNELS.includes(source.plugins?.channel)
    ? source.plugins.channel
    : DEFAULT_CONFIG.plugins.channel;
  const theme = ["system", "dark", "light"].includes(source.ui?.theme)
    ? source.ui.theme
    : DEFAULT_CONFIG.ui.theme;
  const language = SUPPORTED_LANGUAGES.includes(String(source.ui?.language || ""))
    ? String(source.ui.language)
    : DEFAULT_CONFIG.ui.language;

  return {
    schemaVersion: 1,
    ui: { language, theme },
    updates: {
      channel,
      autoCheck: source.updates?.autoCheck !== false,
      lastLaunchedRelease: normalizeReleaseMarker(source.updates?.lastLaunchedRelease),
      baseUrls: clone(DEFAULT_CONFIG.updates.baseUrls)
    },
    plugins: { channel: pluginChannel },
    security: {
      autoLockMinutes: [0, 1, 5, 10, 15, 30, 60].includes(source.security?.autoLockMinutes) ? source.security.autoLockMinutes : 0,
      lockOnBlur: source.security?.lockOnBlur === true,
      requireSystemAuthentication: source.security?.requireSystemAuthentication === true
    }
  };
}

class ConfigStore {
  constructor(rootDir) {
    this.rootDir = rootDir;
    this.filePath = path.join(rootDir, "config", "config.json");
    this.value = clone(DEFAULT_CONFIG);
  }

  load() {
    try {
      const raw = fs.readFileSync(this.filePath, "utf8");
      this.value = normalizeConfig(JSON.parse(raw));
    } catch (error) {
      if (error?.code !== "ENOENT") {
        const backup = `${this.filePath}.invalid-${Date.now()}`;
        try { fs.renameSync(this.filePath, backup); } catch {}
      }
      this.value = clone(DEFAULT_CONFIG);
      this.save();
    }
    return this.get();
  }

  get() {
    return clone(this.value);
  }

  update(patch = {}) {
    const updatePatch = patch.updates && typeof patch.updates === "object" ? patch.updates : {};
    const next = {
      ...this.value,
      ui: { ...this.value.ui, ...(patch.ui || {}) },
      updates: {
        ...this.value.updates,
        channel: updatePatch.channel ?? this.value.updates.channel,
        autoCheck: updatePatch.autoCheck ?? this.value.updates.autoCheck
      },
      plugins: { ...this.value.plugins, ...(patch.plugins || {}) },
      security: { ...this.value.security, ...(patch.security || {}) }
    };
    this.value = normalizeConfig(next);
    this.save();
    return this.get();
  }

  recordLaunchedRelease(release) {
    const marker = normalizeReleaseMarker(release);
    if (!marker) throw new Error("Invalid launched update release metadata.");
    this.value = normalizeConfig({
      ...this.value,
      updates: { ...this.value.updates, lastLaunchedRelease: marker }
    });
    this.save();
    return clone(marker);
  }

  save() {
    atomicWriteJson(this.filePath, this.value);
  }
}

module.exports = {
  ConfigStore,
  CATALOG_CHANNELS,
  DEFAULT_CONFIG,
  SUPPORTED_LANGUAGES,
  normalizeReleaseMarker,
  normalizeConfig
};
