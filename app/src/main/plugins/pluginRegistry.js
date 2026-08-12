"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { compareVersions, parseVersion } = require("../../shared/version");

const PLUGIN_ID_PATTERN = /^[a-z0-9][a-z0-9.-]{2,63}$/;
const PLUGIN_API_VERSION = "1.1.0";
const ALLOWED_PERMISSIONS = new Set([
  "session.read",
  "system.metrics.read",
  "keys.generate",
  "files.read",
  "files.write",
  "files.transfer",
  "users.read",
  "users.manage",
  "nginx.read",
  "nginx.manage",
  "certbot.manage",
  "mail.read",
  "mail.manage",
  "logs.read",
  "remote.exec"
]);

function validateManifest(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Plugin manifest must be an object.");
  const id = String(input.id || "").trim();
  if (!PLUGIN_ID_PATTERN.test(id)) throw new Error("Invalid plugin ID.");
  const version = String(input.version || "").trim();
  parseVersion(version);
  const entry = String(input.entry || "").replace(/\\/g, "/");
  if (!entry || entry.startsWith("/") || entry.split("/").includes("..")) throw new Error("Invalid plugin entry path.");
  const permissions = Array.isArray(input.permissions) ? [...new Set(input.permissions.map(String))] : [];
  for (const permission of permissions) {
    if (!ALLOWED_PERMISSIONS.has(permission)) throw new Error(`Unsupported plugin permission: ${permission}`);
  }
  const schemaVersion = Number(input.schemaVersion || 1);
  if (schemaVersion !== 1) throw new Error(`Unsupported plugin manifest schema: ${schemaVersion}`);
  const minAppVersion = String(input.minAppVersion || "0.0.1");
  parseVersion(minAppVersion);
  const pluginApi = String(input.pluginApi || "^1.0.0");
  if (!/^\^1\.\d+\.\d+$/.test(pluginApi)) throw new Error(`Unsupported plugin API: ${pluginApi}`);
  return {
    schemaVersion,
    id,
    name: String(input.name || id).trim().slice(0, 100),
    description: String(input.description || "").trim().slice(0, 500),
    version,
    publisher: String(input.publisher || "Unknown").trim().slice(0, 100),
    entry,
    pluginApi,
    minAppVersion,
    permissions
  };
}

function supportsPluginApi(range, supportedVersion = PLUGIN_API_VERSION) {
  const required = String(range || "").match(/^\^1\.(\d+)\.(\d+)$/);
  const supported = String(supportedVersion || "").match(/^1\.(\d+)\.(\d+)$/);
  return Boolean(required && supported && (Number(required[1]) < Number(supported[1]) || (Number(required[1]) === Number(supported[1]) && Number(required[2]) <= Number(supported[2]))));
}

class PluginRegistry {
  constructor(rootDir, logger) {
    this.rootDir = path.join(rootDir, "plugins");
    this.logger = logger;
  }

  listInstalled() {
    fs.mkdirSync(this.rootDir, { recursive: true });
    const plugins = [];
    for (const idEntry of fs.readdirSync(this.rootDir, { withFileTypes: true })) {
      if (!idEntry.isDirectory() || !PLUGIN_ID_PATTERN.test(idEntry.name)) continue;
      const idRoot = path.join(this.rootDir, idEntry.name);
      const candidates = [];
      for (const versionEntry of fs.readdirSync(idRoot, { withFileTypes: true })) {
        if (!versionEntry.isDirectory() || versionEntry.name.startsWith(".")) continue;
        const manifestPath = path.join(idRoot, versionEntry.name, "manifest.json");
        try {
          const manifest = validateManifest(JSON.parse(fs.readFileSync(manifestPath, "utf8")));
          if (manifest.id !== idEntry.name || manifest.version !== versionEntry.name) {
            throw new Error("Plugin directory does not match its manifest.");
          }
          const entryPath = path.join(idRoot, versionEntry.name, manifest.entry);
          if (!fs.statSync(entryPath).isFile()) throw new Error("Plugin entry file is missing.");
          let installation = {};
          try { installation = JSON.parse(fs.readFileSync(path.join(idRoot, versionEntry.name, ".installation.json"), "utf8")); } catch {}
          candidates.push({
            ...manifest,
            installedReleaseId: typeof installation.releaseId === "string" ? installation.releaseId : null,
            installedSha512: /^[a-f0-9]{128}$/i.test(String(installation.sha512 || "")) ? String(installation.sha512).toLowerCase() : null,
            installedAt: typeof installation.installedAt === "string" ? installation.installedAt : null,
            installedPublishedAt: typeof installation.publishedAt === "string" ? installation.publishedAt : null
          });
        } catch (error) {
          this.logger?.warn("Ignoring invalid installed plugin.", {
            pluginId: idEntry.name,
            version: versionEntry.name,
            message: error?.message || String(error)
          });
        }
      }
      candidates.sort((left, right) => compareVersions(right.version, left.version));
      if (candidates[0]) plugins.push(candidates[0]);
    }
    return plugins.sort((left, right) => left.name.localeCompare(right.name));
  }

  getInstalled(pluginId) {
    const id = String(pluginId || "");
    if (!PLUGIN_ID_PATTERN.test(id)) throw new Error("Invalid plugin ID.");
    return this.listInstalled().find((plugin) => plugin.id === id) || null;
  }

  resolveEntry(pluginId) {
    const manifest = this.getInstalled(pluginId);
    if (!manifest) throw new Error("Plugin is not installed.");
    const root = path.join(this.rootDir, manifest.id, manifest.version);
    return { manifest, root, entryPath: path.join(root, ...manifest.entry.split("/")) };
  }

  removeInstalled(pluginId) {
    const id = String(pluginId || "");
    if (!PLUGIN_ID_PATTERN.test(id)) throw new Error("Invalid plugin ID.");
    const directory = path.join(this.rootDir, id);
    if (!fs.existsSync(directory)) return { removed: false, pluginId: id };
    fs.rmSync(directory, { recursive: true, force: true });
    this.logger?.info("Plugin removed.", { pluginId: id });
    return { removed: true, pluginId: id };
  }
}

module.exports = {
  ALLOWED_PERMISSIONS,
  PLUGIN_API_VERSION,
  PLUGIN_ID_PATTERN,
  PluginRegistry,
  supportsPluginApi,
  validateManifest
};
