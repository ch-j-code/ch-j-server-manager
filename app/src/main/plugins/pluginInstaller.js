"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const AdmZip = require("adm-zip");
const { compareVersions } = require("../../shared/version");
const { PLUGIN_API_VERSION, supportsPluginApi, validateManifest } = require("./pluginRegistry");

const MAX_ENTRIES = 500;
const MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024;
const ALLOWED_EXTENSIONS = new Set([".css", ".gif", ".html", ".jpeg", ".jpg", ".js", ".json", ".md", ".png", ".svg", ".txt", ".ttf", ".webp", ".woff", ".woff2"]);

function safeEntryName(value) {
  const name = String(value || "").replace(/\\/g, "/");
  if (!name || name.includes("\0") || name.startsWith("/") || /^[A-Za-z]:\//.test(name) || name.split("/").includes("..")) {
    throw new Error(`Unsafe plugin archive path: ${name || "<empty>"}`);
  }
  return name.replace(/^\.\//, "");
}

function isSymlink(entry) {
  const unixMode = (Number(entry.attr || 0) >>> 16) & 0xffff;
  return (unixMode & 0xf000) === 0xa000;
}

class PluginInstaller {
  constructor(options) {
    this.rootDir = path.join(options.storageRoot, "plugins");
    this.appVersion = options.appVersion;
    this.pluginApiVersion = options.pluginApiVersion || PLUGIN_API_VERSION;
    this.logger = options.logger;
  }

  install(packagePath, catalogEntry) {
    const zip = new AdmZip(packagePath);
    const entries = zip.getEntries();
    if (!entries.length || entries.length > MAX_ENTRIES) throw new Error("Plugin archive has an invalid number of entries.");
    let totalBytes = 0;
    const normalized = [];
    for (const entry of entries) {
      const name = safeEntryName(entry.entryName);
      if (isSymlink(entry)) throw new Error(`Plugin archive contains a symbolic link: ${name}`);
      const size = Number(entry.header?.size || 0);
      if (!Number.isSafeInteger(size) || size < 0) throw new Error(`Invalid plugin entry size: ${name}`);
      totalBytes += size;
      if (totalBytes > MAX_UNCOMPRESSED_BYTES) throw new Error("Plugin archive exceeds the uncompressed size limit.");
      if (!entry.isDirectory) {
        const extension = path.posix.extname(name).toLowerCase();
        if (!ALLOWED_EXTENSIONS.has(extension)) throw new Error(`Unsupported plugin file type: ${name}`);
      }
      normalized.push({ entry, name });
    }
    const manifestEntry = normalized.find((item) => item.name === "manifest.json" && !item.entry.isDirectory);
    if (!manifestEntry) throw new Error("Plugin archive has no root manifest.json.");
    if (Number(manifestEntry.entry.header?.size || 0) > 1024 * 1024) throw new Error("Plugin manifest is too large.");
    let manifest;
    try { manifest = validateManifest(JSON.parse(manifestEntry.entry.getData().toString("utf8"))); }
    catch (error) { throw new Error(`Invalid packaged plugin manifest: ${error?.message || String(error)}`); }
    this._assertCatalogMatch(manifest, catalogEntry);
    if (!supportsPluginApi(manifest.pluginApi, this.pluginApiVersion)) throw new Error(`Plugin requires unsupported Plugin API ${manifest.pluginApi}.`);
    if (compareVersions(this.appVersion, manifest.minAppVersion) < 0) throw new Error(`Plugin requires application ${manifest.minAppVersion} or newer.`);

    const idRoot = path.join(this.rootDir, manifest.id);
    const stagingRoot = path.join(this.rootDir, ".staging", `${manifest.id}-${crypto.randomBytes(8).toString("hex")}`);
    const contentRoot = path.join(stagingRoot, manifest.version);
    fs.mkdirSync(contentRoot, { recursive: true, mode: 0o700 });
    try {
      let extractedBytes = 0;
      for (const item of normalized) {
        const destination = path.join(contentRoot, ...item.name.split("/"));
        const relative = path.relative(contentRoot, destination);
        if (relative.startsWith("..") || path.isAbsolute(relative)) throw new Error(`Plugin path escaped staging: ${item.name}`);
        if (item.entry.isDirectory) fs.mkdirSync(destination, { recursive: true, mode: 0o700 });
        else {
          const data = item.entry.getData();
          extractedBytes += data.length;
          if (extractedBytes > MAX_UNCOMPRESSED_BYTES) throw new Error("Plugin archive exceeds the extracted size limit.");
          fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
          fs.writeFileSync(destination, data, { mode: 0o600, flag: "wx" });
        }
      }
      const entryPath = path.join(contentRoot, ...manifest.entry.split("/"));
      if (!fs.statSync(entryPath).isFile()) throw new Error("Packaged plugin entry file is missing.");
      fs.writeFileSync(path.join(contentRoot, ".installation.json"), JSON.stringify({
        schemaVersion: 1,
        releaseId: catalogEntry.releaseId,
        sha512: catalogEntry.sha512,
        installedAt: new Date().toISOString(),
        publishedAt: catalogEntry.publishedAt
      }, null, 2), { mode: 0o600, flag: "wx" });

      fs.mkdirSync(idRoot, { recursive: true, mode: 0o700 });
      const destination = path.join(idRoot, manifest.version);
      if (fs.existsSync(destination)) {
        const existing = this._installation(destination);
        if (existing?.sha512 === catalogEntry.sha512) {
          fs.rmSync(stagingRoot, { recursive: true, force: true });
          return { manifest, reused: true, path: destination };
        }
        const rollbackRoot = path.join(idRoot, ".rollback");
        fs.mkdirSync(rollbackRoot, { recursive: true, mode: 0o700 });
        fs.renameSync(destination, path.join(rollbackRoot, `${manifest.version}-${Date.now()}`));
      }
      fs.renameSync(contentRoot, destination);
      fs.rmSync(stagingRoot, { recursive: true, force: true });
      this.logger?.info("Plugin installed.", { pluginId: manifest.id, version: manifest.version, permissions: manifest.permissions });
      return { manifest, reused: false, path: destination };
    } catch (error) {
      fs.rmSync(stagingRoot, { recursive: true, force: true });
      throw error;
    }
  }

  _assertCatalogMatch(manifest, catalog) {
    if (manifest.id !== catalog.id || manifest.version !== catalog.version) throw new Error("Plugin manifest identity does not match the catalog.");
    if (manifest.pluginApi !== catalog.pluginApi || manifest.minAppVersion !== catalog.minAppVersion) throw new Error("Plugin compatibility metadata does not match the catalog.");
    const packaged = [...manifest.permissions].sort();
    const declared = [...catalog.permissions].sort();
    if (JSON.stringify(packaged) !== JSON.stringify(declared)) throw new Error("Plugin permissions do not match the catalog.");
  }

  _installation(directory) {
    try { return JSON.parse(fs.readFileSync(path.join(directory, ".installation.json"), "utf8")); }
    catch { return null; }
  }
}

module.exports = { ALLOWED_EXTENSIONS, MAX_ENTRIES, MAX_UNCOMPRESSED_BYTES, PluginInstaller, safeEntryName };
