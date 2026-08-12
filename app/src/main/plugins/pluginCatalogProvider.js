"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { Readable, Transform } = require("node:stream");
const { pipeline } = require("node:stream/promises");
const { assertAllowedUrl, normalizeBaseUrl } = require("../security/urlPolicy");
const { SHA512_PATTERN, serverChannel } = require("../../shared/updateContract");
const { compareVersions, parseVersion } = require("../../shared/version");
const { ALLOWED_PERMISSIONS, PLUGIN_ID_PATTERN } = require("./pluginRegistry");
const { cleanDownloadCache, removeCachedFile } = require("../storage/downloadCache");

const MAX_CATALOG_BYTES = 512 * 1024;
const MAX_PLUGIN_BYTES = 512 * 1024 * 1024;

function requiredString(value, field) {
  const normalized = String(value || "").trim();
  if (!normalized) throw new Error(`Missing ${field}.`);
  return normalized;
}

function validatePluginCatalog(payload, expected) {
  if (!payload || typeof payload !== "object" || !Array.isArray(payload.plugins)) {
    throw new Error("Plugin catalog must contain a plugins array.");
  }
  const ids = new Set();
  return payload.plugins.map((source) => {
    const id = requiredString(source.plugin_id, "plugin_id");
    if (!PLUGIN_ID_PATTERN.test(id)) throw new Error(`Invalid plugin ID: ${id}`);
    if (ids.has(id)) throw new Error(`Duplicate plugin ID: ${id}`);
    ids.add(id);
    const version = requiredString(source.version, "version");
    parseVersion(version);
    const minAppVersion = requiredString(source.min_app_version || "0.0.1", "min_app_version");
    parseVersion(minAppVersion);
    const pluginApi = requiredString(source.plugin_api || "^1.0.0", "plugin_api");
    if (!/^\^1\.\d+\.\d+$/.test(pluginApi)) throw new Error(`Unsupported plugin API: ${pluginApi}`);
    const permissions = Array.isArray(source.permissions) ? [...new Set(source.permissions.map(String))] : [];
    for (const permission of permissions) {
      if (!ALLOWED_PERMISSIONS.has(permission)) throw new Error(`Unsupported plugin permission: ${permission}`);
    }
    const sha512 = requiredString(source.sha512, "sha512").toLowerCase();
    if (!SHA512_PATTERN.test(sha512)) throw new Error(`Invalid SHA-512 for ${id}`);
    const size = Number(source.size);
    if (!Number.isSafeInteger(size) || size <= 0 || size > MAX_PLUGIN_BYTES) throw new Error(`Invalid package size for ${id}`);
    const channel = requiredString(source.channel || "stable", "channel").toLowerCase();
    if (channel !== serverChannel(expected.channel)) throw new Error(`Unexpected plugin channel: ${channel}`);
    const publishedAt = requiredString(source.published_at, "published_at");
    if (Number.isNaN(Date.parse(publishedAt))) throw new Error(`Invalid publication date for ${id}`);
    return {
      releaseId: requiredString(source.id, "id"),
      id,
      name: requiredString(source.name || id, "name"),
      version,
      minAppVersion,
      pluginApi,
      permissions,
      channel,
      notes: String(source.notes || ""),
      filename: requiredString(source.filename, "filename"),
      size,
      sha512,
      downloadUrl: requiredString(source.download_url || source.download_path, "download_url"),
      publishedAt
    };
  });
}

function timeoutSignal(timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("Request timeout.")), timeoutMs);
  timer.unref?.();
  return { signal: controller.signal, clear: () => clearTimeout(timer) };
}

async function sha512File(filePath) {
  const hash = crypto.createHash("sha512");
  for await (const chunk of fs.createReadStream(filePath)) hash.update(chunk);
  return hash.digest("hex");
}

function integrityError(message) {
  const error = new Error(message);
  error.code = "PLUGIN_ARTIFACT_INVALID";
  return error;
}

class PluginCatalogProvider {
  constructor(options) {
    this.baseUrls = (options.baseUrls || []).map((value) => normalizeBaseUrl(value).toString());
    if (!this.baseUrls.length) throw new Error("At least one plugin catalog URL is required.");
    this.fetch = options.fetchImpl || globalThis.fetch;
    this.downloadRoot = options.downloadRoot;
    this.logger = options.logger;
    this.requestTimeoutMs = Number(options.requestTimeoutMs || 5000);
    this.downloadTimeoutMs = Number(options.downloadTimeoutMs || 10 * 60 * 1000);
  }

  async list(options) {
    const errors = [];
    const requestedChannel = String(options.channel || "alpha");
    const channels = requestedChannel === "all" ? ["alpha", "beta", "stable"] : [serverChannel(requestedChannel)];
    for (const baseUrl of this.baseUrls) {
      try {
        const pluginsByRelease = new Map();
        for (const selectedChannel of channels) {
          const url = new URL("api/plugins.php", baseUrl);
          url.searchParams.set("app_version", String(options.appVersion || ""));
          url.searchParams.set("plugin_api", String(options.pluginApiVersion || "1.0.0"));
          url.searchParams.set("channel", selectedChannel);
          const response = await this._fetchText(url, "application/json", MAX_CATALOG_BYTES);
          if (response.status !== 200) throw new Error(`Plugin server returned HTTP ${response.status}.`);
          let payload;
          try { payload = JSON.parse(response.text); } catch { throw new Error("Plugin server returned invalid JSON."); }
          const plugins = validatePluginCatalog(payload, { ...options, channel: selectedChannel });
          for (const plugin of plugins) {
            plugin.downloadUrl = this._resolveFileUrl(plugin.downloadUrl, baseUrl).toString();
            pluginsByRelease.set(plugin.releaseId, plugin);
          }
        }
        const plugins = [...pluginsByRelease.values()].sort((a, b) => a.id.localeCompare(b.id) || compareVersions(b.version, a.version) || Date.parse(b.publishedAt) - Date.parse(a.publishedAt));
        return { plugins, sourceBaseUrl: baseUrl };
      } catch (error) {
        errors.push({ baseUrl, message: error?.message || String(error) });
        this.logger?.warn("Plugin catalog endpoint failed.", errors.at(-1));
      }
    }
    const error = new Error("No configured plugin catalog endpoint is reachable.");
    error.code = "PLUGIN_CATALOG_UNREACHABLE";
    error.details = errors;
    throw error;
  }

  async downloadAndVerify(plugin) {
    if (!plugin || !Number.isSafeInteger(plugin.size) || plugin.size <= 0 || plugin.size > MAX_PLUGIN_BYTES) {
      throw new Error("Plugin package size is outside the allowed range.");
    }
    const urls = this._fileUrlCandidates(plugin.downloadUrl);
    const targetDir = path.join(this.downloadRoot, plugin.id, `${plugin.version}-${plugin.releaseId}`.replace(/[^A-Za-z0-9._-]/g, "-"));
    const destination = path.join(targetDir, path.basename(plugin.filename).replace(/[^A-Za-z0-9._-]/g, "-") || "plugin.chjplugin");
    fs.mkdirSync(targetDir, { recursive: true });
    if (fs.existsSync(destination)) {
      const stat = fs.statSync(destination);
      if (stat.isFile() && stat.size === plugin.size && await sha512File(destination) === plugin.sha512) {
        return { path: destination, size: stat.size, sha512: plugin.sha512, reused: true };
      }
      fs.unlinkSync(destination);
    }
    const failures = [];
    for (const url of urls) {
      const tempPath = `${destination}.${crypto.randomBytes(6).toString("hex")}.part`;
      const timeout = timeoutSignal(this.downloadTimeoutMs);
      try {
        const response = await this.fetch(url, { method: "GET", redirect: "manual", signal: timeout.signal, headers: { Accept: "application/octet-stream" } });
        if (response.status !== 200 || !response.body) throw new Error(`Plugin download returned HTTP ${response.status}.`);
        const declared = Number(response.headers.get("content-length") || 0);
        if (declared > 0 && declared !== plugin.size) throw integrityError("Plugin Content-Length does not match the catalog.");
        const hash = crypto.createHash("sha512");
        let received = 0;
        const verifier = new Transform({
          transform(chunk, _encoding, callback) {
            received += chunk.length;
            if (received > plugin.size || received > MAX_PLUGIN_BYTES) return callback(integrityError("Plugin package exceeds its catalog size."));
            hash.update(chunk);
            callback(null, chunk);
          }
        });
        await pipeline(Readable.fromWeb(response.body), verifier, fs.createWriteStream(tempPath, { flags: "wx", mode: 0o600 }));
        if (received !== plugin.size) throw integrityError("Plugin package size does not match the catalog.");
        const actualHash = hash.digest("hex");
        if (actualHash !== plugin.sha512) throw integrityError("Plugin package SHA-512 does not match the catalog.");
        fs.renameSync(tempPath, destination);
        return { path: destination, size: received, sha512: actualHash, reused: false, sourceUrl: url.toString() };
      } catch (error) {
        try { fs.unlinkSync(tempPath); } catch {}
        if (error?.code === "PLUGIN_ARTIFACT_INVALID") throw error;
        failures.push({ url: url.toString(), message: error?.message || String(error) });
        this.logger?.warn("Plugin download endpoint failed; trying fallback.", failures.at(-1));
      } finally {
        timeout.clear();
      }
    }
    const error = new Error("Plugin download failed on all configured endpoints.");
    error.code = "PLUGIN_DOWNLOAD_UNREACHABLE";
    error.details = failures;
    throw error;
  }

  cleanupDownloads() {
    return cleanDownloadCache(this.downloadRoot);
  }

  removeDownloadedPackage(packagePath) {
    return removeCachedFile(this.downloadRoot, packagePath);
  }

  _resolveFileUrl(value, sourceBaseUrl) {
    const resolved = new URL(String(value || "").replace(/^\/+/, ""), sourceBaseUrl).toString();
    return assertAllowedUrl(resolved, this.baseUrls, { pathSegment: "files/" });
  }

  _fileUrlCandidates(value) {
    const original = new URL(this._resolveFileUrl(value, this.baseUrls[0]));
    const sourceBase = this.baseUrls.map((baseUrl) => new URL(baseUrl)).find((base) => (
      base.origin === original.origin && original.pathname.startsWith(base.pathname)
    ));
    if (!sourceBase) throw new Error("Plugin file URL is outside configured base paths.");
    const relative = `${original.pathname.slice(sourceBase.pathname.length)}${original.search}`;
    const candidates = [original];
    for (const baseUrl of this.baseUrls) {
      const candidate = new URL(relative, baseUrl);
      assertAllowedUrl(candidate.toString(), this.baseUrls, { pathSegment: "files/" });
      if (!candidates.some((item) => item.toString() === candidate.toString())) candidates.push(candidate);
    }
    return candidates;
  }

  async _fetchText(url, accept, maxBytes) {
    assertAllowedUrl(url.toString(), this.baseUrls, { pathSegment: "api/" });
    const timeout = timeoutSignal(this.requestTimeoutMs);
    try {
      const response = await this.fetch(url, { method: "GET", redirect: "manual", signal: timeout.signal, headers: { Accept: accept } });
      const declared = Number(response.headers.get("content-length") || 0);
      if (declared > maxBytes) throw new Error("Plugin catalog is too large.");
      const text = await response.text();
      if (Buffer.byteLength(text, "utf8") > maxBytes) throw new Error("Plugin catalog is too large.");
      return { status: response.status, text };
    } finally {
      timeout.clear();
    }
  }
}

module.exports = { MAX_CATALOG_BYTES, MAX_PLUGIN_BYTES, PluginCatalogProvider, validatePluginCatalog };
