"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { Readable, Transform } = require("node:stream");
const { pipeline } = require("node:stream/promises");
const { compareVersions } = require("../../shared/version");
const { assertAllowedUrl, normalizeBaseUrl } = require("../security/urlPolicy");
const { cleanDownloadCache } = require("../storage/downloadCache");
const {
  assertSupportedUpdateTarget,
  normalizeArchitecture,
  normalizePlatform,
  serverChannel,
  validateReleaseListResponse,
  validateReleaseResponse
} = require("../../shared/updateContract");

const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024;

function timeoutSignal(timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error("Request timeout.")), timeoutMs);
  timer.unref?.();
  return { signal: controller.signal, clear: () => clearTimeout(timer) };
}

function safeFilename(value) {
  const basename = path.basename(String(value || "update.bin"));
  const safe = basename.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[-.]+/, "");
  return safe || "update.bin";
}

async function sha512File(filePath) {
  const hash = crypto.createHash("sha512");
  const stream = fs.createReadStream(filePath);
  for await (const chunk of stream) hash.update(chunk);
  return hash.digest("hex");
}

class HashUrlProvider {
  constructor(options) {
    this.baseUrls = (options.baseUrls || []).map((value) => normalizeBaseUrl(value).toString());
    if (this.baseUrls.length === 0) throw new Error("At least one update base URL is required.");
    this.fetch = options.fetchImpl || globalThis.fetch;
    if (typeof this.fetch !== "function") throw new Error("Fetch API is unavailable.");
    this.downloadRoot = options.downloadRoot;
    this.logger = options.logger;
    this.requestTimeoutMs = Number(options.requestTimeoutMs || 5000);
    this.downloadTimeoutMs = Number(options.downloadTimeoutMs || 15 * 60 * 1000);
  }

  async checkForUpdates(options) {
    const currentVersion = String(options.currentVersion || "");
    const platform = normalizePlatform(options.platform);
    const arch = normalizeArchitecture(options.arch);
    const channel = String(options.channel || "alpha");
    const errors = [];

    assertSupportedUpdateTarget(platform, arch);

    for (const baseUrl of this.baseUrls) {
      try {
        const url = new URL("api/latest.php", baseUrl);
        url.searchParams.set("platform", platform);
        url.searchParams.set("arch", arch);
        url.searchParams.set("channel", serverChannel(channel));
        url.searchParams.set("current_version", currentVersion);
        const response = await this._fetchJson(url);
        if (response.status === 404) {
          return { updateAvailable: false, currentVersion, release: null, sourceBaseUrl: baseUrl };
        }
        if (response.status !== 200) throw new Error(`Update server returned HTTP ${response.status}.`);
        const result = validateReleaseResponse(response.payload, { currentVersion, platform, arch, channel });
        if (result.release) {
          result.release.downloadUrl = this._resolveArtifactUrl(result.release.downloadUrl, baseUrl).toString();
        }
        return { ...result, sourceBaseUrl: baseUrl };
      } catch (error) {
        errors.push({ baseUrl, message: error?.message || String(error) });
        this.logger?.warn("Update endpoint failed.", errors.at(-1));
      }
    }
    const error = new Error("No configured update endpoint is reachable.");
    error.code = "UPDATE_ENDPOINT_UNREACHABLE";
    error.details = errors;
    throw error;
  }

  async listReleases(options) {
    const currentVersion = String(options.currentVersion || "");
    const platform = normalizePlatform(options.platform);
    const arch = normalizeArchitecture(options.arch);
    const channel = String(options.channel || "alpha");
    const errors = [];
    const channels = channel === "all" ? ["alpha", "beta", "stable"] : [serverChannel(channel)];

    assertSupportedUpdateTarget(platform, arch);
    for (const baseUrl of this.baseUrls) {
      try {
        const releasesById = new Map();
        for (const selectedChannel of channels) {
          const url = new URL("api/releases.php", baseUrl);
          url.searchParams.set("platform", platform);
          url.searchParams.set("arch", arch);
          url.searchParams.set("channel", selectedChannel);
          const response = await this._fetchJson(url);
          if (response.status !== 200) throw new Error(`Update server returned HTTP ${response.status}.`);
          const result = validateReleaseListResponse(response.payload, { currentVersion, platform, arch, channel: selectedChannel });
          for (const release of result.releases) {
            release.downloadUrl = this._resolveArtifactUrl(release.downloadUrl, baseUrl).toString();
            releasesById.set(release.id, release);
          }
        }
        const releases = [...releasesById.values()].sort((a, b) => compareVersions(b.version, a.version) || Date.parse(b.publishedAt) - Date.parse(a.publishedAt));
        return { currentVersion, releases, sourceBaseUrl: baseUrl };
      } catch (error) {
        errors.push({ baseUrl, message: error?.message || String(error) });
        this.logger?.warn("Update catalog endpoint failed.", errors.at(-1));
      }
    }
    const error = new Error("No configured update catalog endpoint is reachable.");
    error.code = "UPDATE_ENDPOINT_UNREACHABLE";
    error.details = errors;
    throw error;
  }

  async downloadAndVerify(release) {
    if (!release || typeof release !== "object") throw new Error("No update release selected.");
    if (!Number.isSafeInteger(release.size) || release.size <= 0 || release.size > MAX_ARTIFACT_BYTES) {
      throw new Error("Update artifact size is outside the allowed range.");
    }

    const url = this._resolveArtifactUrl(release.downloadUrl, this.baseUrls[0]);
    const filename = safeFilename(release.filename);
    const versionDir = path.join(this.downloadRoot, safeFilename(`${release.version}-${release.id || "release"}`));
    const destination = path.join(versionDir, filename);
    fs.mkdirSync(versionDir, { recursive: true });

    if (fs.existsSync(destination)) {
      const stat = fs.statSync(destination);
      if (stat.isFile() && stat.size === release.size && await sha512File(destination) === release.sha512) {
        return { path: destination, filename, size: stat.size, sha512: release.sha512, reused: true };
      }
      fs.unlinkSync(destination);
    }

    const tempPath = path.join(versionDir, `.${filename}.${crypto.randomBytes(6).toString("hex")}.part`);
    const timeout = timeoutSignal(this.downloadTimeoutMs);
    try {
      const response = await this.fetch(url, {
        method: "GET",
        redirect: "manual",
        signal: timeout.signal,
        headers: { Accept: "application/octet-stream" }
      });
      if (response.status !== 200) throw new Error(`Download server returned HTTP ${response.status}.`);
      if (!response.body) throw new Error("Download response has no body.");
      const declaredLength = Number(response.headers.get("content-length") || 0);
      if (declaredLength > 0 && declaredLength !== release.size) throw new Error("Download Content-Length does not match the catalog.");

      const hash = crypto.createHash("sha512");
      let received = 0;
      const verifier = new Transform({
        transform(chunk, _encoding, callback) {
          received += chunk.length;
          if (received > release.size || received > MAX_ARTIFACT_BYTES) {
            callback(new Error("Downloaded artifact exceeds the expected size."));
            return;
          }
          hash.update(chunk);
          callback(null, chunk);
        }
      });

      await pipeline(Readable.fromWeb(response.body), verifier, fs.createWriteStream(tempPath, { flags: "wx", mode: 0o600 }));
      const actualHash = hash.digest("hex");
      if (received !== release.size) throw new Error(`Downloaded size mismatch: expected ${release.size}, received ${received}.`);
      if (actualHash !== release.sha512) throw new Error("Downloaded SHA-512 does not match the catalog.");
      fs.renameSync(tempPath, destination);
      return { path: destination, filename, size: received, sha512: actualHash, reused: false };
    } catch (error) {
      try { fs.unlinkSync(tempPath); } catch {}
      throw error;
    } finally {
      timeout.clear();
    }
  }

  cleanupDownloads() {
    return cleanDownloadCache(this.downloadRoot);
  }

  _resolveArtifactUrl(value, sourceBaseUrl) {
    const raw = String(value || "").trim();
    const resolved = new URL(raw.replace(/^\/+/, ""), sourceBaseUrl).toString();
    return assertAllowedUrl(resolved, this.baseUrls, { pathSegment: "files/" });
  }

  async _fetchJson(url) {
    assertAllowedUrl(url.toString(), this.baseUrls, { pathSegment: "api/" });
    const timeout = timeoutSignal(this.requestTimeoutMs);
    try {
      const response = await this.fetch(url, {
        method: "GET",
        redirect: "manual",
        signal: timeout.signal,
        headers: { Accept: "application/json" }
      });
      if (response.status === 404) return { status: 404, payload: null };
      const declaredLength = Number(response.headers.get("content-length") || 0);
      if (declaredLength > MAX_MANIFEST_BYTES) throw new Error("Update response is too large.");
      const text = await response.text();
      if (Buffer.byteLength(text, "utf8") > MAX_MANIFEST_BYTES) throw new Error("Update response is too large.");
      let payload;
      try { payload = JSON.parse(text); } catch { throw new Error("Update server returned invalid JSON."); }
      return { status: response.status, payload };
    } finally {
      timeout.clear();
    }
  }
}

module.exports = {
  HashUrlProvider,
  MAX_ARTIFACT_BYTES,
  MAX_MANIFEST_BYTES,
  safeFilename,
  sha512File
};
