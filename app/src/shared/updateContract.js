"use strict";

const { compareVersions, parseVersion } = require("./version");

const SHA512_PATTERN = /^[a-f0-9]{128}$/i;
const BUILD_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/;
const CHANNEL_TO_SERVER = Object.freeze({
  alpha: "alpha",
  beta: "beta",
  stable: "stable"
});
const SUPPORTED_ARCHITECTURES = Object.freeze({
  win: Object.freeze(["x64", "x86", "arm64", "universal"]),
  mac: Object.freeze(["arm64"]),
  ubuntu: Object.freeze(["x64", "arm64", "universal"])
});

function requireString(value, field) {
  const normalized = String(value || "").trim();
  if (!normalized) throw new Error(`Missing ${field}.`);
  return normalized;
}

function normalizeArchitecture(value) {
  const arch = String(value || "").trim().toLowerCase();
  if (arch === "ia32" || arch === "x86") return "x86";
  if (arch === "x64" || arch === "amd64") return "x64";
  if (arch === "arm64" || arch === "aarch64") return "arm64";
  return arch;
}

function normalizePlatform(value) {
  const platform = String(value || "").trim().toLowerCase();
  if (platform === "win32" || platform === "windows") return "win";
  if (platform === "darwin" || platform === "macos") return "mac";
  if (platform === "linux") return "ubuntu";
  return platform;
}

function serverChannel(channel) {
  const normalized = String(channel || "").trim().toLowerCase();
  const mapped = CHANNEL_TO_SERVER[normalized];
  if (!mapped) throw new Error(`Unsupported update channel: ${normalized || "<empty>"}`);
  return mapped;
}

function assertSupportedUpdateTarget(platform, arch) {
  const normalizedPlatform = normalizePlatform(platform);
  const normalizedArch = normalizeArchitecture(arch);
  const allowed = SUPPORTED_ARCHITECTURES[normalizedPlatform];
  if (!allowed) throw new Error(`Unsupported update platform: ${normalizedPlatform || "<empty>"}`);
  if (!allowed.includes(normalizedArch)) {
    throw new Error(`Unsupported update architecture for ${normalizedPlatform}: ${normalizedArch || "<empty>"}`);
  }
  return { platform: normalizedPlatform, arch: normalizedArch };
}

function validateReleaseResponse(payload, expected) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("Update response must be an object.");
  }
  if (!payload.release) {
    return {
      updateAvailable: false,
      currentVersion: expected.currentVersion,
      release: null
    };
  }

  const source = payload.release;
  const version = requireString(source.version, "release.version");
  parseVersion(version);
  const platform = normalizePlatform(requireString(source.platform, "release.platform"));
  const arch = normalizeArchitecture(requireString(source.arch || "universal", "release.arch"));
  const channel = requireString(source.channel || "stable", "release.channel").toLowerCase();
  const expectedPlatform = normalizePlatform(expected.platform);
  const expectedArch = normalizeArchitecture(expected.arch);
  const expectedChannel = serverChannel(expected.channel);

  assertSupportedUpdateTarget(expectedPlatform, expectedArch);
  assertSupportedUpdateTarget(platform, arch);

  if (source.type && source.type !== "app") throw new Error("Release is not an application update.");
  if (platform !== expectedPlatform) throw new Error(`Unexpected release platform: ${platform}`);
  if (arch !== "universal" && arch !== expectedArch) throw new Error(`Unexpected release architecture: ${arch}`);
  if (channel !== expectedChannel) throw new Error(`Unexpected release channel: ${channel}`);

  const sha512 = requireString(source.sha512, "release.sha512").toLowerCase();
  if (!SHA512_PATTERN.test(sha512)) throw new Error("Invalid release SHA-512.");
  const size = Number(source.size);
  if (!Number.isSafeInteger(size) || size <= 0) throw new Error("Invalid release size.");
  const buildId = source.build_id == null || source.build_id === ""
    ? null
    : requireString(source.build_id, "release.build_id");
  if (buildId && !BUILD_ID_PATTERN.test(buildId)) throw new Error("Invalid release build ID.");

  const updateAvailable = compareVersions(version, expected.currentVersion) > 0;
  return {
    updateAvailable,
    currentVersion: expected.currentVersion,
    release: {
      id: requireString(source.id || `${platform}-${arch}-${version}`, "release.id"),
      buildId,
      name: requireString(source.name || "CH-J Server Manager", "release.name"),
      version,
      platform,
      arch,
      channel,
      mandatory: Boolean(source.mandatory),
      notes: String(source.notes || ""),
      sha512,
      size,
      filename: requireString(source.filename, "release.filename"),
      downloadUrl: requireString(source.download_url || source.download_path, "release.download_url"),
      signatureUrl: requireString(source.signature_url || source.signature_path, "release.signature_url"),
      publishedAt: source.published_at ? String(source.published_at) : null
    }
  };
}

function validateReleaseListResponse(payload, expected) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload) || !Array.isArray(payload.releases)) {
    throw new Error("Update catalog response must contain a releases array.");
  }
  const ids = new Set();
  const releases = payload.releases.map((source) => {
    const release = validateReleaseResponse({ release: source }, expected).release;
    if (!release?.publishedAt || Number.isNaN(Date.parse(release.publishedAt))) {
      throw new Error("Invalid release publication date.");
    }
    if (ids.has(release.id)) throw new Error(`Duplicate release id: ${release.id}`);
    ids.add(release.id);
    return release;
  });
  releases.sort((a, b) => compareVersions(b.version, a.version) || Date.parse(b.publishedAt) - Date.parse(a.publishedAt));
  return {
    currentVersion: expected.currentVersion,
    releases
  };
}

module.exports = {
  BUILD_ID_PATTERN,
  CHANNEL_TO_SERVER,
  SHA512_PATTERN,
  SUPPORTED_ARCHITECTURES,
  assertSupportedUpdateTarget,
  normalizeArchitecture,
  normalizePlatform,
  serverChannel,
  validateReleaseListResponse,
  validateReleaseResponse
};
