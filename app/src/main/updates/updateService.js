"use strict";

const { compareVersions } = require("../../shared/version");

class UpdateService {
  constructor(options) {
    this.appVersion = options.appVersion;
    this.buildId = options.buildId || null;
    this.platform = options.platform;
    this.arch = options.arch;
    this.configStore = options.configStore;
    this.providerFactory = options.providerFactory;
    this.logger = options.logger;
    this.lastCheck = null;
    this.releases = [];
    this.selectedReleaseId = null;
    this.lastVerifiedDownload = null;
    this.installerLaunchAuthorized = false;
    this.operation = null;
  }

  getState() {
    const release = this.lastCheck?.release || null;
    const releaseRelation = release ? this._relation(release) : null;
    return {
      status: this.operation || "idle",
      currentVersion: this.appVersion,
      currentBuildId: this.buildId,
      updateAvailable: Boolean(release && releaseRelation !== "sameVersionCurrentRelease"),
      release,
      releases: this.releases,
      selectedReleaseId: this.selectedReleaseId,
      releaseRelation,
      downloaded: this.lastVerifiedDownload ? {
        releaseId: this.lastVerifiedDownload.releaseId,
        filename: this.lastVerifiedDownload.filename,
        size: this.lastVerifiedDownload.size,
        sha512: this.lastVerifiedDownload.sha512,
        signatureVerified: this.lastVerifiedDownload.signatureVerified === true,
        primaryFingerprint: this.lastVerifiedDownload.primaryFingerprint,
        signingFingerprints: this.lastVerifiedDownload.signingFingerprints
      } : null
    };
  }

  async check() {
    if (this.operation) throw new Error("Another update operation is already running.");
    this.operation = "checking";
    try {
      const config = this.configStore.get();
      const provider = this.providerFactory(config.updates);
      const catalog = await provider.listReleases({
        currentVersion: this.appVersion,
        platform: this.platform,
        arch: this.arch,
        channel: config.updates.channel
      });
      this.releases = catalog.releases;
      const preferred = this.releases.find((release) => compareVersions(release.version, this.appVersion) > 0)
        || this.releases[0]
        || null;
      this.selectedReleaseId = preferred?.id || null;
      this.lastCheck = {
        updateAvailable: Boolean(preferred),
        currentVersion: this.appVersion,
        release: preferred,
        sourceBaseUrl: catalog.sourceBaseUrl
      };
      this.lastVerifiedDownload = null;
      this.installerLaunchAuthorized = false;
      this.logger?.info("Update check completed.", {
        channel: config.updates.channel,
        updateAvailable: this.lastCheck.updateAvailable,
        version: this.lastCheck.release?.version || null,
        sourceBaseUrl: this.lastCheck.sourceBaseUrl
      });
      return this.getState();
    } finally {
      this.operation = null;
    }
  }

  select(releaseId) {
    if (this.operation) throw new Error("Another update operation is already running.");
    const release = this.releases.find((item) => item.id === String(releaseId || ""));
    if (!release) throw new Error("Selected release is not available in the current catalog.");
    this.selectedReleaseId = release.id;
    this.lastCheck = {
      ...(this.lastCheck || { currentVersion: this.appVersion }),
      updateAvailable: true,
      release
    };
    this.lastVerifiedDownload = null;
    this.installerLaunchAuthorized = false;
    return this.getState();
  }

  async download() {
    if (this.operation) throw new Error("Another update operation is already running.");
    if (!this.lastCheck?.release) throw new Error("No update release is selected.");
    this.operation = "downloading";
    this.lastVerifiedDownload = null;
    this.installerLaunchAuthorized = false;
    try {
      const provider = this.providerFactory(this.configStore.get().updates);
      this.lastVerifiedDownload = await provider.downloadAndVerify(this.lastCheck.release);
      if (this.lastVerifiedDownload.signatureVerified !== true) {
        this.lastVerifiedDownload = null;
        throw new Error("The update did not pass mandatory OpenPGP verification.");
      }
      this.lastVerifiedDownload.releaseId = this.lastCheck.release.id;
      this.installerLaunchAuthorized = false;
      this.logger?.info("Update downloaded and verified with SHA-512 and OpenPGP.", {
        filename: this.lastVerifiedDownload.filename,
        size: this.lastVerifiedDownload.size,
        reused: this.lastVerifiedDownload.reused,
        primaryFingerprint: this.lastVerifiedDownload.primaryFingerprint,
        signingFingerprints: this.lastVerifiedDownload.signingFingerprints
      });
      return this.getState();
    } finally {
      this.operation = null;
    }
  }

  getVerifiedDownloadPath() {
    return this.lastVerifiedDownload?.signatureVerified === true
      ? this.lastVerifiedDownload.path
      : null;
  }

  async prepareInstallerLaunch() {
    if (this.operation) throw new Error("Another update operation is already running.");
    const release = this.lastCheck?.release;
    if (!release || !this.lastVerifiedDownload || this.lastVerifiedDownload.releaseId !== release.id) {
      throw new Error("No verified update release is ready to install.");
    }
    this.operation = "verifying-signature";
    this.installerLaunchAuthorized = false;
    try {
      const provider = this.providerFactory(this.configStore.get().updates);
      const filePath = await provider.reverifyForInstall(this.lastVerifiedDownload, release);
      this.installerLaunchAuthorized = true;
      return filePath;
    } catch (error) {
      this.lastVerifiedDownload = null;
      throw error;
    } finally {
      this.operation = null;
    }
  }

  cleanupDownloads() {
    const provider = this.providerFactory(this.configStore.get().updates);
    const result = provider.cleanupDownloads?.() || { cleaned: false };
    this.lastVerifiedDownload = null;
    this.installerLaunchAuthorized = false;
    return result;
  }

  markInstallerLaunched() {
    const release = this.lastCheck?.release;
    if (!release || !this.lastVerifiedDownload || this.lastVerifiedDownload.releaseId !== release.id
      || this.lastVerifiedDownload.signatureVerified !== true || !this.installerLaunchAuthorized) {
      throw new Error("No verified update release is ready to install.");
    }
    this.configStore.recordLaunchedRelease({
      id: release.id,
      version: release.version,
      publishedAt: release.publishedAt,
      sha512: release.sha512
    });
    this.installerLaunchAuthorized = false;
    return this.getState();
  }

  _relation(release) {
    const comparison = compareVersions(release.version, this.appVersion);
    if (comparison > 0) return "newerVersion";
    if (comparison < 0) return "olderVersion";
    if (this.buildId && release.buildId === this.buildId) return "sameVersionCurrentRelease";

    const lastLaunched = this.configStore.get().updates.lastLaunchedRelease;
    if (lastLaunched && compareVersions(lastLaunched.version, release.version) === 0) {
      if (lastLaunched.id === release.id || lastLaunched.sha512 === release.sha512) {
        return "sameVersionCurrentRelease";
      }
      const releaseTime = Date.parse(release.publishedAt);
      const launchedTime = Date.parse(lastLaunched.publishedAt);
      if (Number.isFinite(releaseTime) && Number.isFinite(launchedTime)) {
        return releaseTime > launchedTime ? "sameVersionNewerRelease" : "sameVersionOlderRelease";
      }
    }

    const newestSameVersion = this.releases.find((item) => compareVersions(item.version, this.appVersion) === 0);
    return newestSameVersion?.id === release.id
      ? "sameVersionNewerRelease"
      : "sameVersionOlderRelease";
  }
}

module.exports = { UpdateService };
