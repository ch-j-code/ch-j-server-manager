"use strict";

const { compareVersions } = require("../../shared/version");

class PluginService {
  constructor(options) {
    this.appVersion = options.appVersion;
    this.pluginApiVersion = options.pluginApiVersion;
    this.configStore = options.configStore;
    this.registry = options.registry;
    this.installer = options.installer;
    this.providerFactory = options.providerFactory;
    this.runtime = options.runtime;
    this.logger = options.logger;
    this.catalog = [];
    this.sourceBaseUrl = null;
    this.operation = null;
  }

  getState() {
    const installed = this.registry.listInstalled();
    return {
      status: this.operation || "idle",
      installed,
      windows: this.runtime.listWindows?.() || [],
      catalog: this.catalog.map((plugin) => {
        const current = installed.find((item) => item.id === plugin.id);
        const comparison = current ? compareVersions(plugin.version, current.version) : 1;
        const sameArtifact = Boolean(current?.installedSha512 && current.installedSha512 === plugin.sha512);
        return {
          ...plugin,
          installedVersion: current?.version || null,
          installedReleaseId: current?.installedReleaseId || null,
          updateAvailable: Boolean(current && (comparison > 0 || (comparison === 0 && !sameArtifact))),
          installed: Boolean(current && (comparison < 0 || (comparison === 0 && sameArtifact)))
        };
      }),
      sourceBaseUrl: this.sourceBaseUrl
    };
  }

  async checkCatalog() {
    if (this.operation) throw new Error("Another plugin operation is already running.");
    this.operation = "checking";
    try {
      const config = this.configStore.get();
      const provider = this.providerFactory(config.updates);
      const result = await provider.list({ appVersion: this.appVersion, pluginApiVersion: this.pluginApiVersion, channel: config.plugins.channel });
      this.catalog = result.plugins;
      this.sourceBaseUrl = result.sourceBaseUrl;
      this.logger?.info("Plugin catalog checked.", { count: this.catalog.length, channel: config.plugins.channel, sourceBaseUrl: this.sourceBaseUrl });
      return this.getState();
    } finally {
      this.operation = null;
    }
  }

  async install(releaseId) {
    if (this.operation) throw new Error("Another plugin operation is already running.");
    const plugin = this.catalog.find((item) => item.releaseId === String(releaseId || ""));
    if (!plugin) throw new Error("Selected plugin release is not in the current catalog.");
    this.operation = "installing";
    try {
      const provider = this.providerFactory(this.configStore.get().updates);
      const verified = await provider.downloadAndVerify(plugin);
      const result = this.installer.install(verified.path, plugin);
      try {
        const cleanup = provider.removeDownloadedPackage?.(verified.path);
        this.logger?.info("Installed plugin package removed from download cache.", {
          pluginId: plugin.id,
          releaseId: plugin.releaseId,
          removed: cleanup?.removed === true
        });
      } catch (error) {
        this.logger?.warn("Installed plugin package could not be removed from download cache.", {
          pluginId: plugin.id,
          releaseId: plugin.releaseId,
          message: error?.message || String(error)
        });
      }
      return { ...this.getState(), installedPlugin: result.manifest, reused: result.reused };
    } finally {
      this.operation = null;
    }
  }

  cleanupDownloads() {
    const provider = this.providerFactory(this.configStore.get().updates);
    return provider.cleanupDownloads?.() || { cleaned: false };
  }

  open(pluginId) {
    return this.runtime.open(pluginId);
  }

  uninstall(pluginId) {
    if (this.operation) throw new Error("Another plugin operation is already running.");
    const id = String(pluginId || "");
    this.runtime.close(id);
    const result = this.registry.removeInstalled(id);
    return { ...this.getState(), removedPluginId: result.removed ? id : null };
  }
}

module.exports = { PluginService };
