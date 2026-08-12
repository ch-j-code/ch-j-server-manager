"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { PluginService } = require("../src/main/plugins/pluginService");

test("plugin service offers a newer artifact with the same semantic version", () => {
  const installedSha = "a".repeat(128);
  const catalogSha = "b".repeat(128);
  const service = new PluginService({
    appVersion: "0.0.1",
    configStore: {}, installer: {}, providerFactory: () => {}, runtime: {},
    registry: { listInstalled: () => [{ id: "chj.key-generator", version: "0.0.1", installedReleaseId: "old-release", installedSha512: installedSha }] }
  });
  service.catalog = [{ id: "chj.key-generator", version: "0.0.1", releaseId: "new-release", sha512: catalogSha }];
  const plugin = service.getState().catalog[0];
  assert.equal(plugin.installed, false);
  assert.equal(plugin.updateAvailable, true);
  assert.equal(plugin.installedReleaseId, "old-release");

  service.catalog[0].sha512 = installedSha;
  const identical = service.getState().catalog[0];
  assert.equal(identical.installed, true);
  assert.equal(identical.updateAvailable, false);
});

test("plugin service removes the verified package only after installation succeeds", async () => {
  const removed = [];
  const plugin = {
    id: "chj.test", version: "0.0.1", releaseId: "release-1", sha512: "a".repeat(128)
  };
  const service = new PluginService({
    appVersion: "0.0.1",
    configStore: { get: () => ({ updates: {} }) },
    registry: { listInstalled: () => [] },
    runtime: {},
    installer: { install: () => ({ manifest: { id: plugin.id }, reused: false }) },
    providerFactory: () => ({
      downloadAndVerify: async () => ({ path: "/cache/test.chjplugin" }),
      removeDownloadedPackage: (filePath) => { removed.push(filePath); return { removed: true }; }
    })
  });
  service.catalog = [plugin];

  await service.install("release-1");
  assert.deepEqual(removed, ["/cache/test.chjplugin"]);
});

test("plugin service keeps the verified package when installation fails", async () => {
  let cleanupCalled = false;
  const plugin = {
    id: "chj.test", version: "0.0.1", releaseId: "release-1", sha512: "a".repeat(128)
  };
  const service = new PluginService({
    appVersion: "0.0.1",
    configStore: { get: () => ({ updates: {} }) },
    registry: { listInstalled: () => [] },
    runtime: {},
    installer: { install: () => { throw new Error("installation failed"); } },
    providerFactory: () => ({
      downloadAndVerify: async () => ({ path: "/cache/test.chjplugin" }),
      removeDownloadedPackage: () => { cleanupCalled = true; }
    })
  });
  service.catalog = [plugin];

  await assert.rejects(() => service.install("release-1"), /installation failed/);
  assert.equal(cleanupCalled, false);
});
