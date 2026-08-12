"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { PluginRegistry, validateManifest } = require("../src/main/plugins/pluginRegistry");

function manifest(version, overrides = {}) {
  return {
    schemaVersion: 1,
    id: "chj.system-monitor",
    name: "System Monitor",
    version,
    publisher: "CH-J",
    entry: "ui/index.html",
    pluginApi: "^1.0.0",
    minAppVersion: "0.0.1",
    permissions: ["session.read", "system.metrics.read"],
    ...overrides
  };
}

test("manifest validator rejects traversal and unknown permissions", () => {
  assert.throws(() => validateManifest(manifest("0.0.1", { entry: "../main.js" })), /entry/);
  assert.throws(() => validateManifest(manifest("0.0.1", { permissions: ["electron.full"] })), /permission/);
});

test("registry returns the newest valid installed plugin and can remove all of its versions", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-plugins-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const version of ["0.0.1", "0.0.2"]) {
    const versionRoot = path.join(root, "plugins", "chj.system-monitor", version, "ui");
    fs.mkdirSync(versionRoot, { recursive: true });
    fs.writeFileSync(path.join(versionRoot, "index.html"), "<!doctype html>");
    fs.writeFileSync(path.join(versionRoot, "..", "manifest.json"), JSON.stringify(manifest(version)));
    fs.writeFileSync(path.join(versionRoot, "..", ".installation.json"), JSON.stringify({ releaseId: `release-${version}`, sha512: version === "0.0.2" ? "b".repeat(128) : "a".repeat(128), installedAt: "2026-08-07T20:00:00Z" }));
  }
  const registry = new PluginRegistry(root);
  const plugins = registry.listInstalled();
  assert.equal(plugins.length, 1);
  assert.equal(plugins[0].version, "0.0.2");
  assert.equal(plugins[0].installedReleaseId, "release-0.0.2");
  assert.equal(plugins[0].installedSha512, "b".repeat(128));
  assert.deepEqual(registry.removeInstalled("chj.system-monitor"), { removed: true, pluginId: "chj.system-monitor" });
  assert.deepEqual(registry.listInstalled(), []);
  assert.deepEqual(registry.removeInstalled("chj.system-monitor"), { removed: false, pluginId: "chj.system-monitor" });
});
