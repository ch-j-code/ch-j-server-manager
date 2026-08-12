"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const AdmZip = require("adm-zip");
const { ALLOWED_EXTENSIONS, PluginInstaller, safeEntryName } = require("../src/main/plugins/pluginInstaller");
const { PluginRegistry } = require("../src/main/plugins/pluginRegistry");

function manifest() {
  return {
    schemaVersion: 1,
    id: "chj.system-monitor",
    name: "System Monitor",
    version: "0.0.1",
    publisher: "CH-J",
    entry: "ui/index.html",
    pluginApi: "^1.0.0",
    minAppVersion: "0.0.1",
    permissions: ["session.read", "system.metrics.read"]
  };
}

test("plugin installer validates and atomically installs a standalone package", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-plugin-install-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const archive = path.join(root, "system-monitor.chjplugin");
  const zip = new AdmZip();
  zip.addFile("manifest.json", Buffer.from(JSON.stringify(manifest())));
  zip.addFile("ui/index.html", Buffer.from("<!doctype html><script src=\"index.js\"></script>"));
  zip.addFile("ui/index.js", Buffer.from("'use strict';"));
  zip.writeZip(archive);
  const catalog = {
    releaseId: "release-1", id: "chj.system-monitor", version: "0.0.1", pluginApi: "^1.0.0", minAppVersion: "0.0.1",
    permissions: ["session.read", "system.metrics.read"], sha512: "a".repeat(128), publishedAt: "2026-08-07T16:00:00Z"
  };
  const installer = new PluginInstaller({ storageRoot: root, appVersion: "0.0.1" });
  const result = installer.install(archive, catalog);
  assert.equal(result.manifest.id, "chj.system-monitor");
  assert.equal(new PluginRegistry(root).listInstalled()[0].version, "0.0.1");
  assert.equal(installer.install(archive, catalog).reused, true);
});

test("plugin paths reject traversal, absolute paths and drive paths", () => {
  assert.throws(() => safeEntryName("../escape.js"), /Unsafe/);
  assert.throws(() => safeEntryName("/absolute.js"), /Unsafe/);
  assert.throws(() => safeEntryName("C:/escape.js"), /Unsafe/);
  assert.equal(safeEntryName("ui/index.js"), "ui/index.js");
  assert.ok(ALLOWED_EXTENSIONS.has(".ttf"));
});
