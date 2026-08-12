"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { PluginCatalogProvider, validatePluginCatalog } = require("../src/main/plugins/pluginCatalogProvider");

const baseUrl = "https://192.168.10.154/";
const backupBaseUrl = "https://192.168.10.155/";

function plugin(overrides = {}) {
  return {
    id: "release-system-monitor",
    plugin_id: "chj.system-monitor",
    name: "System Monitor",
    version: "0.0.1",
    min_app_version: "0.0.1",
    plugin_api: "^1.0.0",
    permissions: ["session.read", "system.metrics.read"],
    channel: "alpha",
    filename: "chj.system-monitor-0.0.1.chjplugin",
    size: 4096,
    sha512: "a".repeat(128),
    download_url: "https://192.168.10.154/files/plugins/chj.system-monitor/0.0.1/plugin.chjplugin",
    published_at: "2026-08-07T18:00:00+02:00",
    ...overrides
  };
}

test("plugin catalog validates identity, compatibility, permissions and hash", () => {
  const result = validatePluginCatalog({ plugins: [plugin()] }, { channel: "alpha" });
  assert.equal(result[0].id, "chj.system-monitor");
  assert.deepEqual(result[0].permissions, ["session.read", "system.metrics.read"]);
  assert.throws(() => validatePluginCatalog({ plugins: [plugin({ permissions: ["electron.full"] })] }, { channel: "alpha" }), /permission/);
  assert.throws(() => validatePluginCatalog({ plugins: [plugin({ sha512: "bad" })] }, { channel: "alpha" }), /SHA-512/);
  assert.throws(() => validatePluginCatalog({ plugins: [plugin(), plugin()] }, { channel: "alpha" }), /Duplicate plugin ID/);
});

test("all plugin channels are fetched separately and merged locally", async () => {
  const requestedChannels = [];
  const provider = new PluginCatalogProvider({
    baseUrls: [baseUrl],
    fetchImpl: async (url) => {
      const channel = url.searchParams.get("channel");
      requestedChannels.push(channel);
      return new Response(JSON.stringify({
        plugins: [plugin({ id: `${channel}-system-monitor`, channel })]
      }), { status: 200 });
    }
  });
  const result = await provider.list({ appVersion: "0.0.1", channel: "all" });
  assert.deepEqual(requestedChannels, ["alpha", "beta", "stable"]);
  assert.deepEqual(new Set(result.plugins.map((item) => item.channel)), new Set(["alpha", "beta", "stable"]));
});

test("plugin download fails over to the same file path on a configured backup server", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-plugin-fallback-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bytes = Buffer.from("verified-plugin");
  const requested = [];
  const provider = new PluginCatalogProvider({
    baseUrls: [baseUrl, backupBaseUrl],
    downloadRoot: root,
    fetchImpl: async (url) => {
      requested.push(url.toString());
      if (url.hostname === "192.168.10.154") return new Response(null, { status: 503 });
      return new Response(bytes, { status: 200, headers: { "content-length": String(bytes.length) } });
    }
  });
  const result = await provider.downloadAndVerify({
    releaseId: "release-1", id: "chj.system-monitor", version: "0.0.1", filename: "plugin.chjplugin",
    size: bytes.length, sha512: crypto.createHash("sha512").update(bytes).digest("hex"),
    downloadUrl: `${baseUrl}files/plugins/chj.system-monitor/0.0.1/plugin.chjplugin`
  });
  assert.equal(new URL(result.sourceUrl).hostname, "192.168.10.155");
  assert.deepEqual(requested.map((value) => new URL(value).hostname), ["192.168.10.154", "192.168.10.155"]);
  assert.equal(fs.readFileSync(result.path, "utf8"), bytes.toString("utf8"));
});
