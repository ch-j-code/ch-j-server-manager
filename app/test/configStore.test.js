"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { ConfigStore, DEFAULT_CONFIG } = require("../src/main/config/configStore");

test("config store creates defaults and persists allowed changes", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-config-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const store = new ConfigStore(root);
  assert.equal(store.load().updates.channel, "alpha");
  assert.equal(store.load().plugins.channel, "alpha");
  const changed = store.update({ updates: { channel: "all", autoCheck: false }, plugins: { channel: "stable" } });
  assert.equal(changed.updates.channel, "all");
  assert.equal(changed.plugins.channel, "stable");
  assert.equal(changed.updates.autoCheck, false);
  assert.equal(changed.updates.lastLaunchedRelease, null);
  assert.deepEqual(changed.updates.baseUrls, DEFAULT_CONFIG.updates.baseUrls);
  assert.equal(new ConfigStore(root).load().updates.channel, "all");
  assert.equal(new ConfigStore(root).load().plugins.channel, "stable");
  assert.equal(store.update({ ui: { language: "de" } }).ui.language, "de");
  assert.equal(new ConfigStore(root).load().ui.language, "de");
});

test("config store records launched update identity without exposing it to UI patches", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-config-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const store = new ConfigStore(root);
  store.load();
  const release = {
    id: "release-1",
    version: "0.0.1",
    publishedAt: "2026-08-08T15:14:02Z",
    sha512: "a".repeat(128)
  };
  store.recordLaunchedRelease(release);
  store.update({ updates: { lastLaunchedRelease: { id: "forged" } } });
  assert.deepEqual(new ConfigStore(root).load().updates.lastLaunchedRelease, release);
});

test("config only accepts supported UI languages", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-config-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const store = new ConfigStore(root);
  store.load();
  assert.equal(store.update({ ui: { language: "en" } }).ui.language, "en");
  assert.equal(store.update({ ui: { language: "fr" } }).ui.language, "cs");
  assert.equal(store.update({ ui: { language: "../../x" } }).ui.language, "cs");
});

test("untrusted config cannot replace update allowlist", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-config-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const store = new ConfigStore(root);
  store.load();
  const changed = store.update({ updates: { baseUrls: ["https://example.com/"] } });
  assert.deepEqual(changed.updates.baseUrls, DEFAULT_CONFIG.updates.baseUrls);
});
