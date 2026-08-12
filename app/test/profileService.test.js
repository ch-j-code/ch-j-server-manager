"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { ProfileService } = require("../src/main/profiles/profileService");
const { VaultStore } = require("../src/main/security/vaultStore");

test("profile service persists validated profiles and trusted host keys", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-profiles-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const vault = new VaultStore(root);
  await vault.create("correct horse battery staple");
  const profiles = new ProfileService(vault);

  const saved = profiles.save({ label: "NAS", host: "QNAP.local", port: 22, username: "admin", authMethod: "password" });
  assert.equal(saved.host, "qnap.local");
  assert.equal(profiles.list()[0].id, saved.id);
  const fingerprint = "ab".repeat(32);
  profiles.trustHostKey(saved.host, saved.port, fingerprint);
  assert.equal(profiles.getHostKey("QNAP.LOCAL", 22), fingerprint);
  assert.equal(profiles.delete(saved.id).removed, true);
  assert.equal(profiles.list().length, 0);
});

test("profile service rejects invalid connection data", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-profiles-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const vault = new VaultStore(root);
  await vault.create("correct horse battery staple");
  const profiles = new ProfileService(vault);
  assert.throws(() => profiles.save({ host: "bad host", username: "root" }), /host/);
  assert.throws(() => profiles.save({ host: "server.local", port: 70000, username: "root" }), /port/);
  assert.throws(() => profiles.save({ host: "server.local", username: "root", authMethod: "privateKey" }), /private key/);
});

test("profile service stores SSH passwords only in encrypted vault secrets", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-profile-password-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const vault = new VaultStore(root);
  await vault.create("correct horse battery staple");
  const profiles = new ProfileService(vault);
  const saved = profiles.save({ host: "server.local", username: "test", authMethod: "password", storePassword: true, password: "ssh-secret" });
  assert.equal(saved.hasStoredPassword, true);
  assert.equal(Object.prototype.hasOwnProperty.call(saved, "password"), false);
  assert.equal(profiles.getStoredPassword(saved.id), "ssh-secret");
  assert.doesNotMatch(fs.readFileSync(vault.dataPath, "utf8"), /ssh-secret/);

  profiles.save({ ...saved, storePassword: true, password: "" });
  assert.equal(profiles.getStoredPassword(saved.id), "ssh-secret");
  profiles.save({ ...saved, storePassword: false });
  assert.equal(profiles.getStoredPassword(saved.id), null);
});
