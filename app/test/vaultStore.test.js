"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { VaultStore, validatePassword } = require("../src/main/security/vaultStore");

test("vault password accepts 4 to 64 characters", () => {
  assert.equal(validatePassword("1234"), "1234");
  assert.equal(validatePassword("    "), "    ");
  assert.equal(validatePassword("🔐".repeat(64)), "🔐".repeat(64));
  assert.throws(() => validatePassword("123"), /4 to 64/);
  assert.throws(() => validatePassword("x".repeat(65)), /4 to 64/);
});

test("vault preserves and unlocks a four-space password", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-vault-spaces-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const vault = new VaultStore(root);

  await vault.create("    ");
  assert.equal(vault.lock().unlocked, false);
  assert.equal((await vault.unlock("    ")).unlocked, true);
});

test("vault encrypts data and only unlocks with the correct password", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-vault-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const vault = new VaultStore(root);

  assert.equal(vault.status().needsSetup, true);
  const created = await vault.create("correct horse battery staple");
  assert.deepEqual({ initialized: created.initialized, needsSetup: created.needsSetup, unlocked: created.unlocked }, {
    initialized: true, needsSetup: false, unlocked: true
  });
  vault.update((data) => data.profiles.push({ id: "secret-profile", label: "Hidden server" }));

  const encrypted = fs.readFileSync(path.join(root, "vault", "core-v1.data.json"), "utf8");
  assert.doesNotMatch(encrypted, /Hidden server|secret-profile/);
  assert.equal(vault.lock().unlocked, false);
  await assert.rejects(() => vault.unlock("wrong password"), { code: "VAULT_UNLOCK_FAILED" });
  assert.equal(vault.status().unlocked, false);
  await vault.unlock("correct horse battery staple");
  assert.equal(vault.getData().profiles[0].label, "Hidden server");
});

test("vault refuses to overwrite an incomplete vault", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-vault-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, "vault"), { recursive: true });
  fs.writeFileSync(path.join(root, "vault", "core-v1.meta.json"), "{}");
  const vault = new VaultStore(root);
  assert.equal(vault.status().damaged, true);
  await assert.rejects(() => vault.create("correct horse battery staple"), /incomplete/);
});

test("vault reset requires confirmation, deletes protected data and returns to setup", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-vault-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const vault = new VaultStore(root);
  await vault.create("1234");
  vault.update((data) => data.profiles.push({ id: "to-delete", label: "Deleted" }));

  assert.throws(() => vault.reset("wrong"), { code: "VAULT_RESET_CONFIRMATION_REQUIRED" });
  assert.equal(vault.status().initialized, true);
  assert.deepEqual(vault.reset("SMAZAT"), { initialized: false, needsSetup: true, damaged: false, unlocked: false });
  assert.equal(fs.existsSync(path.join(root, "vault")), false);

  await vault.create("new-password");
  assert.deepEqual(vault.getData().profiles, []);
});
