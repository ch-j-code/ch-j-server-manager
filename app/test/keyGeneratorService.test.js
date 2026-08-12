"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { utils: sshUtils } = require("ssh2");
const { KeyGeneratorService } = require("../src/main/keys/keyGeneratorService");

test("key generator creates modern and explicitly confirmed legacy key pairs", () => {
  const service = new KeyGeneratorService();
  for (const input of [
    { type: "ed25519" }, { type: "rsa", bits: 2048 }, { type: "ecdsa", bits: 256 },
    { type: "dsa", bits: 1024, legacyConfirmed: true }, { type: "rsa1", bits: 1024, legacyConfirmed: true }
  ]) {
    const generated = service.generate({ ...input, comment: "test@core" });
    if (input.type === "rsa1") assert.match(generated.privateKey, /^PuTTY-User-Key-File-2: ssh1-rsa/);
    else assert.match(generated.privateKey, /BEGIN PRIVATE KEY/);
    assert.ok(generated.publicKey.length > 40);
    assert.equal(Object.prototype.hasOwnProperty.call(generated, "passphrase"), false);
  }
  assert.throws(() => service.generate({ type: "dsa" }), /explicit confirmation/);
  assert.throws(() => service.generate({ type: "rsa1" }), /explicit confirmation/);
});

test("key generator exports OpenSSH, PEM and PPK formats and reports safe passphrase fallback", () => {
  const service = new KeyGeneratorService();
  for (const input of [
    { type: "ed25519", privateKeyFormat: "openssh" },
    { type: "rsa", bits: 2048, privateKeyFormat: "openssh" },
    { type: "ecdsa", bits: 256, privateKeyFormat: "openssh" },
    { type: "dsa", bits: 1024, privateKeyFormat: "openssh", legacyConfirmed: true }
  ]) {
    const generated = service.generate(input);
    assert.equal(generated.privateKeyFormat, "openssh");
    assert.match(generated.privateKey, /^-----BEGIN OPENSSH PRIVATE KEY-----/);
    assert.match(generated.publicKeyOpenSsh, /^(ssh-|ecdsa-)/);
    const parsed = sshUtils.parseKey(generated.privateKey);
    assert.equal(parsed instanceof Error, false, parsed?.message);
  }
  for (const input of [
    { type: "ed25519" }, { type: "rsa", bits: 2048 }, { type: "ecdsa", bits: 256 },
    { type: "dsa", legacyConfirmed: true }, { type: "rsa1", legacyConfirmed: true }
  ]) {
    const generated = service.generate({ ...input, privateKeyFormat: "ppk" });
    assert.equal(generated.privateKeyFormat, "ppk");
    assert.match(generated.privateKey, /^PuTTY-User-Key-File-2: /);
    assert.match(generated.privateKey, /\nPrivate-MAC: [a-f0-9]{40}\n$/);
  }
  const fallback = service.generate({ type: "ed25519", privateKeyFormat: "openssh", passphrase: "secret" });
  assert.equal(fallback.privateKeyFormat, "pem");
  assert.match(fallback.privateKey, /BEGIN ENCRYPTED PRIVATE KEY/);
  assert.match(fallback.notice, /šifrovaný PEM/);
});

test("key generator saves only a selected generated pair with restrictive private mode", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-keys-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const target = path.join(root, "id_ed25519");
  const service = new KeyGeneratorService({ selectSavePath: async () => ({ canceled: false, path: target }) });
  const generated = service.generate({ type: "ed25519" });
  const saved = await service.save(generated.generationId);
  assert.equal(saved.privatePath, target);
  assert.match(fs.readFileSync(target, "utf8"), /BEGIN PRIVATE KEY/);
  assert.match(fs.readFileSync(`${target}.pub`, "utf8"), /^ssh-ed25519 /);
  if (process.platform !== "win32") assert.equal(fs.statSync(target).mode & 0o777, 0o600);
});
