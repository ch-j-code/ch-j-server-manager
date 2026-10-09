"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), os = require("node:os"), path = require("node:path"), crypto = require("node:crypto");
const { VaultStore } = require("../src/main/security/vaultStore");
const { ConfigStore } = require("../src/main/config/configStore");
const { BiometricService } = require("../src/main/security/biometrics/biometricService");
const { PlatformAdapter } = require("../src/main/security/biometrics/platformAdapter");
const { NativeRunner } = require("../src/main/security/biometrics/nativeRunner");
const { VaultLockController } = require("../src/main/security/vaultLockController");
const { registerCoreIpc } = require("../src/main/ipc/registerCoreIpc");
function failure(code) { return Object.assign(new Error(code), { code }); }
async function setup(t, provider = "touch-id") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-biometric-test-")); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const vault = new VaultStore(root), config = new ConfigStore(root); config.load(); await vault.create("test-password");
  vault.update(data => { data.profiles.push({ id: "kept-profile" }); data.hostKeys.host = "kept-fingerprint"; });
  const keys = new Map(), adapter = {
    info: { provider, protection: provider === "touch-id" ? "biometry-current-set" : "convenience" },
    getAvailability: async () => ({ available: true, code: "BIOMETRIC_AVAILABLE", ...adapter.info }),
    enroll: async () => {}, authenticate: async () => {}, removeEnrollment: async id => { keys.delete(id); },
    storeProtectedKey: async (id, key) => { keys.set(id, Buffer.from(key)); },
    retrieveProtectedKey: async id => Buffer.from(keys.get(id))
  };
  const service = new BiometricService({ storageRoot: root, vaultStore: vault, configStore: config, adapter });
  return { root, vault, config, keys, adapter, service };
}
test("biometric unlock authenticates existing encrypted data without migration or plaintext password", async t => {
  const { vault, service, adapter } = await setup(t);
  const before = [vault.metaPath, vault.dataPath].map(p => fs.readFileSync(p));
  let keyReference; const store = adapter.storeProtectedKey; adapter.storeProtectedKey = async (id, key) => { keyReference = key; await store(id, key); };
  assert.equal((await service.enable()).enabled, true); assert.equal(keyReference.equals(Buffer.alloc(32)), true);
  const metadata = fs.readFileSync(service.file, "utf8"); assert.ok(!metadata.includes("test-password"));
  vault.lock(); assert.equal((await service.unlock()).unlocked, true);
  assert.equal(vault.getData().profiles[0].id, "kept-profile"); assert.equal(vault.getData().hostKeys.host, "kept-fingerprint");
  [vault.metaPath, vault.dataPath].forEach((p, i) => assert.deepEqual(fs.readFileSync(p), before[i]));
});
for (const code of ["BIOMETRIC_CANCELLED", "BIOMETRIC_FAILED", "BIOMETRIC_CREDENTIAL_FAILED", "BIOMETRIC_DEVICE_UNAVAILABLE"]) {
  test(`${code} leaves Vault locked and master-password fallback works`, async t => {
    const { vault, service, adapter } = await setup(t); await service.enable(); vault.lock();
    adapter.retrieveProtectedKey = async () => { throw failure(code); };
    await assert.rejects(service.unlock(), { code }); assert.equal(vault.status().unlocked, false);
    assert.equal((await vault.unlock("test-password")).unlocked, true);
  });
}
test("wrong stored key fails GCM authentication, is zeroed and revokes enrollment", async t => {
  const { vault, service, adapter, keys } = await setup(t); await service.enable(); vault.lock();
  const bad = crypto.randomBytes(32); adapter.retrieveProtectedKey = async () => bad;
  await assert.rejects(service.unlock(), { code: "BIOMETRIC_ENROLLMENT_INVALIDATED" });
  assert.equal(vault.status().unlocked, false); assert.deepEqual(bad, Buffer.alloc(32)); assert.equal(keys.size, 0); assert.equal(service.metadata(), null);
});
for (const code of ["BIOMETRIC_UNAVAILABLE", "BIOMETRIC_NO_ENROLLMENT", "BIOMETRIC_KEYRING_UNAVAILABLE"]) {
  test(`enrollment refused for ${code}`, async t => {
    const { service, adapter, keys } = await setup(t); adapter.getAvailability = async () => ({ available: false, code });
    await assert.rejects(service.enable(), { code }); assert.equal(keys.size, 0); assert.equal(service.metadata(), null);
  });
}
test("macOS changed fingerprint set invalidates enrollment and keeps password recovery", async t => {
  const { service, adapter, vault, keys } = await setup(t); await service.enable(); vault.lock();
  adapter.retrieveProtectedKey = async () => { throw failure("BIOMETRIC_ENROLLMENT_INVALIDATED"); };
  await assert.rejects(service.unlock(), { code: "BIOMETRIC_ENROLLMENT_INVALIDATED" }); assert.equal(keys.size, 0);
  await vault.unlock("test-password"); assert.equal(vault.getData().profiles.length, 1);
});
test("reset revokes OS credential and old metadata cannot unlock a replacement Vault", async t => {
  const { service, vault, keys } = await setup(t); await service.enable(); const metadata = fs.readFileSync(service.file);
  await service.disable({ reset: true }); vault.reset("SMAZAT"); assert.equal(keys.size, 0);
  await vault.create("replacement-password"); fs.writeFileSync(service.file, metadata); vault.lock();
  assert.equal((await service.getStatus()).code, "BIOMETRIC_ENROLLMENT_INVALIDATED");
  await assert.rejects(service.unlock(), { code: "BIOMETRIC_MASTER_PASSWORD_REQUIRED" }); assert.equal(vault.status().unlocked, false);
});
test("failed OS store rolls back even if credential was written before failure", async t => {
  const { service, adapter, keys } = await setup(t);
  adapter.storeProtectedKey = async (id, key) => { keys.set(id, Buffer.from(key)); throw failure("BIOMETRIC_CREDENTIAL_FAILED"); };
  await assert.rejects(service.enable(), { code: "BIOMETRIC_CREDENTIAL_FAILED" }); assert.equal(keys.size, 0); assert.equal(service.metadata(), null);
});
test("timeout and late OS approval cannot unlock Vault", async t => {
  const { service, adapter, vault, keys } = await setup(t); await service.enable(); vault.lock(); service.timeoutMs = 10;
  let release; adapter.retrieveProtectedKey = () => new Promise(resolve => { release = resolve; });
  await assert.rejects(service.unlock(), { code: "BIOMETRIC_TIMEOUT" });
  const key = Buffer.from([...keys.values()][0]); release(key); await new Promise(resolve => setImmediate(resolve));
  assert.equal(vault.status().unlocked, false); assert.deepEqual(key, Buffer.alloc(32));
});
test("manual lock cancels delayed master-password derivation", async t => {
  const { vault } = await setup(t); vault.lock();
  const pending = vault.unlock("test-password"); vault.lock();
  await assert.rejects(pending, { code: "VAULT_UNLOCK_FAILED" }); assert.equal(vault.status().unlocked, false);
});
test("automatic lock zeroes key before awaiting active SSH cleanup and closes plugins", async t => {
  const { vault, service, config } = await setup(t); config.update({ security: { autoLockMinutes: 15, lockOnBlur: true } });
  let now = 0, release, reason, closed = false;
  const controller = new VaultLockController({ vaultStore: vault, configStore: config, biometricService: service, now: () => now,
    sessionManager: { disconnectAll: async value => { reason = value; await new Promise(resolve => { release = resolve; }); } },
    pluginRuntime: { closeAll: () => { closed = true; } } }); t.after(() => controller.dispose());
  now = 14 * 60000; await controller.check(); assert.equal(vault.status().unlocked, true);
  controller.activity(); now += 15 * 60000; const pending = controller.check();
  assert.equal(vault.status().unlocked, false); assert.equal(closed, true); assert.equal(reason, "vault-inactivity"); release(); await pending;
  await vault.unlock("test-password"); const focused = controller.lostFocus(); assert.equal(vault.status().unlocked, false); release(); await focused;
});
test("Windows Hello PIN approval uses desktop HWND and returns only main-process key", async () => {
  const requests = [], expected = crypto.randomBytes(32);
  const adapter = new PlatformAdapter({ platform: "win32", appPath: os.tmpdir(), getMainWindow: () => ({ isDestroyed: () => false, getNativeWindowHandle: () => { const b = Buffer.alloc(8); b.writeBigUInt64LE(12345n); return b; } }), runner: { run: async request => { requests.push(request); return { ok: true, key: expected.toString("base64"), method: "PIN" }; } } });
  await adapter.authenticate("Confirm"); const key = await adapter.retrieveProtectedKey("a".repeat(64), "Unlock");
  assert.deepEqual(key, expected); assert.equal(requests[0].hwnd, "12345"); assert.equal(requests[0].pid, process.pid); assert.equal(adapter.info.protection, "convenience");
});
test("Linux unavailable/insecure credential backend has no plaintext fallback", async () => {
  const adapter = new PlatformAdapter({ platform: "linux", appPath: os.tmpdir(), runner: { run: async () => { throw failure("BIOMETRIC_KEYRING_UNAVAILABLE"); } } });
  assert.equal((await adapter.getAvailability()).available, false);
  await assert.rejects(adapter.retrieveProtectedKey("a".repeat(64)), { code: "BIOMETRIC_KEYRING_UNAVAILABLE" });
});
test("native runner bounds output, handles missing helper and authentication timeout", async () => {
  const runner = code => new NativeRunner({ executable: process.execPath, args: ["-e", code], timeoutMs: 40 });
  await assert.rejects(runner("process.stdout.write('x'.repeat(20000))").run({ op: "retrieve" }), { code: "BIOMETRIC_FAILED" });
  await assert.rejects(runner("setInterval(()=>{},1000)").run({ op: "retrieve" }), { code: "BIOMETRIC_TIMEOUT" });
  await assert.rejects(new NativeRunner({ executable: path.join(os.tmpdir(), "no-such-chj-helper") }).run({ op: "status" }), { code: "BIOMETRIC_UNAVAILABLE" });
});
test("biometric IPC rejects plugin windows and child frames without exposing keys", async () => {
  const handlers = new Map(), mainFrame = {}, sender = { id: 1 }; let calls = 0;
  registerCoreIpc({ ipcMain: { handle: (id, fn) => handlers.set(id, fn), on() {} }, getMainWindow: () => ({ isDestroyed: () => false, webContents: { id: 1, mainFrame } }), biometricService: { getStatus: async () => { calls++; return { enabled: true, available: true }; } } });
  const handler = handlers.get("biometrics:status");
  await assert.rejects(handler({ sender: { id: 2 }, senderFrame: mainFrame }), { code: "UNTRUSTED_IPC_SENDER" });
  await assert.rejects(handler({ sender, senderFrame: {} }), { code: "UNTRUSTED_IPC_SENDER" });
  assert.deepEqual(await handler({ sender, senderFrame: mainFrame }), { ok: true, value: { enabled: true, available: true } }); assert.equal(calls, 1);
});
