"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const openpgp = require("openpgp");
const {
  OpenPgpVerifier,
  TRUSTED_PRIMARY_FINGERPRINT,
  normalizeFingerprint
} = require("../src/main/updates/openPgpVerifier");
const { UpdateService } = require("../src/main/updates/updateService");

let fixturePromise;

async function fixtures() {
  if (!fixturePromise) {
    fixturePromise = (async () => {
      const trusted = await openpgp.generateKey({
        type: "ecc",
        curve: "ed25519Legacy",
        userIDs: [{ name: "CH-J updater test key" }],
        subkeys: [{ sign: true }, { sign: true }],
        format: "object"
      });
      const foreign = await openpgp.generateKey({
        type: "ecc",
        curve: "ed25519Legacy",
        userIDs: [{ name: "Foreign updater test key" }],
        subkeys: [{ sign: true }],
        format: "object"
      });
      return {
        trustedPrivateArmor: trusted.privateKey.armor(),
        trustedPublicArmor: trusted.publicKey.armor(),
        trustedFingerprint: normalizeFingerprint(trusted.publicKey.getFingerprint()),
        trustedSigningFingerprints: trusted.publicKey.getSubkeys().map((key) => normalizeFingerprint(key.getFingerprint())),
        foreignPrivateArmor: foreign.privateKey.armor(),
        foreignPublicArmor: foreign.publicKey.armor(),
        foreignFingerprint: normalizeFingerprint(foreign.publicKey.getFingerprint())
      };
    })();
  }
  return fixturePromise;
}

async function detachedSignature(privateArmor, bytes, subkeyIndex = 0) {
  const privateKey = await openpgp.readPrivateKey({ armoredKey: privateArmor });
  return openpgp.sign({
    message: await openpgp.createMessage({ binary: bytes }),
    signingKeys: privateKey,
    signingKeyIDs: privateKey.getSubkeys()[subkeyIndex].getKeyID(),
    detached: true,
    format: "armored"
  });
}

function verificationFiles(t, publicArmor, bytes, signature) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-openpgp-test-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const publicKeyPath = path.join(root, "trusted.asc");
  const artifactPath = path.join(root, "update.bin");
  const signaturePath = path.join(root, "update.bin.asc");
  fs.writeFileSync(publicKeyPath, publicArmor, { mode: 0o600 });
  fs.writeFileSync(artifactPath, bytes, { mode: 0o600 });
  if (signature !== null) fs.writeFileSync(signaturePath, signature, { mode: 0o600 });
  return { publicKeyPath, artifactPath, signaturePath };
}

function verifierFor(files, trustedPrimaryFingerprint, options = {}) {
  return new OpenPgpVerifier({
    publicKeyPath: files.publicKeyPath,
    trustedPrimaryFingerprint,
    ...options
  });
}

test("bundled production certificate has the hardcoded trusted primary fingerprint", async () => {
  const armoredKey = fs.readFileSync(path.join(__dirname, "..", "ch-j-signing-public.asc"), "utf8");
  const key = await openpgp.readKey({ armoredKey });
  assert.equal(normalizeFingerprint(key.getFingerprint()), TRUSTED_PRIMARY_FINGERPRINT);
  await key.verifyPrimaryKey(new Date());
  const signingSubkey = key.getSubkeys()[0];
  assert.ok(signingSubkey, "production signing subkey is missing");
  const binding = await signingSubkey.verify(new Date());
  assert.ok([...binding.keyFlags].some((flags) => (flags & openpgp.enums.keyFlags.signData) !== 0));
});

test("valid file and detached signature by a trusted signing subkey pass", async (t) => {
  const fixture = await fixtures();
  const bytes = Buffer.from("authentic update artifact");
  const signature = await detachedSignature(fixture.trustedPrivateArmor, bytes, 0);
  const files = verificationFiles(t, fixture.trustedPublicArmor, bytes, signature);
  const result = await verifierFor(files, fixture.trustedFingerprint).verifyFile(files.artifactPath, files.signaturePath);
  assert.equal(result.valid, true);
  assert.deepEqual(result.signingFingerprints, [fixture.trustedSigningFingerprints[0]]);
});

test("an artifact changed after signing is rejected", async (t) => {
  const fixture = await fixtures();
  const signature = await detachedSignature(fixture.trustedPrivateArmor, Buffer.from("original"));
  const files = verificationFiles(t, fixture.trustedPublicArmor, Buffer.from("modified"), signature);
  await assert.rejects(
    () => verifierFor(files, fixture.trustedFingerprint).verifyFile(files.artifactPath, files.signaturePath),
    (error) => error.code === "UPDATE_SIGNATURE_INVALID"
  );
});

test("a missing signature is rejected", async (t) => {
  const fixture = await fixtures();
  const files = verificationFiles(t, fixture.trustedPublicArmor, Buffer.from("update"), null);
  await assert.rejects(
    () => verifierFor(files, fixture.trustedFingerprint).verifyFile(files.artifactPath, files.signaturePath),
    (error) => error.code === "UPDATE_SIGNATURE_FILE_MISSING"
  );
});

test("an empty or malformed signature is rejected", async (t) => {
  const fixture = await fixtures();
  const empty = verificationFiles(t, fixture.trustedPublicArmor, Buffer.from("update"), "");
  await assert.rejects(
    () => verifierFor(empty, fixture.trustedFingerprint).verifyFile(empty.artifactPath, empty.signaturePath),
    (error) => error.code === "UPDATE_SIGNATURE_EMPTY"
  );
  const malformed = verificationFiles(t, fixture.trustedPublicArmor, Buffer.from("update"), "not an OpenPGP signature");
  await assert.rejects(
    () => verifierFor(malformed, fixture.trustedFingerprint).verifyFile(malformed.artifactPath, malformed.signaturePath),
    (error) => error.code === "UPDATE_SIGNATURE_MALFORMED"
  );
});

test("a valid signature from an unrelated keypair is rejected", async (t) => {
  const fixture = await fixtures();
  const bytes = Buffer.from("foreign update");
  const signature = await detachedSignature(fixture.foreignPrivateArmor, bytes);
  const files = verificationFiles(t, fixture.trustedPublicArmor, bytes, signature);
  await assert.rejects(
    () => verifierFor(files, fixture.trustedFingerprint).verifyFile(files.artifactPath, files.signaturePath),
    (error) => error.code === "UPDATE_SIGNATURE_INVALID" || error.code === "UPDATE_SIGNATURE_UNTRUSTED_SIGNER"
  );
});

test("a public certificate with a different primary fingerprint is rejected", async (t) => {
  const fixture = await fixtures();
  const bytes = Buffer.from("update");
  const signature = await detachedSignature(fixture.foreignPrivateArmor, bytes);
  const files = verificationFiles(t, fixture.foreignPublicArmor, bytes, signature);
  await assert.rejects(
    () => verifierFor(files, fixture.trustedFingerprint).verifyFile(files.artifactPath, files.signaturePath),
    (error) => error.code === "UPDATE_PUBLIC_KEY_FINGERPRINT_MISMATCH"
  );
});

test("a second future signing subkey bound to the same primary key passes", async (t) => {
  const fixture = await fixtures();
  const bytes = Buffer.from("future subkey update");
  const signature = await detachedSignature(fixture.trustedPrivateArmor, bytes, 1);
  const files = verificationFiles(t, fixture.trustedPublicArmor, bytes, signature);
  const result = await verifierFor(files, fixture.trustedFingerprint).verifyFile(files.artifactPath, files.signaturePath);
  assert.equal(result.valid, true);
  assert.deepEqual(result.signingFingerprints, [fixture.trustedSigningFingerprints[1]]);
});

test("a revoked signing subkey is rejected", async (t) => {
  const fixture = await fixtures();
  const bytes = Buffer.from("revoked subkey update");
  const signature = await detachedSignature(fixture.trustedPrivateArmor, bytes, 0);
  const privateKey = await openpgp.readPrivateKey({ armoredKey: fixture.trustedPrivateArmor });
  privateKey.subkeys[0] = await privateKey.subkeys[0].revoke(
    privateKey.keyPacket,
    { flag: openpgp.enums.reasonForRevocation.keyRetired, string: "Updater test revocation" },
    new Date()
  );
  const files = verificationFiles(t, privateKey.toPublic().armor(), bytes, signature);
  await assert.rejects(
    () => verifierFor(files, fixture.trustedFingerprint).verifyFile(files.artifactPath, files.signaturePath),
    (error) => ["UPDATE_SIGNATURE_INVALID", "UPDATE_SIGNATURE_UNTRUSTED_SIGNER", "UPDATE_SIGNING_SUBKEY_INVALID"].includes(error.code)
  );
});

test("an expired signing subkey is rejected even when the signature was created before expiry", async (t) => {
  const created = new Date(Date.now() - 120_000);
  const generated = await openpgp.generateKey({
    type: "ecc",
    curve: "ed25519Legacy",
    date: created,
    userIDs: [{ name: "Expired updater test subkey" }],
    subkeys: [{ sign: true, keyExpirationTime: 60 }],
    format: "object"
  });
  const bytes = Buffer.from("expired subkey update");
  const signature = await openpgp.sign({
    message: await openpgp.createMessage({ binary: bytes }),
    signingKeys: generated.privateKey,
    signingKeyIDs: generated.privateKey.getSubkeys()[0].getKeyID(),
    detached: true,
    format: "armored",
    date: new Date(created.getTime() + 30_000)
  });
  const fingerprint = normalizeFingerprint(generated.publicKey.getFingerprint());
  const files = verificationFiles(t, generated.publicKey.armor(), bytes, signature);
  await assert.rejects(
    () => verifierFor(files, fingerprint).verifyFile(files.artifactPath, files.signaturePath),
    (error) => ["UPDATE_SIGNATURE_INVALID", "UPDATE_SIGNATURE_UNTRUSTED_SIGNER", "UPDATE_SIGNING_SUBKEY_INVALID"].includes(error.code)
  );
});

test("a revoked primary key is rejected before artifact verification", async (t) => {
  const fixture = await fixtures();
  const bytes = Buffer.from("revoked primary update");
  const signature = await detachedSignature(fixture.trustedPrivateArmor, bytes);
  const privateKey = await openpgp.readPrivateKey({ armoredKey: fixture.trustedPrivateArmor });
  const revokedKey = await privateKey.revoke(
    { flag: openpgp.enums.reasonForRevocation.keyRetired, string: "Updater test primary revocation" },
    new Date()
  );
  const files = verificationFiles(t, revokedKey.toPublic().armor(), bytes, signature);
  await assert.rejects(
    () => verifierFor(files, fixture.trustedFingerprint).verifyFile(files.artifactPath, files.signaturePath),
    (error) => error.code === "UPDATE_PUBLIC_KEY_INVALID"
  );
});

test("a signing subkey with a corrupted binding signature is rejected", async (t) => {
  const fixture = await fixtures();
  const bytes = Buffer.from("invalid binding update");
  const signature = await detachedSignature(fixture.trustedPrivateArmor, bytes, 0);
  const publicKey = await openpgp.readKey({ armoredKey: fixture.trustedPublicArmor });
  publicKey.subkeys[0].bindingSignatures[0].params.r[0] ^= 1;
  const files = verificationFiles(t, publicKey.armor(), bytes, signature);
  await assert.rejects(
    () => verifierFor(files, fixture.trustedFingerprint).verifyFile(files.artifactPath, files.signaturePath),
    (error) => ["UPDATE_SIGNATURE_INVALID", "UPDATE_SIGNATURE_UNTRUSTED_SIGNER", "UPDATE_SIGNING_SUBKEY_INVALID"].includes(error.code)
  );
});

test("a verification exception fails closed", async (t) => {
  const fixture = await fixtures();
  const bytes = Buffer.from("exception update");
  const signature = await detachedSignature(fixture.trustedPrivateArmor, bytes);
  const files = verificationFiles(t, fixture.trustedPublicArmor, bytes, signature);
  const openpgpImpl = { ...openpgp, verify: async () => { throw new Error("simulated verifier failure"); } };
  await assert.rejects(
    () => verifierFor(files, fixture.trustedFingerprint, { openpgpImpl }).verifyFile(files.artifactPath, files.signaturePath),
    (error) => error.code === "UPDATE_SIGNATURE_INVALID"
  );
});

test("a verification timeout fails closed", async (t) => {
  const fixture = await fixtures();
  const bytes = Buffer.from("timeout update");
  const signature = await detachedSignature(fixture.trustedPrivateArmor, bytes);
  const files = verificationFiles(t, fixture.trustedPublicArmor, bytes, signature);
  const openpgpImpl = { ...openpgp, verify: () => new Promise(() => {}) };
  await assert.rejects(
    () => verifierFor(files, fixture.trustedFingerprint, {
      openpgpImpl,
      verificationTimeoutMs: 20
    }).verifyFile(files.artifactPath, files.signaturePath),
    (error) => error.code === "UPDATE_SIGNATURE_TIMEOUT"
  );
});

test("a missing bundled public key fails closed", async (t) => {
  const fixture = await fixtures();
  const bytes = Buffer.from("missing key update");
  const signature = await detachedSignature(fixture.trustedPrivateArmor, bytes);
  const files = verificationFiles(t, fixture.trustedPublicArmor, bytes, signature);
  fs.unlinkSync(files.publicKeyPath);
  await assert.rejects(
    () => verifierFor(files, fixture.trustedFingerprint).verifyFile(files.artifactPath, files.signaturePath),
    (error) => error.code === "UPDATE_SIGNATURE_FILE_MISSING"
  );
});

test("installer flow cannot start before main-process verification", async () => {
  const selected = {
    id: "release-1",
    version: "0.0.2",
    publishedAt: "2026-08-13T12:00:00Z",
    filename: "update.exe",
    size: 6,
    sha512: "a".repeat(128)
  };
  const configStore = {
    get: () => ({ updates: { channel: "alpha", lastLaunchedRelease: null } }),
    recordLaunchedRelease() { throw new Error("must not record"); }
  };
  const provider = {
    async listReleases() { return { releases: [selected], sourceBaseUrl: "https://updates.example/" }; },
    async downloadAndVerify() {
      return { path: "/tmp/update.exe", filename: "update.exe", size: 6, sha512: selected.sha512, signatureVerified: false };
    },
    async reverifyForInstall() { throw new Error("must not be called"); }
  };
  const service = new UpdateService({
    appVersion: "0.0.1",
    platform: "win32",
    arch: "x64",
    configStore,
    providerFactory: () => provider
  });
  await service.check();
  await assert.rejects(() => service.prepareInstallerLaunch(), /No verified update/);
  await assert.rejects(() => service.download(), /mandatory OpenPGP verification/);
  assert.throws(() => service.markInstallerLaunched(), /No verified update/);
});

test("installer launch is authorized only after the main process re-verifies the tracked artifact", async () => {
  const selected = {
    id: "release-2",
    version: "0.0.2",
    publishedAt: "2026-08-13T12:00:00Z",
    filename: "update.exe",
    size: 6,
    sha512: "b".repeat(128)
  };
  let recorded = null;
  let reverifyCalls = 0;
  const provider = {
    async listReleases() { return { releases: [selected], sourceBaseUrl: "https://updates.example/" }; },
    async downloadAndVerify() {
      return {
        path: "/private/cache/update.exe",
        signaturePath: "/private/cache/update.exe.asc",
        filename: selected.filename,
        size: selected.size,
        sha512: selected.sha512,
        signatureVerified: true,
        primaryFingerprint: "0".repeat(40),
        signingFingerprints: ["1".repeat(40)]
      };
    },
    async reverifyForInstall(download, release) {
      reverifyCalls += 1;
      assert.equal(download.path, "/private/cache/update.exe");
      assert.equal(release.id, selected.id);
      return download.path;
    }
  };
  const service = new UpdateService({
    appVersion: "0.0.1",
    platform: "win32",
    arch: "x64",
    configStore: {
      get: () => ({ updates: { channel: "alpha", lastLaunchedRelease: null } }),
      recordLaunchedRelease(value) { recorded = value; }
    },
    providerFactory: () => provider
  });
  await service.check();
  await service.download();
  assert.throws(() => service.markInstallerLaunched(), /No verified update/);
  assert.equal(await service.prepareInstallerLaunch(), "/private/cache/update.exe");
  service.markInstallerLaunched();
  assert.equal(reverifyCalls, 1);
  assert.equal(recorded.id, selected.id);
});

test("renderer API cannot provide paths, keys, fingerprints, or verified=true", () => {
  const preload = fs.readFileSync(path.join(__dirname, "..", "src", "preload", "corePreload.js"), "utf8");
  const ipc = fs.readFileSync(path.join(__dirname, "..", "src", "main", "ipc", "registerCoreIpc.js"), "utf8");
  assert.match(preload, /downloadUpdate:\s*\(\)\s*=>\s*ipcRenderer\.invoke\("updates:download"\)/);
  assert.match(preload, /installUpdate:\s*\(\)\s*=>\s*ipcRenderer\.invoke\("updates:install"\)/);
  assert.match(ipc, /await updateService\.prepareInstallerLaunch\(\)/);
  assert.doesNotMatch(preload, /verificationSuccess|signaturePath|publicKeyPath|trustedPrimaryFingerprint|verified\s*:/);
});
