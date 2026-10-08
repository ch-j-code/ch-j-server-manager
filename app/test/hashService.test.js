"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vectors = require("./fixtures/hash-vectors.json");
const { LocalHashService } = require("../src/main/hashing/localHashService");
const { ALGORITHMS } = require("../src/main/hashing/hashAlgorithms");

const SIP_KEY = "000102030405060708090a0b0c0d0e0f";
const HIGHWAY_KEY = Array.from({ length: 32 }, (_unused, index) => index.toString(16).padStart(2, "0")).join("");

function requests() {
  return ALGORITHMS.map((algorithm) => ({
    id: algorithm.id,
    ...(algorithm.id === "siphash-2-4" ? { keyHex: SIP_KEY } : {}),
    ...(algorithm.id.startsWith("highwayhash") ? { keyHex: HIGHWAY_KEY } : {})
  }));
}

function fixture(t, files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-local-hash-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const paths = {};
  for (const [name, value] of Object.entries(files)) { paths[name] = path.join(root, name); fs.mkdirSync(path.dirname(paths[name]), { recursive: true }); fs.writeFileSync(paths[name], value); }
  return { root, paths };
}

function serviceFor(filePaths, chunkSize = 1024 * 1024, extras = {}) {
  return new LocalHashService({
    chunkSize,
    selectFilesDialog: async () => ({ canceled: false, paths: filePaths }),
    selectDirectoryDialog: async () => ({ canceled: false, path: extras.directory || path.dirname(filePaths[0]) }),
    selectManifestDialog: async () => ({ canceled: false, path: extras.manifest || filePaths[0] }),
    selectSaveDialog: async () => ({ canceled: false, path: extras.destination || path.join(path.dirname(filePaths[0]), "output.txt") }),
    writeClipboard: extras.writeClipboard || (() => {})
  });
}

async function completed(service, pluginId, start) {
  let job = start;
  for (let attempt = 0; attempt < 3000 && ["queued", "running"].includes(job.state); attempt += 1) { await new Promise((resolve) => setTimeout(resolve, 5)); job = service.status(pluginId, job.jobId); }
  assert.equal(job.state, "completed", JSON.stringify(job.error));
  return job;
}

async function hashFile(service, pluginId = "chj.hash-checksum") {
  const selection = await service.selectFiles(pluginId, { multiple: false });
  const job = await completed(service, pluginId, service.start(pluginId, { selectionId: selection.selectionId, algorithms: requests() }));
  assert.equal(job.results[0].status, "COMPLETED", JSON.stringify(job.results[0].error));
  return Object.fromEntries(job.results[0].hashes.map((hash) => [hash.id, hash.hex]));
}

test("algorithm registry contains every specified exact variant and portable metadata", () => {
  assert.equal(ALGORITHMS.length, 49);
  assert.deepEqual(new Set(ALGORITHMS.map((algorithm) => algorithm.id)), new Set(Object.keys(vectors.vectors.abc)));
  assert.equal(ALGORITHMS.find((item) => item.id === "crc16-ccitt-false").parameters, "poly=0x1021 init=0xffff refin=false refout=false xorout=0x0000");
  assert.deepEqual(ALGORITHMS.find((item) => item.id === "shake128").xof, { defaultBytes: 32, minBytes: 16, maxBytes: 1024 });
  assert.deepEqual(ALGORITHMS.find((item) => item.id === "shake256").xof, { defaultBytes: 64, minBytes: 16, maxBytes: 1024 });
  assert.deepEqual(ALGORITHMS.find((item) => item.id === "kangaroo-twelve").xof, { defaultBytes: 32, minBytes: 16, maxBytes: 1024 });
  for (const id of ["sha512-224", "sha3-224", "sha3-256", "sha3-384", "sha3-512", "shake128", "shake256", "blake2b-512", "blake2s-256", "kangaroo-twelve"]) assert.equal(ALGORITHMS.find((item) => item.id === id).backend, "noble-hashes", id);
});

for (const name of ["empty", "abc", "quick"]) {
  test(`all algorithms match pinned reference vectors for ${name}`, async (t) => {
    const { paths } = fixture(t, { vector: vectors.messages[name] });
    assert.deepEqual(await hashFile(serviceFor([paths.vector], 7)), vectors.vectors[name]);
  });
}

test("all algorithms are invariant across 1 B, 7 B, 64 B, 4 KiB, 64 KiB, and 1 MiB chunks", async (t) => {
  const data = Buffer.alloc(8193); for (let index = 0; index < data.length; index += 1) data[index] = (index * 131 + 17) & 0xff;
  const { paths } = fixture(t, { "stream.bin": data });
  const baseline = await hashFile(serviceFor([paths["stream.bin"]], 1024 * 1024));
  for (const chunkSize of [1, 7, 64, 4096, 65536, 1024 * 1024]) assert.deepEqual(await hashFile(serviceFor([paths["stream.bin"]], chunkSize)), baseline, `chunk size ${chunkSize}`);
});

test("selection tokens are opaque, plugin-owned, and arbitrary renderer paths are ignored", async (t) => {
  const { paths } = fixture(t, { "allowed.txt": "allowed", "secret.txt": "secret" });
  const service = serviceFor([paths["allowed.txt"]]); const selection = await service.selectFiles("owner", { multiple: false });
  assert.equal(JSON.stringify(selection).includes(paths["allowed.txt"]), false);
  assert.throws(() => service.start("attacker", { selectionId: selection.selectionId, algorithms: ["sha256"] }), { code: "HASH_INVALID_SELECTION_TOKEN" });
  assert.throws(() => service.start("owner", { selectionId: "missing", path: paths["secret.txt"], algorithms: ["sha256"] }), { code: "HASH_INVALID_SELECTION_TOKEN" });
  const job = await completed(service, "owner", service.start("owner", { selectionId: selection.selectionId, path: paths["secret.txt"], algorithms: ["sha256"] }));
  assert.equal(job.results[0].file.name, "allowed.txt");
  assert.throws(() => service.status("attacker", job.jobId), { code: "HASH_INVALID_JOB" });
  assert.throws(() => service.status("owner", "unknown-job"), { code: "HASH_INVALID_JOB" });
});

test("a file changed after selection is rejected by its stable file identity", async (t) => {
  const { paths } = fixture(t, { file: "abc" }); const service = serviceFor([paths.file]); const selection = await service.selectFiles("p");
  fs.writeFileSync(paths.file, "xyz"); fs.utimesSync(paths.file, new Date(), new Date(Date.now() + 2000));
  const job = await completed(service, "p", service.start("p", { selectionId: selection.selectionId, algorithms: ["sha256"] }));
  assert.equal(job.results[0].status, "ERROR"); assert.equal(job.results[0].error.code, "HASH_FILE_CHANGED");
});

test("verification reports MATCH and MISMATCH without accepting malformed expected hashes", async (t) => {
  const { paths } = fixture(t, { file: "abc" }); const service = serviceFor([paths.file]); const selection = await service.selectFiles("p");
  let job = await completed(service, "p", service.verify("p", { selectionId: selection.selectionId, algorithm: "sha256", expected: vectors.vectors.abc.sha256.toUpperCase() }));
  assert.equal(job.results[0].status, "MATCH");
  job = await completed(service, "p", service.verify("p", { selectionId: selection.selectionId, algorithm: "sha256", expected: "00".repeat(32) }));
  assert.equal(job.results[0].status, "MISMATCH");
  assert.throws(() => service.verify("p", { selectionId: selection.selectionId, algorithm: "sha256", expected: "not-a-hash" }), { code: "HASH_INVALID_EXPECTED" });
});

test("directory enumeration is bounded to the selected root and never follows symlinks", async (t) => {
  const { root, paths } = fixture(t, { "tree/a.txt": "a", "tree/sub/b.txt": "b", "outside.txt": "outside" });
  try { fs.symlinkSync(paths["outside.txt"], path.join(root, "tree", "escape.txt")); } catch (error) { if (process.platform !== "win32") throw error; }
  const service = serviceFor([paths["tree/a.txt"]], 64, { directory: path.join(root, "tree") }); const directory = await service.selectDirectory("p");
  const job = await completed(service, "p", service.start("p", { selectionId: directory.selectionId, algorithms: ["sha256"], recursive: true }));
  assert.deepEqual(job.results.map((result) => result.file.relativePath), ["a.txt", "sub/b.txt"]);
});

test("manifest generation and verification support GNU and reject traversal and symlink escapes", async (t) => {
  const { root, paths } = fixture(t, { "root/a file.txt": "abc", "root/sub/žluťoučký.txt": "unicode", "outside": "secret" });
  const manifest = path.join(root, "checksums.sha256"); const service = serviceFor([paths["root/a file.txt"], paths["root/sub/žluťoučký.txt"]], 7, { directory: path.join(root, "root"), destination: manifest, manifest });
  const source = await service.selectFiles("p", { multiple: true }); const destination = await service.selectManifestDestination("p", { suggestedName: "checksums.sha256" });
  await completed(service, "p", service.generateManifest("p", { selectionId: source.selectionId, destinationSelectionId: destination.selectionId, algorithm: "sha256", format: "gnu" }));
  const generated = fs.readFileSync(manifest, "utf8"); assert.match(generated, /# Algorithm: sha256/); assert.match(generated, /a file\.txt/); assert.match(generated, /žluťoučký\.txt/);
  const manifestToken = await service.selectManifest("p"); const rootToken = await service.selectDirectory("p");
  const verified = await completed(service, "p", service.verifyManifest("p", { manifestSelectionId: manifestToken.selectionId, rootSelectionId: rootToken.selectionId }));
  assert.deepEqual(verified.results.map((result) => result.status), ["MATCH", "MATCH"]);
  fs.writeFileSync(manifest, `${vectors.vectors.abc.sha256}  ../outside\n`);
  const traversalToken = await service.selectManifest("p"); const traversal = await completed(service, "p", service.verifyManifest("p", { manifestSelectionId: traversalToken.selectionId, rootSelectionId: rootToken.selectionId, algorithmId: "sha256" }));
  assert.equal(traversal.results[0].status, "INVALID ENTRY"); assert.equal(traversal.results[0].error.code, "HASH_PATH_ESCAPE");
});

test("BSD and SFV manifests round-trip spaces and Unicode filenames", async (t) => {
  const { root, paths } = fixture(t, { "root/a file.txt": "abc", "root/žluťoučký.txt": "unicode" });
  for (const [format, algorithm, filename] of [["bsd", "fnv1a-64", "checksums.txt"], ["sfv", "crc32", "checksums.sfv"]]) {
    const destinationPath = path.join(root, filename);
    const service = serviceFor([paths["root/a file.txt"], paths["root/žluťoučký.txt"]], 7, { directory: path.join(root, "root"), destination: destinationPath, manifest: destinationPath });
    const source = await service.selectFiles("p", { multiple: true }); const destination = await service.selectManifestDestination("p", { suggestedName: filename });
    await completed(service, "p", service.generateManifest("p", { selectionId: source.selectionId, destinationSelectionId: destination.selectionId, algorithm, format }));
    const manifest = await service.selectManifest("p"); const selectedRoot = await service.selectDirectory("p");
    const verified = await completed(service, "p", service.verifyManifest("p", { manifestSelectionId: manifest.selectionId, rootSelectionId: selectedRoot.selectionId }));
    assert.deepEqual(verified.results.map((result) => result.status), ["MATCH", "MATCH"], format);
  }
});

test("manifest verification rejects absolute, drive, UNC, traversal, and symlink paths", async (t) => {
  const { root, paths } = fixture(t, { "root/safe.txt": "safe", "outside/secret.txt": "secret", manifest: "" });
  let symlinkCreated = false;
  try { fs.symlinkSync(path.join(root, "outside"), path.join(root, "root", "link"), "dir"); symlinkCreated = true; } catch (error) { if (process.platform !== "win32") throw error; }
  const digest = vectors.vectors.abc.sha256;
  const entries = ["../outside/secret.txt", "/etc/passwd", "C:\\Windows\\system.ini", "\\\\server\\share\\file", ...(symlinkCreated ? ["link/secret.txt"] : [])];
  fs.writeFileSync(paths.manifest, entries.map((entry) => `${digest}  ${entry}`).join("\n"));
  const service = serviceFor([paths.manifest], 7, { directory: path.join(root, "root"), manifest: paths.manifest });
  const manifest = await service.selectManifest("p"); const selectedRoot = await service.selectDirectory("p");
  const job = await completed(service, "p", service.verifyManifest("p", { manifestSelectionId: manifest.selectionId, rootSelectionId: selectedRoot.selectionId, algorithmId: "sha256" }));
  assert.equal(job.results.length, entries.length); assert.ok(job.results.every((result) => result.status === "INVALID ENTRY"));
  assert.ok(job.results.slice(0, 4).every((result) => result.error.code === "HASH_PATH_ESCAPE"));
  if (symlinkCreated) assert.equal(job.results.at(-1).error.code, "HASH_SYMLINK_REJECTED");
});

test("cancel stops an active worker and cleanup removes plugin authorization", async (t) => {
  const { paths } = fixture(t, { large: Buffer.alloc(16 * 1024 * 1024, 0x5a) }); const service = serviceFor([paths.large], 4096); const selection = await service.selectFiles("p");
  const started = service.start("p", { selectionId: selection.selectionId, algorithms: requests() }); const cancelled = await service.cancel("p", started.jobId); assert.equal(cancelled.state, "cancelled");
  service.cleanupPlugin("p");
  assert.throws(() => service.start("p", { selectionId: selection.selectionId, algorithms: ["sha256"] }), { code: "HASH_INVALID_SELECTION_TOKEN" });
  assert.throws(() => service.status("p", started.jobId), { code: "HASH_INVALID_JOB" });

  const other = serviceFor([paths.large], 4096); const otherSelection = await other.selectFiles("p"); const active = other.start("p", { selectionId: otherSelection.selectionId, algorithms: requests() });
  other.cleanupPlugin("p"); await new Promise((resolve) => setTimeout(resolve, 20));
  assert.throws(() => other.status("p", active.jobId), { code: "HASH_INVALID_JOB" });
});

test("all 49 algorithms export uppercase HEX and Base64 without altering digest bytes", async (t) => {
  const { paths } = fixture(t, { file: "abc" });
  const service = serviceFor([paths.file], 7);
  const selection = await service.selectFiles("p");
  for (const output of ["hex-upper", "base64"]) {
    const job = await completed(service, "p", service.start("p", { selectionId: selection.selectionId, algorithms: requests(), output }));
    assert.equal(job.results[0].hashes.length, 49);
    for (const hash of job.results[0].hashes) {
      const reference = vectors.vectors.abc[hash.id];
      assert.equal(hash.hex, reference, hash.id);
      assert.equal(hash.value, output === "base64" ? Buffer.from(reference, "hex").toString("base64") : reference.toUpperCase(), hash.id);
    }
  }
});

test("comparison distinguishes matching and different files using all 49 algorithms", async (t) => {
  const { paths } = fixture(t, { a: "abc", b: "abc", c: "different" });
  const service = serviceFor([paths.a], 7);
  const left = await service.selectFiles("p");
  for (const [file, identical] of [[paths.b, true], [paths.c, false]]) {
    service.selectFilesDialog = async () => ({ canceled: false, paths: [file] });
    const right = await service.selectFiles("p");
    const job = await completed(service, "p", service.compare("p", { leftSelectionId: left.selectionId, rightSelectionId: right.selectionId, algorithms: requests() }));
    assert.equal(job.comparison.identical, identical);
    assert.equal(job.results.every((result) => result.status === "COMPLETED" && result.hashes.length === 49), true);
  }
});
