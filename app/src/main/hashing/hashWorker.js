"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const { parentPort, workerData } = require("node:worker_threads");
const hashWasm = require("hash-wasm");
const { FileView, cityHash32, cityHash64, cityHash128, digest128, numericDigest } = require("./cityHash");
const { createPortableHash } = require("./portableHashes");

const NODE_NAMES = Object.freeze({
  sha224: "sha224", sha256: "sha256", sha384: "sha384", sha512: "sha512",
  "sha512-256": "sha512-256",
  ripemd160: "ripemd160", md5: "md5", sha1: "sha1"
});
const RANDOM_ACCESS = new Set(["cityhash32", "cityhash64", "cityhash128", "farmhash32", "farmhash64", "farmhash128"]);

function isCancelled() { return Atomics.load(workerData.cancelView, 0) === 1; }
function cancelledError() { const error = new Error("Hash job was cancelled."); error.code = "HASH_CANCELLED"; return error; }
function checkCancelled() { if (isCancelled()) throw cancelledError(); }
function statIdentity(stat) { return { dev: String(stat.dev), ino: String(stat.ino), size: String(stat.size), mtimeNs: String(stat.mtimeNs) }; }
function sameIdentity(left, right) { return left.dev === String(right.dev) && left.ino === String(right.ino) && left.size === String(right.size) && left.mtimeNs === String(right.mtimeNs); }

async function createContext(request) {
  if (NODE_NAMES[request.id]) {
    const options = request.id.startsWith("shake") ? { outputLength: request.outputBytes } : undefined;
    return crypto.createHash(NODE_NAMES[request.id], options);
  }
  const portable = createPortableHash(request);
  if (portable) return portable;
  const seed = BigInt(request.seed || "0"); const low = Number(seed & 0xffffffffn); const high = Number((seed >> 32n) & 0xffffffffn);
  switch (request.id) {
    case "sha512-224": {
      const { sha512_224 } = await import("@noble/hashes/sha2.js");
      return sha512_224.create();
    }
    case "sha3-224":
    case "sha3-256":
    case "sha3-384":
    case "sha3-512":
    case "shake128":
    case "shake256": {
      const sha3 = await import("@noble/hashes/sha3.js");
      const name = request.id.replace("-", "_");
      return sha3[name].create(request.id.startsWith("shake") ? { dkLen: request.outputBytes } : undefined);
    }
    case "blake2b-512":
    case "blake2s-256": {
      const { blake2b, blake2s } = await import("@noble/hashes/blake2.js");
      return request.id === "blake2b-512" ? blake2b.create({ dkLen: 64 }) : blake2s.create({ dkLen: 32 });
    }
    case "blake3": return hashWasm.createBLAKE3(256);
    case "whirlpool": return hashWasm.createWhirlpool();
    case "xxh32": return hashWasm.createXXHash32(low);
    case "xxh64": return hashWasm.createXXHash64(low, high);
    case "xxh3-64": return hashWasm.createXXHash3(low, high);
    case "xxh3-128": return hashWasm.createXXHash128(low, high);
    case "crc32": return hashWasm.createCRC32(0xedb88320);
    case "crc32c": return hashWasm.createCRC32(0x82f63b78);
    case "adler32": return hashWasm.createAdler32();
    case "kangaroo-twelve": {
      const { kt128 } = await import("@noble/hashes/sha3-addons.js");
      return kt128.create({ dkLen: request.outputBytes });
    }
    case "highwayhash64":
    case "highwayhash128":
    case "highwayhash256": {
      const { WasmHighwayHash } = require("highwayhasher");
      const hash = await WasmHighwayHash.load(Buffer.from(request.keyHex, "hex"));
      return {
        update: (chunk) => hash.append(chunk),
        finalize64: () => hash.finalize64(),
        finalize128: () => hash.finalize128(),
        finalize256: () => hash.finalize256()
      };
    }
    default: throw Object.assign(new Error(`Unsupported algorithm in worker: ${request.id}`), { code: "HASH_UNSUPPORTED_ALGORITHM" });
  }
}

function finishContext(request, context) {
  if (request.id.startsWith("highwayhash")) {
    const method = request.id === "highwayhash64" ? "finalize64" : (request.id === "highwayhash128" ? "finalize128" : "finalize256");
    return Buffer.from(context[method]());
  }
  const result = context.digest("binary");
  return Buffer.isBuffer(result) ? result : (typeof result === "string" ? Buffer.from(result, "latin1") : Buffer.from(result));
}

async function farmDigests(view, requests) {
  const module = await import("farmhashjs");
  const marker = Object.freeze({ fileView: true });
  const virtual = new Proxy({
    length: view.length,
    readUInt32LE: (offset = 0) => { checkCancelled(); return view.u32(offset); },
    readBigUInt64LE: (offset = 0) => { checkCancelled(); return view.u64(offset); },
    readInt8: (offset = 0) => { checkCancelled(); const value = view.byte(offset); return value > 127 ? value - 256 : value; }
  }, {
    get(target, property) {
      if (property in target) return target[property];
      if (typeof property === "string" && /^\d+$/.test(property)) { checkCancelled(); return view.byte(Number(property)); }
      return undefined;
    }
  });
  const originalFrom = Buffer.from;
  Buffer.from = function patchedFrom(value, ...args) { return value === marker ? virtual : originalFrom(value, ...args); };
  try {
    const results = new Map();
    for (const request of requests) {
      checkCancelled();
      if (request.id === "farmhash32") results.set(request.id, numericDigest(module.fingerprint32(marker), 4));
      if (request.id === "farmhash64") results.set(request.id, numericDigest(module.fingerprint64BigInt(marker), 8));
    }
    return results;
  } finally {
    Buffer.from = originalFrom;
  }
}

async function run() {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
  let fd;
  try {
    fd = fs.openSync(workerData.filePath, flags);
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile()) throw Object.assign(new Error("Only regular files can be hashed."), { code: "HASH_NOT_REGULAR_FILE" });
    if (!sameIdentity(workerData.expected, before)) throw Object.assign(new Error("The selected file changed before hashing started."), { code: "HASH_FILE_CHANGED" });
    const streamRequests = workerData.algorithms.filter((request) => !RANDOM_ACCESS.has(request.id));
    const contexts = new Map();
    for (const request of streamRequests) { checkCancelled(); contexts.set(request.id, await createContext(request)); }
    const buffer = Buffer.allocUnsafe(workerData.chunkSize);
    let position = 0; let lastProgress = 0;
    while (position < Number(before.size)) {
      checkCancelled();
      const bytes = fs.readSync(fd, buffer, 0, Math.min(buffer.length, Number(before.size) - position), position);
      if (!bytes) throw Object.assign(new Error("Selected file ended unexpectedly."), { code: "HASH_FILE_CHANGED" });
      const chunk = buffer.subarray(0, bytes);
      for (const context of contexts.values()) context.update(chunk);
      position += bytes;
      const now = Date.now();
      if (now - lastProgress >= 100 || position === Number(before.size)) { parentPort.postMessage({ type: "progress", bytes: position, total: Number(before.size) }); lastProgress = now; }
      await new Promise((resolve) => setImmediate(resolve));
    }
    const results = new Map();
    for (const request of streamRequests) { checkCancelled(); results.set(request.id, finishContext(request, contexts.get(request.id))); }
    const randomRequests = workerData.algorithms.filter((request) => RANDOM_ACCESS.has(request.id));
    if (randomRequests.length) {
      const view = new FileView(fd, Number(before.size));
      const originalEnsure = view._ensure.bind(view);
      view._ensure = (offset, width) => { checkCancelled(); return originalEnsure(offset, width); };
      if (randomRequests.some((request) => request.id === "cityhash32")) results.set("cityhash32", numericDigest(cityHash32(view), 4));
      if (randomRequests.some((request) => request.id === "cityhash64")) results.set("cityhash64", numericDigest(cityHash64(view), 8));
      let value128 = null;
      if (randomRequests.some((request) => request.id === "cityhash128" || request.id === "farmhash128")) value128 = digest128(cityHash128(view));
      if (randomRequests.some((request) => request.id === "cityhash128")) results.set("cityhash128", value128);
      if (randomRequests.some((request) => request.id === "farmhash128")) results.set("farmhash128", Buffer.from(value128));
      const farms = await farmDigests(view, randomRequests.filter((request) => request.id === "farmhash32" || request.id === "farmhash64"));
      for (const [id, digest] of farms) results.set(id, digest);
    }
    const after = fs.fstatSync(fd, { bigint: true });
    if (!sameIdentity(statIdentity(before), after)) throw Object.assign(new Error("The file changed while it was being hashed."), { code: "HASH_FILE_CHANGED" });
    parentPort.postMessage({ type: "complete", results: workerData.algorithms.map((request) => ({ id: request.id, hex: results.get(request.id).toString("hex") })) });
  } catch (error) {
    parentPort.postMessage({ type: "error", code: error?.code || "HASH_INTERNAL_ERROR", message: error?.message || String(error) });
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
  }
}

void run();
