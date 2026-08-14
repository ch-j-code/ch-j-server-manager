"use strict";

const CATEGORIES = Object.freeze({
  recommended: "Recommended / Cryptographic",
  xof: "XOF",
  legacy: "Legacy Cryptographic",
  broken: "Broken / Compatibility only",
  fast: "Fast non-cryptographic",
  checksums: "Checksums"
});

const definitions = [
  ["sha224", "SHA-224", "legacy", 224, "node-crypto"],
  ["sha256", "SHA-256", "recommended", 256, "node-crypto"],
  ["sha384", "SHA-384", "recommended", 384, "node-crypto"],
  ["sha512", "SHA-512", "recommended", 512, "node-crypto"],
  ["sha512-224", "SHA-512/224", "recommended", 224, "noble-hashes"],
  ["sha512-256", "SHA-512/256", "recommended", 256, "node-crypto"],
  ["sha3-224", "SHA3-224", "recommended", 224, "noble-hashes"],
  ["sha3-256", "SHA3-256", "recommended", 256, "noble-hashes"],
  ["sha3-384", "SHA3-384", "recommended", 384, "noble-hashes"],
  ["sha3-512", "SHA3-512", "recommended", 512, "noble-hashes"],
  ["shake128", "SHAKE128", "xof", null, "noble-hashes", { xof: { defaultBytes: 32, minBytes: 16, maxBytes: 1024 } }],
  ["shake256", "SHAKE256", "xof", null, "noble-hashes", { xof: { defaultBytes: 64, minBytes: 16, maxBytes: 1024 } }],
  ["blake2b-512", "BLAKE2b-512", "recommended", 512, "noble-hashes"],
  ["blake2s-256", "BLAKE2s-256", "recommended", 256, "noble-hashes"],
  ["blake3", "BLAKE3", "recommended", 256, "hash-wasm"],
  ["kangaroo-twelve", "KangarooTwelve", "xof", null, "noble-hashes", { xof: { defaultBytes: 32, minBytes: 16, maxBytes: 1024 } }],
  ["ripemd160", "RIPEMD-160", "legacy", 160, "node-crypto"],
  ["whirlpool", "Whirlpool", "legacy", 512, "hash-wasm"],
  ["tiger", "Tiger", "legacy", 192, "bundled-js"],
  ["tiger2", "Tiger2", "legacy", 192, "bundled-js"],
  ["md5", "MD5", "broken", 128, "node-crypto"],
  ["sha1", "SHA-1", "broken", 160, "node-crypto"],
  ["xxh32", "XXH32", "fast", 32, "hash-wasm", { seeded: true, seedBits: 32 }],
  ["xxh64", "XXH64", "fast", 64, "hash-wasm", { seeded: true, seedBits: 64 }],
  ["xxh3-64", "XXH3-64", "fast", 64, "hash-wasm", { seeded: true, seedBits: 64 }],
  ["xxh3-128", "XXH3-128", "fast", 128, "hash-wasm", { seeded: true, seedBits: 64 }],
  ["murmur3-x86-32", "MurmurHash3 x86 32", "fast", 32, "bundled-js", { seeded: true, seedBits: 32 }],
  ["murmur3-x86-128", "MurmurHash3 x86 128", "fast", 128, "bundled-js", { seeded: true, seedBits: 32 }],
  ["murmur3-x64-128", "MurmurHash3 x64 128", "fast", 128, "bundled-js", { seeded: true, seedBits: 32 }],
  ["cityhash32", "CityHash32", "fast", 32, "bundled-js", { randomAccess: true }],
  ["cityhash64", "CityHash64", "fast", 64, "bundled-js", { randomAccess: true }],
  ["cityhash128", "CityHash128", "fast", 128, "bundled-js", { randomAccess: true }],
  ["farmhash32", "FarmHash32", "fast", 32, "farmhashjs", { randomAccess: true }],
  ["farmhash64", "FarmHash64", "fast", 64, "farmhashjs", { randomAccess: true }],
  ["farmhash128", "FarmHash128", "fast", 128, "bundled-js", { randomAccess: true }],
  ["highwayhash64", "HighwayHash64", "fast", 64, "highwayhasher", { keyed: true, keyBytes: 32 }],
  ["highwayhash128", "HighwayHash128", "fast", 128, "highwayhasher", { keyed: true, keyBytes: 32 }],
  ["highwayhash256", "HighwayHash256", "fast", 256, "highwayhasher", { keyed: true, keyBytes: 32 }],
  ["siphash-2-4", "SipHash-2-4", "fast", 64, "bundled-js", { keyed: true, keyBytes: 16 }],
  ["fnv1-32", "FNV-1 32", "fast", 32, "bundled-js"],
  ["fnv1-64", "FNV-1 64", "fast", 64, "bundled-js"],
  ["fnv1a-32", "FNV-1a 32", "fast", 32, "bundled-js"],
  ["fnv1a-64", "FNV-1a 64", "fast", 64, "bundled-js"],
  ["crc16-ccitt-false", "CRC-16/CCITT-FALSE", "checksums", 16, "bundled-js", { parameters: "poly=0x1021 init=0xffff refin=false refout=false xorout=0x0000" }],
  ["crc32", "CRC-32/ISO-HDLC", "checksums", 32, "hash-wasm", { parameters: "poly=0x04c11db7 init=0xffffffff refin=true refout=true xorout=0xffffffff" }],
  ["crc32c", "CRC-32C/Castagnoli", "checksums", 32, "hash-wasm", { parameters: "poly=0x1edc6f41 init=0xffffffff refin=true refout=true xorout=0xffffffff" }],
  ["crc64-ecma", "CRC-64/ECMA-182", "checksums", 64, "bundled-js", { parameters: "poly=0x42f0e1eba9ea3693 init=0 refin=false refout=false xorout=0" }],
  ["crc64-xz", "CRC-64/XZ", "checksums", 64, "bundled-js", { parameters: "poly=0x42f0e1eba9ea3693 init=all-ones refin=true refout=true xorout=all-ones" }],
  ["adler32", "Adler-32", "checksums", 32, "hash-wasm"]
];

const ALGORITHMS = Object.freeze(definitions.map(([id, name, category, digestBits, backend, extra = {}]) => Object.freeze({
  id,
  name,
  category,
  categoryName: CATEGORIES[category],
  digestBits,
  backend,
  cryptographic: category === "recommended" || category === "xof" || category === "legacy" || category === "broken",
  securityStatus: category === "broken" ? "broken" : (category === "fast" || category === "checksums" ? "non-cryptographic" : "cryptographic"),
  supportsStreaming: !extra.randomAccess,
  ...extra
})));
const BY_ID = new Map(ALGORITHMS.map((algorithm) => [algorithm.id, algorithm]));

function getAlgorithms() {
  return ALGORITHMS.map((algorithm) => ({ ...algorithm, xof: algorithm.xof ? { ...algorithm.xof } : undefined }));
}

function normalizeAlgorithmRequests(input) {
  if (!Array.isArray(input) || input.length < 1 || input.length > ALGORITHMS.length) throw typedError("Select between one and all supported algorithms.", "HASH_INVALID_ALGORITHMS");
  const seen = new Set();
  return input.map((source) => {
    const request = typeof source === "string" ? { id: source } : source;
    const algorithm = BY_ID.get(String(request?.id || ""));
    if (!algorithm || seen.has(algorithm.id)) throw typedError(`Unsupported or duplicate algorithm: ${request?.id || "<empty>"}`, "HASH_UNSUPPORTED_ALGORITHM");
    seen.add(algorithm.id);
    const result = { id: algorithm.id };
    if (algorithm.xof) {
      const outputBytes = Number(request.outputBytes ?? algorithm.xof.defaultBytes);
      if (!Number.isSafeInteger(outputBytes) || outputBytes < algorithm.xof.minBytes || outputBytes > algorithm.xof.maxBytes) {
        throw typedError(`${algorithm.name} output must be ${algorithm.xof.minBytes}-${algorithm.xof.maxBytes} bytes.`, "HASH_INVALID_XOF_LENGTH");
      }
      result.outputBytes = outputBytes;
    }
    if (algorithm.seeded) result.seed = normalizeSeed(request.seed, algorithm.seedBits);
    if (algorithm.keyed) {
      const fallback = "00".repeat(algorithm.keyBytes);
      const keyHex = String(request.keyHex || fallback).trim().toLowerCase();
      if (!new RegExp(`^[0-9a-f]{${algorithm.keyBytes * 2}}$`).test(keyHex)) throw typedError(`${algorithm.name} key must be exactly ${algorithm.keyBytes} bytes in hexadecimal.`, "HASH_INVALID_KEY");
      result.keyHex = keyHex;
      result.defaultKey = !request.keyHex;
    }
    return result;
  });
}

function normalizeSeed(value, bits) {
  if (value === undefined || value === null || String(value).trim() === "") return "0";
  const source = String(value).trim();
  if (!/^(?:0x[0-9a-f]+|[0-9]+)$/i.test(source)) throw typedError("Seed must be an unsigned decimal or 0x-prefixed hexadecimal integer.", "HASH_INVALID_SEED");
  const seed = BigInt(source);
  if (seed < 0n || seed >= (1n << BigInt(bits))) throw typedError(`Seed must fit in ${bits} bits.`, "HASH_INVALID_SEED");
  return seed.toString();
}

function typedError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

module.exports = { ALGORITHMS, BY_ID, CATEGORIES, getAlgorithms, normalizeAlgorithmRequests, typedError };
