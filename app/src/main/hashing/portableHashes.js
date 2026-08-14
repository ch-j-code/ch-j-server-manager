"use strict";

const Tiger = require("./vendor/fbTiger/Tiger");

const MASK64 = 0xffffffffffffffffn;
const u64 = (value) => BigInt.asUintN(64, value);
const rotl32 = (value, bits) => ((value << bits) | (value >>> (32 - bits))) >>> 0;
const rotl64 = (value, bits) => u64((value << BigInt(bits)) | (value >> BigInt(64 - bits)));

class BlockHash {
  constructor(blockSize) {
    this.blockSize = blockSize;
    this.tail = Buffer.alloc(0);
    this.length = 0n;
  }

  update(value) {
    const input = Buffer.isBuffer(value) ? value : Buffer.from(value);
    this.length += BigInt(input.length);
    let data = this.tail.length ? Buffer.concat([this.tail, input]) : input;
    let offset = 0;
    while (offset + this.blockSize <= data.length) {
      this._block(data, offset);
      offset += this.blockSize;
    }
    this.tail = Buffer.from(data.subarray(offset));
    return this;
  }
}

class TigerHash extends BlockHash {
  constructor(tiger2 = false) {
    super(64);
    this.tiger2 = tiger2;
    this.engine = new Tiger(Tiger.L192);
    this.engine._a = { value: 0x0123456789abcdefn };
    this.engine._b = { value: 0xfedcba9876543210n };
    this.engine._c = { value: 0xf096a5b4c3b2e187n };
  }

  _block(data, offset) {
    const words = [];
    for (let index = 0; index < 8; index += 1) words.push(data.readBigUInt64LE(offset + index * 8));
    this.engine._split(words, 0);
    this.engine._compress();
  }

  digest() {
    const bitLength = u64(this.length * 8n);
    const used = this.tail.length;
    const padLength = used < 56 ? 64 - used : 128 - used;
    const padding = Buffer.alloc(padLength);
    padding[0] = this.tiger2 ? 0x80 : 0x01;
    padding.writeBigUInt64LE(bitLength, padLength - 8);
    const final = Buffer.concat([this.tail, padding]);
    for (let offset = 0; offset < final.length; offset += 64) this._block(final, offset);
    const output = Buffer.alloc(24);
    output.writeBigUInt64LE(this.engine._a.value, 0);
    output.writeBigUInt64LE(this.engine._b.value, 8);
    output.writeBigUInt64LE(this.engine._c.value, 16);
    return output;
  }
}

class FnvHash {
  constructor(bits, variant) {
    this.bits = bits;
    this.variant = variant;
    this.mask = bits === 32 ? 0xffffffffn : MASK64;
    this.prime = bits === 32 ? 0x01000193n : 0x100000001b3n;
    this.value = bits === 32 ? 0x811c9dc5n : 0xcbf29ce484222325n;
  }

  update(input) {
    for (const byte of input) {
      if (this.variant === "1a") this.value ^= BigInt(byte);
      this.value = (this.value * this.prime) & this.mask;
      if (this.variant === "1") this.value ^= BigInt(byte);
    }
    return this;
  }

  digest() {
    const output = Buffer.alloc(this.bits / 8);
    if (this.bits === 32) output.writeUInt32BE(Number(this.value), 0);
    else output.writeBigUInt64BE(this.value, 0);
    return output;
  }
}

class Crc16CcittFalse {
  constructor() { this.value = 0xffff; }
  update(input) {
    for (const byte of input) {
      this.value ^= byte << 8;
      for (let bit = 0; bit < 8; bit += 1) this.value = ((this.value & 0x8000) ? ((this.value << 1) ^ 0x1021) : (this.value << 1)) & 0xffff;
    }
    return this;
  }
  digest() { const output = Buffer.alloc(2); output.writeUInt16BE(this.value); return output; }
}

class Crc64 {
  constructor(reflected) {
    this.reflected = reflected;
    this.value = reflected ? MASK64 : 0n;
    this.polynomial = reflected ? 0xc96c5795d7870f42n : 0x42f0e1eba9ea3693n;
  }
  update(input) {
    for (const byte of input) {
      if (this.reflected) {
        this.value ^= BigInt(byte);
        for (let bit = 0; bit < 8; bit += 1) this.value = (this.value & 1n) ? ((this.value >> 1n) ^ this.polynomial) : (this.value >> 1n);
      } else {
        this.value ^= BigInt(byte) << 56n;
        for (let bit = 0; bit < 8; bit += 1) this.value = u64((this.value & (1n << 63n)) ? ((this.value << 1n) ^ this.polynomial) : (this.value << 1n));
      }
    }
    return this;
  }
  digest() {
    const output = Buffer.alloc(8);
    output.writeBigUInt64BE(this.reflected ? (this.value ^ MASK64) : this.value);
    return output;
  }
}

function fmix32(value) {
  value ^= value >>> 16;
  value = Math.imul(value, 0x85ebca6b) >>> 0;
  value ^= value >>> 13;
  value = Math.imul(value, 0xc2b2ae35) >>> 0;
  return (value ^ (value >>> 16)) >>> 0;
}

function fmix64(value) {
  value ^= value >> 33n;
  value = u64(value * 0xff51afd7ed558ccdn);
  value ^= value >> 33n;
  value = u64(value * 0xc4ceb9fe1a85ec53n);
  return u64(value ^ (value >> 33n));
}

class MurmurX86_32 extends BlockHash {
  constructor(seed = 0) { super(4); this.h1 = Number(BigInt(seed) & 0xffffffffn); }
  _block(data, offset) {
    let k1 = data.readUInt32LE(offset);
    k1 = Math.imul(k1, 0xcc9e2d51) >>> 0;
    k1 = rotl32(k1, 15);
    k1 = Math.imul(k1, 0x1b873593) >>> 0;
    this.h1 ^= k1;
    this.h1 = rotl32(this.h1, 13);
    this.h1 = (Math.imul(this.h1, 5) + 0xe6546b64) >>> 0;
  }
  digest() {
    let k1 = 0;
    if (this.tail.length === 3) k1 ^= this.tail[2] << 16;
    if (this.tail.length >= 2) k1 ^= this.tail[1] << 8;
    if (this.tail.length >= 1) {
      k1 ^= this.tail[0];
      k1 = Math.imul(k1, 0xcc9e2d51) >>> 0;
      k1 = rotl32(k1, 15);
      k1 = Math.imul(k1, 0x1b873593) >>> 0;
      this.h1 ^= k1;
    }
    this.h1 = fmix32((this.h1 ^ Number(this.length & 0xffffffffn)) >>> 0);
    const output = Buffer.alloc(4); output.writeUInt32BE(this.h1); return output;
  }
}

class MurmurX86_128 extends BlockHash {
  constructor(seed = 0) {
    super(16);
    const value = Number(BigInt(seed) & 0xffffffffn);
    this.h1 = value; this.h2 = value; this.h3 = value; this.h4 = value;
  }
  _block(data, offset) {
    let k1 = data.readUInt32LE(offset); let k2 = data.readUInt32LE(offset + 4); let k3 = data.readUInt32LE(offset + 8); let k4 = data.readUInt32LE(offset + 12);
    k1 = Math.imul(rotl32(Math.imul(k1, 0x239b961b) >>> 0, 15), 0xab0e9789) >>> 0; this.h1 ^= k1;
    this.h1 = (Math.imul(rotl32(this.h1, 19), 5) + 0x561ccd1b) >>> 0; this.h1 = (this.h1 + this.h2) >>> 0;
    k2 = Math.imul(rotl32(Math.imul(k2, 0xab0e9789) >>> 0, 16), 0x38b34ae5) >>> 0; this.h2 ^= k2;
    this.h2 = (Math.imul(rotl32(this.h2, 17), 5) + 0x0bcaa747) >>> 0; this.h2 = (this.h2 + this.h3) >>> 0;
    k3 = Math.imul(rotl32(Math.imul(k3, 0x38b34ae5) >>> 0, 17), 0xa1e38b93) >>> 0; this.h3 ^= k3;
    this.h3 = (Math.imul(rotl32(this.h3, 15), 5) + 0x96cd1c35) >>> 0; this.h3 = (this.h3 + this.h4) >>> 0;
    k4 = Math.imul(rotl32(Math.imul(k4, 0xa1e38b93) >>> 0, 18), 0x239b961b) >>> 0; this.h4 ^= k4;
    this.h4 = (Math.imul(rotl32(this.h4, 13), 5) + 0x32ac3b17) >>> 0; this.h4 = (this.h4 + this.h1) >>> 0;
  }
  digest() {
    const tail = this.tail; let k1 = 0; let k2 = 0; let k3 = 0; let k4 = 0;
    for (let index = tail.length - 1; index >= 12; index -= 1) k4 ^= tail[index] << ((index - 12) * 8);
    if (tail.length > 12) { k4 = Math.imul(rotl32(Math.imul(k4, 0xa1e38b93) >>> 0, 18), 0x239b961b) >>> 0; this.h4 ^= k4; }
    for (let index = Math.min(tail.length - 1, 11); index >= 8; index -= 1) k3 ^= tail[index] << ((index - 8) * 8);
    if (tail.length > 8) { k3 = Math.imul(rotl32(Math.imul(k3, 0x38b34ae5) >>> 0, 17), 0xa1e38b93) >>> 0; this.h3 ^= k3; }
    for (let index = Math.min(tail.length - 1, 7); index >= 4; index -= 1) k2 ^= tail[index] << ((index - 4) * 8);
    if (tail.length > 4) { k2 = Math.imul(rotl32(Math.imul(k2, 0xab0e9789) >>> 0, 16), 0x38b34ae5) >>> 0; this.h2 ^= k2; }
    for (let index = Math.min(tail.length - 1, 3); index >= 0; index -= 1) k1 ^= tail[index] << (index * 8);
    if (tail.length) { k1 = Math.imul(rotl32(Math.imul(k1, 0x239b961b) >>> 0, 15), 0xab0e9789) >>> 0; this.h1 ^= k1; }
    const length = Number(this.length & 0xffffffffn);
    this.h1 ^= length; this.h2 ^= length; this.h3 ^= length; this.h4 ^= length;
    this.h1 = (this.h1 + this.h2 + this.h3 + this.h4) >>> 0;
    this.h2 = (this.h2 + this.h1) >>> 0; this.h3 = (this.h3 + this.h1) >>> 0; this.h4 = (this.h4 + this.h1) >>> 0;
    this.h1 = fmix32(this.h1); this.h2 = fmix32(this.h2); this.h3 = fmix32(this.h3); this.h4 = fmix32(this.h4);
    this.h1 = (this.h1 + this.h2 + this.h3 + this.h4) >>> 0;
    this.h2 = (this.h2 + this.h1) >>> 0; this.h3 = (this.h3 + this.h1) >>> 0; this.h4 = (this.h4 + this.h1) >>> 0;
    const output = Buffer.alloc(16); output.writeUInt32BE(this.h1, 0); output.writeUInt32BE(this.h2, 4); output.writeUInt32BE(this.h3, 8); output.writeUInt32BE(this.h4, 12); return output;
  }
}

class MurmurX64_128 extends BlockHash {
  constructor(seed = 0) { super(16); this.h1 = BigInt(seed) & MASK64; this.h2 = this.h1; }
  _block(data, offset) {
    let k1 = data.readBigUInt64LE(offset); let k2 = data.readBigUInt64LE(offset + 8);
    k1 = u64(rotl64(u64(k1 * 0x87c37b91114253d5n), 31) * 0x4cf5ad432745937fn); this.h1 ^= k1;
    this.h1 = u64(rotl64(this.h1, 27) + this.h2); this.h1 = u64(this.h1 * 5n + 0x52dce729n);
    k2 = u64(rotl64(u64(k2 * 0x4cf5ad432745937fn), 33) * 0x87c37b91114253d5n); this.h2 ^= k2;
    this.h2 = u64(rotl64(this.h2, 31) + this.h1); this.h2 = u64(this.h2 * 5n + 0x38495ab5n);
  }
  digest() {
    let k1 = 0n; let k2 = 0n;
    for (let index = this.tail.length - 1; index >= 8; index -= 1) k2 ^= BigInt(this.tail[index]) << BigInt((index - 8) * 8);
    if (this.tail.length > 8) { k2 = u64(rotl64(u64(k2 * 0x4cf5ad432745937fn), 33) * 0x87c37b91114253d5n); this.h2 ^= k2; }
    for (let index = Math.min(this.tail.length - 1, 7); index >= 0; index -= 1) k1 ^= BigInt(this.tail[index]) << BigInt(index * 8);
    if (this.tail.length) { k1 = u64(rotl64(u64(k1 * 0x87c37b91114253d5n), 31) * 0x4cf5ad432745937fn); this.h1 ^= k1; }
    this.h1 ^= this.length; this.h2 ^= this.length;
    this.h1 = u64(this.h1 + this.h2); this.h2 = u64(this.h2 + this.h1);
    this.h1 = fmix64(this.h1); this.h2 = fmix64(this.h2);
    this.h1 = u64(this.h1 + this.h2); this.h2 = u64(this.h2 + this.h1);
    const output = Buffer.alloc(16); output.writeBigUInt64BE(this.h1, 0); output.writeBigUInt64BE(this.h2, 8); return output;
  }
}

class SipHash24 extends BlockHash {
  constructor(key) {
    super(8);
    const k0 = key.readBigUInt64LE(0); const k1 = key.readBigUInt64LE(8);
    this.v0 = 0x736f6d6570736575n ^ k0; this.v1 = 0x646f72616e646f6dn ^ k1;
    this.v2 = 0x6c7967656e657261n ^ k0; this.v3 = 0x7465646279746573n ^ k1;
  }
  _round() {
    this.v0 = u64(this.v0 + this.v1); this.v1 = rotl64(this.v1, 13); this.v1 ^= this.v0; this.v0 = rotl64(this.v0, 32);
    this.v2 = u64(this.v2 + this.v3); this.v3 = rotl64(this.v3, 16); this.v3 ^= this.v2;
    this.v0 = u64(this.v0 + this.v3); this.v3 = rotl64(this.v3, 21); this.v3 ^= this.v0;
    this.v2 = u64(this.v2 + this.v1); this.v1 = rotl64(this.v1, 17); this.v1 ^= this.v2; this.v2 = rotl64(this.v2, 32);
  }
  _compress(message) { this.v3 ^= message; this._round(); this._round(); this.v0 ^= message; }
  _block(data, offset) { this._compress(data.readBigUInt64LE(offset)); }
  digest() {
    let final = (this.length & 0xffn) << 56n;
    for (let index = 0; index < this.tail.length; index += 1) final |= BigInt(this.tail[index]) << BigInt(index * 8);
    this._compress(final); this.v2 ^= 0xffn;
    this._round(); this._round(); this._round(); this._round();
    const output = Buffer.alloc(8); output.writeBigUInt64BE(u64(this.v0 ^ this.v1 ^ this.v2 ^ this.v3)); return output;
  }
}

function createPortableHash(request) {
  const seed = BigInt(request.seed || "0");
  switch (request.id) {
    case "tiger": return new TigerHash(false);
    case "tiger2": return new TigerHash(true);
    case "murmur3-x86-32": return new MurmurX86_32(seed);
    case "murmur3-x86-128": return new MurmurX86_128(seed);
    case "murmur3-x64-128": return new MurmurX64_128(seed);
    case "siphash-2-4": return new SipHash24(Buffer.from(request.keyHex, "hex"));
    case "fnv1-32": return new FnvHash(32, "1");
    case "fnv1-64": return new FnvHash(64, "1");
    case "fnv1a-32": return new FnvHash(32, "1a");
    case "fnv1a-64": return new FnvHash(64, "1a");
    case "crc16-ccitt-false": return new Crc16CcittFalse();
    case "crc64-ecma": return new Crc64(false);
    case "crc64-xz": return new Crc64(true);
    default: return null;
  }
}

module.exports = {
  Crc16CcittFalse,
  Crc64,
  FnvHash,
  MurmurX64_128,
  MurmurX86_32,
  MurmurX86_128,
  SipHash24,
  TigerHash,
  createPortableHash
};
