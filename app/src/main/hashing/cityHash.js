"use strict";

// Ported from google/cityhash. See vendor/cityHash/LICENSE.txt.

const fs = require("node:fs");

const MASK64 = 0xffffffffffffffffn;
const k0 = 0xc3a5c85c97cb3127n;
const k1 = 0xb492b66fbe98f273n;
const k2 = 0x9ae16a3b2f90404fn;
const c1 = 0xcc9e2d51;
const c2 = 0x1b873593;
const u64 = (value) => BigInt.asUintN(64, value);
const u32 = (value) => value >>> 0;

class FileView {
  constructor(fd, length, cacheBytes = 1024 * 1024) {
    this.fd = fd;
    this.length = length;
    this.cacheBytes = cacheBytes;
    this.cache = Buffer.alloc(0);
    this.cacheStart = -1;
  }
  _ensure(offset, width) {
    if (!Number.isSafeInteger(offset) || offset < 0 || offset + width > this.length) throw new RangeError("Hash reader access is outside the selected file.");
    if (offset >= this.cacheStart && offset + width <= this.cacheStart + this.cache.length) return;
    const start = Math.floor(offset / this.cacheBytes) * this.cacheBytes;
    const bytes = Math.min(this.cacheBytes + 16, this.length - start);
    this.cache = Buffer.allocUnsafe(bytes);
    let read = 0;
    while (read < bytes) {
      const count = fs.readSync(this.fd, this.cache, read, bytes - read, start + read);
      if (!count) throw new Error("Selected file ended unexpectedly.");
      read += count;
    }
    this.cacheStart = start;
  }
  byte(offset) { this._ensure(offset, 1); return this.cache[offset - this.cacheStart]; }
  u32(offset) { this._ensure(offset, 4); return this.cache.readUInt32LE(offset - this.cacheStart); }
  u64(offset) { this._ensure(offset, 8); return this.cache.readBigUInt64LE(offset - this.cacheStart); }
}

function rotate32(value, shift) { return shift === 0 ? u32(value) : u32((value >>> shift) | (value << (32 - shift))); }
function rotate64(value, shift) { return shift === 0 ? u64(value) : u64((value >> BigInt(shift)) | (value << BigInt(64 - shift))); }
function bswap32(value) { return (((value & 0xff) << 24) | ((value & 0xff00) << 8) | ((value >>> 8) & 0xff00) | (value >>> 24)) >>> 0; }
function bswap64(value) {
  let output = 0n;
  for (let index = 0n; index < 8n; index += 1n) output |= ((value >> (index * 8n)) & 0xffn) << ((7n - index) * 8n);
  return output;
}
function fmix(value) { value ^= value >>> 16; value = Math.imul(value, 0x85ebca6b); value ^= value >>> 13; value = Math.imul(value, 0xc2b2ae35); return u32(value ^ (value >>> 16)); }
function mur(a, h) { a = Math.imul(a, c1); a = rotate32(a, 17); a = Math.imul(a, c2); h ^= a; h = rotate32(h, 19); return u32(Math.imul(h, 5) + 0xe6546b64); }
function shiftMix(value) { return u64(value ^ (value >> 47n)); }
function hashLen16(u, v, mul = 0x9ddfea08eb382d69n) {
  let a = u64((u ^ v) * mul); a ^= a >> 47n;
  let b = u64((v ^ a) * mul); b ^= b >> 47n;
  return u64(b * mul);
}
function weakHash(view, offset, a, b) {
  const w = view.u64(offset); const x = view.u64(offset + 8); const y = view.u64(offset + 16); const z = view.u64(offset + 24);
  a = u64(a + w); b = rotate64(u64(b + a + z), 21); const c = a;
  a = u64(a + x + y); b = u64(b + rotate64(a, 44));
  return [u64(a + z), u64(b + c)];
}

function cityHash32(view, base = 0, length = view.length - base) {
  const fetch = (offset) => view.u32(base + offset);
  if (length <= 4) {
    let b = 0; let c = 9;
    for (let index = 0; index < length; index += 1) { const byte = view.byte(base + index); const signed = byte > 127 ? byte - 256 : byte; b = u32(Math.imul(b, c1) + signed); c ^= b; }
    return fmix(mur(b, mur(length, c)));
  }
  if (length <= 12) {
    let a = length; let b = u32(length * 5); const c = u32(9 + fetch((length >>> 1) & 4)); const d = b;
    a = u32(a + fetch(0)); b = u32(b + fetch(length - 4));
    return fmix(mur(c, mur(b, mur(a, d))));
  }
  if (length <= 24) {
    const a = fetch(-4 + (length >>> 1)); const b = fetch(4); const c = fetch(length - 8);
    const d = fetch(length >>> 1); const e = fetch(0); const f = fetch(length - 4);
    return fmix(mur(f, mur(e, mur(d, mur(c, mur(b, mur(a, length)))))));
  }
  let h = u32(length); let g = Math.imul(c1, h) >>> 0; let f = g;
  const tail = [length - 4, length - 8, length - 16, length - 12, length - 20].map((offset) => Math.imul(rotate32(Math.imul(fetch(offset), c1), 17), c2) >>> 0);
  h ^= tail[0]; h = u32(Math.imul(rotate32(h, 19), 5) + 0xe6546b64);
  h ^= tail[2]; h = u32(Math.imul(rotate32(h, 19), 5) + 0xe6546b64);
  g ^= tail[1]; g = u32(Math.imul(rotate32(g, 19), 5) + 0xe6546b64);
  g ^= tail[3]; g = u32(Math.imul(rotate32(g, 19), 5) + 0xe6546b64);
  f = u32(f + tail[4]); f = u32(Math.imul(rotate32(f, 19), 5) + 0xe6546b64);
  let offset = 0; let iterations = Math.floor((length - 1) / 20);
  do {
    const a0 = Math.imul(rotate32(Math.imul(fetch(offset), c1), 17), c2) >>> 0;
    const a1 = fetch(offset + 4);
    const a2 = Math.imul(rotate32(Math.imul(fetch(offset + 8), c1), 17), c2) >>> 0;
    const a3 = Math.imul(rotate32(Math.imul(fetch(offset + 12), c1), 17), c2) >>> 0;
    const a4 = fetch(offset + 16);
    h ^= a0; h = u32(Math.imul(rotate32(h, 18), 5) + 0xe6546b64);
    f = u32(f + a1); f = Math.imul(rotate32(f, 19), c1) >>> 0;
    g = u32(g + a2); g = u32(Math.imul(rotate32(g, 18), 5) + 0xe6546b64);
    h ^= u32(a3 + a1); h = u32(Math.imul(rotate32(h, 19), 5) + 0xe6546b64);
    g ^= a4; g = Math.imul(bswap32(g), 5) >>> 0;
    h = bswap32(u32(h + Math.imul(a4, 5))); f = u32(f + a0);
    const oldF = f; f = g; g = h; h = oldF;
    offset += 20; iterations -= 1;
  } while (iterations);
  g = Math.imul(rotate32(Math.imul(rotate32(g, 11), c1), 17), c1) >>> 0;
  f = Math.imul(rotate32(Math.imul(rotate32(f, 11), c1), 17), c1) >>> 0;
  h = rotate32(u32(h + g), 19); h = u32(Math.imul(h, 5) + 0xe6546b64); h = Math.imul(rotate32(h, 17), c1) >>> 0;
  h = rotate32(u32(h + f), 19); h = u32(Math.imul(h, 5) + 0xe6546b64); return Math.imul(rotate32(h, 17), c1) >>> 0;
}

function hash0to16(view, offset, length) {
  if (length >= 8) { const mul = u64(k2 + BigInt(length * 2)); const a = u64(view.u64(offset) + k2); const b = view.u64(offset + length - 8); return hashLen16(u64(rotate64(b, 37) * mul + a), u64((rotate64(a, 25) + b) * mul), mul); }
  if (length >= 4) { const mul = u64(k2 + BigInt(length * 2)); const a = BigInt(view.u32(offset)); return hashLen16(BigInt(length) + (a << 3n), BigInt(view.u32(offset + length - 4)), mul); }
  if (length > 0) { const a = BigInt(view.byte(offset)); const b = BigInt(view.byte(offset + (length >>> 1))); const c = BigInt(view.byte(offset + length - 1)); const y = a + (b << 8n); const z = BigInt(length) + (c << 2n); return u64(shiftMix(u64(y * k2 ^ z * k0)) * k2); }
  return k2;
}
function hash17to32(view, offset, length) {
  const mul = u64(k2 + BigInt(length * 2)); const a = u64(view.u64(offset) * k1); const b = view.u64(offset + 8);
  const c = u64(view.u64(offset + length - 8) * mul); const d = u64(view.u64(offset + length - 16) * k2);
  return hashLen16(u64(rotate64(u64(a + b), 43) + rotate64(c, 30) + d), u64(a + rotate64(u64(b + k2), 18) + c), mul);
}
function hash33to64(view, offset, length) {
  const mul = u64(k2 + BigInt(length * 2)); let a = u64(view.u64(offset) * k2); let b = view.u64(offset + 8); const c = view.u64(offset + length - 24); const d = view.u64(offset + length - 32);
  const e = u64(view.u64(offset + 16) * k2); const f = u64(view.u64(offset + 24) * 9n); const g = view.u64(offset + length - 8); const h = u64(view.u64(offset + length - 16) * mul);
  const u = u64(rotate64(u64(a + g), 43) + u64((rotate64(b, 30) + c) * 9n)); const v = u64(((a + g) ^ d) + f + 1n);
  const w = u64(bswap64(u64((u + v) * mul)) + h); const x = u64(rotate64(u64(e + f), 42) + c); const y = u64((bswap64(u64((v + w) * mul)) + g) * mul); const z = u64(e + f + c);
  a = u64(bswap64(u64((x + z) * mul + y)) + b); b = u64(shiftMix(u64((z + a) * mul + d + h)) * mul); return u64(b + x);
}

function cityHash64(view, base = 0, length = view.length - base) {
  if (length <= 16) return hash0to16(view, base, length);
  if (length <= 32) return hash17to32(view, base, length);
  if (length <= 64) return hash33to64(view, base, length);
  let x = view.u64(base + length - 40); let y = u64(view.u64(base + length - 16) + view.u64(base + length - 56));
  let z = hashLen16(u64(view.u64(base + length - 48) + BigInt(length)), view.u64(base + length - 24));
  let v = weakHash(view, base + length - 64, BigInt(length), z); let w = weakHash(view, base + length - 32, u64(y + k1), x);
  x = u64(x * k1 + view.u64(base)); let remaining = (length - 1) & ~63; let offset = base;
  do {
    x = u64(rotate64(u64(x + y + v[0] + view.u64(offset + 8)), 37) * k1); y = u64(rotate64(u64(y + v[1] + view.u64(offset + 48)), 42) * k1);
    x ^= w[1]; y = u64(y + v[0] + view.u64(offset + 40)); z = u64(rotate64(u64(z + w[0]), 33) * k1);
    v = weakHash(view, offset, u64(v[1] * k1), u64(x + w[0])); w = weakHash(view, offset + 32, u64(z + w[1]), u64(y + view.u64(offset + 16)));
    [z, x] = [x, z]; offset += 64; remaining -= 64;
  } while (remaining);
  return hashLen16(u64(hashLen16(v[0], w[0]) + u64(shiftMix(y) * k1) + z), u64(hashLen16(v[1], w[1]) + x));
}

function cityMurmur(view, offset, length, seed) {
  let a = seed[0]; let b = seed[1]; let c = 0n; let d = 0n; let position = offset; let remaining = length;
  if (remaining <= 16) { a = u64(shiftMix(u64(a * k1)) * k1); c = u64(b * k1 + hash0to16(view, position, remaining)); d = shiftMix(u64(a + (remaining >= 8 ? view.u64(position) : c))); }
  else {
    c = hashLen16(u64(view.u64(position + remaining - 8) + k1), a); d = hashLen16(u64(b + BigInt(remaining)), u64(c + view.u64(position + remaining - 16))); a = u64(a + d);
    do { a ^= u64(shiftMix(u64(view.u64(position) * k1)) * k1); a = u64(a * k1); b ^= a; c ^= u64(shiftMix(u64(view.u64(position + 8) * k1)) * k1); c = u64(c * k1); d ^= c; position += 16; remaining -= 16; } while (remaining > 16);
  }
  a = hashLen16(a, c); b = hashLen16(d, b); return [u64(a ^ b), hashLen16(b, a)];
}

function cityHash128WithSeed(view, base, length, seed) {
  if (length < 128) return cityMurmur(view, base, length, seed);
  let x = seed[0]; let y = seed[1]; let z = u64(BigInt(length) * k1); let offset = base; let remaining = length;
  let v = [u64(rotate64(y ^ k1, 49) * k1 + view.u64(offset)), 0n]; v[1] = u64(rotate64(v[0], 42) * k1 + view.u64(offset + 8));
  let w = [u64(rotate64(u64(y + z), 35) * k1 + x), u64(rotate64(u64(x + view.u64(offset + 88)), 53) * k1)];
  do {
    for (let pass = 0; pass < 2; pass += 1) {
      x = u64(rotate64(u64(x + y + v[0] + view.u64(offset + 8)), 37) * k1); y = u64(rotate64(u64(y + v[1] + view.u64(offset + 48)), 42) * k1);
      x ^= w[1]; y = u64(y + v[0] + view.u64(offset + 40)); z = u64(rotate64(u64(z + w[0]), 33) * k1);
      v = weakHash(view, offset, u64(v[1] * k1), u64(x + w[0])); w = weakHash(view, offset + 32, u64(z + w[1]), u64(y + view.u64(offset + 16))); [z, x] = [x, z]; offset += 64;
    }
    remaining -= 128;
  } while (remaining >= 128);
  x = u64(x + rotate64(u64(v[0] + z), 49) * k0); y = u64(y * k0 + rotate64(w[1], 37)); z = u64(z * k0 + rotate64(w[0], 27)); w[0] = u64(w[0] * 9n); v[0] = u64(v[0] * k0);
  for (let done = 0; done < remaining;) {
    done += 32; y = u64(rotate64(u64(x + y), 42) * k0 + v[1]); w[0] = u64(w[0] + view.u64(offset + remaining - done + 16)); x = u64(x * k0 + w[0]);
    z = u64(z + w[1] + view.u64(offset + remaining - done)); w[1] = u64(w[1] + v[0]); v = weakHash(view, offset + remaining - done, u64(v[0] + z), v[1]); v[0] = u64(v[0] * k0);
  }
  x = hashLen16(x, v[0]); y = hashLen16(u64(y + z), w[0]); return [u64(hashLen16(u64(x + v[1]), w[1]) + y), u64(hashLen16(u64(x + w[1]), u64(y + v[1])))];
}

function cityHash128(view, base = 0, length = view.length - base) {
  return length >= 16 ? cityHash128WithSeed(view, base + 16, length - 16, [view.u64(base), u64(view.u64(base + 8) + k0)]) : cityHash128WithSeed(view, base, length, [k0, k1]);
}

function numericDigest(value, bytes) { const output = Buffer.alloc(bytes); if (bytes === 4) output.writeUInt32BE(value); else output.writeBigUInt64BE(value); return output; }
function digest128(value) { const output = Buffer.alloc(16); output.writeBigUInt64BE(value[1], 0); output.writeBigUInt64BE(value[0], 8); return output; }

module.exports = { FileView, cityHash32, cityHash64, cityHash128, digest128, numericDigest };
