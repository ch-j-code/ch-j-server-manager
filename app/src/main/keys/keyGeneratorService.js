"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const TYPES = new Set(["ed25519", "rsa", "ecdsa", "dsa", "rsa1"]);
const PRIVATE_KEY_FORMATS = new Set(["pem", "openssh", "ppk"]);
const BITS = Object.freeze({ rsa: [2048, 3072, 4096], ecdsa: [256, 384, 521], dsa: [1024], rsa1: [1024] });
const CURVES = Object.freeze({
  256: ["prime256v1", "ecdsa-sha2-nistp256", "nistp256", 32],
  384: ["secp384r1", "ecdsa-sha2-nistp384", "nistp384", 48],
  521: ["secp521r1", "ecdsa-sha2-nistp521", "nistp521", 66]
});

function decodeBase64Url(value) {
  const source = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(source.padEnd(Math.ceil(source.length / 4) * 4, "="), "base64");
}

function sshUint32(value) {
  const result = Buffer.alloc(4); result.writeUInt32BE(Number(value) >>> 0); return result;
}

function sshString(value) {
  const data = Buffer.isBuffer(value) ? value : Buffer.from(String(value), "utf8");
  return Buffer.concat([sshUint32(data.length), data]);
}

function stripLeadingZeroBytes(value) {
  let data = Buffer.from(value || []);
  while (data.length > 1 && data[0] === 0) data = data.subarray(1);
  return data;
}

function sshMpint(value) {
  let data = stripLeadingZeroBytes(value);
  if (!data.length || data.every((byte) => byte === 0)) data = Buffer.alloc(0);
  else if (data[0] & 0x80) data = Buffer.concat([Buffer.from([0]), data]);
  return sshString(data);
}

function comment(value) {
  return String(value || "").replace(/[\r\n\t]+/g, " ").trim().slice(0, 200);
}

function normalize(payload = {}) {
  const type = String(payload.type || "ed25519").toLowerCase();
  if (!TYPES.has(type)) throw new Error("Unsupported key type.");
  if ((type === "dsa" || type === "rsa1") && payload.legacyConfirmed !== true) throw new Error("Legacy key generation requires explicit confirmation.");
  const allowed = BITS[type] || [];
  const defaults = { rsa: 4096, ecdsa: 256, dsa: 1024, rsa1: 1024 };
  const bits = allowed.includes(Number(payload.bits)) ? Number(payload.bits) : (defaults[type] || 0);
  const passphrase = String(payload.passphrase || "");
  if (passphrase.length > 1024 || passphrase.includes("\0")) throw new Error("Invalid key passphrase.");
  const requestedFormat = String(payload.privateKeyFormat || "pem").toLowerCase();
  if (!PRIVATE_KEY_FORMATS.has(requestedFormat)) throw new Error("Unsupported private key format.");
  return { type, bits, passphrase, privateKeyFormat: requestedFormat, comment: comment(payload.comment) };
}

function generatePair(type, bits) {
  if (type === "ed25519") return crypto.generateKeyPairSync("ed25519");
  if (type === "rsa" || type === "rsa1") return crypto.generateKeyPairSync("rsa", { modulusLength: bits, publicExponent: 0x10001 });
  if (type === "ecdsa") return crypto.generateKeyPairSync("ec", { namedCurve: CURVES[bits][0] });
  return crypto.generateKeyPairSync("dsa", { modulusLength: 1024, divisorLength: 160 });
}

function readDerLength(buffer, offset) {
  if (offset >= buffer.length) throw new Error("Invalid DER length.");
  const first = buffer[offset];
  if ((first & 0x80) === 0) return { length: first, nextOffset: offset + 1 };
  const bytes = first & 0x7f;
  if (!bytes || offset + 1 + bytes > buffer.length) throw new Error("Invalid DER length bytes.");
  let length = 0;
  for (let index = 0; index < bytes; index += 1) length = (length * 256) + buffer[offset + 1 + index];
  if (!Number.isSafeInteger(length)) throw new Error("Unsupported DER length size.");
  return { length, nextOffset: offset + 1 + bytes };
}

function readDerElement(buffer, offset = 0) {
  if (!Buffer.isBuffer(buffer) || offset < 0 || offset >= buffer.length) throw new Error("Invalid DER input.");
  const lengthInfo = readDerLength(buffer, offset + 1);
  const valueStart = lengthInfo.nextOffset; const valueEnd = valueStart + lengthInfo.length;
  if (valueEnd > buffer.length) throw new Error("Invalid DER element bounds.");
  return { tag: buffer[offset], valueStart, valueEnd, nextOffset: valueEnd };
}

function derInteger(buffer, element) {
  if (element.tag !== 0x02) throw new Error("Expected DER INTEGER.");
  return stripLeadingZeroBytes(buffer.subarray(element.valueStart, element.valueEnd));
}

function dsaParameters(buffer, algorithm) {
  let cursor = algorithm.valueStart;
  const oid = readDerElement(buffer, cursor); cursor = oid.nextOffset;
  const params = readDerElement(buffer, cursor);
  if (oid.tag !== 0x06 || params.tag !== 0x30 || params.nextOffset !== algorithm.valueEnd) throw new Error("Invalid DSA parameters.");
  cursor = params.valueStart;
  const p = readDerElement(buffer, cursor); cursor = p.nextOffset;
  const q = readDerElement(buffer, cursor); cursor = q.nextOffset;
  const g = readDerElement(buffer, cursor); cursor = g.nextOffset;
  if (cursor !== params.valueEnd) throw new Error("Invalid DSA parameter payload.");
  return { p: derInteger(buffer, p), q: derInteger(buffer, q), g: derInteger(buffer, g) };
}

function dsaPublicNumbers(publicKey) {
  const buffer = Buffer.from(publicKey.export({ type: "spki", format: "der" }));
  const root = readDerElement(buffer); let cursor = root.valueStart;
  const algorithm = readDerElement(buffer, cursor); cursor = algorithm.nextOffset;
  const subject = readDerElement(buffer, cursor);
  if (root.tag !== 0x30 || root.nextOffset !== buffer.length || algorithm.tag !== 0x30 || subject.tag !== 0x03 || subject.nextOffset !== root.valueEnd) throw new Error("Invalid DSA SPKI structure.");
  const encoded = buffer.subarray(subject.valueStart + 1, subject.valueEnd);
  const y = readDerElement(encoded);
  if (buffer[subject.valueStart] !== 0 || y.nextOffset !== encoded.length) throw new Error("Invalid DSA public value.");
  return { ...dsaParameters(buffer, algorithm), y: derInteger(encoded, y) };
}

function dsaPrivateNumbers(privateKey) {
  const buffer = Buffer.from(privateKey.export({ type: "pkcs8", format: "der" }));
  const root = readDerElement(buffer); let cursor = root.valueStart;
  const version = readDerElement(buffer, cursor); cursor = version.nextOffset;
  const algorithm = readDerElement(buffer, cursor); cursor = algorithm.nextOffset;
  const octet = readDerElement(buffer, cursor);
  if (root.tag !== 0x30 || root.nextOffset !== buffer.length || version.tag !== 0x02 || algorithm.tag !== 0x30 || octet.tag !== 0x04 || octet.nextOffset !== root.valueEnd) throw new Error("Invalid DSA PKCS#8 structure.");
  const encoded = buffer.subarray(octet.valueStart, octet.valueEnd); const x = readDerElement(encoded);
  if (x.nextOffset !== encoded.length) throw new Error("Invalid DSA private value.");
  return { ...dsaParameters(buffer, algorithm), x: derInteger(encoded, x) };
}

function keyNumbers(type, pair) {
  if (type === "dsa") return { ...dsaPublicNumbers(pair.publicKey), ...dsaPrivateNumbers(pair.privateKey) };
  const privateJwk = pair.privateKey.export({ format: "jwk" });
  const publicJwk = pair.publicKey.export({ format: "jwk" });
  if (type === "ed25519") return { seed: decodeBase64Url(privateJwk.d), publicRaw: decodeBase64Url(publicJwk.x) };
  if (type === "rsa" || type === "rsa1") return Object.fromEntries(["n", "e", "d", "p", "q", "qi"].map((key) => [key, stripLeadingZeroBytes(decodeBase64Url(privateJwk[key]))]));
  return { d: stripLeadingZeroBytes(decodeBase64Url(privateJwk.d)), x: decodeBase64Url(publicJwk.x), y: decodeBase64Url(publicJwk.y) };
}

function publicMaterial(type, bits, numbers, keyComment) {
  const suffix = keyComment ? ` ${keyComment}` : "";
  if (type === "ed25519") {
    const algorithm = "ssh-ed25519";
    const blob = Buffer.concat([sshString(algorithm), sshString(numbers.publicRaw)]);
    return { algorithm, blob, line: `${algorithm} ${blob.toString("base64")}${suffix}` };
  }
  if (type === "rsa" || type === "rsa1") {
    if (type === "rsa1") {
      const exponent = BigInt(`0x${numbers.e.toString("hex")}`).toString();
      const modulus = BigInt(`0x${numbers.n.toString("hex")}`).toString();
      return { algorithm: "ssh1-rsa", blob: Buffer.concat([sshMpint(numbers.e), sshMpint(numbers.n)]), line: `${bits} ${exponent} ${modulus}${suffix}` };
    }
    const algorithm = "ssh-rsa"; const blob = Buffer.concat([sshString(algorithm), sshMpint(numbers.e), sshMpint(numbers.n)]);
    return { algorithm, blob, line: `${algorithm} ${blob.toString("base64")}${suffix}` };
  }
  if (type === "dsa") {
    const algorithm = "ssh-dss";
    const blob = Buffer.concat([sshString(algorithm), sshMpint(numbers.p), sshMpint(numbers.q), sshMpint(numbers.g), sshMpint(numbers.y)]);
    return { algorithm, blob, line: `${algorithm} ${blob.toString("base64")}${suffix}` };
  }
  const [, algorithm, curve, size] = CURVES[bits];
  const x = numbers.x.length === size ? numbers.x : Buffer.concat([Buffer.alloc(size - numbers.x.length), numbers.x]);
  const y = numbers.y.length === size ? numbers.y : Buffer.concat([Buffer.alloc(size - numbers.y.length), numbers.y]);
  const point = Buffer.concat([Buffer.from([4]), x, y]);
  const blob = Buffer.concat([sshString(algorithm), sshString(curve), sshString(point)]);
  return { algorithm, curve, point, blob, line: `${algorithm} ${blob.toString("base64")}${suffix}` };
}

function pemBlock(name, raw) {
  const base64 = Buffer.from(raw).toString("base64"); const lines = [];
  for (let index = 0; index < base64.length; index += 70) lines.push(base64.slice(index, index + 70));
  return `-----BEGIN ${name}-----\n${lines.join("\n")}\n-----END ${name}-----\n`;
}

function openSshPrivate(type, numbers, material, keyComment) {
  const check = crypto.randomBytes(4); let fields;
  if (type === "ed25519") fields = [sshString(material.algorithm), sshString(numbers.publicRaw), sshString(Buffer.concat([numbers.seed, numbers.publicRaw]))];
  else if (type === "rsa") fields = [sshString(material.algorithm), sshMpint(numbers.n), sshMpint(numbers.e), sshMpint(numbers.d), sshMpint(numbers.qi), sshMpint(numbers.p), sshMpint(numbers.q)];
  else if (type === "dsa") fields = [sshString(material.algorithm), sshMpint(numbers.p), sshMpint(numbers.q), sshMpint(numbers.g), sshMpint(numbers.y), sshMpint(numbers.x)];
  else fields = [sshString(material.algorithm), sshString(material.curve), sshString(material.point), sshMpint(numbers.d)];
  let privateSection = Buffer.concat([check, check, ...fields, sshString(keyComment)]);
  const paddingLength = (8 - (privateSection.length % 8)) % 8;
  if (paddingLength) privateSection = Buffer.concat([privateSection, Buffer.from(Array.from({ length: paddingLength }, (_unused, index) => index + 1))]);
  const raw = Buffer.concat([
    Buffer.from("openssh-key-v1\0", "ascii"), sshString("none"), sshString("none"), sshString(Buffer.alloc(0)),
    sshUint32(1), sshString(material.blob), sshString(privateSection)
  ]);
  return pemBlock("OPENSSH PRIVATE KEY", raw);
}

function ppkPrivateBlob(type, numbers) {
  if (type === "ed25519") return sshString(Buffer.concat([numbers.seed, numbers.publicRaw]));
  if (type === "rsa" || type === "rsa1") return Buffer.concat([sshMpint(numbers.d), sshMpint(numbers.p), sshMpint(numbers.q), sshMpint(numbers.qi)]);
  if (type === "dsa") return sshMpint(numbers.x);
  return sshMpint(numbers.d);
}

function ppkV2(type, material, numbers, keyComment) {
  const publicBlob = material.blob; const privateBlob = ppkPrivateBlob(type, numbers);
  const macData = Buffer.concat([sshString(material.algorithm), sshString("none"), sshString(keyComment), sshString(publicBlob), sshString(privateBlob)]);
  const macKey = crypto.createHash("sha1").update("putty-private-key-file-mac-key", "utf8").digest();
  const privateMac = crypto.createHmac("sha1", macKey).update(macData).digest("hex");
  const lines = (buffer) => buffer.toString("base64").match(/.{1,64}/g) || [""];
  const publicLines = lines(publicBlob); const privateLines = lines(privateBlob);
  return [`PuTTY-User-Key-File-2: ${material.algorithm}`, "Encryption: none", `Comment: ${keyComment}`, `Public-Lines: ${publicLines.length}`, ...publicLines, `Private-Lines: ${privateLines.length}`, ...privateLines, `Private-MAC: ${privateMac}`].join("\n") + "\n";
}

function exportPem(privateKey, passphrase) {
  const options = { type: "pkcs8", format: "pem" };
  if (passphrase) Object.assign(options, { cipher: "aes-256-cbc", passphrase });
  return String(privateKey.export(options));
}

function chooseFormat(input) {
  if (input.type === "rsa1") {
    if (input.passphrase) throw new Error("SSH1 RSA PPK export cannot be protected by a passphrase. Remove it or use a modern key type.");
    return { format: "ppk", notice: input.privateKeyFormat === "ppk" ? "SSH1 RSA je zastaralý formát." : "SSH1 RSA se ukládá jako PuTTY PPK v2." };
  }
  if (input.passphrase && input.privateKeyFormat !== "pem") {
    return { format: "pem", notice: `${input.privateKeyFormat === "ppk" ? "PPK v2" : "OpenSSH"} export s passphrase není ve vestavěném backendu dostupný; byl bezpečně použit šifrovaný PEM/PKCS#8.` };
  }
  return { format: input.privateKeyFormat, notice: input.privateKeyFormat === "ppk" ? "PPK v2 je určen hlavně pro kompatibilitu se staršími nástroji PuTTY." : "" };
}

class KeyGeneratorService {
  constructor(options = {}) {
    this.selectSavePath = options.selectSavePath;
    this.generations = new Map();
  }

  generate(payload) {
    const input = normalize(payload); const pair = generatePair(input.type, input.bits);
    const numbers = keyNumbers(input.type, pair); const material = publicMaterial(input.type, input.bits, numbers, input.comment);
    const privateKeyPem = exportPem(pair.privateKey, input.passphrase);
    const selected = chooseFormat(input);
    const privateKeyOpenSSH = selected.format === "openssh" ? openSshPrivate(input.type, numbers, material, input.comment) : "";
    const privateKeyPpk = selected.format === "ppk" ? ppkV2(input.type, material, numbers, input.comment) : "";
    const privateKey = selected.format === "openssh" ? privateKeyOpenSSH : selected.format === "ppk" ? privateKeyPpk : privateKeyPem;
    const generationId = crypto.randomUUID();
    const baseName = { ed25519: "id_ed25519", rsa: "id_rsa", ecdsa: "id_ecdsa", dsa: "id_dsa", rsa1: "id_rsa1" }[input.type];
    const suggestedName = selected.format === "ppk" ? `${baseName}.ppk` : baseName;
    const result = {
      generationId, type: input.type, bits: input.bits, privateKeyFormat: selected.format, privateKey,
      privateKeyPem, privateKeyOpenSSH, privateKeyPpk, publicKey: material.line, publicKeyOpenSsh: material.line,
      suggestedName, legacy: input.type === "dsa" || input.type === "rsa1", notice: selected.notice
    };
    this.generations.set(generationId, { ...result, createdAt: Date.now() });
    while (this.generations.size > 20) this.generations.delete(this.generations.keys().next().value);
    return { ...result };
  }

  async save(generationId) {
    const generated = this.generations.get(String(generationId || ""));
    if (!generated || Date.now() - generated.createdAt > 10 * 60 * 1000) throw new Error("Generated key expired. Generate it again.");
    if (typeof this.selectSavePath !== "function") throw new Error("Key save dialog is unavailable.");
    const selected = await this.selectSavePath(generated.suggestedName);
    if (!selected || selected.canceled || !selected.path) return { canceled: true };
    const privatePath = path.resolve(selected.path); const publicPath = `${privatePath}.pub`;
    await fs.promises.writeFile(privatePath, generated.privateKey, { encoding: "utf8", mode: 0o600 });
    await fs.promises.writeFile(publicPath, generated.publicKey, { encoding: "utf8", mode: 0o644 });
    await Promise.allSettled([fs.promises.chmod(privatePath, 0o600), fs.promises.chmod(publicPath, 0o644)]);
    return { canceled: false, privatePath, publicPath, privateKeyFormat: generated.privateKeyFormat };
  }
}

module.exports = { BITS, KeyGeneratorService, PRIVATE_KEY_FORMATS, normalize };
