"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { promisify } = require("node:util");
const { atomicWriteJson } = require("../storage/atomicFile");

const scryptAsync = promisify(crypto.scrypt);
const KEY_LENGTH = 32;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const AAD = Buffer.from("CHJ_CORE_VAULT_V1", "utf8");
const SCRYPT = Object.freeze({ N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
const MIN_PASSWORD_LENGTH = 4;
const MAX_PASSWORD_LENGTH = 64;

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function initialVault() {
  return {
    schemaVersion: 1,
    profiles: [],
    hostKeys: {},
    secrets: {}
  };
}

function validatePassword(password) {
  const value = String(password || "");
  if (value.includes("\0")) throw new Error("Password contains an invalid character.");
  const length = Array.from(value).length;
  if (length < MIN_PASSWORD_LENGTH || length > MAX_PASSWORD_LENGTH) {
    throw new Error(`Vault password must contain ${MIN_PASSWORD_LENGTH} to ${MAX_PASSWORD_LENGTH} characters.`);
  }
  return value;
}

function validateVaultData(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Vault data is invalid.");
  if (Number(value.schemaVersion) !== 1) throw new Error("Unsupported vault data schema.");
  if (!Array.isArray(value.profiles)) throw new Error("Vault profiles are invalid.");
  if (!value.hostKeys || typeof value.hostKeys !== "object" || Array.isArray(value.hostKeys)) throw new Error("Vault host keys are invalid.");
  if (!value.secrets || typeof value.secrets !== "object" || Array.isArray(value.secrets)) value.secrets = {};
  return value;
}

class VaultStore {
  constructor(rootDir) {
    this.rootDir = path.join(rootDir, "vault");
    this.metaPath = path.join(this.rootDir, "core-v1.meta.json");
    this.dataPath = path.join(this.rootDir, "core-v1.data.json");
    this.key = null;
    this.data = null;
    this.generation = 0;
  }

  status() {
    const metaExists = fs.existsSync(this.metaPath);
    const dataExists = fs.existsSync(this.dataPath);
    const initialized = metaExists && dataExists;
    return {
      initialized,
      needsSetup: !metaExists && !dataExists,
      damaged: metaExists !== dataExists,
      unlocked: Boolean(this.key && this.data)
    };
  }

  async create(password) {
    const generation = this.generation;
    const status = this.status();
    if (status.initialized) throw new Error("Vault is already initialized.");
    if (status.damaged) throw new Error("Vault files are incomplete. Restore or remove them before setup.");
    const normalized = validatePassword(password);
    const salt = crypto.randomBytes(SALT_LENGTH);
    const key = await this._deriveKey(normalized, salt);
    if (generation !== this.generation || !this.status().needsSetup) { key.fill(0); throw new Error("Vault operation cancelled."); }
    const data = initialVault();
    const now = new Date().toISOString();
    try {
      atomicWriteJson(this.metaPath, {
        formatVersion: 1,
        dataSchemaVersion: 1,
        createdAt: now,
        updatedAt: now,
        cipher: "aes-256-gcm",
        kdf: { name: "scrypt", N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, keyLength: KEY_LENGTH },
        salt: salt.toString("base64")
      });
      this._writeEncryptedData(data, key);
      this._setSession(key, data);
      return this.status();
    } catch (error) {
      key.fill(0);
      try { fs.unlinkSync(this.metaPath); } catch {}
      try { fs.unlinkSync(this.dataPath); } catch {}
      throw error;
    }
  }

  async unlock(password) {
    const generation = this.generation, instance = this.instanceId();
    if (!this.status().initialized) throw new Error("Vault setup is required or its files are incomplete.");
    const normalized = validatePassword(password);
    let key;
    try {
      const meta = JSON.parse(fs.readFileSync(this.metaPath, "utf8"));
      if (meta.formatVersion !== 1 || meta.cipher !== "aes-256-gcm" || meta.kdf?.name !== "scrypt") {
        throw new Error("Unsupported vault format.");
      }
      const salt = Buffer.from(String(meta.salt || ""), "base64");
      if (salt.length !== SALT_LENGTH) throw new Error("Vault salt is invalid.");
      key = await this._deriveKey(normalized, salt, meta.kdf);
      if (generation !== this.generation || instance !== this.instanceId()) throw new Error("Vault operation cancelled.");
      const data = this._readEncryptedData(key);
      this._setSession(key, data);
      return this.status();
    } catch (error) {
      key?.fill(0);
      const failure = new Error("Vault password is incorrect or the vault is damaged.");
      failure.code = "VAULT_UNLOCK_FAILED";
      throw failure;
    }
  }

  // Main-process-only key operations. No IPC route exposes these buffers.
  instanceId() {
    if (!this.status().initialized) return null;
    const meta = JSON.parse(fs.readFileSync(this.metaPath, "utf8"));
    return crypto.createHash("sha256").update(JSON.stringify([meta.formatVersion, meta.createdAt, meta.salt])).digest("hex");
  }

  async withUnlockKey(operation) {
    this._assertUnlocked();
    const copy = Buffer.from(this.key);
    try { return await operation(copy); } finally { copy.fill(0); }
  }

  async verifyPassword(password) {
    this._assertUnlocked();
    const generation = this.generation;
    const meta = JSON.parse(fs.readFileSync(this.metaPath, "utf8"));
    const key = await this._deriveKey(validatePassword(password), Buffer.from(meta.salt, "base64"), meta.kdf);
    try {
      this._assertUnlocked();
      if (generation !== this.generation) throw Object.assign(new Error("Master password required."), { code: "BIOMETRIC_MASTER_PASSWORD_REQUIRED" });
      if (!crypto.timingSafeEqual(key, this.key)) throw Object.assign(new Error("Master password required."), { code: "BIOMETRIC_MASTER_PASSWORD_REQUIRED" });
      this._readEncryptedData(key);
      return true;
    } finally { key.fill(0); }
  }

  unlockWithKey(key) {
    if (!this.status().initialized || !Buffer.isBuffer(key) || key.length !== KEY_LENGTH) {
      throw Object.assign(new Error("Invalid protected unlocking key."), { code: "BIOMETRIC_INVALID_KEY" });
    }
    const copy = Buffer.from(key);
    try {
      const data = this._readEncryptedData(copy); // AES-GCM authentication must succeed first.
      this._setSession(copy, data);
      return this.status();
    } catch (_) {
      copy.fill(0);
      throw Object.assign(new Error("Biometric enrollment is no longer valid. Use the master password."), { code: "BIOMETRIC_ENROLLMENT_INVALIDATED" });
    }
  }

  lock() {
    this.generation++;
    if (Buffer.isBuffer(this.key)) this.key.fill(0);
    this.key = null;
    this.data = null;
    return this.status();
  }

  reset(confirmation) {
    if (confirmation !== "SMAZAT") {
      const error = new Error("Vault reset confirmation is invalid.");
      error.code = "VAULT_RESET_CONFIRMATION_REQUIRED";
      throw error;
    }
    this.lock();
    fs.rmSync(this.rootDir, { recursive: true, force: true });
    const status = this.status();
    if (!status.needsSetup) {
      const error = new Error("Vault data could not be removed completely.");
      error.code = "VAULT_RESET_FAILED";
      throw error;
    }
    return status;
  }

  getData() {
    this._assertUnlocked();
    return clone(this.data);
  }

  replaceData(nextData) {
    this._assertUnlocked();
    const normalized = validateVaultData(clone(nextData));
    this._writeEncryptedData(normalized, this.key);
    this.data = normalized;
    return this.getData();
  }

  update(mutator) {
    this._assertUnlocked();
    const draft = this.getData();
    const result = mutator(draft);
    this.replaceData(draft);
    return result;
  }

  _assertUnlocked() {
    if (!this.key || !this.data) {
      const error = new Error("Vault is locked.");
      error.code = "VAULT_LOCKED";
      throw error;
    }
  }

  async _deriveKey(password, salt, params = SCRYPT) {
    return Buffer.from(await scryptAsync(password, salt, KEY_LENGTH, {
      N: Number(params.N || SCRYPT.N),
      r: Number(params.r || SCRYPT.r),
      p: Number(params.p || SCRYPT.p),
      maxmem: SCRYPT.maxmem
    }));
  }

  _writeEncryptedData(data, key) {
    const plaintext = Buffer.from(JSON.stringify(validateVaultData(clone(data))), "utf8");
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(AAD);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();
    try {
      atomicWriteJson(this.dataPath, {
        formatVersion: 1,
        updatedAt: new Date().toISOString(),
        iv: iv.toString("base64"),
        authTag: authTag.toString("base64"),
        ciphertext: ciphertext.toString("base64")
      });
    } finally {
      plaintext.fill(0);
      ciphertext.fill(0);
    }
  }

  _readEncryptedData(key) {
    const blob = JSON.parse(fs.readFileSync(this.dataPath, "utf8"));
    if (blob.formatVersion !== 1) throw new Error("Unsupported encrypted vault data.");
    const iv = Buffer.from(String(blob.iv || ""), "base64");
    const authTag = Buffer.from(String(blob.authTag || ""), "base64");
    const ciphertext = Buffer.from(String(blob.ciphertext || ""), "base64");
    if (iv.length !== IV_LENGTH || authTag.length !== 16 || ciphertext.length === 0) throw new Error("Encrypted vault data is invalid.");
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(AAD);
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    try {
      return validateVaultData(JSON.parse(plaintext.toString("utf8")));
    } finally {
      plaintext.fill(0);
      ciphertext.fill(0);
    }
  }

  _setSession(key, data) {
    this.lock();
    this.key = key;
    this.data = validateVaultData(clone(data));
  }
}

module.exports = {
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
  VaultStore,
  initialVault,
  validatePassword,
  validateVaultData
};
