"use strict";
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { atomicWriteJson } = require("../../storage/atomicFile");
const { biometricError } = require("./nativeRunner");
const REASONS = Object.freeze({ cs: "Ověřte svou totožnost pro CH-J Server Manager", de: "Identität für CH-J Server Manager bestätigen", en: "Verify your identity for CH-J Server Manager" });
class BiometricService {
  constructor({ storageRoot, vaultStore, configStore, adapter, timeoutMs = 70000 }) {
    Object.assign(this, { vaultStore, configStore, adapter, timeoutMs });
    this.file = path.join(storageRoot, "security", "biometrics.json"); this.epoch = 0; this.active = null;
  }
  reason() { return REASONS[this.configStore.get().ui.language] || REASONS.en; }
  metadata() {
    try {
      const value = JSON.parse(fs.readFileSync(this.file, "utf8"));
      if (value.schema !== 1 || !/^[a-f0-9]{64}$/.test(value.entryId) || !/^[a-f0-9]{64}$/.test(value.vaultId)) return null;
      return value;
    } catch { return null; }
  }
  validMetadata() {
    const value = this.metadata();
    return value && value.vaultId === this.vaultStore.instanceId() && value.provider === this.adapter.info.provider ? value : null;
  }
  async getStatus() {
    const availability = await this.adapter.getAvailability();
    const enrolled = this.metadata(), valid = this.validMetadata();
    return { ...availability, enrolled: Boolean(enrolled), enabled: Boolean(valid), code: enrolled && !valid ? "BIOMETRIC_ENROLLMENT_INVALIDATED" : availability.code };
  }
  cancel(code = "BIOMETRIC_CANCELLED") { this.epoch++; this.active?.abort(biometricError(code)); }
  async run(work) {
    if (this.active) throw biometricError("BIOMETRIC_BUSY");
    const controller = new AbortController(), epoch = this.epoch; this.active = controller;
    const check = () => { if (controller.signal.aborted || epoch !== this.epoch) throw controller.signal.reason || biometricError("BIOMETRIC_CANCELLED"); };
    let abort;
    const interrupted = new Promise((_, reject) => { abort = () => reject(controller.signal.reason || biometricError("BIOMETRIC_CANCELLED")); controller.signal.addEventListener("abort", abort, { once: true }); });
    const timer = setTimeout(() => this.cancel("BIOMETRIC_TIMEOUT"), this.timeoutMs);
    try { return await Promise.race([Promise.resolve().then(() => work({ signal: controller.signal, check })), interrupted]); }
    finally { clearTimeout(timer); controller.signal.removeEventListener("abort", abort); if (this.active === controller) this.active = null; }
  }
  async enable() {
    this.vaultStore._assertUnlocked();
    return this.run(async options => {
      const availability = await this.adapter.getAvailability(); options.check();
      if (!availability.available) throw biometricError(availability.code || "BIOMETRIC_UNAVAILABLE");
      const vaultId = this.vaultStore.instanceId(), entryId = crypto.randomBytes(32).toString("hex"), previous = this.metadata();
      await this.adapter.enroll(entryId, this.reason(), options); options.check();
      let attempted = false;
      try {
        await this.vaultStore.withUnlockKey(async key => { options.check(); attempted = true; await this.adapter.storeProtectedKey(entryId, key, options); options.check(); });
        if (vaultId !== this.vaultStore.instanceId()) throw biometricError("BIOMETRIC_ENROLLMENT_INVALIDATED");
        options.check(); atomicWriteJson(this.file, { schema: 1, vaultId, entryId, provider: this.adapter.info.provider });
      } catch (error) { if (attempted) await this.adapter.removeEnrollment(entryId).catch(() => {}); throw error; }
      if (previous && previous.entryId !== entryId) await this.adapter.removeEnrollment(previous.entryId).catch(() => {});
      return this.getStatus();
    });
  }
  async disable({ reset = false } = {}) {
    if (!reset) this.vaultStore._assertUnlocked();
    this.cancel(); const previous = this.metadata();
    // Revocation takes effect locally even if the OS credential store is currently offline.
    try { fs.unlinkSync(this.file); } catch (error) { if (error.code !== "ENOENT") throw error; }
    if (previous) await this.adapter.removeEnrollment(previous.entryId).catch(() => {});
    return { enabled: false, enrolled: false };
  }
  async unlock() {
    if (this.vaultStore.status().unlocked) return this.vaultStore.status();
    const meta = this.validMetadata(); if (!meta) throw biometricError("BIOMETRIC_MASTER_PASSWORD_REQUIRED");
    return this.run(async options => {
      let key;
      try {
        key = await this.adapter.retrieveProtectedKey(meta.entryId, this.reason(), options); options.check();
        if (meta.vaultId !== this.vaultStore.instanceId() || this.validMetadata()?.entryId !== meta.entryId) throw biometricError("BIOMETRIC_ENROLLMENT_INVALIDATED");
        return this.vaultStore.unlockWithKey(key);
      } catch (error) {
        if (["BIOMETRIC_ENROLLMENT_INVALIDATED", "BIOMETRIC_INVALID_KEY"].includes(error.code)) { try { fs.unlinkSync(this.file); } catch {} await this.adapter.removeEnrollment(meta.entryId).catch(() => {}); }
        throw error;
      } finally { if (Buffer.isBuffer(key)) key.fill(0); }
    });
  }
  async authenticateSensitiveAction() {
    this.vaultStore._assertUnlocked();
    return this.run(async options => { await this.adapter.authenticate(this.reason(), options); options.check(); return { authenticated: true }; });
  }
  async requireSensitiveAction() {
    if (this.configStore.get().security.requireSystemAuthentication) await this.authenticateSensitiveAction();
  }
}
module.exports = { BiometricService, REASONS };
