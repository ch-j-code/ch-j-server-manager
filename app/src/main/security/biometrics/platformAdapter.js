"use strict";
const path = require("node:path");
const { NativeRunner, biometricError } = require("./nativeRunner");
const PROVIDERS = Object.freeze({ darwin: { provider: "touch-id", protection: "biometry-current-set" }, win32: { provider: "windows-hello", protection: "convenience" }, linux: { provider: "fprintd", protection: "convenience" } });
class PlatformAdapter {
  constructor({ platform = process.platform, resourcesPath, appPath, isPackaged = false, getMainWindow = () => null, runner } = {}) {
    this.platform = platform; this.info = PROVIDERS[platform] || { provider: "none", protection: "unavailable" }; this.getMainWindow = getMainWindow;
    const root = isPackaged ? path.join(resourcesPath, "biometrics") : path.join(appPath, "build", "biometrics");
    this.runner = runner || new NativeRunner(platform === "linux" ? { executable: "/usr/bin/python3", args: [isPackaged ? path.join(root, "linux.py") : path.join(appPath, "src/main/security/biometrics/native/linux.py")] } : { executable: path.join(root, platform === "win32" ? "chj-biometric.exe" : "chj-biometric") });
  }
  async call(op, entryId, reason, key, options) {
    if (!PROVIDERS[this.platform]) throw biometricError("BIOMETRIC_UNAVAILABLE");
    if (entryId && !/^[a-f0-9]{64}$/.test(entryId)) throw biometricError("BIOMETRIC_FAILED");
    const window = this.getMainWindow(); let hwnd = "0";
    if (this.platform === "win32" && op !== "status" && op !== "remove") {
      if (!window || window.isDestroyed()) throw biometricError("BIOMETRIC_CANCELLED");
      const buffer = window.getNativeWindowHandle(); hwnd = (buffer.length === 8 ? buffer.readBigUInt64LE() : BigInt(buffer.readUInt32LE())).toString();
    }
    return this.runner.run({ op, entryId, reason: String(reason || "CH-J Server Manager").slice(0, 200), key: key?.toString("base64"), hwnd, pid: process.pid }, options);
  }
  async getAvailability() {
    try {
      const value = await this.call("status");
      return { ...this.info, available: value.available === true, code: value.code || (value.available ? "BIOMETRIC_AVAILABLE" : "BIOMETRIC_UNAVAILABLE") };
    } catch (error) { return { ...this.info, available: false, code: error.code || "BIOMETRIC_UNAVAILABLE" }; }
  }
  enroll(entryId, reason, options) { return this.call("authenticate", entryId, reason, null, options); }
  authenticate(reason, options) { return this.call("authenticate", null, reason, null, options); }
  removeEnrollment(entryId, options) { return this.call("remove", entryId, null, null, options); }
  storeProtectedKey(entryId, key, options) { return this.call("store", entryId, null, key, options); }
  async retrieveProtectedKey(entryId, reason, options) {
    // Each native retrieve operation includes fresh OS authentication before releasing a key.
    const result = await this.call("retrieve", entryId, reason, null, options);
    if (!/^[A-Za-z0-9+/]{43}=$/.test(result.key || "")) throw biometricError("BIOMETRIC_INVALID_KEY");
    const key = Buffer.from(result.key, "base64"); result.key = null;
    if (key.length !== 32) { key.fill(0); throw biometricError("BIOMETRIC_INVALID_KEY"); }
    return key;
  }
}
module.exports = { PlatformAdapter, PROVIDERS };
