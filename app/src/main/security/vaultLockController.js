"use strict";
const { EventEmitter } = require("node:events");
class VaultLockController extends EventEmitter {
  constructor({ vaultStore, configStore, biometricService, sessionManager, pluginRuntime, diagnosticsService, now = Date.now, pollMs = 5000 }) {
    super(); Object.assign(this, { vaultStore, configStore, biometricService, sessionManager, pluginRuntime, diagnosticsService, now });
    this.lastActivity = now(); this.locking = null;
    this.timer = setInterval(() => { void this.check().catch(() => {}); }, pollMs); this.timer.unref?.();
  }
  activity() { this.lastActivity = this.now(); }
  async check() {
    const config = this.configStore.get().security;
    if (config.autoLockMinutes > 0 && this.vaultStore.status().unlocked && this.now() - this.lastActivity >= config.autoLockMinutes * 60000) await this.lock("inactivity");
  }
  async lostFocus() { if (this.configStore.get().security.lockOnBlur && this.vaultStore.status().unlocked) await this.lock("focus-loss"); }
  async lock(reason = "manual") {
    if (this.locking) return this.locking;
    this.biometricService.cancel();
    // Clear the key synchronously, before waiting for potentially slow SSH cleanup.
    const status = this.vaultStore.lock();
    this.locking = (async () => {
      try { this.pluginRuntime.closeAll(); this.diagnosticsService?.stopAll(); await this.sessionManager.disconnectAll("vault-" + reason); }
      finally { this.emit("locked", { ...status, reason }); }
      return status;
    })();
    try { return await this.locking; } finally { this.locking = null; }
  }
  dispose() { clearInterval(this.timer); this.biometricService.cancel(); }
}
module.exports = { VaultLockController };
