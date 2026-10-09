"use strict";
const { spawn } = require("node:child_process");
function biometricError(code, message = code) { return Object.assign(new Error(message), { code }); }
class NativeRunner {
  constructor({ executable, args = [], timeoutMs = 65000, spawnImpl = spawn } = {}) { Object.assign(this, { executable, args, timeoutMs, spawnImpl }); }
  run(request, { signal } = {}) {
    if (signal?.aborted) return Promise.reject(biometricError("BIOMETRIC_CANCELLED"));
    return new Promise((resolve, reject) => {
      let child, output = Buffer.alloc(0), settled = false, timer;
      const finish = (error, result) => {
        if (settled) { if (result?.key) result.key = null; return; }
        settled = true; clearTimeout(timer); signal?.removeEventListener("abort", abort);
        output.fill(0); output = Buffer.alloc(0);
        if (error) { try { child?.kill(); } catch {} reject(error); } else resolve(result);
      };
      const abort = () => finish(biometricError("BIOMETRIC_CANCELLED"));
      try { child = this.spawnImpl(this.executable, this.args, { shell: false, windowsHide: true, stdio: ["pipe", "pipe", "pipe"] }); }
      catch { finish(biometricError("BIOMETRIC_UNAVAILABLE")); return; }
      signal?.addEventListener("abort", abort, { once: true });
      timer = setTimeout(() => finish(biometricError("BIOMETRIC_TIMEOUT")), request.op === "status" ? Math.min(8000, this.timeoutMs) : this.timeoutMs);
      child.on("error", () => finish(biometricError("BIOMETRIC_UNAVAILABLE")));
      child.stdin.on("error", () => finish(biometricError("BIOMETRIC_UNAVAILABLE")));
      // Never forward helper stderr, stdin or raw responses to logs or the renderer.
      child.stderr.on("data", () => {});
      child.stdout.on("data", chunk => {
        if (settled) return;
        if (output.length + chunk.length > 16384) { finish(biometricError("BIOMETRIC_FAILED")); return; }
        const previous = output; output = Buffer.concat([output, chunk]); previous.fill(0);
      });
      child.once("close", code => {
        if (settled) return;
        try {
          const value = JSON.parse(output.toString("utf8"));
          if (code !== 0 || value.ok !== true) throw biometricError(/^BIOMETRIC_[A-Z_]+$/.test(value.code) ? value.code : "BIOMETRIC_FAILED");
          finish(null, value);
        } catch (error) { finish(error.code?.startsWith("BIOMETRIC_") ? error : biometricError("BIOMETRIC_FAILED")); }
      });
      const input = Buffer.from(JSON.stringify(request) + "\n");
      child.stdin.end(input, () => input.fill(0));
    });
  }
}
module.exports = { NativeRunner, biometricError };
