"use strict";

const { execFile } = require("node:child_process");
const net = require("node:net");
const { performance } = require("node:perf_hooks");

function parsePing(stdout) {
  // Parse the reply, not the average or a process duration. Windows localizes
  // "time", so accept the numeric '=…ms' field without relying on that word.
  const match = String(stdout).match(/(?:time\s*[=<]|[=<])\s*(\d+(?:[.,]\d+)?)\s*ms\b/i);
  if (!match) return null;
  const value = Number(match[1].replace(",", "."));
  // '<1ms' is an upper bound, not an exact measurement.
  return Number.isFinite(value) && value > 0 && !/<\s*\d+(?:[.,]\d+)?\s*ms/i.test(stdout) ? value : null;
}

function measurePing(address, { signal, platform = process.platform, run = execFile } = {}) {
  if (!net.isIP(address) || !["win32", "darwin", "linux"].includes(platform)) return Promise.resolve(null);
  const ipv6 = net.isIP(address) === 6;
  const executable = platform === "darwin" ? (ipv6 ? "/sbin/ping6" : "/sbin/ping") : platform === "win32" ? "ping.exe" : "ping";
  const args = platform === "win32" ? [ipv6 ? "-6" : "-4", "-n", "1", "-w", "4000", address]
    : platform === "darwin" ? ["-n", "-c", "1", ...(ipv6 ? [] : ["-W", "4000"]), address]
      : [ipv6 ? "-6" : "-4", "-n", "-c", "1", "-W", "4", address];
  return new Promise((resolve) => {
    run(executable, args, { shell: false, windowsHide: true, timeout: 5000, maxBuffer: 32 * 1024, signal, env: { ...process.env, LC_ALL: "C", LANG: "C" } },
      (error, stdout) => resolve(error ? null : parsePing(stdout)));
  });
}

class LatencyMonitor {
  constructor({ ping = measurePing, now = () => performance.now(), intervalMs = 12000 } = {}) {
    this.ping = ping;
    this.now = now;
    this.intervalMs = intervalMs;
  }

  start(record, request, publish) {
    const controller = new AbortController();
    let timer;
    let stopped = false;
    const sample = async () => {
      const started = this.now();
      const ssh = Promise.resolve().then(request).then(() => {
        const elapsed = this.now() - started;
        return Number.isFinite(elapsed) && elapsed > 0 ? elapsed : null;
      }).catch(() => null);
      const ping = Promise.resolve().then(() => this.ping(record.address, { signal: controller.signal })).catch(() => null);
      const [pingMs, sshRttMs] = await Promise.all([ping, ssh]);
      if (stopped) return;
      const valid = (value) => typeof value === "number" && Number.isFinite(value) && value > 0 ? value : null;
      publish({ pingMs: valid(pingMs), sshRttMs: valid(sshRttMs), measuredAt: new Date().toISOString() });
      // Schedule only after both finish: no overlapping probes or intervals.
      timer = setTimeout(sample, this.intervalMs);
      timer.unref?.();
    };
    void sample();
    return () => { stopped = true; clearTimeout(timer); controller.abort(); };
  }
}

module.exports = { LatencyMonitor, measurePing, parsePing };
