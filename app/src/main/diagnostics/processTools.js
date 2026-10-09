"use strict";
const { spawn } = require("node:child_process");
const net = require("node:net");
const { setTimeout: delay } = require("node:timers/promises");
const { DiagnosticError, checkAbort, stats, now } = require("./common");
const { parsePing } = require("../sessions/latencyMonitor");
function runProcess(executable, args, { timeoutMs = 5000, signal, onLine, maxBytes = 256 * 1024, spawnImpl = spawn } = {}) {
  checkAbort(signal);
  return new Promise((resolve, reject) => {
    const child = spawnImpl(executable, args, { shell: false, windowsHide: true, env: { ...process.env, LC_ALL: "C", LANG: "C" }, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = [], stderr = [], bytes = 0, pending = "", failure, settled = false, killTimer;
    const terminate = (error) => { failure ||= error; child.kill(); killTimer ||= setTimeout(() => child.kill("SIGKILL"), 1000); killTimer.unref?.(); };
    const abort = () => terminate(new DiagnosticError("CANCELLED"));
    const timer = setTimeout(() => terminate(new DiagnosticError("TIMEOUT")), timeoutMs);
    signal?.addEventListener("abort", abort, { once: true });
    const finish = (error, code) => { if (settled) return; settled = true; clearTimeout(timer); clearTimeout(killTimer); signal?.removeEventListener("abort", abort); if (pending && onLine) onLine(pending); error || failure ? reject(error || failure) : resolve({ code, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr).toString("utf8") }); };
    child.once("error", (error) => finish(error));
    child.stdout.on("data", (chunk) => { bytes += chunk.length; if (bytes > maxBytes) return terminate(new DiagnosticError("OUTPUT_LIMIT")); stdout.push(chunk); if (onLine) { pending += chunk.toString("utf8"); const lines = pending.split(/\r?\n/); pending = lines.pop(); lines.forEach(onLine); } });
    child.stderr.on("data", (chunk) => { bytes += chunk.length; if (bytes > maxBytes) return terminate(new DiagnosticError("OUTPUT_LIMIT")); stderr.push(chunk); });
    child.once("close", (code) => finish(null, code));
  });
}
function pingCommand(address, timeoutMs, platform = process.platform) {
  if (!net.isIP(address)) throw new DiagnosticError("INVALID_IP");
  const v6 = net.isIP(address) === 6;
  if (platform === "win32") return { executable: "ping.exe", args: [v6 ? "-6" : "-4", "-n", "1", "-w", String(timeoutMs), address] };
  if (platform === "darwin") return { executable: v6 ? "/sbin/ping6" : "/sbin/ping", args: ["-n", "-c", "1", ...(v6 ? [] : ["-W", String(timeoutMs)]), address] };
  if (platform === "linux") return { executable: "ping", args: [v6 ? "-6" : "-4", "-n", "-c", "1", "-W", String(Math.ceil(timeoutMs / 1000)), address] };
  throw new DiagnosticError("PLATFORM_UNSUPPORTED");
}
function parsePingReply(output) {
  const rttMs = parsePing(output), upper = String(output).match(/<\s*(\d+(?:[.,]\d+)?)\s*ms/i), ttl = String(output).match(/(?:ttl|hlim|hop limit)[=:\s]+(\d+)/i);
  return { received: rttMs !== null || Boolean(upper), rttMs, upperBoundMs: upper ? Number(upper[1].replace(",", ".")) : null, ttl: ttl ? Number(ttl[1]) : null };
}
async function ping(address, options, signal, progress, runner = runProcess) {
  const packets = []; let sent = 0, received = 0, cycle = 0;
  do {
    for (let index = 0; index < options.count; index++) {
      checkAbort(signal); sent++; let packet;
      try {
        const command = pingCommand(address, options.timeoutMs);
        const result = await runner(command.executable, command.args, { timeoutMs: options.timeoutMs + 500, signal });
        const raw = result.stdout.toString("utf8"); const reply = parsePingReply(raw);
        const explicitTimeout = /Request timed out|Request timeout|Zeitüberschreitung|Vypršel.*časov[ýy].*limit/i.test(raw);
        packet = { sequence: sent, address, ...reply, status: reply.received ? "success" : explicitTimeout ? "timeout" : "no-reply", raw: (raw + result.stderr).slice(0, 4096) };
        if (!reply.received && (result.code > (process.platform === "darwin" ? 2 : 1) || /not permitted|permission denied|invalid option|unknown option|network is unreachable|no route to host|general failure|transmit failed/i.test(result.stderr))) packet.status = "error";
      } catch (error) {
        if (signal.aborted) throw error;
        packet = { sequence: sent, address, received: false, rttMs: null, status: error.code === "ENOENT" ? "unavailable" : error.code === "TIMEOUT" ? "timeout" : "error", code: error.code, raw: String(error.message).slice(0, 400) };
      }
      packet.measuredAt = new Date().toISOString();
      if (["unavailable", "error"].includes(packet.status)) sent--;
      if (packet.received) received++;
      packets.push(packet); if (packets.length > 500) packets.shift();
      progress({ kind: "ping-packet", ...packet, sent, received, lossPercent: sent ? 100 * (sent - received) / sent : null, statistics: stats(packets.map((p) => p.rttMs)) });
      if (["unavailable", "error"].includes(packet.status)) return { status: packet.status, code: packet.code || "PING_TOOL_ERROR", reason: packet.raw, address, packets, sent, received, lossPercent: sent ? 100 * (sent - received) / sent : null, statistics: stats(packets.map((p) => p.rttMs)), note: "ICMP failure does not establish server unavailability or prove a firewall." };
      if (index + 1 < options.count) await delay(1000, undefined, { signal });
    }
    cycle++;
    if (options.continuous || cycle < options.repetitions) await delay(1000, undefined, { signal });
  } while (options.continuous || cycle < options.repetitions);
  return { status: received ? "success" : "warning", address, sent, received, lossPercent: sent ? 100 * (sent - received) / sent : null, packets, statistics: stats(packets.map((p) => p.rttMs)), note: "No ICMP reply may mean filtering or loss; it does not establish server unavailability." };
}
function tracerouteCommand(address, options, platform = process.platform) {
  const v6 = net.isIP(address) === 6;
  if (!net.isIP(address)) throw new DiagnosticError("INVALID_IP");
  if (platform === "win32") return { executable: "tracert.exe", args: [v6 ? "-6" : "-4", "-d", "-h", String(options.maxHops), "-w", String(options.timeoutMs), address] };
  if (platform === "darwin") return { executable: v6 ? "/usr/sbin/traceroute6" : "/usr/sbin/traceroute", args: ["-n", "-m", String(options.maxHops), "-w", String(Math.ceil(options.timeoutMs / 1000)), address] };
  if (platform === "linux") return { executable: "traceroute", args: [v6 ? "-6" : "-4", "-n", "-m", String(options.maxHops), "-w", String(options.timeoutMs / 1000), address] };
  throw new DiagnosticError("PLATFORM_UNSUPPORTED");
}
function parseHop(line) {
  const match = String(line).match(/^\s*(\d{1,2})\s+(.+)/); if (!match) return null;
  const tokens = match[2].split(/\s+/), addresses = tokens.map((token) => token.replace(/[()[\],]/g, "")).filter((value) => net.isIP(value));
  const probes = [...match[2].matchAll(/(<\s*)?(\d+(?:[.,]\d+)?)\s*ms|\*/gi)].map((m) => m[0] === "*" ? { status: "timeout", rttMs: null } : { status: "success", rttMs: m[1] ? null : Number(m[2].replace(",", ".")), upperBoundMs: m[1] ? Number(m[2]) : null });
  if (!probes.length && !addresses.length) return null;
  return { hop: Number(match[1]), addresses: [...new Set(addresses)], probes, averageMs: stats(probes.map((p) => p.rttMs)).average, lossPercent: probes.length ? 100 * probes.filter((p) => p.status === "timeout").length / probes.length : null, raw: line.slice(0, 1024) };
}
async function traceroute(address, options, signal, progress, runner = runProcess) {
  const routes = [];
  for (let iteration = 0; iteration < options.repetitions; iteration++) {
    checkAbort(signal); const hops = [], command = tracerouteCommand(address, options);
    try {
      const result = await runner(command.executable, command.args, { signal, timeoutMs: Math.min(180000, options.maxHops * Math.ceil(options.timeoutMs / 1000) * 1000 * 3 + 2000), onLine(line) { const hop = parseHop(line); if (hop) { hops.push(hop); progress({ kind: "trace-hop", iteration, address, ...hop }); } } });
      routes.push({ iteration, hops, exitCode: result.code, raw: result.stdout.toString("utf8").slice(0, 32000), reason: result.stderr.slice(0, 1000) });
    } catch (error) { if (signal.aborted) throw error; if (hops.length) routes.push({ iteration, hops, incomplete: true, reason: error.message }); return { status: error.code === "ENOENT" ? "unavailable" : "error", code: error.code, reason: error.message, address, routes }; }
  }
  return { status: routes.some((route) => route.hops.some((hop) => hop.addresses.some((ip) => ip === address || net.isIP(ip) === 6 && net.isIP(address) === 6 && new URL(`http://[${ip}]/`).hostname === new URL(`http://[${address}]/`).hostname))) ? "success" : routes.every((route) => route.exitCode !== 0 && !route.hops.length) ? "error" : "warning", address, routes, effectiveProbeTimeoutMs: process.platform === "darwin" ? Math.ceil(options.timeoutMs / 1000) * 1000 : options.timeoutMs, routeChanged: routes.length > 1 ? routes.some((route) => JSON.stringify(route.hops.map((h) => h.addresses)) !== JSON.stringify(routes[0].hops.map((h) => h.addresses))) : null, method: process.platform === "win32" ? "ICMP tracert" : "System UDP traceroute", note: "Intermediate timeouts do not prove a broken route. Loss is the fraction of unanswered displayed probes, not end-to-end packet loss." };
}
module.exports = { runProcess, pingCommand, parsePingReply, ping, tracerouteCommand, parseHop, traceroute };
