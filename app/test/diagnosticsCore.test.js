"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { parseTarget, normalizeOptions, stats } = require("../src/main/diagnostics/common");
const { DiagnosticsHistory, scrub, exportReport } = require("../src/main/diagnostics/historyStore");
const { DiagnosticsService, sameIp } = require("../src/main/diagnostics/diagnosticsService");
const { once } = require("node:events");
const fixtureReport = () => ({ id: "a".repeat(32), createdAt: new Date().toISOString(), status: "completed", options: normalizeOptions({ target: "https://localhost/?token=secret", tools: ["ping"] }), addresses: [{ address: "127.0.0.1", family: 4 }], results: { ping: [{ address: "127.0.0.1", status: "success", packets: [{ sequence: 1, rttMs: 1.25 }] }] }, progress: [] });
test("diagnostics validates URLs, IDNA, literals and bounded options before any network activity", () => {
  assert.equal(parseTarget("2001:db8::1").url, "https://[2001:db8::1]/");
  assert.equal(parseTarget("[::1]").host, "::1");
  assert.equal(parseTarget("https://münchen.de/a").host, "xn--mnchen-3ya.de");
  assert.equal(parseTarget("host.test:8443/path").port, 8443);
  for (const value of ["", "a b", "a\n--flag", "-bad.test", "https://user:password@host.test", "file:///tmp/a", "https://host.test\\evil", "; rm -rf /"]) assert.throws(() => parseTarget(value));
  for (const options of [{ count: 0 }, { timeoutMs: 100000 }, { maxHops: 100 }, { ports: Array.from({ length: 17 }, (_, i) => i + 1).join(",") }, { ports: "22;bad" }, { selectedIp: "--help" }, { protocols: ["4"] }, { tools: ["shell"] }, { resolver: "custom", customDns: "evil.test" }]) assert.throws(() => normalizeOptions({ target: "localhost", ...options }));
  assert.ok(sameIp("::1", "0:0:0:0:0:0:0:1")); assert.equal(sameIp("::1", "127.0.0.1"), false);
});
test("statistics exclude unknowns and use measured sequence for jitter", () => {
  const result = stats([1, null, 5, undefined, NaN, 2, 4]);
  assert.equal(result.average, 3); assert.equal(result.median, 3); assert.equal(result.p95, 5);
  assert.equal(result.jitter, 3); assert.equal(result.stddev, Math.sqrt(2.5));
  assert.equal(stats([]).average, null);
});
test("history round-trips private metadata, sanitizes secrets, exports CSV/TXT and rejects malformed imports", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-diagnostics-")); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const history = new DiagnosticsHistory(root), report = fixtureReport();
  report.options.target.input = "localhost/?token=othersecret";
  report.results.http = [{ comparisons: [{ protocol: "1.1", address: "127.0.0.1", samples: [{ status: "success", headers: { "set-cookie": "session=secret", authorization: "secret" }, timings: { totalMs: 12 } }] }] }];
  history.add(report); const content = fs.readFileSync(history.file, "utf8");
  assert.ok(!content.includes("secret")); assert.ok(!content.includes("?token"));
  // Windows uses ACLs and does not expose POSIX permission bits through stat.
  if (process.platform !== "win32") assert.equal(fs.statSync(history.file).mode & 0o777, 0o600);
  const loaded = new DiagnosticsHistory(root); assert.equal(loaded.list().length, 1);
  const exported = exportReport(loaded.get(report.id), "json"); const imported = new DiagnosticsHistory(); assert.equal(imported.import(exported), report.id);
  assert.match(exportReport(report, "csv"), /rttMs/); assert.match(exportReport(report, "txt"), /CH-J Server Diagnostics/);
  assert.throws(() => imported.import("{")); assert.throws(() => imported.import(JSON.stringify({ schema: 1, report: { ...report, addresses: "bad" } })));
  const malformed = structuredClone(report); malformed.results.http[0].comparisons[0].samples = "bad";
  assert.throws(() => imported.import(JSON.stringify({ schema: 1, report: malformed })));
  assert.throws(() => imported.import('{"schema":1,"report":{"__proto__":{}}}'));
  let nested = {}; for (let i = 0; i < 30; i++) nested = { nested }; assert.throws(() => scrub(nested));
  imported.remove(report.id); assert.deepEqual(imported.list(), []);
});
function fakeDns(addresses) { return { resolve: async () => addresses, run: async () => ({ status: "success", queries: [] }) }; }
function completion(service) { return new Promise((resolve) => { const listener = (event) => { if (event.kind === "complete") { service.off("progress", listener); resolve(event.report); } }; service.on("progress", listener); }); }
test("dual-stack continuous probes run concurrently, stop preserves packets and completion waits for cleanup", async () => {
  const active = new Set(), cleaned = new Set();
  const service = new DiagnosticsService({ dns: fakeDns([{ address: "127.0.0.1", family: 4 }, { address: "::1", family: 6 }]), adapters: {
    ping: async (address, options, signal, progress) => {
      active.add(address); progress({ kind: "ping-packet", address, sequence: 1, status: "success", sent: 1, received: 1, lossPercent: 0, rttMs: 0.5 });
      await once(signal, "abort"); await new Promise((resolve) => setTimeout(resolve, address === "::1" ? 20 : 5)); cleaned.add(address); throw Object.assign(new Error("CANCELLED"), { code: "CANCELLED" });
    }
  } });
  const done = completion(service); const { id } = service.start({ target: "localhost", tools: ["ping", "dns"], mode: "both", continuous: true });
  assert.throws(() => service.start({ target: "localhost" }), { code: "DIAGNOSTICS_BUSY" });
  await new Promise((resolve) => setTimeout(resolve, 30)); assert.equal(active.size, 2); service.cancel(id);
  const report = await done; assert.equal(report.status, "cancelled"); assert.equal(cleaned.size, 2);
  assert.equal(report.results.ping.length, 2); assert.equal(report.results.ping[0].packets.length, 1); assert.equal(report.results.ping[1].received, 1);
  assert.equal(service.history.list().length, 1);
});
test("stopping a single tool lets other tools finish; offline and unavailable remain structured results", async () => {
  const service = new DiagnosticsService({ dns: fakeDns([{ address: "127.0.0.1", family: 4 }]), adapters: { ping: async (_address, _options, signal) => { await once(signal, "abort"); throw Object.assign(new Error("CANCELLED"), { code: "CANCELLED" }); }, tcp: async () => ({ status: "warning", ports: [{ port: 443, status: "refused" }] }) } });
  const done = completion(service); const { id } = service.start({ target: "localhost", tools: ["ping", "tcp"] });
  await new Promise((r) => setTimeout(r, 15)); service.cancel(id, "ping"); const report = await done;
  assert.equal(report.status, "completed"); assert.equal(report.results.ping[0].status, "cancelled"); assert.equal(report.results.tcp[0].ports[0].status, "refused");
  const offline = new DiagnosticsService({ dns: { resolve: async () => { throw Object.assign(new Error("offline"), { code: "ENETUNREACH" }); }, run: async () => ({ status: "warning", queries: [] }) } });
  const offDone = completion(offline); offline.start({ target: "offline.test", tools: ["ping", "dns"] }); const offReport = await offDone;
  assert.equal(offReport.resolutionError.code, "ENETUNREACH"); assert.equal(offReport.results.ping[0].status, "not-tested");
});
test("specific IPv6 selections are canonicalized and unresolved addresses are rejected", async () => {
  const service = new DiagnosticsService({ dns: fakeDns([{ address: "::1", family: 6 }, { address: "127.0.0.1", family: 4 }]) });
  let done = completion(service); service.start({ target: "localhost", tools: ["dns"], selectedIp: "0:0:0:0:0:0:0:1" }); assert.equal((await done).addresses[0].family, 6);
  done = completion(service); service.start({ target: "localhost", tools: ["dns"], selectedIp: "127.0.0.2" }); assert.equal((await done).error.code, "SELECTED_IP_NOT_RESOLVED");
});
