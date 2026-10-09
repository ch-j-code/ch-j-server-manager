"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { setImmediate: nextTurn } = require("node:timers/promises");
const { LatencyMonitor, measurePing, parsePing } = require("../src/main/sessions/latencyMonitor");
const { SessionManager } = require("../src/main/sessions/sessionManager");

test("ICMP reply parser accepts platform/localized replies and never invents failed/upper-bound values", () => {
  for (const reply of ["64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=24.1 ms", "Antwort von 192.0.2.1: Bytes=32 Zeit=24,1ms TTL=64"]) assert.equal(parsePing(reply), 24.1);
  for (const reply of ["100% packet loss", "Request timed out.", "Reply: time<1ms", "time=0 ms"]) assert.equal(parsePing(reply), null);
});

test("ICMP uses fixed executable arguments without a shell on all client platforms and addresses", async () => {
  for (const platform of ["win32", "darwin", "linux"]) {
    for (const address of ["192.0.2.1", "2001:db8::1"]) {
      let call;
      assert.equal(await measurePing(address, { platform, run(executable, args, options, callback) {
        call = { executable, args, options }; callback(null, "time=31 ms");
      } }), 31);
      assert.equal(call.args.at(-1), address); assert.equal(call.options.shell, false);
      assert.equal(call.options.timeout, 5000); assert.ok(call.args.includes("1"));
    }
  }
  assert.equal(await measurePing("host;touch /tmp/unsafe", { run() { assert.fail("Untrusted command executed"); } }), null);
  assert.equal(await measurePing("192.0.2.1", { run(_exe, _args, _options, cb) { cb(new Error("Blocked")); } }), null);
});

test("monitor measures monotonic SSH duration, tolerates ICMP loss, refreshes without overlap and stops", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let now = 100, calls = 0, resolveRequest;
  const values = [];
  const monitor = new LatencyMonitor({ now: () => now, ping: async () => null, intervalMs: 12000 });
  const stop = monitor.start({ address: "192.0.2.1" }, () => { calls++; return new Promise((resolve) => { resolveRequest = resolve; }); }, (v) => values.push(v));
  await nextTurn();
  t.mock.timers.tick(60000); await nextTurn(); assert.equal(calls, 1);
  now = 131.25; resolveRequest(); await nextTurn();
  assert.equal(values[0].sshRttMs, 31.25); assert.equal(values[0].pingMs, null);
  t.mock.timers.tick(12000); await nextTurn(); assert.equal(calls, 2);
  stop(); resolveRequest(); await nextTurn(); t.mock.timers.tick(60000); await nextTurn();
  assert.equal(calls, 2); assert.equal(values.length, 1);
});

test("failed SSH request publishes unavailable without affecting another session", async () => {
  const values = [], stops = [];
  const monitor = new LatencyMonitor({ ping: async (address) => address === "192.0.2.1" ? 24 : null });
  stops.push(monitor.start({ address: "192.0.2.1" }, async () => { throw new Error("Timeout"); }, (v) => values.push(["a", v])));
  stops.push(monitor.start({ address: "192.0.2.2" }, async () => {}, (v) => values.push(["b", v])));
  await nextTurn(); stops.forEach((stop) => stop());
  assert.equal(values.find(([id]) => id === "a")[1].pingMs, 24);
  assert.equal(values.find(([id]) => id === "a")[1].sshRttMs, null);
  assert.equal(values.find(([id]) => id === "b")[1].pingMs, null);
});

test("connected sessions start/stop monitoring and reject stale results after reconnect", async () => {
  const fingerprint = "ab".repeat(32), callbacks = [], stops = [];
  const manager = new SessionManager({
    profileService: { get: () => ({ id: "p", host: "192.0.2.1", port: 22, username: "user", authMethod: "password" }), getHostKey: () => fingerprint, markUsed() {} },
    latencyMonitor: { start(record, request, publish) { callbacks.push({ record, request, publish }); const stop = { count: 0 }; stops.push(stop); return () => { stop.count++; }; } },
    clientFactory() {
      const client = new EventEmitter();
      client.connect = () => setImmediate(() => client.emit("ready")); client.end = () => {};
      client.shell = (_opts, cb) => { const stream = new EventEmitter(); stream.end = () => {}; cb(null, stream); };
      client.exec = (command, cb) => {
        assert.equal(command, "true"); const stream = new EventEmitter(); stream.stderr = new EventEmitter(); cb(null, stream); setImmediate(() => stream.emit("close", 0));
      };
      return client;
    }
  });
  try {
    await manager.connect({ sessionId: "s", profileId: "p", password: "secret" });
    assert.equal(callbacks.length, 1); await callbacks[0].request();
    callbacks[0].publish({ pingMs: 24, sshRttMs: 31 });
    assert.equal(manager.list()[0].latency.sshRttMs, 31);
    await manager.connect({ sessionId: "s", profileId: "p", password: "secret" });
    assert.equal(stops[0].count, 1); assert.equal(manager.list()[0].latency.sshRttMs, null);
    callbacks[0].publish({ pingMs: 999, sshRttMs: 999 });
    assert.equal(manager.list()[0].latency.sshRttMs, null);
    callbacks[1].publish({ pingMs: null, sshRttMs: 12 });
    assert.equal(manager.list()[0].state, "connected");
  } finally { await manager.disconnectAll(); }
  assert.equal(stops[1].count, 1);
});

test("SSH request timeout closes the channel, releases pending work and accepts no late result", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let closed = 0;
  const channel = new EventEmitter(); channel.stderr = new EventEmitter(); channel.close = () => { closed++; };
  const record = { client: { exec(_cmd, cb) { cb(null, channel); } } };
  const manager = new SessionManager({});
  const result = assert.rejects(manager._execFixed(record, "true", 5000), { code: "REMOTE_COMMAND_TIMEOUT" });
  t.mock.timers.tick(5000); await result;
  assert.equal(closed, 1); assert.equal(record.pendingExec.size, 0);
  channel.emit("close", 0);
});

test("terminal latency displays milliseconds, unavailable states and resets on disconnect", () => {
  const fs = require("node:fs"), vm = require("node:vm");
  const source = fs.readFileSync(require.resolve("../src/renderer/app.js"), "utf8");
  const fn = source.slice(source.indexOf("function renderTerminalLatency()"), source.indexOf("async function connectTerminal"));
  const element = {}, state = { terminalStateKind: "connected", terminalLatency: { pingMs: 24, sshRttMs: 31.25 } };
  const { createI18n } = require("../src/renderer/i18n");
  for (const language of ["cs", "de", "en"]) {
    vm.runInNewContext(fn + "\nrenderTerminalLatency();", { state, $: () => element, t: createI18n(language).t });
    assert.match(element.textContent, /24\.0 ms/); assert.match(element.textContent, /31\.3 ms/); assert.equal(element.hidden, false);
  }
  state.terminalLatency = { pingMs: null, sshRttMs: 0 };
  vm.runInNewContext(fn + "\nrenderTerminalLatency();", { state, $: () => element, t: createI18n("en").t });
  assert.match(element.textContent, /Unavailable/); assert.doesNotMatch(element.textContent, /0 ms/);
  state.terminalStateKind = "disconnected";
  vm.runInNewContext(fn + "\nrenderTerminalLatency();", { state, $: () => element, t: createI18n("en").t });
  assert.equal(element.hidden, true);
});
