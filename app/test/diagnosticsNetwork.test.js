"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const dgram = require("node:dgram");
const net = require("node:net");
const { once } = require("node:events");
const { DnsDiagnostics, TYPES, parseResponse, readName, reverseName } = require("../src/main/diagnostics/dnsDiagnostics");
const { pingCommand, tracerouteCommand, parsePingReply, parseHop, ping, traceroute, runProcess } = require("../src/main/diagnostics/processTools");
const { normalizeOptions } = require("../src/main/diagnostics/common");
function name(value) { return Buffer.concat([...value.split(".").map((part) => Buffer.concat([Buffer.from([part.length]), Buffer.from(part)])), Buffer.from([0])]); }
function answer(packet, code = 0, records = []) {
  const header = Buffer.from(packet.subarray(0, 12)); header.writeUInt16BE(0x8180 | code, 2); header.writeUInt16BE(records.length, 6);
  return Buffer.concat([header, packet.subarray(12), ...records.map(([type, data]) => {
    const fields = Buffer.alloc(12); fields.writeUInt16BE(0xc00c); fields.writeUInt16BE(TYPES[type], 2); fields.writeUInt16BE(1, 4); fields.writeUInt32BE(60, 6); fields.writeUInt16BE(data.length, 10);
    return Buffer.concat([fields, data]);
  })]);
}
const options = normalizeOptions({ target: "example.test", tools: ["dns"], timeoutMs: 250, resolver: "custom", customDns: "127.0.0.1" });
const signal = () => new AbortController().signal;
test("DNS wire decoding retains TTL, NXDOMAIN/NODATA/SERVFAIL, DNSSEC records and never claims validation", () => {
  const header = Buffer.alloc(12); header.writeUInt16BE(1234); header.writeUInt16BE(1, 4);
  const packet = Buffer.concat([header, name("example.test"), Buffer.from([0, 1, 0, 1])]);
  const decoded = parseResponse(answer(packet, 0, [["A", Buffer.from([127,0,0,1])], ["DS", Buffer.from([0,1,8,2,0xab,0xcd])], ["DNSKEY", Buffer.from([1,1,3,8,1,2,3])]]), 1234, "A");
  assert.equal(decoded.records[0].ttl, 60); assert.equal(decoded.questionName, "example.test"); assert.equal(decoded.records[1].value.digest, "abcd"); assert.equal(decoded.dnssec, "not-validated");
  assert.equal(parseResponse(answer(packet, 3), 1234, "A").status, "nxdomain");
  assert.equal(parseResponse(answer(packet, 2), 1234, "A").status, "servfail");
  assert.equal(parseResponse(answer(packet), 1234, "A").status, "nodata");
  assert.throws(() => parseResponse(answer(packet), 999, "A")); assert.throws(() => readName(Buffer.from([0xc0,0]), 0));
  assert.equal(reverseName("127.0.0.1"), "1.0.0.127.in-addr.arpa"); assert.ok(reverseName("::1").endsWith("ip6.arpa")); assert.equal(reverseName("::ffff:127.0.0.1").split(".").length, 34);
});
test("local DNS handles UDP, truncated-response TCP fallback, IPv4-only/IPv6-only/dual-stack and timeout", async (t) => {
  const udp = dgram.createSocket("udp4"), tcp = net.createServer(); let tcpQueries = 0;
  udp.bind(0, "127.0.0.1"); await once(udp, "listening"); const port = udp.address().port;
  await new Promise((resolve) => tcp.listen(port, "127.0.0.1", resolve));
  t.after(async () => { udp.close(); await new Promise((resolve) => tcp.close(resolve)); });
  const respond = (packet) => {
    const query = readName(packet, 12), type = packet.readUInt16BE(query.end), host = query.name;
    if (host === "missing.test") return answer(packet, 3);
    const records = [];
    if (type === TYPES.A && host !== "v6.test") records.push(["A", Buffer.from([127,0,0,1])]);
    if (type === TYPES.AAAA && host !== "v4.test") { const data = Buffer.alloc(16); data[15] = 1; records.push(["AAAA", data]); }
    return answer(packet, 0, records);
  };
  udp.on("message", (packet, remote) => {
    const host = readName(packet, 12).name; if (host === "timeout.test") return;
    const response = host === "tcp.test" ? answer(packet) : respond(packet); if (host === "tcp.test") response[2] |= 2;
    udp.send(response, remote.port, remote.address);
  });
  tcp.on("connection", (socket) => { socket.once("data", (data) => { tcpQueries++; const response = respond(data.subarray(2)), size = Buffer.alloc(2); size.writeUInt16BE(response.length); socket.end(Buffer.concat([size, response])); }); });
  const dns = new DnsDiagnostics(); dns.servers = () => [`127.0.0.1:${port}`];
  assert.equal((await dns.resolve("v4.test", options, signal())).length, 1);
  assert.equal((await dns.resolve("v6.test", options, signal()))[0].family, 6);
  assert.equal((await dns.resolve("dual.test", options, signal())).length, 2);
  await assert.rejects(dns.resolve("missing.test", options, signal()), { code: "DNS_NO_ADDRESS" });
  assert.equal((await dns.query("tcp.test", "A", options, signal())).records[0].value, "127.0.0.1"); assert.equal(tcpQueries, 1);
  await assert.rejects(dns.query("timeout.test", "A", options, signal()), { code: "TIMEOUT" });
  const controller = new AbortController(); controller.abort(); await assert.rejects(dns.query("timeout.test", "A", options, controller.signal), { code: "CANCELLED" });
});
test("DNS detects CNAME chains and compares repeated answers from the chosen resolver", async () => {
  const dns = new DnsDiagnostics(); let aQueries = 0;
  dns.query = async (host, type) => ({ name: host, type, status: "success", durationMs: 1, records: host === "alias.test" && ["A", "CNAME"].includes(type) ? [{ name: host, type: "CNAME", value: "target.test", section: "answer", ttl: 60 }] : host === "target.test" && type === "A" ? [{ name: host, type, value: "127.0.0.1", section: "answer", ttl: 60 }] : type === "AAAA" ? [{ name: host, type, value: (++aQueries > 1 ? "::2" : "::1"), section: "answer" }] : [] });
  assert.equal((await dns.resolve("alias.test", { ...options, mode: "ipv4" }, signal()))[0].address, "127.0.0.1");
  const result = await dns.run("alias.test", options, signal(), () => {}); assert.deepEqual(result.cnameChain, ["alias.test → target.test"]); assert.equal(result.consistency.find((r) => r.type === "AAAA").status, "changed");
});
test("OS command arguments and localized ping/traceroute parsers handle both IP families", () => {
  for (const platform of ["win32", "darwin", "linux"]) for (const address of ["127.0.0.1", "::1"]) {
    const ping = pingCommand(address, 500, platform), trace = tracerouteCommand(address, { timeoutMs: 500, maxHops: 3 }, platform);
    assert.equal(ping.args.at(-1), address); assert.equal(trace.args.at(-1), address); assert.ok(trace.args.includes("3"));
  }
  assert.throws(() => pingCommand("localhost;bad", 500, "linux"));
  assert.equal(parsePingReply("Antwort von 127.0.0.1: Bytes=32 Zeit=1,25ms TTL=64").rttMs, 1.25);
  assert.equal(parsePingReply("Reply: time<1ms TTL=128").rttMs, null); assert.equal(parsePingReply("Reply: time<1ms TTL=128").received, true);
  assert.equal(parsePingReply("64 bytes from ::1: icmp_seq=0 hlim=64 time=0.032 ms").ttl, 64);
  const hop = parseHop(" 2  192.0.2.1  1.20 ms  *  1.40 ms"); assert.equal(hop.hop, 2); assert.equal(hop.probes.length, 3); assert.ok(Math.abs(hop.averageMs - 1.3) < 1e-12);
  assert.equal(parseHop(" 3    <1 ms     2 ms     *     2001:db8::1").addresses[0], "2001:db8::1");
  assert.equal(parseHop("traceroute to example"), null);
});
test("ICMP absence and missing tools do not claim a server is offline; traceroute updates are progressive", async () => {
  const settings = { ...options, count: 1, repetitions: 1, continuous: false, maxHops: 3 }, events = [];
  const blocked = await ping("127.0.0.1", settings, signal(), (event) => events.push(event), async () => ({ code: 1, stdout: Buffer.from("Request timed out."), stderr: "" }));
  assert.equal(blocked.status, "warning"); assert.equal(blocked.packets[0].status, "timeout"); assert.equal(blocked.lossPercent, 100); assert.equal(blocked.packets[0].rttMs, null); assert.ok(blocked.packets[0].measuredAt);
  const missing = await ping("127.0.0.1", settings, signal(), () => {}, async () => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); }); assert.equal(missing.status, "unavailable");
  const trace = await traceroute("127.0.0.1", settings, signal(), (event) => events.push(event), async (_exe, _args, { onLine }) => { onLine("1 * * *"); onLine("2 127.0.0.1 0.1 ms 0.2 ms 0.3 ms"); return { code: 0, stdout: Buffer.from("trace"), stderr: "" }; });
  assert.equal(trace.status, "success"); assert.equal(trace.routes[0].hops.length, 2); assert.equal(events.filter((e) => e.kind === "trace-hop").length, 2);
});
test("process runner uses argument arrays with shell disabled and terminates on timeout, abort and output limit", async () => {
  const { spawn } = require("node:child_process"); let config;
  const result = await runProcess(process.execPath, ["-e", "process.stdout.write('ok')"], { spawnImpl: (exe, args, options) => { config = options; return spawn(exe, args, options); } });
  assert.equal(result.stdout.toString(), "ok"); assert.equal(config.shell, false);
  await assert.rejects(runProcess(process.execPath, ["-e", "setInterval(()=>{},1000)"], { timeoutMs: 30 }), { code: "TIMEOUT" });
  await assert.rejects(runProcess(process.execPath, ["-e", "process.stdout.write('x'.repeat(10000))"], { maxBytes: 50 }), { code: "OUTPUT_LIMIT" });
  const controller = new AbortController(), work = runProcess(process.execPath, ["-e", "setInterval(()=>{},1000)"], { signal: controller.signal }); controller.abort(); await assert.rejects(work, { code: "CANCELLED" });
  await assert.rejects(runProcess("chj-nonexistent-diagnostic-tool", []), { code: "ENOENT" });
});

test("system resolution honors localhost/hosts-file entries and remains timeout/cancel bounded", async () => {
  const dns = new DnsDiagnostics(); const addresses = await dns.resolve("localhost", { ...options, resolver: "system", timeoutMs: 1000 }, signal());
  assert.ok(addresses.some((a) => ["127.0.0.1", "::1"].includes(a.address)));
  const hanging = new DnsDiagnostics({ lookup() {} });
  await assert.rejects(hanging.resolve("localhost", { ...options, resolver: "system", timeoutMs: 20 }, signal()), { code: "TIMEOUT" });
  const controller = new AbortController(), work = hanging.resolve("localhost", { ...options, resolver: "system" }, controller.signal); controller.abort(); await assert.rejects(work);
});
