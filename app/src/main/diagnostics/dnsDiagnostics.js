"use strict";
const dns = require("node:dns");
const dgram = require("node:dgram");
const net = require("node:net");
const crypto = require("node:crypto");
const { hostname, DiagnosticError, boundedSignal, checkAbort, now, mapLimit, errorResult } = require("./common");
const TYPES = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, DS: 43, DNSKEY: 48, CAA: 257 };
const PROVIDERS = { cloudflare: ["1.1.1.1", "2606:4700:4700::1111"], google: ["8.8.8.8", "2001:4860:4860::8888"], quad9: ["9.9.9.9", "2620:fe::fe"] };
function readName(buffer, position) {
  let cursor = position, end, labels = [], seen = new Set();
  for (let count = 0; count < 128; count++) {
    if (cursor >= buffer.length || seen.has(cursor)) throw new DiagnosticError("DNS_MALFORMED");
    seen.add(cursor); const length = buffer[cursor++];
    if ((length & 0xc0) === 0xc0) { if (cursor >= buffer.length) throw new DiagnosticError("DNS_MALFORMED"); end ??= cursor + 1; cursor = ((length & 0x3f) << 8) | buffer[cursor]; continue; }
    if (length & 0xc0 || length > 63 || cursor + length > buffer.length) throw new DiagnosticError("DNS_MALFORMED");
    if (!length) return { name: labels.join("."), end: end ?? cursor };
    labels.push(buffer.subarray(cursor, cursor + length).toString("ascii")); cursor += length;
  }
  throw new DiagnosticError("DNS_MALFORMED");
}
function parseResponse(buffer, id, type) {
  if (buffer.length < 12 || buffer.readUInt16BE(0) !== id || !(buffer[2] & 0x80)) throw new DiagnosticError("DNS_MALFORMED");
  const code = buffer[3] & 15; const status = { 0: "success", 2: "servfail", 3: "nxdomain", 5: "refused" }[code] || "error";
  let cursor = 12;
  const questions = buffer.readUInt16BE(4), total = buffer.readUInt16BE(6) + buffer.readUInt16BE(8) + buffer.readUInt16BE(10);
  if (questions !== 1 || total > 1024) throw new DiagnosticError("DNS_MALFORMED");
  const question = readName(buffer, cursor); cursor = question.end;
  if (cursor + 4 > buffer.length || buffer.readUInt16BE(cursor) !== TYPES[type] || buffer.readUInt16BE(cursor + 2) !== 1) throw new DiagnosticError("DNS_MALFORMED");
  cursor += 4; const records = [];
  for (let index = 0; index < total; index++) {
    const owner = readName(buffer, cursor); cursor = owner.end;
    if (cursor + 10 > buffer.length) throw new DiagnosticError("DNS_MALFORMED");
    const number = buffer.readUInt16BE(cursor), cls = buffer.readUInt16BE(cursor + 2), ttl = buffer.readUInt32BE(cursor + 4), length = buffer.readUInt16BE(cursor + 8);
    cursor += 10; const end = cursor + length;
    if (end > buffer.length) throw new DiagnosticError("DNS_MALFORMED");
    const recordType = Object.keys(TYPES).find((key) => TYPES[key] === number);
    let value;
    if (number === 1 && length === 4) value = [...buffer.subarray(cursor, end)].join(".");
    else if (number === 28 && length === 16) value = Array.from({ length: 8 }, (_, n) => buffer.readUInt16BE(cursor + n * 2).toString(16)).join(":");
    else if ([2, 5, 12].includes(number)) value = readName(buffer, cursor).name;
    else if (number === 15 && length >= 3) value = { priority: buffer.readUInt16BE(cursor), exchange: readName(buffer, cursor + 2).name };
    else if (number === 33 && length >= 7) value = { priority: buffer.readUInt16BE(cursor), weight: buffer.readUInt16BE(cursor + 2), port: buffer.readUInt16BE(cursor + 4), name: readName(buffer, cursor + 6).name };
    else if (number === 16) { value = []; let p = cursor; while (p < end) { const size = buffer[p++]; if (p + size > end) throw new DiagnosticError("DNS_MALFORMED"); value.push(buffer.subarray(p, p + size).toString("utf8")); p += size; } }
    else if (number === 6) { const first = readName(buffer, cursor), second = readName(buffer, first.end); if (second.end + 20 > end) throw new DiagnosticError("DNS_MALFORMED"); value = { nsname: first.name, hostmaster: second.name }; ["serial", "refresh", "retry", "expire", "minttl"].forEach((key, n) => { value[key] = buffer.readUInt32BE(second.end + n * 4); }); }
    else if (number === 43 && length >= 4) value = { keyTag: buffer.readUInt16BE(cursor), algorithm: buffer[cursor + 2], digestType: buffer[cursor + 3], digest: buffer.subarray(cursor + 4, end).toString("hex") };
    else if (number === 48 && length >= 4) value = { flags: buffer.readUInt16BE(cursor), protocol: buffer[cursor + 2], algorithm: buffer[cursor + 3], publicKey: buffer.subarray(cursor + 4, end).toString("base64") };
    else if (number === 257 && length >= 2 && cursor + 2 + buffer[cursor + 1] <= end) value = { flags: buffer[cursor], tag: buffer.subarray(cursor + 2, cursor + 2 + buffer[cursor + 1]).toString(), value: buffer.subarray(cursor + 2 + buffer[cursor + 1], end).toString() };
    if (recordType && cls === 1 && value !== undefined) records.push({ name: owner.name, type: recordType, ttl, value, section: index < buffer.readUInt16BE(6) ? "answer" : "authority/additional" });
    cursor = end;
  }
  return { questionName: question.name, status: status === "success" && !records.some((r) => r.type === type && r.section === "answer") ? "nodata" : status, records, truncated: Boolean(buffer[2] & 2), dnssec: "not-validated", resolverAdFlag: Boolean(buffer[3] & 32) };
}
function reverseName(address) {
  if (net.isIP(address) === 4) return address.split(".").reverse().join(".") + ".in-addr.arpa";
  if (net.isIP(address) !== 6) throw new DiagnosticError("INVALID_IP");
  // URL canonicalization expands embedded IPv4 to two hexadecimal groups.
  const value = new URL(`http://[${address}]/`).hostname.slice(1, -1), halves = value.split("::"), left = halves[0] ? halves[0].split(":") : [], right = halves[1] ? halves[1].split(":") : [];
  return [...left, ...Array(8 - left.length - right.length).fill("0"), ...right].map((part) => part.padStart(4, "0")).join("").split("").reverse().join(".") + ".ip6.arpa";
}
function serverAddress(value) {
  const v6 = String(value).match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (v6) return { host: v6[1], port: Number(v6[2] || 53) };
  if (net.isIP(value)) return { host: value, port: 53 };
  const v4 = String(value).match(/^([\d.]+):(\d+)$/);
  if (v4 && net.isIP(v4[1]) === 4) return { host: v4[1], port: Number(v4[2]) };
  throw new DiagnosticError("INVALID_DNS_SERVER");
}
function exchange(packet, server, signal, tcp = false) {
  checkAbort(signal);
  checkAbort(signal);
  return new Promise((resolve, reject) => {
    const address = serverAddress(server), socket = tcp ? net.createConnection({ host: address.host, port: address.port }) : dgram.createSocket(net.isIP(address.host) === 6 ? "udp6" : "udp4");
    let done = false, data = Buffer.alloc(0);
    const finish = (error, response) => { if (done) return; done = true; signal?.removeEventListener("abort", abort); if (tcp) socket.destroy(); else { try { socket.close(); } catch {} } error ? reject(error) : resolve(response); };
    const abort = () => finish(signal.reason || new DiagnosticError("CANCELLED"));
    signal?.addEventListener("abort", abort, { once: true }); socket.once("error", finish);
    if (tcp) {
      socket.once("connect", () => { const size = Buffer.alloc(2); size.writeUInt16BE(packet.length); socket.write(Buffer.concat([size, packet])); });
      socket.on("data", (chunk) => { data = Buffer.concat([data, chunk]); if (data.length > 65537) return finish(new DiagnosticError("DNS_TOO_LARGE")); if (data.length >= 2 && data.length >= data.readUInt16BE(0) + 2) finish(null, data.subarray(2, data.readUInt16BE(0) + 2)); });
      socket.once("end", () => finish(new DiagnosticError("DNS_INCOMPLETE")));
    } else {
      socket.once("message", (response) => finish(null, response));
      socket.connect(address.port, address.host, () => socket.send(packet, (error) => { if (error) finish(error); }));
    }
  });
}
class DnsDiagnostics {
  constructor({ lookup = dns.lookup } = {}) { this.lookup = lookup; }
  systemLookup(host, options, signal) {
    checkAbort(signal);
    const started = now(), limit = boundedSignal(signal, options.timeoutMs);
    return new Promise((resolve, reject) => {
      let done = false;
      const finish = (error, addresses) => {
        if (done) return; done = true; limit.signal.removeEventListener("abort", abort); limit.close();
        error ? reject(error) : resolve(addresses.map((a) => ({ ...a, dnsMs: now() - started, method: "OS resolver (hosts file / system DNS); TTL unavailable" })));
      };
      const abort = () => finish(limit.signal.reason || new DiagnosticError("CANCELLED"));
      limit.signal.addEventListener("abort", abort, { once: true });
      try { this.lookup(host, { all: true, verbatim: true, family: options.mode === "ipv4" ? 4 : options.mode === "ipv6" ? 6 : 0 }, finish); }
      catch (error) { finish(error); }
    });
  }
  servers(options) { return options.resolver === "custom" ? [options.customDns] : PROVIDERS[options.resolver] || dns.getServers(); }
  async query(name, type, options, signal) {
    const started = now(), queryName = hostname(name), id = crypto.randomBytes(2).readUInt16BE();
    const header = Buffer.alloc(12); header.writeUInt16BE(id); header.writeUInt16BE(0x0100, 2); header.writeUInt16BE(1, 4);
    const question = Buffer.concat([...queryName.split(".").map((part) => Buffer.concat([Buffer.from([Buffer.byteLength(part)]), Buffer.from(part)])), Buffer.from([0, TYPES[type] >> 8, TYPES[type] & 255, 0, 1])]);
    const packet = Buffer.concat([header, question]), limit = boundedSignal(signal, options.timeoutMs);
    let failure;
    try {
      for (const server of this.servers(options)) {
        try {
          let response = await exchange(packet, server, limit.signal);
          if (response[2] & 2) response = await exchange(packet, server, limit.signal, true);
          const result = parseResponse(response, id, type);
          if (result.questionName && result.questionName !== queryName) throw new DiagnosticError("DNS_MALFORMED");
          return { name: queryName, type, server, durationMs: now() - started, ...result };
        } catch (error) { failure = error; if (limit.signal.aborted) break; }
      }
      throw failure || new DiagnosticError("DNS_UNAVAILABLE");
    } finally { limit.close(); }
  }
  async resolve(host, options, signal) {
    checkAbort(signal);
    if (net.isIP(host)) return [{ address: host, family: net.isIP(host), dnsMs: 0 }];
    if (options.resolver === "system") { const addresses = await this.systemLookup(host, options, signal); if (!addresses.length) throw new DiagnosticError("DNS_NO_ADDRESS"); return addresses; }
    const types = options.mode === "ipv4" ? ["A"] : options.mode === "ipv6" ? ["AAAA"] : ["A", "AAAA"];
    const results = await Promise.all(types.map(async (type) => {
      let name = host, duration = 0, seen = new Set();
      for (let i = 0; i < 8; i++) {
        if (seen.has(name)) throw new DiagnosticError("DNS_CNAME_LOOP"); seen.add(name);
        const result = await this.query(name, type, options, signal); duration += result.durationMs;
        const addresses = result.records.filter((r) => r.type === type && r.section === "answer");
        if (addresses.length) return addresses.map((r) => ({ address: r.value, family: type === "A" ? 4 : 6, dnsMs: duration, ttl: r.ttl }));
        const cname = result.records.find((r) => r.type === "CNAME" && r.section === "answer");
        if (!cname) return [];
        name = cname.value;
      }
      throw new DiagnosticError("DNS_CNAME_LIMIT");
    }).map((promise) => promise.catch((error) => { if (signal?.aborted) throw error; return []; })));
    const addresses = results.flat();
    if (!addresses.length) throw new DiagnosticError("DNS_NO_ADDRESS");
    return addresses;
  }
  async run(host, options, signal, progress) {
    const name = net.isIP(host) ? reverseName(host) : host;
    const types = net.isIP(host) ? ["PTR"] : Object.keys(TYPES);
    const queries = await mapLimit(types, 3, async (type) => {
      checkAbort(signal);
      let result; try { result = await this.query(name, type, options, signal); } catch (error) { result = { type, name, ...errorResult(error) }; }
      progress?.({ kind: "dns-record", ...result }); return result;
    });
    const cnames = queries.flatMap((q) => q.records || []).filter((r) => r.type === "CNAME" && r.section === "answer");
    const seen = new Set([host]); let next = cnames.find((r) => r.name === host)?.value, cnameError;
    for (let index = 0; next && index < 8; index++) {
      checkAbort(signal);
      if (seen.has(next)) { cnameError = "DNS_CNAME_LOOP"; break; }
      seen.add(next);
      try {
        const query = await this.query(next, "CNAME", options, signal);
        const record = query.records.find((r) => r.type === "CNAME" && r.section === "answer" && r.name === next);
        if (!record) { next = null; break; }
        cnames.push(record); next = record.value;
      } catch (error) { if (signal.aborted) throw error; cnameError = error.code; break; }
    }
    if (next && !cnameError) cnameError = "DNS_CNAME_LIMIT";
    const consistency = [];
    if (!net.isIP(host)) {
      for (const type of ["A", "AAAA"]) {
        checkAbort(signal);
        const first = queries.find((q) => q.type === type);
        try {
          const second = await this.query(host, type, options, signal);
          const values = (q) => (q.records || []).filter((r) => [type, "CNAME"].includes(r.type) && r.section === "answer").map((r) => JSON.stringify([r.name, r.type, r.value])).sort();
          consistency.push({ type, status: first?.status === second.status && JSON.stringify(values(first)) === JSON.stringify(values(second)) ? "consistent" : "changed", first: values(first), second: values(second) });
        } catch (error) { if (signal.aborted) throw error; consistency.push({ type, ...errorResult(error) }); }
      }
    } else {
      for (const record of (queries[0]?.records || []).filter((r) => r.type === "PTR").slice(0, 4)) {
        try {
          const answers = await this.resolve(record.value, { ...options, mode: net.isIP(host) === 4 ? "ipv4" : "ipv6" }, signal);
          const canonical = (address) => net.isIP(address) === 6 ? new URL(`http://[${address}]/`).hostname : address;
          consistency.push({ type: "forward-confirmed-PTR", name: record.value, status: answers.some((a) => canonical(a.address) === canonical(host)) ? "consistent" : "changed" });
        } catch (error) { if (signal.aborted) throw error; consistency.push({ type: "forward-confirmed-PTR", name: record.value, ...errorResult(error) }); }
      }
    }
    return { status: queries.some((q) => q.status === "success") ? "success" : "warning", queries,
      cnameChain: [...new Set(cnames.map((r) => `${r.name} → ${r.value}`))], cnameError, consistency,
      dnssec: "not-validated", note: "Repeated answers / forward-confirmed PTR from the selected resolver. Changes can reflect load balancing; this is not authoritative consistency or DNSSEC validation." };
  }
}
module.exports = { TYPES, PROVIDERS, DnsDiagnostics, parseResponse, readName, reverseName };
