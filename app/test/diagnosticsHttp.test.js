"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const http2 = require("node:http2");
const tls = require("node:tls");
const net = require("node:net");
const crypto = require("node:crypto");
const zlib = require("node:zlib");
const fs = require("node:fs");
const path = require("node:path");
const { once } = require("node:events");
const { Server } = require("ssh2");
const { parseTarget, normalizeOptions } = require("../src/main/diagnostics/common");
const { HttpDiagnostics, nativeRequest, http3Request, getCurlCapability, MAX_BODY, securityHeaders } = require("../src/main/diagnostics/httpDiagnostics");
const { tlsProbe, tcpProbe, websocketProbe, sshIdentification } = require("../src/main/diagnostics/socketDiagnostics");
const fixtures = path.join(__dirname, "fixtures", "diagnostics");
const key = fs.readFileSync(path.join(fixtures, "server-key.pem")), cert = fs.readFileSync(path.join(fixtures, "server.pem")), ca = fs.readFileSync(path.join(fixtures, "ca.pem"));
const signal = () => new AbortController().signal;
const settings = { timeoutMs: 1000 };
async function listen(t, server, host = "127.0.0.1") {
  const sockets = new Set(); server.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  server.listen(0, host); await once(server, "listening");
  t.after(async () => { for (const socket of sockets) { if (socket.destroy) socket.destroy(); else socket.end(); } await new Promise((resolve) => server.close(resolve)); }); return server.address().port;
}
const dns = { resolve: async () => [{ address: "127.0.0.1", family: 4 }] };
test("HTTP/1.1 measures actual bytes, headers, cold/warm reuse and bounded redirect chains", async (t) => {
  const server = http.createServer((req, res) => {
    if (req.url === "/loop") { res.writeHead(302, { location: "/loop" }); return res.end(); }
    if (req.url === "/redirect") { res.writeHead(301, { location: "/ok" }); return res.end(); }
    res.writeHead(200, { "content-type": "text/plain", "set-cookie": "password=private", "content-security-policy": "frame-ancestors 'none'" }); res.end("measured body");
  });
  const port = await listen(t, server), service = new HttpDiagnostics(dns), target = parseTarget(`http://localhost:${port}/redirect`);
  const options = normalizeOptions({ target: target.url, tools: ["http"], protocols: ["1.1"], repetitions: 3, warm: true });
  const result = await service.run(target, "127.0.0.1", options, signal(), () => {}), samples = result.comparisons[0].samples;
  assert.equal(samples.length, 3); assert.equal(samples[0].negotiated, "1.1"); assert.equal(samples[0].downloadedBytes, 13);
  assert.equal(samples[0].redirectCount, 1); assert.equal(samples[0].headers["set-cookie"], "[redacted]");
  assert.ok(samples[1].reused); assert.equal(samples[1].timings.tcpMs, null); assert.ok(samples[0].timings.totalMs > 0);
  assert.ok(!("_body" in samples[0])); assert.equal(result.comparisons[0].errorRate, 0);
  const resources = service.resources();
  try { await assert.rejects(service.request(parseTarget(`http://localhost:${port}/loop`), "127.0.0.1", "1.1", options, signal(), resources), { code: "REDIRECT_LOOP" }); }
  finally { service.dispose(resources); }
  assert.equal(securityHeaders({ "content-security-policy": "frame-ancestors 'none'" }, true).find((h) => h.name === "x-frame-options").status, "superseded-by-csp-frame-ancestors");
});
test("HTTP/2 uses real h2 TLS ALPN, verifies certificates and reuses the negotiated session", async (t) => {
  const server = http2.createSecureServer({ key, cert }); server.on("sessionError", () => {}); server.on("stream", (stream) => { stream.respond({ ":status": 200, "content-type": "text/plain" }); stream.end("h2 payload"); });
  const port = await listen(t, server), service = new HttpDiagnostics(dns, { ca }), target = parseTarget(`https://localhost:${port}/`);
  const options = normalizeOptions({ target: target.url, tools: ["http"], protocols: ["2"], repetitions: 3, warm: true });
  const result = await service.run(target, "127.0.0.1", options, signal(), () => {}), samples = result.comparisons[0].samples;
  assert.equal(samples[0].negotiated, "2"); assert.equal(samples[0].alpn, "h2"); assert.equal(samples[0].downloadedBytes, 10);
  assert.equal(samples[0].reused, false); assert.equal(samples[1].reused, true); assert.equal(samples[2].timings.tlsMs, null);
  await assert.rejects(nativeRequest(new URL(target.url), "127.0.0.1", "2", { ...settings, signal: signal() }));
});
test("HTTP timeout, cancellation and body cap terminate local requests", async (t) => {
  const server = http.createServer((req, res) => { if (req.url === "/large") res.end(Buffer.alloc(MAX_BODY + 1)); });
  const port = await listen(t, server);
  await assert.rejects(nativeRequest(new URL(`http://127.0.0.1:${port}/large`), "127.0.0.1", "1.1", { ...settings, signal: signal() }), { code: "BODY_LIMIT" });
  await assert.rejects(nativeRequest(new URL(`http://127.0.0.1:${port}/hang`), "127.0.0.1", "1.1", { timeoutMs: 30, signal: signal() }), { code: "TIMEOUT" });
  const controller = new AbortController(), request = nativeRequest(new URL(`http://127.0.0.1:${port}/hang`), "127.0.0.1", "1.1", { ...settings, signal: controller.signal });
  controller.abort(); await assert.rejects(request, { code: "CANCELLED" });
});
test("compression confirms gzip/deflate/Brotli using real decompression and rejects ignored Accept-Encoding", async (t) => {
  const body = Buffer.from("compression test ".repeat(100));
  const server = http.createServer((req, res) => {
    const encoding = req.headers["accept-encoding"];
    const compress = { gzip: zlib.gzipSync, deflate: zlib.deflateSync, br: zlib.brotliCompressSync, zstd: zlib.zstdCompressSync }[encoding];
    if (req.url !== "/ignored" && compress) { res.setHeader("content-encoding", encoding); res.end(compress(body)); } else res.end(body);
  });
  const port = await listen(t, server), service = new HttpDiagnostics(dns);
  for (const ignored of [false, true]) {
    const target = parseTarget(`http://localhost:${port}/${ignored ? "ignored" : "ok"}`), options = normalizeOptions({ target: target.url, tools: ["compression"] });
    const result = await service.compression(target, "127.0.0.1", options, signal(), () => {}), br = result.results.find((r) => r.encoding === "br");
    assert.equal(br.status, ignored ? "unsupported" : "success"); if (!ignored) { assert.equal(br.decodedBytes, body.length); assert.ok(br.ratio < 1); assert.equal(br.comparable, true); }
  }
});
test("HTTP/3 requires HTTP3-enabled curl, --http3-only and an actual version 3 result; fallback is rejected", async () => {
  const url = new URL("https://localhost/"), calls = [];
  const metrics = { http_version: "3", response_code: 200, remote_ip: "127.0.0.1", remote_port: 443, size_download: 4, content_type: "text/plain", time_appconnect: 0.02, time_starttransfer: 0.03, time_total: 0.04, speed_download: 100 };
  const runner = async (_exe, args) => { calls.push(args); return args.includes("--version") ? { stdout: Buffer.from("curl 8.10.0 test\nFeatures: SSL HTTP2 HTTP3\n") } : { code: 0, stdout: Buffer.from("HTTP/3 103\r\nlink: </early.css>\r\n\r\nHTTP/3 200\r\ncontent-type: text/plain\r\n\r\nbody\nCHJ_METRICS:" + JSON.stringify(metrics)), stderr: "" }; };
  const result = await http3Request(url, "127.0.0.1", settings, signal(), runner);
  assert.equal(result.negotiated, "3"); assert.equal(result.headers["content-type"], "text/plain"); assert.equal(result.headers.link, undefined); assert.equal(result.timings.tcpMs, null); assert.equal(result.timings.quicHandshakeMs, 20);
  assert.ok(calls[1].includes("--http3-only")); assert.ok(!calls[1].includes("--http3")); assert.ok(!calls[1].includes("--insecure")); assert.equal(calls[1][0], "--disable");
  metrics.http_version = "2"; assert.equal((await http3Request(url, "127.0.0.1", settings, signal(), runner)).code, "HTTP3_FALLBACK_REJECTED");
  assert.equal((await http3Request(url, "127.0.0.1", settings, signal(), async () => ({ stdout: Buffer.from("curl 8.7.1\nFeatures: SSL HTTP2\n") }))).code, "HTTP3_UNAVAILABLE");
  assert.equal((await http3Request(new URL("https://localhost:444/"), "127.0.0.1", settings, signal(), runner)).code, "HTTP3_REQUIRES_UDP443");
  assert.equal((await getCurlCapability(async () => { throw Object.assign(new Error("missing"), { code: "ENOENT" }); })).available, false);
});
test("TLS inspection differentiates trust, hostname mismatch and expiration without changing global verification", async (t) => {
  const server = tls.createServer({ key, cert }), expiredServer = tls.createServer({ key, cert: fs.readFileSync(path.join(fixtures, "expired.pem")) });
  const port = await listen(t, server), expiredPort = await listen(t, expiredServer), target = parseTarget(`https://localhost:${port}/`), prior = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  const valid = await tlsProbe(target, "127.0.0.1", settings, signal(), "TLSv1.3", ca); assert.equal(valid.valid, true); assert.equal(valid.chain[0].publicKeyBits, 2048); assert.ok(valid.chain[0].signatureAlgorithm); assert.ok(valid.chain[0].fingerprint256);
  const mismatch = await tlsProbe({ ...target, host: "mismatch.test" }, "127.0.0.1", settings, signal(), "TLSv1.2", ca); assert.equal(mismatch.status, "invalid"); assert.ok(mismatch.errors.includes("ERR_TLS_CERT_ALTNAME_INVALID"));
  const untrusted = await tlsProbe(target, "127.0.0.1", settings, signal(), "TLSv1.3"); assert.equal(untrusted.valid, false);
  const expired = await tlsProbe({ ...target, port: expiredPort }, "127.0.0.1", settings, signal(), "TLSv1.3", ca); assert.equal(expired.valid, false); assert.ok(expired.errors.includes("CERT_HAS_EXPIRED")); assert.ok(expired.chain[0].daysUntilExpiration < 0);
  assert.equal(process.env.NODE_TLS_REJECT_UNAUTHORIZED, prior);
});
test("TCP reports actual connected/refused states and WebSocket validates the Upgrade accept hash", async (t) => {
  const tcp = net.createServer(), tcpPort = await listen(t, tcp); assert.equal((await tcpProbe("127.0.0.1", tcpPort, settings, signal())).status, "connected");
  const closed = net.createServer(); closed.listen(0, "127.0.0.1"); await once(closed, "listening"); const closedPort = closed.address().port; await new Promise((r) => closed.close(r));
  assert.equal((await tcpProbe("127.0.0.1", closedPort, settings, signal())).status, "refused");
  const ws = http.createServer((_req, res) => res.end());
  ws.on("upgrade", (req, socket) => { const accept = crypto.createHash("sha1").update(req.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64"); socket.write("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: " + (req.url === "/bad" ? "invalid" : accept) + "\r\n\r\n"); });
  const port = await listen(t, ws);
  assert.equal((await websocketProbe(parseTarget(`ws://localhost:${port}/ok`), "127.0.0.1", settings, signal())).valid, true);
  assert.equal((await websocketProbe(parseTarget(`ws://localhost:${port}/bad`), "127.0.0.1", settings, signal())).valid, false);
});
test("SSH fingerprint is observed from a real handshake before any authentication request", async (t) => {
  let authentications = 0;
  const server = new Server({ hostKeys: [crypto.createPrivateKey(key).export({ type: "pkcs1", format: "pem" })] }, (client) => { client.on("error", () => {}); client.on("authentication", (ctx) => { authentications++; ctx.reject(); }); });
  server.on("error", () => {}); const port = await listen(t, server);
  const result = await sshIdentification("127.0.0.1", { timeoutMs: 2000, sshPort: port }, signal());
  assert.match(result.fingerprint, /^SHA256:/); assert.equal(result.authenticated, false); assert.equal(authentications, 0);
});
test("IPv6 HTTP and HTTPS are measured over a real local IPv6 socket", async (t) => {
  const server = http.createServer((_req, res) => res.end("v6")); let port;
  try { port = await listen(t, server, "::1"); } catch (error) { if (["EAFNOSUPPORT", "EADDRNOTAVAIL"].includes(error.code)) return t.skip("IPv6 loopback unavailable"); throw error; }
  const response = await nativeRequest(new URL(`http://[::1]:${port}/`), "::1", "1.1", { ...settings, signal: signal() });
  assert.equal(response.serverIp, "::1"); assert.equal(response.downloadedBytes, 2); assert.equal(response.negotiated, "1.1");
  const secureServer = require("node:https").createServer({ key, cert }, (_req, res) => res.end("v6 TLS"));
  const securePort = await listen(t, secureServer, "::1");
  const secure = await nativeRequest(new URL(`https://[::1]:${securePort}/`), "::1", "1.1", { ...settings, ca, signal: signal() });
  assert.equal(secure.status, "success"); assert.equal(secure.serverIp, "::1"); assert.ok(secure.timings.tlsMs > 0);
});
