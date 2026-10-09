"use strict";
const http = require("node:http");
const https = require("node:https");
const http2 = require("node:http2");
const net = require("node:net");
const zlib = require("node:zlib");
const crypto = require("node:crypto");
const { verifyPeerIdentity, DiagnosticError, parseTarget, checkAbort, boundedSignal, now, stats, errorResult } = require("./common");
const { runProcess } = require("./processTools");
const MAX_BODY = 2 * 1024 * 1024;
const PRIVATE_HEADERS = /^(?:set-cookie|cookie|authorization|proxy-authorization|www-authenticate|proxy-authenticate|authentication-info|proxy-authentication-info|set-cookie2)$/i;
function safeHeaders(headers) {
  const result = {};
  for (const [key, value] of Object.entries(headers)) {
    if (key.startsWith(":")) continue;
    result[key.toLowerCase()] = PRIVATE_HEADERS.test(key) ? "[redacted]" : String(value).slice(0, 8192);
  }
  return result;
}
function securityHeaders(headers, httpsTarget) {
  const keys = ["strict-transport-security", "content-security-policy", "x-content-type-options", "referrer-policy", "permissions-policy", "x-frame-options"];
  return keys.map((name) => ({ name, value: headers[name] || null, status: headers[name] ? "present" : name === "strict-transport-security" && !httpsTarget ? "not-applicable" : name === "x-frame-options" && /(?:^|;)\s*frame-ancestors\s/i.test(headers["content-security-policy"] || "") ? "superseded-by-csp-frame-ancestors" : "missing", note: "Presence alone does not establish correct policy or website security." }));
}
function consume(stream, onEnd, fail) {
  let bytes = 0, chunks = [];
  stream.on("data", (chunk) => { bytes += chunk.length; if (bytes > MAX_BODY) { stream.destroy(); fail(new DiagnosticError("BODY_LIMIT")); return; } chunks.push(chunk); });
  stream.once("end", () => onEnd(Buffer.concat(chunks), bytes));
  stream.once("error", fail);
}
function nativeRequest(url, address, protocol, { signal, timeoutMs, encoding = "identity", agent, sessionCache, ca } = {}) {
  checkAbort(signal);
  return new Promise((resolve, reject) => {
    let request, session, socket, finished = false, connectAt = null, secureAt = null, firstAt = null, tcpStart = now(), reused = false;
    const start = tcpStart;
    const sessionError = (error) => finish(error);
    const finish = (error, result) => { if (finished) return; finished = true; session?.removeListener("error", sessionError); clearTimeout(timer); signal?.removeEventListener("abort", abort); if (error) { request?.destroy(); if (session) session.destroy(); reject(error); } else { if (session && !sessionCache) session.close(); resolve(result); } };
    const abort = () => finish(new DiagnosticError("CANCELLED"));
    const timer = setTimeout(() => finish(new DiagnosticError("TIMEOUT")), timeoutMs);
    signal?.addEventListener("abort", abort, { once: true });
    const lookup = (_host, options, callback) => options?.all ? callback(null, [{ address, family: net.isIP(address) }]) : callback(null, address, net.isIP(address));
    const tlsHost = url.hostname.replace(/^\[|\]$/g, "");
    const bind = (value) => {
      socket = value;
      if (!socket.connecting) return;
      socket.once("connect", () => { connectAt = now(); });
      socket.once("secureConnect", () => { secureAt = now(); });
    };
    const complete = (statusCode, headers, body, bytes, negotiated, alpn) => finish(null, { status: protocol === "1.1" && negotiated !== "1.1" ? "unsupported" : "success", negotiated, statusCode,
      serverIp: socket?.remoteAddress || address, port: Number(url.port || (url.protocol === "https:" ? 443 : 80)), headers: safeHeaders(headers),
      contentType: headers["content-type"] || null, contentLength: /^\d+$/.test(String(headers["content-length"])) ? Number(headers["content-length"]) : null,
      downloadedBytes: bytes, bodyHash: crypto.createHash("sha256").update(body).digest("hex"), _body: body,
      reused, alpn: alpn || null, timings: { tcpMs: reused ? null : connectAt === null ? null : connectAt - tcpStart,
        tlsMs: reused || url.protocol !== "https:" || secureAt === null ? null : secureAt - (connectAt ?? start),
        ttfbMs: firstAt === null ? null : firstAt - start, downloadMs: firstAt === null ? null : now() - firstAt, totalMs: now() - start },
      bytesPerSecond: bytes / Math.max(0.001, (now() - (firstAt ?? start)) / 1000) });
    try {
      if (protocol === "1.1") {
        const transport = url.protocol === "https:" ? https : http;
        request = transport.request(url, { method: "GET", lookup, family: net.isIP(address), agent: agent || false,
          rejectUnauthorized: true, ca, servername: net.isIP(tlsHost) ? "" : tlsHost, checkServerIdentity: (_name, cert) => verifyPeerIdentity(tlsHost, cert), ALPNProtocols: ["http/1.1"], maxHeaderSize: 32768,
          headers: { "accept-encoding": encoding, "user-agent": "CH-J-Server-Diagnostics/1", accept: "*/*" } }, (response) => {
          firstAt = now(); reused = Boolean(request.reusedSocket); socket = response.socket;
          consume(response, (body, bytes) => complete(response.statusCode, response.headers, body, bytes, response.httpVersion, socket?.alpnProtocol), (error) => finish(error));
        });
        request.once("socket", bind); request.once("error", (error) => finish(error)); request.end();
      } else {
        const key = url.origin + "|" + address;
        session = sessionCache?.get(key);
        if (session?.destroyed || session?.closed) session = null;
        reused = Boolean(session);
        if (!session) {
          session = http2.connect(url.origin, { lookup, family: net.isIP(address), rejectUnauthorized: true, ca,
            servername: net.isIP(tlsHost) ? "" : tlsHost, checkServerIdentity: (_name, cert) => verifyPeerIdentity(tlsHost, cert), ALPNProtocols: ["h2"], maxSessionMemory: 2, settings: { enablePush: false, maxHeaderListSize: 32768 } });
          session.on("error", () => {});
          sessionCache?.set(key, session);
          bind(session.socket);
        } else socket = session.socket;
        session.on("error", sessionError);
        const open = () => {
          if (finished) return;
          try {
          if (url.protocol === "https:" && session.alpnProtocol !== "h2") return finish(new DiagnosticError("HTTP2_NOT_NEGOTIATED"));
          request = session.request({ ":method": "GET", ":path": url.pathname + url.search, "accept-encoding": encoding, "user-agent": "CH-J-Server-Diagnostics/1" }, { endStream: true });
          request.once("response", (headers) => { firstAt = now(); consume(request, (body, bytes) => complete(headers[":status"], headers, body, bytes, "2", session.alpnProtocol), (error) => finish(error)); });
          request.once("error", (error) => finish(error));
          request.once("aborted", () => finish(new DiagnosticError("HTTP_ABORTED")));
          } catch (error) { finish(error); }
        };
        if (session.connecting) session.once("connect", open); else open();
      }
    } catch (error) { finish(error); }
  });
}
let curlCapability;
async function getCurlCapability(runner = runProcess, signal) {
  checkAbort(signal);
  if (runner === runProcess && curlCapability) return curlCapability;
  let result;
  try {
    const output = (await runner(process.platform === "win32" ? "curl.exe" : "curl", ["--disable", "--version"], { timeoutMs: 3000, signal })).stdout.toString();
    const version = output.match(/^curl (\d+)\.(\d+)\.(\d+)/);
    result = { available: Boolean(version) && /Features:.*\bHTTP3\b/i.test(output) && (Number(version[1]) > 7 || Number(version[1]) === 7 && Number(version[2]) >= 88), version: version?.[0] || null,
      reason: /Features:.*\bHTTP3\b/i.test(output) ? "curl must support --http3-only (7.88+)" : "curl was not built with HTTP/3 / QUIC", raw: output.slice(0, 3000) };
  } catch (error) { if (signal?.aborted) throw new DiagnosticError("CANCELLED"); result = { available: false, reason: error.code === "ENOENT" ? "curl executable is missing" : error.message }; }
  if (runner === runProcess) curlCapability = result;
  return result;
}
async function http3Request(url, address, options, signal, runner = runProcess) {
  const capability = await getCurlCapability(runner, signal);
  if (!capability.available) return { status: "unavailable", code: "HTTP3_UNAVAILABLE", reason: capability.reason, capability };
  if (url.protocol !== "https:" || Number(url.port || 443) !== 443) return { status: "unavailable", code: "HTTP3_REQUIRES_UDP443", reason: "HTTP/3 comparison uses HTTPS over UDP/443." };
  // No config files, proxies, cookies, credentials, redirects or protocol fallback.
  const args = ["--disable", "--silent", "--show-error", "--http3-only", "--noproxy", "*", "--proto", "=https", "--max-time", String(options.timeoutMs / 1000), "--connect-timeout", String(options.timeoutMs / 1000),
    "--max-filesize", String(MAX_BODY), "--output", "-", "--dump-header", "-", "--header", "Accept-Encoding: identity",
    ...(net.isIP(url.hostname.replace(/^\[|\]$/g, "")) ? [] : ["--resolve", `${url.hostname}:443:${net.isIP(address) === 6 ? `[${address}]` : address}`]),
    "--write-out", "\nCHJ_METRICS:%{json}", "--url", url.href];
  const result = await runner(process.platform === "win32" ? "curl.exe" : "curl", args, { signal, timeoutMs: options.timeoutMs + 1000, maxBytes: MAX_BODY + 131072 });
  const output = result.stdout, marker = output.lastIndexOf("\nCHJ_METRICS:");
  if (marker < 0) throw new DiagnosticError("HTTP3_INVALID_RESULT");
  let metrics; try { metrics = JSON.parse(output.subarray(marker + 13).toString()); } catch { throw new DiagnosticError("HTTP3_INVALID_RESULT"); }
  if (result.code !== 0) return { status: "error", code: `CURL_${result.code}`, reason: result.stderr.slice(0, 400), negotiated: metrics.http_version || null };
  if (String(metrics.http_version) !== "3") return { status: "error", code: "HTTP3_FALLBACK_REJECTED", negotiated: metrics.http_version || null };
  const requiredMetrics = ["time_total", "time_starttransfer", "time_appconnect", "size_download", "speed_download", "response_code", "remote_port"];
  if (requiredMetrics.some((key) => !Number.isFinite(metrics[key]) || metrics[key] < 0)) throw new DiagnosticError("HTTP3_INVALID_RESULT");
  if (metrics.size_download > MAX_BODY) throw new DiagnosticError("BODY_LIMIT");
  let head, headerCursor = 0;
  const headers = {};
  // curl can print informational responses (e.g. 103) before the final headers.
  // Walk only leading header blocks; body contents never select the response headers.
  for (let index = 0; index < 8; index++) {
    const end = output.indexOf("\r\n\r\n", headerCursor);
    if (end < 0 || end > 32768 || end >= marker) throw new DiagnosticError("HTTP3_INVALID_RESULT");
    const candidate = output.subarray(headerCursor, end).toString(), status = candidate.match(/^HTTP\/3(?:\.0)?\s+(\d{3})\b/);
    if (!status) throw new DiagnosticError("HTTP3_INVALID_RESULT");
    if (Number(status[1]) >= 200) {
      if (Number(status[1]) !== Number(metrics.response_code)) throw new DiagnosticError("HTTP3_INVALID_RESULT");
      head = candidate; break;
    }
    headerCursor = end + 4;
  }
  if (!head) throw new DiagnosticError("HTTP3_INVALID_RESULT");
  head.split("\r\n").slice(1).forEach((line) => { const at = line.indexOf(":"); if (at > 0) headers[line.slice(0, at).toLowerCase()] = line.slice(at + 1).trim(); });
  return { status: "success", negotiated: "3", alpn: "h3", statusCode: metrics.response_code, serverIp: metrics.remote_ip, port: metrics.remote_port, headers: safeHeaders(headers),
    downloadedBytes: metrics.size_download, contentType: metrics.content_type, reused: null, reuseReason: "Independent curl process; reuse not asserted", timings: { dnsMs: null, tcpMs: null, tlsMs: null,
      quicHandshakeMs: metrics.time_appconnect * 1000, ttfbMs: metrics.time_starttransfer * 1000, downloadMs: (metrics.time_total - metrics.time_starttransfer) * 1000, totalMs: metrics.time_total * 1000 }, bytesPerSecond: metrics.speed_download };
}
function decodeBody(body, encoding, signal) {
  checkAbort(signal);
  const methods = { gzip: "createGunzip", deflate: "createInflate", br: "createBrotliDecompress", zstd: "createZstdDecompress" };
  if (encoding === "identity") return Promise.resolve(body);
  if (typeof zlib[methods[encoding]] !== "function") throw new DiagnosticError("COMPRESSION_CLIENT_UNAVAILABLE");
  return new Promise((resolve, reject) => {
    const decoder = zlib[methods[encoding]](); const pieces = []; let size = 0;
    const abort = () => decoder.destroy(new DiagnosticError("CANCELLED")); signal?.addEventListener("abort", abort, { once: true });
    decoder.on("data", (piece) => { size += piece.length; if (size > MAX_BODY * 4) decoder.destroy(new DiagnosticError("DECOMPRESSION_LIMIT")); else pieces.push(piece); });
    decoder.once("error", (error) => { signal?.removeEventListener("abort", abort); reject(error); });
    decoder.once("end", () => { signal?.removeEventListener("abort", abort); resolve(Buffer.concat(pieces)); }); decoder.end(body);
  });
}
class HttpDiagnostics {
  constructor(dnsService, options = {}) { this.dns = dnsService; this.ca = options.ca; this.h3 = options.h3 || http3Request; }
  async request(target, address, protocol, options, signal, resources, encoding = "identity") {
    let url = new URL(target.url); if (url.protocol === "ws:") url.protocol = "http:"; if (url.protocol === "wss:") url.protocol = "https:";
    const visited = new Set(), redirects = []; const started = now(); let redirectMs = 0, dnsMs = 0, hadDns = false;
    for (let hop = 0; hop <= 8; hop++) {
      checkAbort(signal); parseTarget(url.href);
      if (visited.has(url.href)) throw new DiagnosticError("REDIRECT_LOOP"); visited.add(url.href);
      const host = url.hostname.replace(/^\[|\]$/g, ""); let ip = address;
      if (host !== target.host || !options.selectedIp && !net.isIP(host)) {
        const dnsStart = now(); const list = await this.dns.resolve(host, { ...options, mode: net.isIP(address) === 6 ? "ipv6" : "ipv4" }, signal); dnsMs += now() - dnsStart; hadDns = true;
        ip = host === target.host && list.some((entry) => entry.address === address) ? address : list[0].address;
      }
      const beforeRequestElapsed = now() - started;
      const result = protocol === "3" ? await this.h3(url, ip, options, signal) : await nativeRequest(url, ip, protocol, { ...options, signal, encoding, ca: this.ca, agent: options.warm ? url.protocol === "https:" ? resources.https : resources.http : null, sessionCache: options.warm ? resources.h2 : null });
      if (result.status !== "success") return { ...result, redirects };
      if ([301, 302, 303, 307, 308].includes(result.statusCode) && result.headers.location) {
        if (hop === 8) throw new DiagnosticError("REDIRECT_LIMIT");
        const next = new URL(result.headers.location, url); parseTarget(next.href);
        redirects.push({ from: url.href, to: next.href, statusCode: result.statusCode, crossDomain: next.hostname !== url.hostname, downgrade: url.protocol === "https:" && next.protocol === "http:" });
        redirectMs += result.timings.totalMs; url = next; continue;
      }
      return { ...result, url: url.href, redirects, redirectCount: redirects.length, securityHeaders: securityHeaders(result.headers, url.protocol === "https:"),
        timings: { ...result.timings, finalResponseTtfbMs: result.timings.ttfbMs, ttfbMs: result.timings.ttfbMs === null ? null : beforeRequestElapsed + result.timings.ttfbMs, dnsMs: hadDns ? dnsMs : null, redirectMs, totalMs: now() - started }, dnsReason: hadDns ? null : "Pinned IP or IP literal; no DNS operation in this request." };
    }
  }
  resources() { return { http: new http.Agent({ keepAlive: true, maxSockets: 1 }), https: new https.Agent({ keepAlive: true, maxSockets: 1 }), h2: new Map() }; }
  dispose(resources) { resources.http.destroy(); resources.https.destroy(); resources.h2.forEach((session) => session.destroy()); }
  async run(target, address, options, signal, progress) {
    const resources = this.resources(), comparisons = [];
    try {
      const targets = [target];
      if (options.compareSchemes) { const url = new URL(target.url); url.protocol = url.protocol === "http:" ? "https:" : "http:"; url.port = ""; targets.push(parseTarget(url.href)); }
      for (const tested of targets) for (const protocol of options.protocols) {
        const samples = [];
        for (let iteration = 0; iteration < options.repetitions; iteration++) {
          checkAbort(signal); let sample;
          try { sample = await this.request(tested, address, protocol, options, signal, resources); }
          catch (error) { if (signal.aborted) throw error; sample = errorResult(error); if (["HTTP2_NOT_NEGOTIATED", "ERR_HTTP2_ERROR", "ERR_HTTP2_SESSION_ERROR"].includes(error.code)) sample.status = "unsupported"; }
          delete sample._body;
          samples.push({ iteration, ...sample }); progress({ kind: "http-sample", protocol, address, scheme: new URL(tested.url).protocol, iteration, ...sample });
          if (["unavailable", "unsupported"].includes(sample.status)) break;
        }
        comparisons.push({ protocol, url: tested.url, address, connection: options.warm ? "warm-if-reused" : "cold", samples, statistics: stats(samples.map((s) => s.timings?.totalMs)), errorRate: 100 * samples.filter((s) => s.status !== "success").length / samples.length });
      }
      return { status: comparisons.some((c) => c.samples.some((s) => s.status === "success")) ? "success" : "warning", comparisons, note: "Network/server request timings; no page rendering or Lighthouse score is measured." };
    } finally { this.dispose(resources); }
  }
  async compression(target, address, options, signal, progress) {
    const resources = this.resources(), results = []; let identity;
    try {
      for (const encoding of ["identity", "gzip", "deflate", "br", "zstd"]) {
        checkAbort(signal); let result;
        if (encoding === "zstd" && !zlib.createZstdDecompress) { results.push({ encoding, status: "unavailable", code: "COMPRESSION_CLIENT_UNAVAILABLE" }); continue; }
        try {
          const response = await this.request(target, address, "1.1", { ...options, warm: false }, signal, resources, encoding);
          const actual = String(response.headers?.["content-encoding"] || "identity").toLowerCase().trim();
          if (response.status !== "success") result = response;
          else if (actual !== encoding) result = { status: "unsupported", actualEncoding: actual, downloadedBytes: response.downloadedBytes, reason: "Server did not use the requested content encoding." };
          else {
            const decoded = await decodeBody(response._body, encoding, signal);
            const decodedHash = crypto.createHash("sha256").update(decoded).digest("hex");
            if (encoding === "identity") identity = { hash: decodedHash, bytes: decoded.length, url: response.url, statusCode: response.statusCode };
            const comparable = identity && identity.hash === decodedHash && identity.url === response.url && identity.statusCode === response.statusCode;
            result = { status: "success", actualEncoding: actual, downloadedBytes: response.downloadedBytes, decodedBytes: decoded.length, decodedHash, comparable: Boolean(comparable), ratio: comparable && identity.bytes > 0 ? response.downloadedBytes / identity.bytes : null, statusCode: response.statusCode };
          }
        } catch (error) { if (signal.aborted) throw error; result = errorResult(error); }
        results.push({ encoding, ...result }); progress({ kind: "compression", address, encoding, ...result });
      }
      return { status: results.some((r) => r.encoding === "br" && r.status === "success") ? "success" : "warning", results, note: "Compression is confirmed by Content-Encoding and bounded decompression. Ratios require identical decoded content." };
    } finally { this.dispose(resources); }
  }
}
module.exports = { HttpDiagnostics, nativeRequest, http3Request, getCurlCapability, safeHeaders, securityHeaders, decodeBody, MAX_BODY };
