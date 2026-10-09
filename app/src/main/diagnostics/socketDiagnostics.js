"use strict";
const net = require("node:net");
const tls = require("node:tls");
const crypto = require("node:crypto");
const { Client } = require("ssh2");
const { verifyPeerIdentity, SERVICES, DiagnosticError, checkAbort, now, mapLimit, errorResult } = require("./common");
function algorithmOid(raw) {
  try {
    function element(at) { const tag = raw[at++]; let length = raw[at++]; if (length & 128) { const count = length & 127; if (count > 4) throw new Error(); length = 0; for (let n = 0; n < count; n++) length = length * 256 + raw[at++]; } if (at + length > raw.length) throw new Error(); return { tag, start: at, end: at + length }; }
    const root = element(0), tbs = element(root.start), algorithm = element(tbs.end), oid = element(algorithm.start);
    if (oid.tag !== 6) return null;
    const bytes = raw.subarray(oid.start, oid.end), arcs = [Math.floor(bytes[0] / 40), bytes[0] % 40]; let value = 0;
    for (const byte of bytes.subarray(1)) { value = value * 128 + (byte & 127); if (!(byte & 128)) { arcs.push(value); value = 0; } }
    return arcs.join(".");
  } catch { return null; }
}
function certificateInfo(cert, host) {
  const x509 = new crypto.X509Certificate(cert.raw), key = x509.publicKey, details = key.asymmetricKeyDetails || {};
  return { subject: x509.subject, issuer: x509.issuer, san: x509.subjectAltName || null, validFrom: x509.validFrom, validUntil: x509.validTo,
    daysUntilExpiration: Math.floor((new Date(x509.validTo).getTime() - Date.now()) / 86400000), fingerprint256: x509.fingerprint256,
    publicKeyType: key.asymmetricKeyType, publicKeyBits: details.modulusLength || ({ prime256v1: 256, secp384r1: 384, secp521r1: 521 }[details.namedCurve]) || null,
    publicKeyCurve: details.namedCurve || null, signatureAlgorithm: x509.signatureAlgorithm || algorithmOid(cert.raw),
    hostnameMatches: Boolean(net.isIP(host) ? x509.checkIP(host) : x509.checkHost(host)),
    selfSigned: x509.checkIssued(x509) && x509.verify(x509.publicKey), serialNumber: x509.serialNumber };
}
function tlsProbe(target, address, options, signal, version, ca) {
  checkAbort(signal);
  return new Promise((resolve, reject) => {
    const started = now(), host = target.host, port = target.port;
    // Inspection-only socket: collect invalid chains too, then explicitly require
    // both OpenSSL chain authorization AND hostname verification for a valid result.
    // No HTTP/authentication/application payload is sent on this socket.
    const socket = tls.connect({ host: address, port, servername: net.isIP(host) ? undefined : host, minVersion: version, maxVersion: version, rejectUnauthorized: false, ca, ALPNProtocols: ["h2", "http/1.1"] });
    let done = false;
    const finish = (error, result) => { if (done) return; done = true; clearTimeout(timer); signal?.removeEventListener("abort", abort); socket.destroy(); error ? reject(error) : resolve(result); };
    const abort = () => finish(new DiagnosticError("CANCELLED"));
    const timer = setTimeout(() => finish(new DiagnosticError("TIMEOUT")), options.timeoutMs);
    signal?.addEventListener("abort", abort, { once: true });
    socket.once("error", (error) => finish(error));
    socket.once("secureConnect", () => {
      try {
        const chain = [], seen = new Set(); let cert = socket.getPeerCertificate(true);
        while (cert?.raw && chain.length < 12) {
          const fingerprint = crypto.createHash("sha256").update(cert.raw).digest("hex"); if (seen.has(fingerprint)) break; seen.add(fingerprint);
          chain.push(certificateInfo(cert, host)); cert = cert.issuerCertificate;
        }
        const hostnameError = verifyPeerIdentity(host, socket.getPeerCertificate());
        const errors = []; if (!socket.authorized) errors.push(String(socket.authorizationError || "UNTRUSTED_CHAIN")); if (hostnameError) errors.push(hostnameError.code || "HOSTNAME_MISMATCH");
        if (!chain.length) errors.push("CERTIFICATE_MISSING");
        finish(null, { status: errors.length ? "invalid" : chain[0].daysUntilExpiration < 30 ? "warning" : "valid", valid: errors.length === 0,
          requestedVersion: version, negotiatedVersion: socket.getProtocol(), address, port, sni: net.isIP(host) ? null : host,
          durationMs: now() - started, cipher: socket.getCipher(), alpn: socket.alpnProtocol || null, chain, errors,
          validation: "OpenSSL trust/date/signature verification plus explicit hostname verification; revocation/CT not independently audited." });
      } catch (error) { finish(error); }
    });
  });
}
async function runTls(target, address, options, signal, progress, ca) {
  const results = [];
  for (const version of ["TLSv1.2", "TLSv1.3"]) {
    let result; try { result = await tlsProbe(target, address, options, signal, version, ca); }
    catch (error) { if (signal.aborted) throw error; result = { ...errorResult(error), requestedVersion: version }; if (/protocol version|unsupported protocol/i.test(error.message)) result.status = "unsupported"; }
    results.push(result); progress({ kind: "tls", address, ...result });
  }
  return { status: results.some((r) => r.status === "invalid") ? results.some((r) => r.valid) ? "warning" : "failed" : results.some((r) => r.valid) ? "success" : "warning", results };
}
function tcpProbe(address, port, options, signal, connect = net.createConnection) {
  checkAbort(signal);
  return new Promise((resolve, reject) => {
    const started = now(), socket = connect({ host: address, port }); let done = false, connectedAt, banner = Buffer.alloc(0), bannerTimer;
    const finish = (error) => { if (done) return; done = true; clearTimeout(timer); clearTimeout(bannerTimer); signal?.removeEventListener("abort", abort); socket.destroy(); if (signal.aborted) return reject(new DiagnosticError("CANCELLED"));
      resolve({ address, family: net.isIP(address), port, standardService: SERVICES[port] || null, status: error ? error.code === "ECONNREFUSED" ? "refused" : error.code === "TIMEOUT" || error.code === "ETIMEDOUT" ? "timeout" : "error" : "connected",
        code: error?.code || null, connectionMs: connectedAt ? connectedAt - started : null, banner: banner.length ? banner.toString("utf8").replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "").slice(0, 512) : null,
        serviceNote: "Standard port assignment is a label, not service verification." }); };
    const abort = () => finish(new DiagnosticError("CANCELLED")); const timer = setTimeout(() => finish(new DiagnosticError("TIMEOUT")), options.timeoutMs);
    signal?.addEventListener("abort", abort, { once: true }); socket.once("error", finish);
    socket.once("connect", () => { connectedAt = now(); if ([21, 22, 25, 110, 143, 587].includes(port)) bannerTimer = setTimeout(() => finish(), Math.min(500, options.timeoutMs)); else finish(); });
    socket.on("data", (chunk) => { banner = Buffer.concat([banner, chunk]).subarray(0, 512); finish(); });
    socket.once("end", () => finish(connectedAt ? undefined : new DiagnosticError("TCP_CLOSED")));
  });
}
function sshIdentification(address, options, signal) {
  checkAbort(signal);
  return new Promise((resolve, reject) => {
    const client = new Client(); let done = false, identification = null;
    const finish = (error, value) => { if (done) return; done = true; clearTimeout(timer); signal?.removeEventListener("abort", abort); client.destroy(); error ? reject(error) : resolve(value); };
    const abort = () => finish(new DiagnosticError("CANCELLED")), timer = setTimeout(() => finish(new DiagnosticError("TIMEOUT")), options.timeoutMs);
    signal?.addEventListener("abort", abort, { once: true });
    client.on("greeting", (value) => { identification = String(value).slice(0, 512); });
    client.on("handshake", (negotiated) => { identification ||= negotiated?.serverIdent || null; });
    client.on("error", (error) => { if (!done) finish(error); });
    try { client.connect({ host: address, port: options.sshPort || 22, username: "diagnostics-no-auth", readyTimeout: options.timeoutMs, authHandler: () => false,
      hostVerifier(key) { const fingerprint = "SHA256:" + crypto.createHash("sha256").update(key).digest("base64").replace(/=+$/, ""); finish(null, { status: "success", fingerprint, identification, authenticated: false, note: "Observed handshake key; not trusted or added to SSH known hosts." }); return false; } }); } catch (error) { finish(error); }
  });
}
async function runTcp(address, options, signal, progress) {
  const ports = await mapLimit(options.ports, 4, async (port) => { const result = await tcpProbe(address, port, options, signal); progress({ kind: "tcp", ...result }); return result; });
  let ssh = null;
  if (ports.some((p) => p.port === 22 && p.status === "connected")) {
    try { ssh = await sshIdentification(address, options, signal); ssh.identification ||= ports.find((p) => p.port === 22)?.banner || null; } catch (error) { if (signal.aborted) throw error; ssh = errorResult(error); }
  }
  return { status: ports.some((p) => p.status === "connected") ? "success" : "warning", ports, ssh };
}
function websocketProbe(target, address, options, signal, ca) {
  checkAbort(signal);
  return new Promise((resolve, reject) => {
    const url = new URL(target.url), secure = ["wss:", "https:"].includes(url.protocol), key = crypto.randomBytes(16).toString("base64"), started = now();
    const transport = secure ? require("node:https") : require("node:http");
    url.protocol = secure ? "https:" : "http:";
    const request = transport.request(url, { method: "GET", agent: false, rejectUnauthorized: true, ca, servername: net.isIP(target.host) ? "" : target.host, checkServerIdentity: (_name, cert) => verifyPeerIdentity(target.host, cert), maxHeaderSize: 16384,
      lookup: (_host, config, callback) => config?.all ? callback(null, [{ address, family: net.isIP(address) }]) : callback(null, address, net.isIP(address)),
      headers: { Connection: "Upgrade", Upgrade: "websocket", "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": key } });
    let done = false;
    const finish = (error, value) => { if (done) return; done = true; clearTimeout(timer); signal?.removeEventListener("abort", abort); request.destroy(); error ? reject(error) : resolve(value); };
    const abort = () => finish(new DiagnosticError("CANCELLED")), timer = setTimeout(() => finish(new DiagnosticError("TIMEOUT")), options.timeoutMs);
    signal?.addEventListener("abort", abort, { once: true }); request.once("error", (error) => finish(error));
    request.once("upgrade", (response, socket) => {
      const expected = crypto.createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
      const valid = response.statusCode === 101 && String(response.headers.upgrade).toLowerCase() === "websocket" && /\bupgrade\b/i.test(response.headers.connection || "") && response.headers["sec-websocket-accept"] === expected;
      socket.destroy(); finish(null, { status: valid ? "success" : "failed", valid, statusCode: response.statusCode, durationMs: now() - started, address, secure });
    });
    request.once("response", (response) => { response.destroy(); finish(null, { status: "unsupported", statusCode: response.statusCode, durationMs: now() - started, address }); }); request.end();
  });
}
module.exports = { certificateInfo, algorithmOid, tlsProbe, runTls, tcpProbe, runTcp, sshIdentification, websocketProbe };
