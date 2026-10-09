"use strict";
const net = require("node:net");
const tls = require("node:tls");
const { X509Certificate } = require("node:crypto");
const { domainToASCII } = require("node:url");
const { performance } = require("node:perf_hooks");
const TOOLS = ["dns", "ping", "traceroute", "http", "compression", "tls", "tcp", "websocket"];
const SERVICES = { 21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS TCP", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP Submission", 993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis" };
class DiagnosticError extends Error {
  constructor(code, message = code) { super(message); this.code = code; }
}
// Verify IP SANs directly. Node TLS releases that IDNA-normalize every host can
// misclassify an unbracketed IPv6 literal as a DNS name. Trust verification stays on.
function verifyPeerIdentity(host, cert) {
  if (!net.isIP(host)) return tls.checkServerIdentity(host, cert);
  try { if (new X509Certificate(cert.raw).checkIP(host)) return undefined; } catch {}
  return new DiagnosticError("ERR_TLS_CERT_ALTNAME_INVALID", "Certificate IP SAN does not match the requested IP address.");
}
function hostname(raw) {
  const value = String(raw || "").replace(/^\[|\]$/g, "");
  if (net.isIP(value)) return value;
  const ascii = domainToASCII(value.replace(/\.$/, "")).toLowerCase();
  if (!ascii || ascii.length > 253 || !ascii.split(".").every((label) => /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/i.test(label))) throw new DiagnosticError("INVALID_HOST");
  return ascii;
}
function parseTarget(raw) {
  const input = String(raw || "").trim();
  if (!input || input.length > 2048 || /[\x00-\x20\x7f\\]/.test(input)) throw new DiagnosticError("INVALID_TARGET");
  let url;
  const literal = net.isIP(input.replace(/^\[|\]$/g, ""));
  try { url = new URL(literal === 6 ? `https://[${hostname(input)}]/` : /^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `https://${input}`); }
  catch { throw new DiagnosticError("INVALID_URL"); }
  if (!["http:", "https:", "ws:", "wss:"].includes(url.protocol) || url.username || url.password) throw new DiagnosticError("URL_AUTH_OR_SCHEME_FORBIDDEN");
  const host = hostname(url.hostname);
  url.hash = "";
  return { input, host, url: url.href, port: Number(url.port || (["https:", "wss:"].includes(url.protocol) ? 443 : 80)), type: net.isIP(host) ? `ipv${net.isIP(host)}` : input.includes("://") ? "url" : "hostname" };
}
function integer(value, fallback, min, max) {
  if (value === undefined || value === "") return fallback;
  const number = Number(value);
  if (!Number.isInteger(number) || number < min || number > max) throw new DiagnosticError("INVALID_PARAMETER");
  return number;
}
function normalizeOptions(source = {}) {
  const target = parseTarget(source.target);
  const mode = source.mode || "auto";
  if (!["auto", "ipv4", "ipv6", "both"].includes(mode)) throw new DiagnosticError("INVALID_IP_MODE");
  const tools = source.tools === undefined ? TOOLS.filter((tool) => tool !== "websocket") : source.tools;
  if (!Array.isArray(tools) || !tools.length || tools.length > TOOLS.length || tools.some((tool) => !TOOLS.includes(tool))) throw new DiagnosticError("INVALID_TOOLS");
  const portsText = String(source.ports || "22,80,443");
  if (portsText.length > 512) throw new DiagnosticError("PORT_LIMIT");
  const ports = [...new Set(portsText.split(/[,;\s]+/).filter(Boolean).map((port) => integer(port, 443, 1, 65535)))];
  if (!ports.length || ports.length > 16) throw new DiagnosticError("PORT_LIMIT");
  const resolver = source.resolver || "system";
  if (!["system", "custom", "cloudflare", "google", "quad9"].includes(resolver)) throw new DiagnosticError("INVALID_RESOLVER");
  const customDns = String(source.customDns || "");
  if (resolver === "custom" && !net.isIP(customDns)) throw new DiagnosticError("INVALID_DNS_SERVER");
  const selectedIp = String(source.selectedIp || "");
  if (selectedIp && !net.isIP(selectedIp)) throw new DiagnosticError("INVALID_IP");
  const protocols = source.protocols || ["1.1", "2", "3"];
  if (!Array.isArray(protocols) || !protocols.length || protocols.length > 3 || protocols.some((p) => !["1.1", "2", "3"].includes(p))) throw new DiagnosticError("INVALID_PROTOCOL");
  return { target, tools: [...new Set(tools)], mode, selectedIp, resolver, customDns,
    timeoutMs: integer(source.timeoutMs, 5000, 250, 30000), count: integer(source.count, 4, 1, 100),
    repetitions: integer(source.repetitions, 1, 1, 20), maxHops: integer(source.maxHops, 20, 1, 40),
    continuous: source.continuous === true, warm: source.warm === true, protocols: [...new Set(protocols)], ports,
    compareSchemes: source.compareSchemes === true };
}
function stats(values) {
  const list = values.filter((v) => typeof v === "number" && Number.isFinite(v)).sort((a, b) => a - b);
  if (!list.length) return { min: null, average: null, median: null, max: null, p95: null, stddev: null, jitter: null };
  const average = list.reduce((a, b) => a + b, 0) / list.length;
  const sequence = values.filter((v) => typeof v === "number" && Number.isFinite(v));
  return { min: list[0], average, median: list.length % 2 ? list[(list.length - 1) / 2] : (list[list.length / 2 - 1] + list[list.length / 2]) / 2,
    max: list.at(-1), p95: list[Math.ceil(list.length * 0.95) - 1], stddev: Math.sqrt(list.reduce((sum, v) => sum + (v - average) ** 2, 0) / list.length),
    jitter: sequence.length < 2 ? null : sequence.slice(1).reduce((sum, v, index) => sum + Math.abs(v - sequence[index]), 0) / (sequence.length - 1) };
}
function checkAbort(signal) { if (signal?.aborted) throw new DiagnosticError("CANCELLED"); }
function errorResult(error) { return { status: error?.code === "CANCELLED" || error?.name === "AbortError" ? "cancelled" : "error", code: error?.code || "DIAGNOSTIC_ERROR", reason: String(error?.message || error).slice(0, 400) }; }
async function mapLimit(items, limit, fn) {
  const results = new Array(items.length); let cursor = 0;
  const outcomes = await Promise.allSettled(Array.from({ length: Math.min(limit, items.length) }, async () => { while (cursor < items.length) { const index = cursor++; results[index] = await fn(items[index], index); } }));
  const failure = outcomes.find((entry) => entry.status === "rejected");
  if (failure) throw failure.reason;
  return results;
}
function boundedSignal(parent, timeoutMs) {
  const controller = new AbortController();
  const abort = () => controller.abort(parent?.reason);
  parent?.addEventListener("abort", abort, { once: true });
  if (parent?.aborted) abort();
  const timer = setTimeout(() => controller.abort(new DiagnosticError("TIMEOUT")), timeoutMs);
  return { signal: controller.signal, close() { clearTimeout(timer); parent?.removeEventListener("abort", abort); } };
}
module.exports = { verifyPeerIdentity, DiagnosticError, TOOLS, SERVICES, hostname, parseTarget, normalizeOptions, integer, stats, checkAbort, errorResult, mapLimit, boundedSignal, now: () => performance.now() };
