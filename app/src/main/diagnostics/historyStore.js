"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { atomicWriteJson } = require("../storage/atomicFile");
const net = require("node:net");
const { DiagnosticError, normalizeOptions, TOOLS } = require("./common");
// History contains measured metadata, never response bodies, credentials or URL queries.
function scrub(value, key = "", depth = 0) {
  if (depth > 24) throw new DiagnosticError("IMPORT_INVALID");
  if (/password|passphrase|privatekey|cookie|authoriz|authenticat|api.?key|secret|token/i.test(key)) return "[redacted]";
  if (typeof value === "string") {
    if (key === "input" || /^(?:https?|wss?):\/\//i.test(value)) {
      try { const url = new URL(value.includes("://") ? value : `https://${value}`); url.username = ""; url.password = ""; url.search = ""; url.hash = ""; return url.href; } catch {}
    }
    if (key.toLowerCase() === "location") return value.split(/[?#]/)[0].slice(0, 16000);
    return value.slice(0, 16000);
  }
  if (Array.isArray(value)) return value.slice(0, 500).map((v) => scrub(v, "", depth + 1));
  if (value && typeof value === "object") {
    const result = {};
    for (const [k, v] of Object.entries(value)) {
      if (["_body", "raw", "__proto__", "constructor", "prototype"].includes(k)) continue;
      result[k] = scrub(v, k, depth + 1);
    }
    return result;
  }
  return typeof value === "number" && !Number.isFinite(value) ? null : value;
}
function validateReport(report) {
  const invalid = () => { throw new DiagnosticError("IMPORT_INVALID"); };
  const object = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
  const objects = (v) => Array.isArray(v) && v.length <= 500 && v.every(object);
  if (!object(report) || !/^[a-f0-9]{32}$/.test(report.id) || !Number.isFinite(Date.parse(report.createdAt)) ||
      !["completed", "cancelled", "failed"].includes(report.status) || !object(report.options) || !object(report.options.target) || !object(report.results)) invalid();
  let options;
  try { options = normalizeOptions({ ...report.options, target: report.options.target.url, ports: report.options.ports?.join(",") }); } catch { invalid(); }
  if (options.target.host !== report.options.target.host || !objects(report.addresses) || report.addresses.some((a) => net.isIP(a.address) !== a.family)) invalid();
  let nodes = 0;
  const arrayKeys = new Set(["comparisons", "samples", "routes", "hops", "probes", "queries", "records", "packets", "ports", "redirects", "securityHeaders", "chain"]);
  function walk(value, depth = 0) {
    if (++nodes > 50000 || depth > 24) invalid();
    if (Array.isArray(value)) { if (value.length > 500) invalid(); for (const child of value) walk(child, depth + 1); }
    else if (object(value)) {
      for (const [key, child] of Object.entries(value)) {
        if (["__proto__", "constructor", "prototype"].includes(key)) invalid();
        if (arrayKeys.has(key) && !(key === "ports" && Array.isArray(child) && child.every(Number.isInteger)) && !objects(child)) invalid();
        if (["addresses", "errors"].includes(key) && !Array.isArray(child)) invalid();
        walk(child, depth + 1);
      }
      if ("comparisons" in value && value.comparisons.some((g) => !objects(g.samples))) invalid();
      if ("routes" in value && value.routes.some((r) => !objects(r.hops))) invalid();
      if ("hop" in value && (!Array.isArray(value.addresses) || !value.addresses.every((a) => typeof a === "string") || !objects(value.probes))) invalid();
    }
  }
  walk(report);
  for (const [tool, result] of Object.entries(report.results)) {
    if (!TOOLS.includes(tool)) invalid();
    if (tool === "dns" ? !object(result) && !objects(result) : !objects(result)) invalid();
    if (tool === "tcp" && result.some((entry) => entry.ports !== undefined && !objects(entry.ports))) invalid();
    if (["tls", "compression"].includes(tool) && result.some((entry) => entry.results !== undefined && !objects(entry.results))) invalid();
  }
  if (report.progress !== undefined && !objects(report.progress)) invalid();
  return scrub({ ...report, options });
}
function rows(report) {
  const result = [];
  for (const [tool, entries] of Object.entries(report.results || {})) for (const entry of Array.isArray(entries) ? entries : [entries]) {
    if (tool === "ping") for (const packet of entry.packets || []) result.push({ tool, address: entry.address, sequence: packet.sequence, status: packet.status, rttMs: packet.rttMs });
    else if (tool === "http") for (const group of entry.comparisons || []) for (const sample of group.samples || []) result.push({ tool, address: group.address, protocol: group.protocol, sequence: sample.iteration, status: sample.status, httpStatus: sample.statusCode, dnsMs: sample.timings?.dnsMs, tcpMs: sample.timings?.tcpMs, tlsMs: sample.timings?.tlsMs, ttfbMs: sample.timings?.ttfbMs, totalMs: sample.timings?.totalMs, bytes: sample.downloadedBytes });
    else if (tool === "tcp") for (const port of entry.ports || []) result.push({ tool, address: port.address, port: port.port, status: port.status, tcpMs: port.connectionMs });
    else result.push({ tool, address: entry.address, status: entry.status, detail: JSON.stringify(entry) });
  }
  return result;
}
function exportReport(report, format) {
  const safe = scrub(report);
  if (format === "json") return JSON.stringify({ schema: 1, report: safe }, null, 2) + "\n";
  if (format === "txt") return `CH-J Server Diagnostics\n${safe.createdAt}\n${safe.options?.target?.host || ""}\n\n${JSON.stringify(safe, null, 2)}\n`;
  if (format !== "csv") throw new DiagnosticError("INVALID_EXPORT_FORMAT");
  const table = rows(safe), keys = [...new Set(table.flatMap((row) => Object.keys(row)))];
  const cell = (value) => { let text = value === null || value === undefined ? "" : String(value); if (/^\s*[=+@-]|^[\t\r\n]/.test(text)) text = "'" + text; return '"' + text.replace(/"/g, '""') + '"'; };
  return [keys.map(cell).join(","), ...table.map((row) => keys.map((key) => cell(row[key])).join(","))].join("\r\n") + "\r\n";
}
class DiagnosticsHistory {
  constructor(root) { this.file = root ? path.join(root, "diagnostics", "history.json") : null; this.items = []; this.loaded = false; }
  load() {
    if (this.loaded) return;
    if (!this.file || !fs.existsSync(this.file)) { this.loaded = true; return; }
    const attrs = fs.lstatSync(this.file); if (!attrs.isFile() || attrs.isSymbolicLink() || attrs.size > 12 * 1024 * 1024) throw new DiagnosticError("HISTORY_INVALID");
    const document = JSON.parse(fs.readFileSync(this.file, "utf8")); if (document.schema !== 1 || !Array.isArray(document.items)) throw new DiagnosticError("HISTORY_INVALID");
    this.items = document.items.slice(0, 30).map(validateReport); this.loaded = true;
  }
  add(report) { this.load(); this.items = this.items.filter((item) => item.id !== report.id); this.items.unshift(scrub(report)); this.items = this.items.slice(0, 30); while (Buffer.byteLength(JSON.stringify(this.items)) > 10 * 1024 * 1024) this.items.pop(); this.persist(); }
  persist() { if (this.file) atomicWriteJson(this.file, { schema: 1, items: this.items }); }
  list() { this.load(); return this.items.map((item) => ({ id: item.id, createdAt: item.createdAt, target: item.options.target, mode: item.options.mode, tools: item.options.tools, status: item.status })); }
  get(id) { this.load(); const report = this.items.find((item) => item.id === id); if (!report) throw new DiagnosticError("HISTORY_NOT_FOUND"); return scrub(report); }
  remove(id) { this.load(); this.items = id ? this.items.filter((item) => item.id !== id) : []; this.persist(); return this.list(); }
  import(text) {
    if (typeof text !== "string" || Buffer.byteLength(text) > 2 * 1024 * 1024) throw new DiagnosticError("IMPORT_LIMIT");
    let value;
    try { value = JSON.parse(text); } catch { throw new DiagnosticError("IMPORT_INVALID"); }
    if (value?.schema !== 1) throw new DiagnosticError("IMPORT_INVALID");
    const report = validateReport(value.report); this.add(report); return report.id;
  }
}
module.exports = { DiagnosticsHistory, scrub, exportReport, rows, validateReport };
