"use strict";
const { EventEmitter } = require("node:events");
const crypto = require("node:crypto");
const net = require("node:net");
const { normalizeOptions, DiagnosticError, checkAbort, errorResult, boundedSignal, now } = require("./common");
const { DnsDiagnostics, reverseName } = require("./dnsDiagnostics");
const { ping, traceroute } = require("./processTools");
const { HttpDiagnostics } = require("./httpDiagnostics");
const { runTls, runTcp, websocketProbe } = require("./socketDiagnostics");
const { DiagnosticsHistory, exportReport, scrub } = require("./historyStore");
function sameIp(a, b) {
  if (net.isIP(a) !== net.isIP(b)) return false;
  return a === b || net.isIP(a) === 6 && new URL(`http://[${a}]/`).hostname === new URL(`http://[${b}]/`).hostname;
}
class DiagnosticsService extends EventEmitter {
  constructor(options = {}) {
    super();
    this.dns = options.dns || new DnsDiagnostics();
    this.http = options.http || new HttpDiagnostics(this.dns);
    this.history = options.history || new DiagnosticsHistory(options.storageRoot);
    this.jobs = new Map(); this.resolvers = new Set();
    this.adapters = { ping, traceroute, tls: runTls, tcp: runTcp,
      websocket: (target, address, settings, signal) => websocketProbe(target, address, settings, signal), ...options.adapters };
  }
  async resolve(source) {
    if (this.resolvers.size >= 2) throw new DiagnosticError("DIAGNOSTICS_BUSY");
    const options = normalizeOptions({ ...source, tools: ["dns"] });
    const controller = new AbortController(), bounded = boundedSignal(controller.signal, 30000);
    this.resolvers.add(controller);
    try { return { target: options.target, addresses: await this.dns.resolve(options.target.host, options, bounded.signal) }; }
    finally { bounded.close(); this.resolvers.delete(controller); }
  }
  start(source) {
    if ([...this.jobs.values()].some((job) => job.report.status === "running")) throw new DiagnosticError("DIAGNOSTICS_BUSY");
    const options = normalizeOptions(source), id = crypto.randomBytes(16).toString("hex"), controller = new AbortController();
    const report = { id, createdAt: new Date().toISOString(), status: "running", options, results: {}, progress: [], addresses: [] };
    const job = { report, controller, tools: new Map(), cancelledTools: new Set() };
    this.jobs.set(id, job);
    while (this.jobs.size > 5) this.jobs.delete(this.jobs.keys().next().value);
    setImmediate(() => { job.promise = this._run(job).catch((error) => this._finish(job, errorResult(error))); });
    return { id, report: scrub(report) };
  }
  cancel(id, tool) {
    const job = this.jobs.get(String(id)); if (!job) throw new DiagnosticError("JOB_NOT_FOUND");
    if (tool) {
      if (!job.report.options.tools.includes(tool)) throw new DiagnosticError("INVALID_TOOLS");
      job.cancelledTools.add(tool); job.tools.get(tool)?.abort();
    } else job.controller.abort();
    return { cancelling: true };
  }
  stopAll() {
    for (const job of this.jobs.values()) if (job.report.status === "running") job.controller.abort();
    for (const controller of this.resolvers) controller.abort();
  }
  get(id) { const job = this.jobs.get(id); return job ? scrub(job.report) : this.history.get(id); }
  _emit(job, event) {
    const value = { jobId: job.report.id, ...event };
    if (event.kind !== "snapshot" && event.kind !== "complete") {
      job.report.progress.push(scrub(event));
      if (job.report.progress.length > 500) job.report.progress.shift();
    }
    this.emit("progress", value);
  }
  _finish(job, failure) {
    if (job.report.status !== "running") return;
    job.report.status = job.controller.signal.aborted ? "cancelled" : failure ? "failed" : "completed";
    job.report.finishedAt = new Date().toISOString();
    if (failure) job.report.error = failure;
    if (job.controller.signal.reason?.code) job.report.error = errorResult(job.controller.signal.reason);
    try { this.history.add(job.report); } catch (error) { job.report.historyError = error.code || "HISTORY_WRITE_FAILED"; }
    this._emit(job, { kind: "complete", report: scrub(job.report) });
  }
  async _address(job, tool, item, signal, progress) {
    const { report } = job, { options } = report;
    try {
      checkAbort(signal); let result;
      if (tool === "http") result = await this.http.run(options.target, item.address, options, signal, progress);
      else if (tool === "compression") result = await this.http.compression(options.target, item.address, options, signal, progress);
      else if (tool === "tls" || tool === "websocket") result = await this.adapters[tool](options.target, item.address, options, signal, progress);
      else result = await this.adapters[tool](item.address, options, signal, progress);
      if (tool === "traceroute") {
        const addresses = [...new Set(result.routes?.flatMap((route) => route.hops.flatMap((hop) => hop.addresses)) || [])].slice(0, options.maxHops);
        result.reverseDns = {};
        for (const address of addresses) {
          checkAbort(signal);
          try { const query = await this.dns.query(reverseName(address), "PTR", options, signal); result.reverseDns[address] = query.records.filter((r) => r.type === "PTR").map((r) => r.value); }
          catch (error) { if (signal.aborted) throw error; result.reverseDns[address] = []; }
        }
      }
      return { address: item.address, family: item.family, ...result };
    } catch (error) {
      const partial = { address: item.address, family: item.family, ...errorResult(error) };
      if (tool === "ping") {
        const latest = report.livePing?.[item.address];
        if (latest) Object.assign(partial, { sent: latest.sent, received: latest.received, lossPercent: latest.lossPercent, statistics: latest.statistics });
        partial.packets = report.progress.filter((e) => e.kind === "ping-packet" && e.address === item.address);
      }
      if (tool === "traceroute") partial.routes = [{ hops: report.progress.filter((e) => e.kind === "trace-hop" && e.address === item.address) }];
      if (tool === "http") partial.comparisons = options.protocols.map((protocol) => ({ protocol, address: item.address, samples: report.progress.filter((e) => e.kind === "http-sample" && e.address === item.address && e.protocol === protocol) }));
      return partial;
    }
  }
  async _run(job) {
    const { report, controller } = job, { options } = report, signal = controller.signal;
    const deadline = setTimeout(() => controller.abort(new DiagnosticError("JOB_TIME_LIMIT")), options.continuous ? 30 * 60 * 1000 : 5 * 60 * 1000);
    try {
      checkAbort(signal); const started = now();
      try { report.addresses = await this.dns.resolve(options.target.host, options, signal); }
      catch (error) { if (signal.aborted) throw error; report.resolutionError = errorResult(error); }
      report.resolvedAddresses = [...report.addresses]; report.resolutionMs = now() - started;
      if (options.selectedIp) {
        const selected = report.addresses.filter((item) => sameIp(item.address, options.selectedIp));
        if (!selected.length) throw new DiagnosticError("SELECTED_IP_NOT_RESOLVED");
        report.addresses = selected;
      }
      if (options.mode === "ipv4") report.addresses = report.addresses.filter((a) => a.family === 4);
      if (options.mode === "ipv6") report.addresses = report.addresses.filter((a) => a.family === 6);
      if (options.mode === "auto") report.addresses = [report.addresses.find((a) => a.family === 4) || report.addresses[0]].filter(Boolean);
      if (options.mode === "both") report.addresses = [report.addresses.find((a) => a.family === 4), report.addresses.find((a) => a.family === 6)].filter(Boolean);
      this._emit(job, { kind: "resolved", addresses: report.addresses, resolvedAddresses: report.resolvedAddresses, resolutionMs: report.resolutionMs, error: report.resolutionError });
      // Two tools at a time; at most two IP families per tool. All workers settle before completion.
      const queue = [...options.tools]; let cursor = 0;
      await Promise.all(Array.from({ length: Math.min(2, queue.length) }, async () => {
        while (cursor < queue.length && !signal.aborted) {
          const tool = queue[cursor++], sub = new AbortController(); job.tools.set(tool, sub);
          const abort = () => sub.abort(); signal.addEventListener("abort", abort, { once: true });
          if (signal.aborted || job.cancelledTools.has(tool)) sub.abort();
          this._emit(job, { kind: "tool-start", tool });
          const progress = (event) => {
            if (event.kind === "ping-packet") { report.livePing ||= {}; report.livePing[event.address] = event; }
            this._emit(job, { tool, ...event });
          };
          try {
            checkAbort(sub.signal);
            if (tool === "dns") report.results.dns = await this.dns.run(options.target.host, options, sub.signal, progress);
            else if (!report.addresses.length) report.results[tool] = [{ status: "not-tested", code: "NO_ADDRESS" }];
            else report.results[tool] = await Promise.all(report.addresses.map((item) => this._address(job, tool, item, sub.signal, progress)));
          } catch (error) { report.results[tool] = [{ ...errorResult(error) }]; }
          finally {
            this._emit(job, { kind: "tool-complete", tool, result: scrub(report.results[tool]) });
            signal.removeEventListener("abort", abort); job.tools.delete(tool);
          }
        }
      }));
      this._finish(job);
    } catch (error) { this._finish(job, errorResult(error)); }
    finally { clearTimeout(deadline); }
  }
  export(id, format) { return exportReport(this.get(id), format); }
}
module.exports = { DiagnosticsService, sameIp };
