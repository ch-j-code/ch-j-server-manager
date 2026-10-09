"use strict";
(function(root) {
  const SERVICE_PORTS = [[22,"SSH"],[21,"FTP"],[25,"SMTP"],[53,"DNS TCP"],[80,"HTTP"],[110,"POP3"],[143,"IMAP"],[443,"HTTPS"],[445,"SMB"],[587,"SMTP Submission"],[993,"IMAPS"],[995,"POP3S"],[3306,"MySQL"],[3389,"RDP"],[5432,"PostgreSQL"],[6379,"Redis"]];
  function mount(host, { api, language, getTheme, setTheme }) {
    host.classList.add("diagnostics");
    const tr = (key) => root.CHJ_DIAGNOSTICS_I18N.t(language(), key);
    const state = { report: null, jobId: null, running: false, starting: false, pending: [], tab: "overview", events: [], history: [], selected: new Set() };
    const fields = {}, panels = {}, tabs = {}, runButtons = [], stopButtons = [];
    function el(tag, className, text) { const value = document.createElement(tag); if (className) value.className = className; if (text !== undefined) value.textContent = text; return value; }
    function labelText(key, tag = "span") { const value = el(tag); value.dataset.diagText = key; value.textContent = tr(key); return value; }
    function button(key, action, className = "button") { const value = labelText(key, "button"); value.type = "button"; value.className = className; value.addEventListener("click", () => { Promise.resolve().then(action).catch(showError); }); return value; }
    function input(name, key, type, value, parent, attrs = {}) { const label = el("label"), field = el("input"); field.type = type; field.value = value; Object.assign(field, attrs); fields[name] = field; label.append(labelText(key), field); parent.append(label); return field; }
    function select(name, key, choices, parent) { const label = el("label"), field = el("select"); fields[name] = field; for (const [value, text] of choices) { const option = labelText(text, "option"); option.value = value; field.append(option); } label.append(labelText(key), field); parent.append(label); return field; }
    const intro = el("div", "section-heading"); intro.append(labelText("Server Diagnostics", "h2"), labelText("Network diagnostics without an SSH connection", "p")); host.append(intro);
    const form = el("form", "diag-toolbar panel"); form.addEventListener("submit", (event) => { event.preventDefault(); void run().catch(showError); }); host.append(form);
    input("target", "Target", "text", "", form, { placeholder: "example.org", maxLength: 2048, required: true, autocomplete: "off", spellcheck: false });
    const detected = el("small", "diag-detected"); form.firstChild.append(detected);
    select("mode", "IP mode", [["auto","Auto"],["ipv4","IPv4"],["ipv6","IPv6"],["both","Both"]], form);
    select("selectedIp", "Selected IP", [["","Auto"]], form);
    const resolveButton = button("Resolve addresses", resolve); form.append(resolveButton);
    const runAll = button("Run Diagnostics", () => run(), "button primary"); form.append(runAll); runButtons.push(runAll);
    const stopAll = button("Stop", () => stop()); form.append(stopAll); stopButtons.push(stopAll);
    const settings = el("details", "diag-settings panel"); settings.append(labelText("Settings", "summary")); host.append(settings);
    const controls = el("div", "diag-controls"); settings.append(controls);
    input("timeoutMs", "Timeout (ms)", "number", "5000", controls, { min: 250, max: 30000, step: 250 });
    input("count", "Packets", "number", "4", controls, { min: 1, max: 100 });
    input("repetitions", "Repetitions", "number", "1", controls, { min: 1, max: 20 });
    input("maxHops", "Max hops", "number", "20", controls, { min: 1, max: 40 });
    select("resolver", "DNS resolver", [["system","System DNS"],["custom","Custom DNS"],["cloudflare","Cloudflare"],["google","Google"],["quad9","Quad9"]], controls);
    input("customDns", "Custom DNS IP", "text", "", controls, { placeholder: "192.168.1.1" });
    select("theme", "Theme", [["system","System"],["dark","Dark"],["light","Light"]], controls).value = getTheme() || "system";
    input("continuous", "Continuous ping (max 30 min)", "checkbox", "", controls);
    input("warm", "Warm connection", "checkbox", "", controls);
    input("compareSchemes", "Compare HTTP / HTTPS", "checkbox", "", controls);
    const protocols = el("fieldset", "diag-checks"); protocols.append(labelText("Protocols", "legend")); controls.append(protocols);
    for (const protocol of ["1.1","2","3"]) { const field = input("protocol" + protocol, "HTTP/" + protocol, "checkbox", "", protocols); field.checked = true; }
    settings.append(labelText("External DNS is used only when selected here.", "p"));
    const status = el("div", "diag-status"); status.setAttribute("role", "status"); status.setAttribute("aria-live", "polite"); host.append(status);
    const nav = el("div", "diag-tabs"); nav.setAttribute("role", "tablist"); host.append(nav);
    const names = { overview: "Overview", ping: "Ping & Traceroute", dns: "DNS", http: "HTTP & Performance", tls: "SSL / TLS", tcp: "TCP & Ports", history: "History" };
    for (const [name, key] of Object.entries(names)) { const tab = button(key, () => switchTab(name)); tab.setAttribute("role", "tab"); tab.id = "diag-tab-" + name; tab.setAttribute("aria-controls", "diag-panel-" + name); tabs[name] = tab; nav.append(tab); const panel = el("article", "panel diag-panel"); panel.setAttribute("role", "tabpanel"); panel.id = "diag-panel-" + name; panel.setAttribute("aria-labelledby", tab.id); panels[name] = panel; host.append(panel); }
    const content = {};
    function tools(panel, definitions) {
      const actions = el("div", "diag-actions"); panel.append(actions);
      for (const [tool, name] of definitions) { const runButton = button(name, () => run([tool]), "button primary"); actions.append(runButton); runButtons.push(runButton); const stopButton = button("Stop", () => stop(tool)); stopButton.dataset.tool = tool; actions.append(stopButton); stopButtons.push(stopButton); }
    }
    tools(panels.overview, [["overview","Run Diagnostics"]]); tools(panels.ping, [["ping","Ping"],["traceroute","Traceroute"]]); tools(panels.dns, [["dns","Run"]]); tools(panels.http, [["http","Run"],["compression","Compression"],["websocket","WebSocket handshake"]]); tools(panels.tls, [["tls","Run"]]); tools(panels.tcp, [["tcp","Run"]]);
    panels.ping.append(labelText("ICMP filtering cannot establish that a server is offline.", "p"), labelText("Intermediate hop timeouts do not prove a broken route.", "p"));
    panels.dns.append(labelText("DNSSEC not validated. DS/DNSKEY presence is not proof of validation.", "p"));
    panels.http.append(labelText("Network/server timings, not page rendering or Lighthouse scores.", "p"));
    panels.tcp.append(labelText("Port names are standard assignments, not verified services.", "p"));
    const portsArea = el("div", "diag-controls"); panels.tcp.append(portsArea); input("ports", "Ports (max 16)", "text", "22,80,443", portsArea);
    const presetArea = el("details", "diag-presets"); presetArea.append(labelText("Port presets", "summary")); panels.tcp.append(presetArea);
    for (const [port, name] of SERVICE_PORTS) { const label = el("label"), check = el("input"); check.type = "checkbox"; check.checked = [22,80,443].includes(port); check.addEventListener("change", () => { const current = new Set(fields.ports.value.split(/[,;\s]+/).filter(Boolean)); check.checked ? current.add(String(port)) : current.delete(String(port)); fields.ports.value = [...current].join(","); }); label.append(check, document.createTextNode(name + " — " + port)); presetArea.append(label); }
    const historyActions = el("div", "diag-actions"); historyActions.append(button("Refresh history", loadHistory), button("Import JSON", async () => { const result = await invoke(api.import()); if (result.id) { await loadHistory(); await openHistory(result.id); } }), button("Compare selected", compareHistory)); panels.history.append(historyActions);
    for (const name of Object.keys(names)) { content[name] = el("div", "diag-content"); panels[name].append(content[name]); }
    const exports = el("div", "diag-actions diag-export"); exports.append(button("Copy report", async () => { if (!state.report) return; await invoke(api.copy(state.report.id)); status.textContent = tr("Copied"); }));
    for (const format of ["json","csv","txt"]) exports.append(button(format.toUpperCase(), () => state.report ? invoke(api.export(state.report.id, format)) : undefined)); host.append(exports);
    const raw = el("details", "diag-raw"); raw.append(labelText("Raw details", "summary")); const rawText = el("pre"); raw.append(rawText); host.append(raw);
    function format(value, unit = "") { return typeof value === "number" && Number.isFinite(value) ? value.toLocaleString(language(), { maximumFractionDigits: 2 }) + (unit ? " " + unit : "") : "N/A"; }
    function bytes(value) { return typeof value === "number" ? value >= 1048576 ? format(value / 1048576, "MiB") : format(value / 1024, "KiB") : "N/A"; }
    function statusNode(value) { return el("span", "diag-badge diag-" + String(value || "not-tested").replace(/[^a-z-]/g, ""), tr(value || "not-tested")); }
    function table(parent, columns, rows) { if (!rows.length) { parent.append(labelText("No results yet", "p")); return; } const wrap = el("div", "diag-table-wrap"), table = el("table"), head = el("thead"), row = el("tr"); columns.forEach(([name]) => row.append(el("th", "", tr(name)))); head.append(row); table.append(head); const body = el("tbody"); for (const item of rows) { const row = el("tr"); for (const [, get] of columns) { const value = get(item), cell = el("td"); if (value instanceof Node) cell.append(value); else cell.textContent = value === null || value === undefined ? "N/A" : typeof value === "object" ? JSON.stringify(value) : String(value); row.append(cell); } body.append(row); } table.append(body); wrap.append(table); parent.append(wrap); }
    function detail(parent, title, value) { const item = el("details", "diag-detail"); item.append(el("summary", "", title), el("pre", "", JSON.stringify(value, null, 2))); parent.append(item); }
    function packetList() { const complete = (state.report?.results.ping || []).flatMap((entry) => (entry.packets || []).map((packet) => ({ ...packet, address: entry.address }))); return complete.length ? complete : state.events.filter((event) => event.kind === "ping-packet"); }
    function graph(parent, packets, valueKey = "rttMs") {
      if (!packets.length) return;
      const canvas = el("canvas", "diag-chart"); canvas.width = 900; canvas.height = 200; canvas.setAttribute("role", "img"); canvas.setAttribute("aria-label", tr("Latency (ms)")); parent.append(canvas);
      const ctx = canvas.getContext("2d"); if (!ctx) return; const max = Math.max(1, ...packets.map((p) => Number.isFinite(p[valueKey]) ? p[valueKey] : 0)); ctx.clearRect(0,0,900,200); ctx.font = "12px sans-serif"; ctx.fillStyle = "#8299b0"; ctx.fillText(format(max, "ms"), 5, 15); ctx.fillText("0 ms", 5, 188);
      ctx.strokeStyle = "#5c748c"; ctx.beginPath(); ctx.moveTo(55,15); ctx.lineTo(55,180); ctx.lineTo(890,180); ctx.stroke();
      packets.slice(-200).forEach((packet, index, all) => { const x = 65 + index * 810 / Math.max(1, all.length - 1), value = packet[valueKey], success = typeof value === "number" && Number.isFinite(value); const y = success ? 175 - 150 * value / max : 180;
        ctx.fillStyle = success ? "#38bc96" : packet.status === "timeout" ? "#e85d75" : "#ddad42"; ctx.strokeStyle = ctx.fillStyle;
        if (success) { ctx.beginPath(); ctx.arc(x,y,3,0,2*Math.PI); ctx.fill(); } else if (packet.upperBoundMs) { ctx.beginPath(); ctx.arc(x,y,4,0,2*Math.PI); ctx.stroke(); } else if (packet.status === "timeout") ctx.fillRect(x-3,y-3,6,6); else { ctx.beginPath(); ctx.moveTo(x-3,y-3); ctx.lineTo(x+3,y+3); ctx.moveTo(x-3,y+3); ctx.lineTo(x+3,y-3); ctx.stroke(); }
      }); parent.append(el("p", "diag-legend", "● " + tr("success") + " · × " + tr("No reply") + " · ○ " + tr("Below measurement precision") + " · ■ " + tr("Timeout")));
    }
    function overviewRows(report) {
      const addresses = report.resolvedAddresses || report.addresses;
      const rows = [{ name: "IPv4", value: addresses.filter((a) => a.family === 4).map((a) => a.address).join(", ") || "N/A" },
        { name: "IPv6", value: addresses.filter((a) => a.family === 6).map((a) => a.address).join(", ") || "N/A" },
        { name: "Resolution (ms)", value: format(report.resolutionMs, "ms") }];
      for (const [tool, entries] of Object.entries(report.results || {})) {
        for (const entry of Array.isArray(entries) ? entries : [entries]) {
          const suffix = entry.address ? " · " + entry.address : "";
          rows.push({ name: tool.toUpperCase() + suffix, value: statusNode(entry.status), reason: entry.reason || entry.code });
          if (tool === "ping") rows.push({ name: tr("Packet loss") + suffix, value: format(entry.lossPercent, "%") },
            { name: tr("Average") + " RTT" + suffix, value: format(entry.statistics?.average, "ms") });
          if (tool === "http") for (const group of entry.comparisons || []) for (const sample of group.samples.slice(-1)) {
            const tested = "HTTP/" + group.protocol + suffix + (group.url ? " · " + String(group.url).split(":")[0] : "");
            rows.push({ name: tested, value: statusNode(sample.status), reason: sample.reason || sample.code });
            if (sample.timings) rows.push({ name: "TTFB · " + tested, value: format(sample.timings.ttfbMs, "ms") },
              { name: tr("Total") + " · " + tested, value: format(sample.timings.totalMs, "ms") });
          }
          if (tool === "compression") rows.push({ name: "Brotli" + suffix, value: statusNode(entry.results?.find((r) => r.encoding === "br")?.status) });
        }
      }
      return rows;
    }

    function render() {
      host.dataset.theme = fields.theme.value;
      runButtons.forEach((button) => { button.disabled = state.running; }); stopButtons.forEach((button) => { button.disabled = !state.running || state.starting || Boolean(button.dataset.tool && !state.report?.options.tools.includes(button.dataset.tool)); }); resolveButton.disabled = state.running;
      for (const name of Object.keys(content)) if (name !== "history") content[name].replaceChildren();
      const report = state.report;
      if (!report) { content.overview.append(labelText("No results yet", "p")); return; }
      const results = report.results || {};
      table(content.overview, [["Tool", (r) => tr(r.name)], ["Value", (r) => r.value], ["Status", (r) => r.reason || ""]], overviewRows(report));
      const latestTools = new Map(); for (const event of state.events) if (["tool-start","tool-complete"].includes(event.kind)) latestTools.set(event.tool, event);
      const events = [...latestTools.values()]; table(content.overview, [["Tool", (e) => e.tool], ["Status", (e) => statusNode(e.kind === "tool-start" ? "running" : "completed")]], events.slice(-16));
      const packets = packetList(); for (const address of [...new Set(packets.map((p) => p.address))]) { content.ping.append(el("h3", "", address)); graph(content.ping, packets.filter((p) => p.address === address)); }
      table(content.ping, [["Address", (p) => p.address],["Sequence", (p) => p.sequence],["Date", (p) => p.measuredAt ? new Date(p.measuredAt).toLocaleTimeString(language()) : "N/A"],["Status", (p) => statusNode(p.status)],["Latency (ms)", (p) => p.upperBoundMs ? "<" + format(p.upperBoundMs) : format(p.rttMs)],["TTL / Hop Limit", (p) => p.ttl]], packets.slice(-200));
      const pingStats = results.ping?.length ? results.ping : Object.values(report.livePing || {});
      table(content.ping, [["Address", (p) => p.address],["Sent", (p) => p.sent],["Received", (p) => p.received],["Packet loss", (p) => format(p.lossPercent, "%")],...[['Min','min'],['Average','average'],['Max','max'],['Jitter','jitter'],['Standard deviation','stddev']].map(([label,key]) => [label,(p) => format(p.statistics?.[key], "ms")])], pingStats);
      for (const entry of results.ping || []) if (entry.reason || entry.code) content.ping.append(el("p", "", tr(entry.code || entry.status) + " · " + (entry.reason || "")));
      for (const trace of results.traceroute || []) { table(content.ping, [["Hop", (h) => h.hop],["Address", (h) => h.addresses.join(", ")],["Reverse DNS", (h) => h.addresses.flatMap((a) => trace.reverseDns?.[a] || []).join(", ") || "N/A"],["Probes (ms)", (h) => h.probes.map((p) => p.status === "timeout" ? "*" : p.upperBoundMs ? "<" + p.upperBoundMs : format(p.rttMs)).join(" / ")],["Average", (h) => format(h.averageMs,"ms")],["Packet loss", (h) => format(h.lossPercent,"%")]], trace.routes?.flatMap((r) => r.hops) || []); content.ping.append(el("p", "", (trace.method || "") + " · " + tr("Route changed") + ": " + (trace.routeChanged === null || trace.routeChanged === undefined ? "N/A" : tr(trace.routeChanged ? "Yes" : "No")))); detail(content.ping, "Traceroute · " + (trace.address || ""), trace); }
      if (!results.traceroute) table(content.ping, [["Hop", (h) => h.hop],["Address", (h) => h.addresses.join(", ")],["Average", (h) => format(h.averageMs,"ms")]], state.events.filter((e) => e.kind === "trace-hop"));
      const dnsQueries = results.dns?.queries || state.events.filter((e) => e.kind === "dns-record");
      table(content.dns, [["Record", (q) => q.type],["Name", (q) => q.name],["Status", (q) => statusNode(q.status)],["Resolution (ms)", (q) => format(q.durationMs)]], dnsQueries);
      table(content.dns, [["Name", (r) => r.name],["Record", (r) => r.type],["TTL (s)", (r) => r.ttl],["Value", (r) => r.value]], dnsQueries.flatMap((q) => q.records || []));
      if (results.dns) detail(content.dns, tr("DNS consistency and CNAME chain"), results.dns);
      const samples = (results.http || []).flatMap((entry) => (entry.comparisons || []).flatMap((group) => group.samples.map((sample) => ({ ...sample, protocol: group.protocol, address: group.address }))));
      const displayed = samples.length ? samples : state.events.filter((e) => e.kind === "http-sample");
      graph(content.http, displayed.map((s) => ({ ...s, rttMs: s.timings?.totalMs })));
      table(content.http, [["Address", (s) => s.serverIp || s.address],["Protocols", (s) => "HTTP/" + s.protocol],["Negotiated", (s) => s.negotiated],["Status", (s) => statusNode(s.status)],["HTTP status", (s) => s.statusCode],["Reason", (s) => s.code === "HTTP3_UNAVAILABLE" ? tr("HTTP/3 testing unavailable") + " · " + (s.reason || "") : s.reason || s.code || ""],...[['DNS','dnsMs'],['TCP','tcpMs'],['TLS','tlsMs'],['TTFB','ttfbMs'],['Redirect','redirectMs'],['Download','downloadMs'],['Total','totalMs']].map(([name,key]) => [name+' (ms)',(s) => format(s.timings?.[key])]),["Downloaded", (s) => bytes(s.downloadedBytes)],["Speed", (s) => format(s.bytesPerSecond / 1048576,"MiB/s")],["Reuse", (s) => s.reused === null || s.reused === undefined ? "N/A" : tr(s.reused ? "Yes" : "No")]], displayed);
      for (const entry of results.http || []) for (const group of entry.comparisons || []) { table(content.http, [["Protocols", () => "HTTP/"+group.protocol],...[['Min','min'],['Average','average'],['Median','median'],['Max','max'],['P95','p95']].map(([name,key]) => [name,(g) => format(g.statistics?.[key],"ms")]),["Error rate", (g) => format(g.errorRate,"%")]], [group]); }
      displayed.forEach((sample) => detail(content.http, "HTTP/" + sample.protocol + " · " + tr(sample.status), sample));
      const compression = (results.compression || []).flatMap((entry) => entry.results || []); table(content.http, [["Encoding", (r) => r.encoding],["Status", (r) => statusNode(r.status)],["Actual encoding", (r) => r.actualEncoding],["Downloaded", (r) => bytes(r.downloadedBytes)],["Decoded", (r) => bytes(r.decodedBytes)],["Ratio", (r) => format(r.ratio)]], compression.length ? compression : state.events.filter((e) => e.kind === "compression"));
      for (const entry of results.websocket || []) detail(content.http, tr("WebSocket handshake"), entry);
      const tlsResults = (results.tls || []).flatMap((entry) => entry.results || []); const shownTls = tlsResults.length ? tlsResults : state.events.filter((e) => e.kind === "tls");
      table(content.tls, [["Protocols", (r) => r.requestedVersion],["Negotiated", (r) => r.negotiatedVersion],["Status", (r) => statusNode(r.status)],["Certificate", (r) => r.chain?.[0]?.subject],["Issuer", (r) => r.chain?.[0]?.issuer],["Expires", (r) => r.chain?.[0]?.validUntil],["Days remaining", (r) => r.chain?.[0]?.daysUntilExpiration],["Status", (r) => (r.errors || [r.code]).filter(Boolean).join(", ")]], shownTls); shownTls.forEach((r) => detail(content.tls, r.requestedVersion || "TLS", r));
      const portResults = (results.tcp || []).flatMap((entry) => entry.ports || []); table(content.tcp, [["Address", (p) => p.address],["Port", (p) => p.port],["Service label", (p) => p.standardService],["Status", (p) => statusNode(p.status)],["TCP (ms)", (p) => format(p.connectionMs)],["Banner", (p) => p.banner]], portResults.length ? portResults : state.events.filter((e) => e.kind === "tcp")); for (const entry of results.tcp || []) if (entry.ssh) detail(content.tcp, "SSH", entry.ssh);
      rawText.textContent = JSON.stringify(report, null, 2);
      status.replaceChildren(statusNode(report.status), document.createTextNode(" · " + report.options.target.host + (report.error ? " · " + tr(report.error.code) : "")));
    }
    nav.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault(); const keys = Object.keys(tabs), index = keys.indexOf(state.tab);
      const next = event.key === "Home" ? 0 : event.key === "End" ? keys.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + keys.length) % keys.length;
      switchTab(keys[next]); tabs[keys[next]].focus();
    });
    let renderPending = false;
    function scheduleRender() { if (!renderPending) { renderPending = true; requestAnimationFrame(() => { renderPending = false; render(); }); } }
    async function invoke(promise) { const result = await promise; if (!result.ok) throw Object.assign(new Error(tr(result.error.code)), result.error); return result.value; }
    function showError(error) { status.textContent = tr(error.code || "error") + (error.message && error.message !== error.code ? " · " + error.message : ""); status.classList.add("diag-error-text"); }
    function options(tools) { return { target: fields.target.value, mode: fields.mode.value, selectedIp: fields.selectedIp.value, timeoutMs: Number(fields.timeoutMs.value), count: Number(fields.count.value), repetitions: Number(fields.repetitions.value), maxHops: Number(fields.maxHops.value), resolver: fields.resolver.value, customDns: fields.customDns.value, continuous: fields.continuous.checked, warm: fields.warm.checked, compareSchemes: fields.compareSchemes.checked, ports: fields.ports.value, protocols: ["1.1","2","3"].filter((p) => fields["protocol"+p].checked), tools }; }
    async function run(tools) { if (state.running) return; if (!form.reportValidity()) return; if (tools?.[0] === "overview") tools = undefined; state.running = true; state.starting = true; state.pending = []; render(); let result; try { result = await invoke(api.start(options(tools))); } catch (error) { state.running = false; state.starting = false; state.pending = []; render(); throw error; } state.report = result.report; state.jobId = result.id; state.events = []; state.running = true; state.starting = false; for (const event of state.pending) receive(event); state.pending = []; status.classList.remove("diag-error-text"); render(); }
    async function stop(tool) { if (state.jobId) await invoke(api.cancel(state.jobId, tool)); }
    async function resolve() { const result = await invoke(api.resolve(options(["dns"]))); fields.selectedIp.replaceChildren(); const auto = labelText("Auto", "option"); auto.value = ""; fields.selectedIp.append(auto); for (const ip of result.addresses) { const option = el("option","",ip.address + " · IPv"+ip.family); option.value = ip.address; fields.selectedIp.append(option); } detected.textContent = result.target.type; status.textContent = result.addresses.map((a) => a.address).join(" · "); }
    async function loadHistory() { state.history = await invoke(api.history()); renderHistory(); }
    function renderHistory() { content.history.replaceChildren(); if (!state.history.length) { content.history.append(labelText("No history", "p")); return; } table(content.history, [["", (entry) => { const check = el("input"); check.type = "checkbox"; check.checked = state.selected.has(entry.id); check.addEventListener("change", () => check.checked ? state.selected.add(entry.id) : state.selected.delete(entry.id)); return check; }],["Date", (entry) => new Date(entry.createdAt).toLocaleString(language())],["Target", (entry) => entry.target.host],["IP mode", (entry) => entry.mode],["Status", (entry) => statusNode(entry.status)],["", (entry) => { const actions = el("div", "diag-actions"); actions.append(button("Open", () => openHistory(entry.id)), button("Delete", async () => { await invoke(api.removeHistory(entry.id)); state.selected.delete(entry.id); await loadHistory(); })); return actions; }]], state.history); }
    async function openHistory(id) { if (state.running) throw Object.assign(new Error(tr("DIAGNOSTICS_BUSY")), { code: "DIAGNOSTICS_BUSY" }); state.report = await invoke(api.get(id)); state.events = state.report.progress || []; render(); switchTab("overview"); }
    async function compareHistory() { if (state.selected.size !== 2) { status.textContent = tr("Compare exactly two reports"); return; } const reports = await Promise.all([...state.selected].map((id) => invoke(api.get(id)))); const values = reports.map(overviewRows), keys = [...new Set(values.flatMap((r) => r.map((v) => v.name)))]; const comparison = el("div"); table(comparison, [["Tool", (r) => tr(r)], ...reports.map((report,index) => [new Date(report.createdAt).toLocaleString(language()), (name) => values[index].find((r) => r.name === name)?.value ?? "N/A"])], keys); content.history.append(comparison); }
    function switchTab(name) { state.tab = name; for (const key of Object.keys(panels)) { panels[key].hidden = key !== name; tabs[key].setAttribute("aria-selected", String(key === name)); tabs[key].tabIndex = key === name ? 0 : -1; tabs[key].classList.toggle("active",key === name); } if (name === "history") void loadHistory().catch(showError); }
    fields.target.addEventListener("input", () => { fields.selectedIp.replaceChildren(); const auto = labelText("Auto", "option"); auto.value = ""; fields.selectedIp.append(auto); const raw = fields.target.value; detected.textContent = raw.includes("://") ? "URL" : raw.includes(":") ? "IPv6" : /^\d+(?:\.\d+){3}$/.test(raw) ? "IPv4" : "Hostname"; });
    fields.mode.addEventListener("change", () => { fields.selectedIp.value = ""; }); fields.resolver.addEventListener("change", () => { fields.selectedIp.value = ""; });
    fields.theme.addEventListener("change", async () => { try { await setTheme(fields.theme.value); render(); } catch (error) { showError(error); } });
    function receive(event) {
      if (event.jobId !== state.jobId) return;
      state.events.push(event); if (state.events.length > 500) state.events.shift();
      if (event.kind === "resolved") { state.report.addresses = event.addresses; state.report.resolvedAddresses = event.resolvedAddresses; state.report.resolutionMs = event.resolutionMs; }
      if (event.kind === "tool-complete") state.report.results[event.tool] = event.result;
      if (event.kind === "ping-packet") { state.report.livePing ||= {}; state.report.livePing[event.address] = event; }
      if (event.kind === "complete") { state.report = event.report; state.running = false; void loadHistory().catch(showError); }
      scheduleRender();
    }
    const unsubscribe = api.onProgress((event) => { if (state.starting) { if (state.pending.length < 500) state.pending.push(event); } else receive(event); });
    function refreshLanguage() { host.querySelectorAll("[data-diag-text]").forEach((node) => { node.textContent = tr(node.dataset.diagText); }); render(); renderHistory(); }
    switchTab("overview"); render();
    return { refreshLanguage, dispose() { unsubscribe(); }, state };
  }
  root.CHJ_DIAGNOSTICS = { mount };
})(globalThis);
