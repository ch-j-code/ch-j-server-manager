"use strict";

const api = window.chjPlugin.hashing;
const state = { algorithms: [], calculateSelection: null, verifySelection: null, compareA: null, compareB: null, manifestSource: null, manifestFile: null, manifestRoot: null, activeJobId: null, activeJob: null };
const $ = (id) => document.getElementById(id);

function setText(id, value) { $(id).textContent = value; }
function describeSelection(selection) { return selection?.files?.map((file) => `${file.name} (${formatBytes(file.size)})`).join(", ") || selection?.name || "Nothing selected"; }
function formatBytes(value) { const bytes = Number(value || 0); if (bytes < 1024) return `${bytes} B`; const units = ["KiB", "MiB", "GiB", "TiB"]; let amount = bytes; let unit = -1; do { amount /= 1024; unit += 1; } while (amount >= 1024 && unit < units.length - 1); return `${amount.toFixed(amount >= 100 ? 0 : amount >= 10 ? 1 : 2)} ${units[unit]}`; }
function formatDuration(ms) { const seconds = Math.max(0, Number(ms || 0) / 1000); if (seconds < 60) return `${seconds.toFixed(1)} s`; return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`; }
function errorMessage(error) { return error?.message || String(error || "Unknown error"); }
async function action(callback) { try { await callback(); } catch (error) { setText("summary", errorMessage(error)); $("summary").className = "summary failed"; } }

function buildAlgorithmList() {
  const root = $("algorithmList"); root.replaceChildren();
  const groups = new Map();
  for (const algorithm of state.algorithms) {
    if (!groups.has(algorithm.categoryName)) groups.set(algorithm.categoryName, []);
    groups.get(algorithm.categoryName).push(algorithm);
  }
  for (const [name, algorithms] of groups) {
    const group = document.createElement("section"); group.className = "algorithm-group";
    const heading = document.createElement("h4"); heading.textContent = name; group.append(heading);
    for (const algorithm of algorithms) {
      const row = document.createElement("label"); row.className = "algorithm";
      const checkbox = document.createElement("input"); checkbox.type = "checkbox"; checkbox.dataset.algorithm = algorithm.id; checkbox.checked = ["sha256", "sha512", "blake3"].includes(algorithm.id);
      const title = document.createElement("span"); title.textContent = algorithm.name; row.append(checkbox, title);
      if (algorithm.xof || algorithm.seeded || algorithm.keyed) {
        const advanced = document.createElement("span"); advanced.className = "advanced";
        const input = document.createElement("input"); input.dataset.optionFor = algorithm.id;
        if (algorithm.xof) { input.type = "number"; input.min = algorithm.xof.minBytes; input.max = algorithm.xof.maxBytes; input.value = algorithm.xof.defaultBytes; input.title = "Output length in bytes"; input.placeholder = "Output bytes"; }
        else if (algorithm.seeded) { input.value = "0"; input.title = `${algorithm.seedBits}-bit seed`; input.placeholder = "Seed (default 0)"; }
        else { input.value = ""; input.title = `${algorithm.keyBytes}-byte hexadecimal key`; input.placeholder = `HEX key (${algorithm.keyBytes} bytes; zero key if blank)`; }
        advanced.append(input); row.append(advanced);
      }
      group.append(row);
    }
    root.append(group);
  }
}

function algorithmRequest(algorithm, optionRoot = document) {
  const request = { id: algorithm.id }; const input = optionRoot.querySelector(`[data-option-for="${algorithm.id}"]`);
  if (algorithm.xof) request.outputBytes = Number(input?.value || algorithm.xof.defaultBytes);
  if (algorithm.seeded) request.seed = input?.value || "0";
  if (algorithm.keyed && input?.value.trim()) request.keyHex = input.value.trim();
  return request;
}
function selectedAlgorithms() { return state.algorithms.filter((algorithm) => document.querySelector(`[data-algorithm="${algorithm.id}"]`)?.checked).map((algorithm) => algorithmRequest(algorithm)); }
function simpleAlgorithm(id) { const algorithm = state.algorithms.find((item) => item.id === id); return algorithmRequest(algorithm); }

function populateSelect(id, filter = () => true) {
  const select = $(id); const first = select.querySelector("option[value='']"); select.replaceChildren(); if (first) select.append(first);
  for (const algorithm of state.algorithms.filter(filter)) { const option = document.createElement("option"); option.value = algorithm.id; option.textContent = algorithm.name; select.append(option); }
}

async function chooseFiles(multiple) { const result = await api.selectFiles(multiple); return result.canceled ? null : result; }
async function chooseDirectory() { const result = await api.selectDirectory(); return result.canceled ? null : result; }
function acceptJob(job) { state.activeJobId = job.jobId; state.activeJob = job; renderJob(job); }

function renderJob(job) {
  if (!job || (state.activeJobId && job.jobId !== state.activeJobId)) return;
  state.activeJob = job; state.activeJobId = job.jobId;
  setText("jobState", `${job.state.toUpperCase()} · ${job.filesCompleted}/${job.filesTotal}${job.currentFile ? ` · ${job.currentFile.name}` : ""}`);
  $("progressBar").style.width = `${Math.max(0, Math.min(100, job.percent || 0))}%`;
  $("progressStats").replaceChildren(...[
    `${formatBytes(job.bytes)} / ${formatBytes(job.totalBytes)}`,
    `${Number(job.percent || 0).toFixed(1)}%`,
    `${formatBytes(job.throughputBytesPerSecond)}/s`,
    `Elapsed ${formatDuration(job.elapsedMs)}`,
    job.etaMs == null ? "ETA —" : `ETA ${formatDuration(job.etaMs)}`
  ].map((text) => { const span = document.createElement("span"); span.textContent = text; return span; }));
  $("cancel").classList.toggle("hidden", !["queued", "running"].includes(job.state));
  $("copyAll").classList.toggle("hidden", !job.results.some((result) => result.hashes?.length));
  $("exportResults").classList.toggle("hidden", job.state !== "completed" || !job.results.some((result) => result.hashes?.length));
  const summary = $("summary"); summary.className = "summary";
  if (job.error) { summary.textContent = `${job.error.code}: ${job.error.message}`; summary.classList.add("failed"); }
  else if (job.mode === "compare" && job.state === "completed") { summary.textContent = job.comparison?.identical ? "IDENTICAL digests" : "DIFFERENT digests"; summary.classList.add(job.comparison?.identical ? "match" : "mismatch"); }
  else if (job.mode === "verify" && job.results[0]) { summary.textContent = job.results[0].status; summary.classList.add(job.results[0].status === "MATCH" ? "match" : "mismatch"); }
  else if (job.state === "completed") { const matches = job.results.filter((result) => result.status === "MATCH").length; const failures = job.results.filter((result) => !["COMPLETED", "MATCH"].includes(result.status)).length; summary.textContent = job.mode === "verify-manifest" ? `${matches} matched · ${failures} failed` : `${job.results.length} file(s) completed`; }
  else summary.textContent = "";
  renderResults(job);
}

function renderResults(job) {
  const body = $("results"); body.replaceChildren();
  for (const result of job.results) {
    const hashes = result.hashes?.length ? result.hashes : [null];
    for (const hash of hashes) {
      const row = document.createElement("tr");
      for (const value of [result.file.relativePath, formatBytes(result.file.size), hash?.id || "—", hash?.value || (result.error?.message || "—"), result.status]) { const cell = document.createElement("td"); cell.textContent = value; if (value === hash?.value) cell.className = "digest"; row.append(cell); }
      row.children[4].className = `status-${String(result.status).toLowerCase().replace(/\s+/g, "-")}`;
      const controls = document.createElement("td");
      if (hash) { const copy = document.createElement("button"); copy.className = "small ghost"; copy.textContent = "Copy"; copy.addEventListener("click", () => action(async () => { await api.copyResult({ jobId: job.jobId, fileId: result.file.fileId, algorithmId: hash.id, compact: true }); copy.textContent = "Copied"; setTimeout(() => { copy.textContent = "Copy"; }, 1200); })); controls.append(copy); }
      row.append(controls); body.append(row);
    }
  }
}

document.querySelectorAll(".tab").forEach((button) => button.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach((item) => item.classList.toggle("active", item === button));
  document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.toggle("active", panel.id === button.dataset.tab));
}));

$("closeButton").addEventListener("click", () => window.chjPlugin.close());
$("calculateMode").addEventListener("change", () => $("recursiveLabel").classList.toggle("hidden", $("calculateMode").value !== "directory"));
$("calculatePick").addEventListener("click", () => action(async () => { const mode = $("calculateMode").value; state.calculateSelection = mode === "directory" ? await chooseDirectory() : await chooseFiles(mode === "multiple"); setText("calculateSelection", describeSelection(state.calculateSelection)); }));
$("selectAll").addEventListener("click", () => document.querySelectorAll("[data-algorithm]").forEach((input) => { input.checked = true; }));
$("selectNone").addEventListener("click", () => document.querySelectorAll("[data-algorithm]").forEach((input) => { input.checked = false; }));
$("recommended").addEventListener("click", () => document.querySelectorAll("[data-algorithm]").forEach((input) => { input.checked = ["sha256", "sha512", "blake3"].includes(input.dataset.algorithm); }));
$("calculateStart").addEventListener("click", () => action(async () => { if (!state.calculateSelection) throw new Error("Choose local input first."); const algorithms = selectedAlgorithms(); if (!algorithms.length) throw new Error("Select at least one algorithm."); acceptJob(await api.start({ selectionId: state.calculateSelection.selectionId, algorithms, recursive: $("recursive").checked, output: $("output").value })); }));

$("verifyPick").addEventListener("click", () => action(async () => { state.verifySelection = await chooseFiles(false); setText("verifySelection", describeSelection(state.verifySelection)); }));
$("expected").addEventListener("input", () => { const value = $("expected").value.trim(); if (!/^[0-9a-f]+$/i.test(value)) return setText("detection", ""); const candidates = state.algorithms.filter((algorithm) => algorithm.digestBits && algorithm.digestBits / 4 === value.length); setText("detection", candidates.length ? `Length candidates: ${candidates.map((item) => item.name).join(", ")}. Length alone is not definitive.` : "No fixed-length algorithm matches this length."); });
$("verifyStart").addEventListener("click", () => action(async () => { if (!state.verifySelection) throw new Error("Choose a local file first."); acceptJob(await api.verify({ selectionId: state.verifySelection.selectionId, algorithm: simpleAlgorithm($("verifyAlgorithm").value), expected: $("expected").value })); }));

$("comparePickA").addEventListener("click", () => action(async () => { state.compareA = await chooseFiles(false); setText("compareA", describeSelection(state.compareA)); }));
$("comparePickB").addEventListener("click", () => action(async () => { state.compareB = await chooseFiles(false); setText("compareB", describeSelection(state.compareB)); }));
$("compareStart").addEventListener("click", () => action(async () => { if (!state.compareA || !state.compareB) throw new Error("Choose both local files first."); const algorithms = [...$("compareAlgorithm").selectedOptions].map((option) => simpleAlgorithm(option.value)); if (!algorithms.length) throw new Error("Select at least one comparison algorithm."); acceptJob(await api.compare({ leftSelectionId: state.compareA.selectionId, rightSelectionId: state.compareB.selectionId, algorithms })); }));

$("manifestSourcePick").addEventListener("click", () => action(async () => { state.manifestSource = $("manifestSourceMode").value === "directory" ? await chooseDirectory() : await chooseFiles(true); setText("manifestSource", describeSelection(state.manifestSource)); }));
$("manifestFormat").addEventListener("change", () => { if ($("manifestFormat").value === "sfv") $("manifestAlgorithm").value = "crc32"; });
$("manifestGenerate").addEventListener("click", () => action(async () => { if (!state.manifestSource) throw new Error("Choose local source files first."); const id = $("manifestAlgorithm").value; const extension = $("manifestFormat").value === "sfv" ? "sfv" : (id === "crc32" ? "checksums" : id.replace(/-/g, "")); const destination = await api.selectManifestDestination(`checksums.${extension}`); if (destination.canceled) return; acceptJob(await api.generateManifest({ selectionId: state.manifestSource.selectionId, destinationSelectionId: destination.selectionId, algorithm: simpleAlgorithm(id), format: $("manifestFormat").value, recursive: $("manifestRecursive").checked })); }));
$("manifestPick").addEventListener("click", () => action(async () => { const result = await api.selectManifest(); state.manifestFile = result.canceled ? null : result; setText("manifestSelection", describeSelection(result.canceled ? null : { files: [result.file] })); }));
$("manifestRootPick").addEventListener("click", () => action(async () => { state.manifestRoot = await chooseDirectory(); setText("manifestRoot", describeSelection(state.manifestRoot)); }));
$("manifestVerify").addEventListener("click", () => action(async () => { if (!state.manifestFile || !state.manifestRoot) throw new Error("Choose a manifest and its local root directory."); acceptJob(await api.verifyManifest({ manifestSelectionId: state.manifestFile.selectionId, rootSelectionId: state.manifestRoot.selectionId, algorithmId: $("manifestVerifyAlgorithm").value || undefined })); }));

$("cancel").addEventListener("click", () => action(async () => { if (state.activeJobId) renderJob(await api.cancel(state.activeJobId)); }));
$("copyAll").addEventListener("click", () => action(async () => { await api.copyResult({ jobId: state.activeJobId }); $("copyAll").textContent = "Copied"; setTimeout(() => { $("copyAll").textContent = "Copy all"; }, 1200); }));
$("exportResults").addEventListener("click", () => action(async () => { const destination = await api.selectManifestDestination("hash-results.txt"); if (!destination.canceled) await api.exportResults({ jobId: state.activeJobId, destinationSelectionId: destination.selectionId, format: "text" }); }));

api.onProgress((job) => renderJob(job));

action(async () => {
  state.algorithms = await api.getAlgorithms(); buildAlgorithmList();
  const fixed = (algorithm) => !algorithm.xof;
  populateSelect("verifyAlgorithm", fixed); populateSelect("compareAlgorithm", fixed); populateSelect("manifestAlgorithm", (algorithm) => fixed(algorithm) && !algorithm.keyed && !algorithm.seeded); populateSelect("manifestVerifyAlgorithm", fixed);
  $("verifyAlgorithm").value = "sha256"; $("compareAlgorithm").value = "sha256"; $("manifestAlgorithm").value = "sha256";
});
