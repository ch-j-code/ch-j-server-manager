"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { EventEmitter } = require("node:events");
const { Worker } = require("node:worker_threads");
const { BY_ID, getAlgorithms, normalizeAlgorithmRequests, typedError } = require("./hashAlgorithms");

const MAX_SELECTIONS_PER_PLUGIN = 64;
const MAX_FILES_PER_JOB = 10000;
const MAX_MANIFEST_BYTES = 10 * 1024 * 1024;
const DEFAULT_CHUNK_SIZE = 1024 * 1024;
const TOKEN_TTL_MS = 30 * 60 * 1000;
const OUTPUTS = new Set(["hex-lower", "hex-upper", "base64"]);
const FORMATS = new Set(["gnu", "bsd", "sfv"]);

function randomId(prefix) { return `${prefix}_${crypto.randomBytes(24).toString("base64url")}`; }
function cleanName(value) { return String(value || "").replace(/[\r\n\0]/g, "_"); }
function safeError(error) {
  const code = String(error?.code || "HASH_INTERNAL_ERROR");
  const known = new Set(["ENOENT", "EACCES", "EPERM", "HASH_CANCELLED", "HASH_FILE_CHANGED", "HASH_NOT_REGULAR_FILE", "HASH_INVALID_MANIFEST", "HASH_PATH_ESCAPE", "HASH_SYMLINK_REJECTED", "HASH_UNSUPPORTED_ALGORITHM"]);
  return { code: known.has(code) ? code : "HASH_INTERNAL_ERROR", message: known.has(code) ? String(error?.message || "Hash operation failed.") : "An internal hashing error occurred." };
}
function containsPath(root, candidate) { const relative = path.relative(root, candidate); return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative)); }
function statIdentity(stat) { return { dev: String(stat.dev), ino: String(stat.ino), size: String(stat.size), mtimeNs: String(stat.mtimeNs) }; }
function nowMs() { return Date.now(); }

class LocalHashService extends EventEmitter {
  constructor(options = {}) {
    super();
    this.selectFilesDialog = options.selectFilesDialog;
    this.selectDirectoryDialog = options.selectDirectoryDialog;
    this.selectManifestDialog = options.selectManifestDialog;
    this.selectSaveDialog = options.selectSaveDialog;
    this.writeClipboard = options.writeClipboard;
    this.workerPath = options.workerPath || path.join(__dirname, "hashWorker.js");
    this.Worker = options.Worker || Worker;
    this.logger = options.logger;
    this.chunkSize = Number(options.chunkSize || DEFAULT_CHUNK_SIZE);
    this.selections = new Map();
    this.jobs = new Map();
  }

  getAlgorithms() { return getAlgorithms(); }

  async selectFiles(pluginId, payload = {}) {
    const multiple = payload.multiple === true;
    const result = await this.selectFilesDialog({ multiple });
    if (result.canceled) return { canceled: true, selectionId: null, files: [] };
    const sources = Array.isArray(result.paths) ? result.paths : [];
    if (!sources.length || (!multiple && sources.length !== 1)) throw typedError("The file picker returned an invalid selection.", "HASH_INVALID_SELECTION");
    const files = sources.map((source) => this._authorizeRegularFile(source));
    const commonRoot = files.length > 1 ? this._commonDirectory(files.map((file) => path.dirname(file.path))) : path.dirname(files[0].path);
    for (const file of files) file.relativePath = path.relative(commonRoot, file.path).split(path.sep).join("/");
    const selection = this._storeSelection(pluginId, { type: "files", files });
    return { canceled: false, selectionId: selection.id, files: files.map((file) => this._publicFile(file)) };
  }

  async selectDirectory(pluginId) {
    const result = await this.selectDirectoryDialog();
    if (result.canceled) return { canceled: true, selectionId: null };
    const directory = this._authorizeDirectory(result.path);
    const selection = this._storeSelection(pluginId, { type: "directory", directory });
    return { canceled: false, selectionId: selection.id, name: path.basename(directory.path) || directory.path };
  }

  async selectManifest(pluginId) {
    const result = await this.selectManifestDialog();
    if (result.canceled) return { canceled: true, selectionId: null };
    const file = this._authorizeRegularFile(result.path, MAX_MANIFEST_BYTES);
    const selection = this._storeSelection(pluginId, { type: "manifest", files: [file] });
    return { canceled: false, selectionId: selection.id, file: this._publicFile(file) };
  }

  async selectManifestDestination(pluginId, payload = {}) {
    const suggestedName = cleanName(payload.suggestedName || "checksums.sha256");
    const result = await this.selectSaveDialog({ suggestedName });
    if (result.canceled) return { canceled: true, selectionId: null };
    const destination = path.resolve(String(result.path || ""));
    const parent = fs.realpathSync.native(path.dirname(destination));
    const parentStat = fs.statSync(parent);
    if (!parentStat.isDirectory()) throw typedError("Manifest destination directory is invalid.", "HASH_INVALID_DESTINATION");
    let existing = null;
    try { existing = fs.lstatSync(destination); } catch (error) { if (error.code !== "ENOENT") throw error; }
    if (existing?.isSymbolicLink() || (existing && !existing.isFile())) throw typedError("Manifest destination must be a regular file and cannot be a symbolic link.", "HASH_SYMLINK_REJECTED");
    const selection = this._storeSelection(pluginId, { type: "destination", destination, parent });
    return { canceled: false, selectionId: selection.id, name: path.basename(destination) };
  }

  start(pluginId, payload = {}) {
    const algorithms = normalizeAlgorithmRequests(payload.algorithms);
    const output = OUTPUTS.has(payload.output) ? payload.output : "hex-lower";
    const selection = this._selection(pluginId, payload.selectionId, ["files", "directory"]);
    const files = selection.type === "files" ? selection.files : this._enumerateDirectory(selection.directory, payload.recursive === true);
    return this._startJob(pluginId, { mode: "calculate", algorithms, output, files });
  }

  verify(pluginId, payload = {}) {
    const algorithms = normalizeAlgorithmRequests([payload.algorithm]);
    const selection = this._selection(pluginId, payload.selectionId, ["files"]);
    if (selection.files.length !== 1) throw typedError("Verify requires exactly one selected file.", "HASH_INVALID_SELECTION");
    const expected = this._normalizeExpected(payload.expected, algorithms[0], payload.expectedEncoding);
    return this._startJob(pluginId, { mode: "verify", algorithms, output: "hex-lower", files: selection.files, expected });
  }

  compare(pluginId, payload = {}) {
    const algorithms = normalizeAlgorithmRequests(payload.algorithms || ["sha256"]);
    const left = this._selection(pluginId, payload.leftSelectionId, ["files"]);
    const right = this._selection(pluginId, payload.rightSelectionId, ["files"]);
    if (left.files.length !== 1 || right.files.length !== 1) throw typedError("Compare requires one file in each selection.", "HASH_INVALID_SELECTION");
    return this._startJob(pluginId, { mode: "compare", algorithms, output: "hex-lower", files: [left.files[0], right.files[0]] });
  }

  generateManifest(pluginId, payload = {}) {
    const algorithms = normalizeAlgorithmRequests([payload.algorithm]);
    const algorithm = BY_ID.get(algorithms[0].id);
    if (algorithm.xof || algorithm.keyed || algorithm.seeded) throw typedError("Checksum manifests require a fixed, unkeyed, unseeded algorithm.", "HASH_INVALID_MANIFEST");
    const format = FORMATS.has(payload.format) ? payload.format : "gnu";
    if (format === "sfv" && algorithms[0].id !== "crc32") throw typedError("SFV manifests require CRC-32/ISO-HDLC.", "HASH_INVALID_MANIFEST");
    const source = this._selection(pluginId, payload.selectionId, ["files", "directory"]);
    const destination = this._selection(pluginId, payload.destinationSelectionId, ["destination"]);
    const files = source.type === "files" ? source.files : this._enumerateDirectory(source.directory, payload.recursive === true);
    return this._startJob(pluginId, { mode: "generate-manifest", algorithms, output: "hex-lower", files, manifest: { format, destination: destination.destination } });
  }

  verifyManifest(pluginId, payload = {}) {
    const manifestSelection = this._selection(pluginId, payload.manifestSelectionId, ["manifest"]);
    const rootSelection = this._selection(pluginId, payload.rootSelectionId, ["directory"]);
    const parsed = this._parseManifest(manifestSelection.files[0].path, payload.algorithmId);
    const files = [];
    for (const entry of parsed.entries) {
      if (entry.invalid) {
        files.push({ id: randomId("file"), name: path.basename(entry.filename), relativePath: entry.filename, size: 0, preflightError: { code: "HASH_INVALID_MANIFEST", message: "Invalid checksum manifest entry." }, algorithms: [{ id: entry.algorithmId }], expected: entry.expected });
        continue;
      }
      try {
        const relativePath = this._safeManifestPath(entry.filename);
        const candidate = path.resolve(rootSelection.directory.path, ...relativePath.split("/"));
        if (!containsPath(rootSelection.directory.path, candidate)) throw typedError("Manifest path escapes the selected directory.", "HASH_PATH_ESCAPE");
        this._assertNoSymlinkComponents(rootSelection.directory.path, relativePath);
        const file = this._authorizeRegularFile(candidate);
        if (!containsPath(rootSelection.directory.path, file.path)) throw typedError("Manifest path resolves outside the selected directory.", "HASH_PATH_ESCAPE");
        files.push({ ...file, relativePath, algorithms: [normalizeAlgorithmRequests([{ id: entry.algorithmId }])[0]], expected: entry.expected });
      } catch (error) {
        files.push({ id: randomId("file"), name: path.basename(entry.filename), relativePath: entry.filename, size: 0, preflightError: safeError(error), algorithms: [{ id: entry.algorithmId }], expected: entry.expected });
      }
    }
    return this._startJob(pluginId, { mode: "verify-manifest", algorithms: parsed.algorithms, output: "hex-lower", files, manifest: { sourceName: manifestSelection.files[0].name } });
  }

  exportResults(pluginId, payload = {}) {
    const job = this._job(pluginId, payload.jobId);
    if (job.state !== "completed") throw typedError("Only completed hash results can be exported.", "HASH_JOB_NOT_COMPLETED");
    const destination = this._selection(pluginId, payload.destinationSelectionId, ["destination"]);
    const format = payload.format === "json" ? "json" : "text";
    const serializable = job.results.map((result) => ({ file: result.file.relativePath, size: result.file.size, status: result.status, hashes: Object.fromEntries((result.hashes || []).map((hash) => [hash.id, hash.value])) }));
    const text = format === "json" ? `${JSON.stringify({ generatedBy: "CH-J Server Manager Hash & Checksum", results: serializable }, null, 2)}\n` : `${serializable.flatMap((result) => (Object.entries(result.hashes).length ? Object.entries(result.hashes).map(([id, value]) => `${result.file}\t${result.size}\t${id}\t${value}\t${result.status}`) : [`${result.file}\t${result.size}\t\t\t${result.status}`])).join("\n")}\n`;
    this._writeAuthorized(destination.destination, text);
    return { ok: true, name: path.basename(destination.destination), format };
  }

  copyResult(pluginId, payload = {}) {
    const job = this._job(pluginId, payload.jobId);
    const lines = [];
    for (const result of job.results) {
      if (payload.fileId && result.file.fileId !== payload.fileId) continue;
      for (const hash of result.hashes || []) {
        if (payload.algorithmId && hash.id !== payload.algorithmId) continue;
        lines.push(payload.compact === true ? hash.value : `${hash.value}  ${result.file.relativePath}  (${hash.id})`);
      }
    }
    if (!lines.length) throw typedError("No matching completed result is available to copy.", "HASH_RESULT_NOT_FOUND");
    this.writeClipboard(lines.join("\n"));
    return { ok: true, count: lines.length };
  }

  status(pluginId, jobId) { return this._publicJob(this._job(pluginId, jobId)); }

  async cancel(pluginId, jobId) {
    const job = this._job(pluginId, jobId);
    if (["completed", "failed", "cancelled"].includes(job.state)) return this._publicJob(job);
    job.cancelled = true;
    Atomics.store(job.cancelView, 0, 1);
    const worker = job.worker;
    job.worker = null;
    if (worker) await worker.terminate();
    job.state = "cancelled"; job.error = { code: "HASH_CANCELLED", message: "Hash job was cancelled." }; job.completedAt = nowMs();
    this._emit(job);
    return this._publicJob(job);
  }

  cleanupPlugin(pluginId) {
    const id = String(pluginId || "");
    this.selections.delete(id);
    for (const job of [...this.jobs.values()]) {
      if (job.pluginId !== id) continue;
      if (["completed", "failed", "cancelled"].includes(job.state)) this.jobs.delete(job.id);
      else void this.cancel(id, job.id).finally(() => this.jobs.delete(job.id));
    }
  }

  _startJob(pluginId, source) {
    if (!source.files.length) throw typedError("No regular files were selected.", "HASH_EMPTY_SELECTION");
    if (source.files.length > MAX_FILES_PER_JOB) throw typedError(`A job can contain at most ${MAX_FILES_PER_JOB} files.`, "HASH_TOO_MANY_FILES");
    const id = randomId("job"); const startedAt = nowMs(); const cancelBuffer = new SharedArrayBuffer(4); const cancelView = new Int32Array(cancelBuffer);
    const job = { id, pluginId: String(pluginId), state: "queued", mode: source.mode, algorithms: source.algorithms, output: source.output, files: source.files, expected: source.expected, manifest: source.manifest, results: [], currentIndex: -1, bytes: 0, totalBytes: source.files.reduce((sum, file) => sum + Number(file.size || 0), 0), startedAt, completedAt: null, error: null, cancelled: false, cancelBuffer, cancelView, worker: null };
    this.jobs.set(id, job); this._emit(job);
    setImmediate(() => this._runJob(job).catch((error) => this._failJob(job, error)));
    return this._publicJob(job);
  }

  async _runJob(job) {
    job.state = "running"; this._emit(job);
    let completedBytes = 0;
    for (let index = 0; index < job.files.length; index += 1) {
      if (job.cancelled) throw Object.assign(new Error("Hash job was cancelled."), { code: "HASH_CANCELLED" });
      const file = job.files[index]; job.currentIndex = index; job.bytes = completedBytes; this._emit(job);
      if (file.preflightError) { job.results.push({ file: this._publicFile(file), status: file.preflightError.code === "ENOENT" ? "MISSING" : "INVALID ENTRY", error: file.preflightError }); continue; }
      try {
        const algorithms = file.algorithms || job.algorithms;
        const hashes = await this._hashFile(job, file, algorithms, completedBytes);
        const result = { file: this._publicFile(file), status: "COMPLETED", hashes: hashes.map((hash) => this._formatResult(hash, job.output)) };
        if (job.mode === "verify") { result.expected = job.expected.hex; result.actual = hashes[0].hex; result.status = crypto.timingSafeEqual(Buffer.from(result.expected, "hex"), Buffer.from(result.actual, "hex")) ? "MATCH" : "MISMATCH"; }
        if (job.mode === "verify-manifest") { result.expected = file.expected; result.actual = hashes[0].hex; result.status = this._safeHexEqual(file.expected, hashes[0].hex) ? "MATCH" : "MISMATCH"; }
        job.results.push(result);
      } catch (error) {
        if (error?.code === "HASH_CANCELLED") throw error;
        job.results.push({ file: this._publicFile(file), status: "ERROR", error: safeError(error) });
      }
      completedBytes += Number(file.size || 0); job.bytes = completedBytes; this._emit(job);
    }
    if (job.mode === "compare") {
      const complete = job.results.length === 2 && job.results.every((result) => result.status === "COMPLETED");
      job.comparison = { digestBased: true, identical: complete && job.algorithms.every((algorithm) => job.results[0].hashes.find((hash) => hash.id === algorithm.id)?.hex === job.results[1].hashes.find((hash) => hash.id === algorithm.id)?.hex) };
    }
    if (job.mode === "generate-manifest") this._writeManifest(job);
    job.state = "completed"; job.completedAt = nowMs(); job.currentIndex = -1; this._emit(job);
    this.logger?.info("Local hash job completed.", { pluginId: job.pluginId, jobId: job.id, mode: job.mode, files: job.files.length, algorithms: job.algorithms.map((item) => item.id) });
  }

  _hashFile(job, file, algorithms, completedBytes) {
    return new Promise((resolve, reject) => {
      const worker = new this.Worker(this.workerPath, { workerData: { filePath: file.path, expected: file.identity, algorithms, chunkSize: this.chunkSize, cancelView: job.cancelView } });
      job.worker = worker; let settled = false;
      const finish = (callback, value) => { if (settled) return; settled = true; job.worker = null; callback(value); };
      worker.on("message", (message) => {
        if (message?.type === "progress") { job.bytes = completedBytes + Number(message.bytes || 0); this._emit(job); }
        if (message?.type === "complete") finish(resolve, message.results);
        if (message?.type === "error") finish(reject, Object.assign(new Error(message.message), { code: message.code }));
      });
      worker.once("error", (error) => finish(reject, error));
      worker.once("exit", (code) => { if (!settled) finish(reject, Object.assign(new Error(job.cancelled ? "Hash job was cancelled." : `Hash worker stopped with code ${code}.`), { code: job.cancelled ? "HASH_CANCELLED" : "HASH_WORKER_EXIT" })); });
    });
  }

  _failJob(job, error) {
    if (job.state === "cancelled") return;
    job.state = error?.code === "HASH_CANCELLED" ? "cancelled" : "failed"; job.error = safeError(error); job.completedAt = nowMs(); job.worker = null; this._emit(job);
    this.logger?.warn("Local hash job failed.", { pluginId: job.pluginId, jobId: job.id, code: job.error.code, message: error?.message || String(error) });
  }

  _emit(job) { this.emit("progress", { pluginId: job.pluginId, job: this._publicJob(job) }); }

  _publicJob(job) {
    const elapsedMs = Math.max(0, (job.completedAt || nowMs()) - job.startedAt); const throughput = elapsedMs > 0 ? job.bytes / (elapsedMs / 1000) : 0; const remaining = Math.max(0, job.totalBytes - job.bytes);
    return { jobId: job.id, mode: job.mode, state: job.state, algorithms: job.algorithms.map((item) => ({ ...item })), filesCompleted: job.results.length, filesTotal: job.files.length, currentFile: job.currentIndex >= 0 ? this._publicFile(job.files[job.currentIndex]) : null, bytes: job.bytes, totalBytes: job.totalBytes, percent: job.totalBytes ? Math.min(100, (job.bytes / job.totalBytes) * 100) : (job.state === "completed" ? 100 : 0), throughputBytesPerSecond: throughput, elapsedMs, etaMs: throughput > 0 ? (remaining / throughput) * 1000 : null, results: job.results.map((result) => ({ ...result, hashes: result.hashes?.map((hash) => ({ ...hash })) })), comparison: job.comparison ? { ...job.comparison } : null, manifest: job.manifestResult ? { ...job.manifestResult } : null, error: job.error ? { ...job.error } : null };
  }

  _publicFile(file) { return { fileId: file.id, name: file.name, relativePath: file.relativePath || file.name, size: Number(file.size || 0) }; }
  _formatResult(result, output) { const bytes = Buffer.from(result.hex, "hex"); return { id: result.id, hex: result.hex, value: output === "base64" ? bytes.toString("base64") : (output === "hex-upper" ? result.hex.toUpperCase() : result.hex), encoding: output }; }

  _authorizeRegularFile(source, maxBytes = Number.MAX_SAFE_INTEGER) {
    const original = path.resolve(String(source || "")); const lstat = fs.lstatSync(original);
    if (lstat.isSymbolicLink()) throw typedError("Symbolic links are not accepted as file selections.", "HASH_SYMLINK_REJECTED");
    const canonical = fs.realpathSync.native(original); const stat = fs.statSync(canonical, { bigint: true });
    if (!stat.isFile()) throw typedError("Only regular files can be selected.", "HASH_NOT_REGULAR_FILE");
    if (stat.size > BigInt(maxBytes) || stat.size > BigInt(Number.MAX_SAFE_INTEGER)) throw typedError("Selected file exceeds the supported size.", "HASH_FILE_TOO_LARGE");
    return { id: randomId("file"), path: canonical, name: path.basename(canonical), size: Number(stat.size), identity: statIdentity(stat) };
  }

  _authorizeDirectory(source) {
    const original = path.resolve(String(source || "")); const lstat = fs.lstatSync(original);
    if (lstat.isSymbolicLink()) throw typedError("Symbolic links are not accepted as directory selections.", "HASH_SYMLINK_REJECTED");
    const canonical = fs.realpathSync.native(original); const stat = fs.statSync(canonical);
    if (!stat.isDirectory()) throw typedError("The selection is not a directory.", "HASH_INVALID_SELECTION");
    return { path: canonical };
  }

  _enumerateDirectory(directory, recursive) {
    const root = directory.path;
    const files = []; const visit = (current, relativeRoot) => {
      const currentLstat = fs.lstatSync(current);
      if (currentLstat.isSymbolicLink()) return;
      const canonical = fs.realpathSync.native(current);
      if (!containsPath(root, canonical) || !fs.statSync(canonical).isDirectory()) throw typedError("Directory traversal left the selected root.", "HASH_PATH_ESCAPE");
      const entries = fs.readdirSync(canonical, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
      for (const entry of entries) {
        if (files.length >= MAX_FILES_PER_JOB) throw typedError(`A job can contain at most ${MAX_FILES_PER_JOB} files.`, "HASH_TOO_MANY_FILES");
        if (entry.isSymbolicLink()) continue;
        const fullPath = path.join(canonical, entry.name); const relativePath = relativeRoot ? `${relativeRoot}/${entry.name}` : entry.name;
        if (entry.isDirectory()) { if (recursive) visit(fullPath, relativePath); continue; }
        if (!entry.isFile()) continue;
        const file = this._authorizeRegularFile(fullPath);
        if (!containsPath(root, file.path)) throw typedError("Directory traversal left the selected root.", "HASH_PATH_ESCAPE");
        files.push({ ...file, relativePath });
      }
    };
    visit(directory.path, ""); return files;
  }

  _commonDirectory(directories) {
    let candidate = path.resolve(directories[0]);
    while (!directories.every((directory) => containsPath(candidate, path.resolve(directory)))) {
      const parent = path.dirname(candidate);
      if (parent === candidate) return candidate;
      candidate = parent;
    }
    return candidate;
  }

  _storeSelection(pluginId, source) {
    const owner = String(pluginId || ""); let values = this.selections.get(owner);
    if (!values) { values = new Map(); this.selections.set(owner, values); }
    const cutoff = nowMs() - TOKEN_TTL_MS; for (const [id, item] of values) if (item.createdAt < cutoff) values.delete(id);
    while (values.size >= MAX_SELECTIONS_PER_PLUGIN) values.delete(values.keys().next().value);
    const selection = { ...source, id: randomId("selection"), createdAt: nowMs() }; values.set(selection.id, selection); return selection;
  }

  _selection(pluginId, selectionId, types) {
    const selection = this.selections.get(String(pluginId || ""))?.get(String(selectionId || ""));
    if (!selection || nowMs() - selection.createdAt > TOKEN_TTL_MS || !types.includes(selection.type)) throw typedError("Unknown, expired, or unauthorized selection token.", "HASH_INVALID_SELECTION_TOKEN");
    return selection;
  }
  _job(pluginId, jobId) { const job = this.jobs.get(String(jobId || "")); if (!job || job.pluginId !== String(pluginId || "")) throw typedError("Unknown or unauthorized hash job.", "HASH_INVALID_JOB"); return job; }

  _normalizeExpected(value, algorithm, encoding = "hex") {
    const source = String(value || "").trim(); let bytes;
    if (encoding === "base64") { if (!/^[A-Za-z0-9+/]*={0,2}$/.test(source)) throw typedError("Expected digest is not valid Base64.", "HASH_INVALID_EXPECTED"); bytes = Buffer.from(source, "base64"); }
    else { if (!/^[0-9a-f]+$/i.test(source) || source.length % 2) throw typedError("Expected digest must be hexadecimal.", "HASH_INVALID_EXPECTED"); bytes = Buffer.from(source, "hex"); }
    const requestBytes = algorithm.outputBytes || (BY_ID.get(algorithm.id).digestBits / 8);
    if (bytes.length !== requestBytes) throw typedError(`Expected digest must be exactly ${requestBytes} bytes.`, "HASH_INVALID_EXPECTED");
    return { hex: bytes.toString("hex") };
  }
  _safeHexEqual(left, right) { try { const a = Buffer.from(String(left), "hex"); const b = Buffer.from(String(right), "hex"); return a.length === b.length && crypto.timingSafeEqual(a, b); } catch { return false; } }

  _safeManifestPath(value) {
    const source = String(value || "").replace(/\\/g, "/");
    if (!source || source.includes("\0") || source.startsWith("/") || source.startsWith("//") || /^[A-Za-z]:\//.test(source)) throw typedError("Manifest contains an absolute or invalid path.", "HASH_PATH_ESCAPE");
    const segments = source.split("/"); if (segments.some((segment) => !segment || segment === "." || segment === "..")) throw typedError("Manifest contains path traversal.", "HASH_PATH_ESCAPE");
    return segments.join("/");
  }

  _assertNoSymlinkComponents(root, relativePath) {
    let current = root;
    for (const segment of relativePath.split("/")) { current = path.join(current, segment); const stat = fs.lstatSync(current); if (stat.isSymbolicLink()) throw typedError("Manifest path contains a symbolic link.", "HASH_SYMLINK_REJECTED"); }
  }

  _parseManifest(filePath, requestedAlgorithm) {
    const text = fs.readFileSync(filePath, "utf8"); if (Buffer.byteLength(text) > MAX_MANIFEST_BYTES) throw typedError("Checksum manifest is too large.", "HASH_INVALID_MANIFEST");
    const entries = []; let declared = null;
    const bsdNames = new Map(getAlgorithms().filter((algorithm) => !algorithm.xof).map((algorithm) => [algorithm.name.replace(/[^A-Za-z0-9]/g, "").toUpperCase(), algorithm.id]));
    const mapName = (value) => bsdNames.get(String(value).replace(/[^A-Za-z0-9]/g, "").toUpperCase()) || null;
    for (const rawLine of text.replace(/^\uFEFF/, "").split(/\r?\n/)) {
      if (!rawLine.trim()) continue;
      const header = rawLine.match(/^#\s*Algorithm:\s*([a-z0-9-]+)\s*$/i); if (header) { declared = header[1].toLowerCase(); continue; }
      if (rawLine.startsWith("#") || rawLine.startsWith(";")) continue;
      let match = rawLine.match(/^(.+?) \((.*)\) = ([0-9a-fA-F]+)$/);
      if (match) { const id = mapName(match[1]); if (!id) throw typedError(`Unsupported BSD manifest algorithm: ${match[1]}`, "HASH_INVALID_MANIFEST"); entries.push({ algorithmId: id, filename: match[2], expected: match[3].toLowerCase() }); continue; }
      match = rawLine.match(/^([0-9a-fA-F]+) [ *](.+)$/);
      if (match) { entries.push({ algorithmId: null, filename: match[2], expected: match[1].toLowerCase() }); continue; }
      match = rawLine.match(/^(.+?)\s+([0-9a-fA-F]{8})$/);
      if (match) { entries.push({ algorithmId: "crc32", filename: match[1], expected: match[2].toLowerCase() }); continue; }
      entries.push({ algorithmId: null, filename: rawLine, expected: "", invalid: true });
    }
    if (!entries.length) throw typedError("Checksum manifest contains no entries.", "HASH_INVALID_MANIFEST");
    const fallback = requestedAlgorithm || declared || this._algorithmFromExtension(filePath);
    for (const entry of entries) {
      if (entry.invalid) { entry.algorithmId = fallback || "sha256"; continue; }
      entry.algorithmId ||= fallback;
      if (!entry.algorithmId) {
        const candidates = getAlgorithms().filter((algorithm) => algorithm.digestBits && algorithm.digestBits / 4 === entry.expected.length);
        if (candidates.length !== 1) throw typedError("Manifest digest length is ambiguous; select the algorithm explicitly.", "HASH_AMBIGUOUS_ALGORITHM");
        entry.algorithmId = candidates[0].id;
      }
      const algorithm = BY_ID.get(entry.algorithmId); if (!algorithm || algorithm.xof || !new RegExp(`^[0-9a-f]{${algorithm.digestBits / 4}}$`).test(entry.expected)) entry.invalid = true;
    }
    const algorithms = normalizeAlgorithmRequests([...new Set(entries.map((entry) => entry.algorithmId))]);
    return { entries, algorithms };
  }

  _algorithmFromExtension(filePath) {
    const extension = path.extname(filePath).slice(1).toLowerCase();
    return ({ sha224: "sha224", sha256: "sha256", sha384: "sha384", sha512: "sha512", sha3: "sha3-256", blake3: "blake3", md5: "md5", sha1: "sha1", sfv: "crc32" })[extension] || null;
  }

  _writeManifest(job) {
    const { format, destination } = job.manifest; const algorithm = BY_ID.get(job.algorithms[0].id); const lines = [];
    if (format !== "sfv") lines.push(`# Algorithm: ${algorithm.id}`);
    for (const result of job.results) {
      if (result.status !== "COMPLETED") continue;
      const filename = cleanName(result.file.relativePath).replace(/\\/g, "/"); const digest = result.hashes[0].hex;
      if (format === "bsd") lines.push(`${algorithm.name} (${filename}) = ${digest}`);
      else if (format === "sfv") lines.push(`${filename} ${digest.toUpperCase()}`);
      else lines.push(`${digest}  ${filename}`);
    }
    this._writeAuthorized(destination, `${lines.join("\n")}\n`);
    job.manifestResult = { name: path.basename(destination), entries: lines.length - (format === "sfv" ? 0 : 1), format };
  }

  _writeAuthorized(destination, text) {
    const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | (fs.constants.O_NOFOLLOW || 0); const fd = fs.openSync(destination, flags, 0o600);
    try { fs.writeFileSync(fd, text, "utf8"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  }
}

module.exports = { DEFAULT_CHUNK_SIZE, LocalHashService, MAX_FILES_PER_JOB, MAX_MANIFEST_BYTES, containsPath, safeError };
