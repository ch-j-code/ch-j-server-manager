"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const archiver = require("archiver");

const MAX_TEXT_BYTES = 25 * 1024 * 1024;
const MAX_TRANSFER_BYTES = 16 * 1024 * 1024 * 1024;
const MAX_BATCH_ENTRIES = 10000;
const MAX_SELECTED_ENTRIES = 100;
const ARCHIVE_FORMATS = new Set(["zip", "tar", "tar.gz"]);
const DEFINITE_EDITOR_FAILURES = new Set([
  "FILE_CONFLICT", "FILE_PERMISSION_DENIED", "FILE_NOT_FOUND", "FILE_UNSAFE_PATH", "FILE_UNSAFE_TYPE_OR_LINK",
  "FILE_UNSAFE_WORKSPACE", "FILE_UNSAFE_PRIVILEGED_DIRECTORY", "FILE_UPLOAD_INCOMPLETE", "FILE_TOO_LARGE",
  "FILE_METADATA_UNSUPPORTED", "FILE_REMOTE_IO_FAILED", "FILE_SUDO_FAILED", "FILE_DEPENDENCY_UNAVAILABLE",
  "FILE_SUDO_PASSWORD_INVALID", "FILE_SUDO_AUTHORIZATION_REQUIRED", "FILE_LINUX_REQUIRED"
]);

function normalizeRemotePath(value) {
  const raw = String(value || "").trim();
  if (!raw || raw.length > 4096 || !raw.startsWith("/") || /[\0\r\n]/.test(raw)) throw new Error("Remote path must be an absolute path.");
  return path.posix.normalize(raw);
}

function call(sftp, method, ...args) {
  return new Promise((resolve, reject) => {
    sftp[method](...args, (error, result) => error ? reject(error) : resolve(result));
  });
}

function safeEntryName(value) {
  const name = String(value || "");
  if (!name || name === "." || name === ".." || /[\/\\\0]/.test(name)) throw new Error("Remote entry name cannot be represented safely on the local filesystem.");
  return name;
}

function selectedPaths(result) {
  if (!result || result.canceled) return [];
  const values = Array.isArray(result.paths) ? result.paths : result.path ? [result.path] : [];
  return [...new Set(values.map(String).filter(Boolean))].slice(0, MAX_SELECTED_ENTRIES + 1);
}

class RemoteFileService {
  constructor(options) {
    this.sessionManager = options.sessionManager;
    this.selectUploadPath = options.selectUploadPath;
    this.selectDownloadPath = options.selectDownloadPath;
    this.selectDownloadDirectory = options.selectDownloadDirectory;
    this.selectArchivePath = options.selectArchivePath;
    this.logger = options.logger;
    this.edits = new Map();
    this.legacyEdits = new Map();
  }

  async list(sessionId, remotePath) {
    const target = normalizeRemotePath(remotePath || "/");
    return this._withSftp(sessionId, async (sftp) => {
      const entries = await call(sftp, "readdir", target);
      return (entries || []).filter((entry) => entry.filename && entry.filename !== "." && entry.filename !== "..").map((entry) => {
        const attrs = entry.attrs || {};
        const isDirectory = typeof attrs.isDirectory === "function" && attrs.isDirectory();
        const isSymbolicLink = typeof attrs.isSymbolicLink === "function" && attrs.isSymbolicLink();
        return {
          name: String(entry.filename),
          path: path.posix.join(target, entry.filename),
          type: isDirectory ? "directory" : isSymbolicLink ? "symlink" : "file",
          size: Math.max(0, Number(attrs.size) || 0),
          modifiedAt: Number(attrs.mtime) > 0 ? new Date(Number(attrs.mtime) * 1000).toISOString() : null,
          mode: Number(attrs.mode) || 0
        };
      }).sort((left, right) => {
        const order = { directory: 0, file: 1, symlink: 2 };
        return order[left.type] === order[right.type] ? left.name.localeCompare(right.name) : order[left.type] - order[right.type];
      });
    });
  }

  _editorPath(value) {
    const raw = String(value || "");
    if (!raw || raw.length > 4096 || !raw.startsWith("/") || /[\0\r\n]/.test(raw)) throw new Error("Remote path must be an absolute path.");
    if (raw.split("/").some((part) => part === "." || part === "..")) throw new Error("Editor paths cannot contain traversal components.");
    return path.posix.normalize(raw);
  }

  _identity(sessionId) {
    const session = this.sessionManager.list().find((entry) => entry.sessionId === sessionId && entry.state === "connected");
    if (!session) throw new Error("The editor session is not connected.");
    return JSON.stringify([sessionId, session.profileId, session.host, session.port, session.username]);
  }

  async readText(sessionId, remotePath, options = {}, owner = "core") {
    const target = this._editorPath(remotePath);
    const identity = this._identity(sessionId);
    const value = await this.sessionManager.remoteEditor(sessionId, { operation: "read", path: target }, options);
    const data = Buffer.from(value.data, "base64");
    if (data.length > MAX_TEXT_BYTES) throw new Error(`Text editor limit is ${MAX_TEXT_BYTES} bytes.`);
    let text;
    try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data); }
    catch { throw new Error("The selected file is not valid UTF-8 text."); }
    if (crypto.createHash("sha256").update(data).digest("hex") !== value.baseline.hash) throw new Error("Remote editor content verification failed.");
    if (this.edits.size >= 1000) throw new Error("Close unused editor documents before opening more files.");
    const editId = crypto.randomBytes(16).toString("hex");
    this.edits.set(editId, { target, identity, owner, baseline: value.baseline, busy: false, uncertain: false });
    const key = JSON.stringify([owner, identity, target]);
    // A legacy call has no document identifier. Once two documents are open,
    // choosing either baseline would silently defeat conflict detection.
    this.legacyEdits.set(key, this.legacyEdits.has(key) ? null : editId);
    return { path: target, text, size: data.length, editId, baselineHash: value.baseline.hash, metadata: value.baseline,
      modifiedAt: new Date(Number(BigInt(value.baseline.mtimeNs) / 1000000n)).toISOString() };
  }

  async writeText(sessionId, remotePath, text, options = {}, owner = "core") {
    const target = this._editorPath(remotePath);
    const data = Buffer.from(String(text ?? ""), "utf8");
    if (data.length > MAX_TEXT_BYTES) throw new Error(`Text editor limit is ${MAX_TEXT_BYTES} bytes.`);
    const identity = this._identity(sessionId);
    const legacyId = this.legacyEdits.get(JSON.stringify([owner, identity, target]));
    if (!options.editId && legacyId === null) {
      const error = new Error("FILE_EDIT_ID_REQUIRED: Multiple documents are open for this path; pass the editId returned by readText.");
      error.code = "FILE_EDIT_ID_REQUIRED";
      throw error;
    }
    const editId = options.editId || legacyId;
    const edit = this.edits.get(editId);
    if (!edit || edit.target !== target || edit.identity !== identity || edit.owner !== owner) throw new Error("Reopen this file to capture an editor baseline before saving.");
    if (edit.busy || edit.uncertain) {
      const error = new Error("FILE_RESULT_UNKNOWN: Inspect recovery before starting another save.");
      error.code = "FILE_RESULT_UNKNOWN";
      throw error;
    }
    edit.busy = true;
    let recovery;
    let submitted = false;
    try {
      const hash = crypto.createHash("sha256").update(data).digest("hex");
      const id = crypto.randomBytes(16).toString("hex");
      recovery = await this.sessionManager.remoteEditor(sessionId, { operation: "prepare", id, path: target, baseline: edit.baseline, hash });
      await this._uploadEditorCopy(sessionId, recovery.temporary, data);
      submitted = true;
      const saved = await this.sessionManager.remoteEditor(sessionId, {
        operation: "finalize", id, uid: recovery.uid, path: target, baseline: edit.baseline, hash
      }, options);
      if (saved.status !== "saved" || saved.hash !== hash || saved.baseline?.hash !== hash) {
        const error = new Error("Remote save could not be confirmed."); error.code = "FILE_RESULT_UNKNOWN"; throw error;
      }
      edit.baseline = saved.baseline;
      let recoveryAvailable = false;
      try { await this.sessionManager.remoteEditor(sessionId, { operation: "cleanup", id, uid: recovery.uid }, options); }
      catch { recoveryAvailable = true; }
      this.logger?.info("Remote editor save confirmed.", { sessionId, path: target, bytes: data.length });
      return { path: target, size: data.length, status: "saved", editId, baselineHash: hash, recoveryId: id, recoveryAvailable };
    } catch (error) {
      const knownFailure = DEFINITE_EDITOR_FAILURES.has(error.code);
      edit.uncertain = submitted && !knownFailure;
      error.code = edit.uncertain ? "FILE_RESULT_UNKNOWN" : error.code || "FILE_UPLOAD_FAILED";
      error.recoveryId = recovery?.recoveryId;
      error.recoveryPath = recovery?.temporary;
      error.status = edit.uncertain ? "unknown" : "failed";
      error.message = `${error.code}: Save was not confirmed. Keep editor content and inspect recovery${recovery ? " (" + recovery.recoveryId + ")" : ""}.`;
      throw error;
    } finally {
      edit.busy = false;
      if (edit.dispose) this.closeText(editId, owner);
    }
  }

  async saveText(sessionId, remotePath, text, options = {}, owner = "core") {
    try { return { ok: true, value: await this.writeText(sessionId, remotePath, text, options, owner) }; }
    catch (error) { return { ok: false, error: { code: error.code || "FILE_SAVE_FAILED", message: error.message,
      status: error.status || "failed", recoveryId: error.recoveryId, recoveryPath: error.recoveryPath } }; }
  }

  _uploadEditorCopy(sessionId, temporary, data) {
    return new Promise((resolve, reject) => {
      let sftp;
      let settled = false;
      const finish = (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { sftp?.end?.(); } catch {}
        if (error) reject(error); else resolve();
      };
      const timer = setTimeout(() => finish(Object.assign(new Error("Editor upload timed out."), { code: "FILE_UPLOAD_TIMEOUT" })), 60000);
      timer.unref?.();
      Promise.resolve().then(() => this.sessionManager.openSftp(sessionId)).then((channel) => {
        if (settled) { try { channel.end?.(); } catch {} return; }
        sftp = channel;
        call(sftp, "writeFile", temporary, data, { flag: "wx", mode: 0o600 }).then(() => finish(), finish);
      }, finish);
    });
  }

  async _recovery(sessionId, operation, recoveryId, options = {}) {
    const request = { operation, id: recoveryId };
    if (options.sudo === true) {
      const identity = await this.sessionManager.remoteEditor(sessionId, { operation: "identity" });
      request.uid = identity.uid;
    }
    return this.sessionManager.remoteEditor(sessionId, request, options);
  }

  listRecovery(sessionId, options = {}) {
    return this._recovery(sessionId, "list", undefined, options);
  }

  async readRecovery(sessionId, recoveryId, options = {}) {
    const result = await this._recovery(sessionId, "inspect", recoveryId, options);
    const data = Buffer.from(result.data, "base64");
    if (!result.complete || data.length > MAX_TEXT_BYTES || crypto.createHash("sha256").update(data).digest("hex") !== result.hash) {
      throw new Error("FILE_RECOVERY_UNVERIFIED: Recovery content could not be verified.");
    }
    let text;
    try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data); }
    catch { throw new Error("Recovery file is not valid UTF-8 text."); }
    const { data: _data, ...summary } = result;
    return { ...summary, text };
  }

  cleanupRecovery(sessionId, recoveryId, options = {}) {
    return this._recovery(sessionId, "cleanup", recoveryId, options);
  }

  closeText(editId, owner = "core") {
    const edit = this.edits.get(editId);
    if (!edit || edit.owner !== owner || edit.busy) return { closed: false };
    this.edits.delete(editId);
    const key = JSON.stringify([owner, edit.identity, edit.target]);
    const remaining = [...this.edits].filter(([, other]) => other.owner === owner && other.identity === edit.identity && other.target === edit.target);
    if (!remaining.length) this.legacyEdits.delete(key);
    else this.legacyEdits.set(key, remaining.length === 1 ? remaining[0][0] : null);
    return { closed: true };
  }

  cleanupPlugin(owner) {
    for (const [id, edit] of this.edits) {
      if (edit.owner !== owner) continue;
      if (edit.busy) edit.dispose = true;
      else this.closeText(id, owner);
    }
  }

  async createFile(sessionId, remotePath) {
    const target = normalizeRemotePath(remotePath);
    if (target === "/") throw new Error("The remote root cannot be a file.");
    return this._withSftp(sessionId, async (sftp) => {
      await call(sftp, "writeFile", target, Buffer.alloc(0), { flag: "wx", mode: 0o644 });
      this.logger?.warn("Remote file created.", { sessionId, path: target });
      return { path: target, size: 0 };
    });
  }

  async mkdir(sessionId, remotePath) {
    const target = normalizeRemotePath(remotePath);
    if (target === "/") throw new Error("The remote root already exists.");
    return this._withSftp(sessionId, async (sftp) => {
      await call(sftp, "mkdir", target, { mode: 0o755 });
      this.logger?.warn("Remote directory created.", { sessionId, path: target });
      return { path: target };
    });
  }

  async rename(sessionId, fromPath, toPath) {
    const from = normalizeRemotePath(fromPath); const to = normalizeRemotePath(toPath);
    if (from === "/" || to === "/") throw new Error("The remote root cannot be renamed.");
    return this._withSftp(sessionId, async (sftp) => {
      await call(sftp, "rename", from, to);
      this.logger?.warn("Remote entry renamed.", { sessionId, from, to });
      return { from, to };
    });
  }

  async remove(sessionId, remotePath) {
    const target = normalizeRemotePath(remotePath);
    if (target === "/") throw new Error("The remote root cannot be removed.");
    return this._withSftp(sessionId, async (sftp) => {
      const attrs = await call(sftp, "lstat", target);
      const isDirectory = typeof attrs?.isDirectory === "function" && attrs.isDirectory();
      await call(sftp, isDirectory ? "rmdir" : "unlink", target);
      this.logger?.warn("Remote entry removed.", { sessionId, path: target, type: isDirectory ? "directory" : "file" });
      return { path: target, type: isDirectory ? "directory" : "file" };
    });
  }

  async removeMany(sessionId, remotePaths, recursive = false) {
    const targets = this._normalizeSelection(remotePaths);
    if (targets.some((target) => target === "/")) throw new Error("The remote root cannot be removed.");
    return this._withSftp(sessionId, async (sftp) => {
      const state = { entries: 0, bytes: 0 };
      for (const target of [...targets].sort((left, right) => right.length - left.length)) await this._removeRemoteEntry(sftp, target, Boolean(recursive), state);
      this.logger?.warn("Remote entries removed.", { sessionId, selected: targets.length, entries: state.entries, recursive: Boolean(recursive) });
      return { selected: targets.length, entries: state.entries };
    });
  }

  async upload(sessionId, remoteDirectory) {
    const directory = normalizeRemotePath(remoteDirectory || "/");
    if (typeof this.selectUploadPath !== "function") throw new Error("Upload dialog is unavailable.");
    const selected = await this.selectUploadPath();
    const localPaths = selectedPaths(selected);
    if (!localPaths.length) return { canceled: true, items: [] };
    if (localPaths.length > MAX_SELECTED_ENTRIES) throw new Error(`At most ${MAX_SELECTED_ENTRIES} entries can be uploaded at once.`);
    return this._withSftp(sessionId, async (sftp) => {
      const state = { entries: 0, bytes: 0 };
      const items = [];
      for (const localPath of localPaths) {
        const target = path.posix.join(directory, path.basename(localPath));
        const result = await this._uploadLocalEntry(sftp, localPath, target, state);
        items.push({ path: target, type: result.type, size: result.size });
      }
      this.logger?.info("Entries uploaded through Core.", { sessionId, directory, entries: state.entries, bytes: state.bytes });
      return { canceled: false, items, entries: state.entries, size: state.bytes };
    });
  }

  async download(sessionId, remotePath) {
    const target = normalizeRemotePath(remotePath);
    if (typeof this.selectDownloadPath !== "function") throw new Error("Download dialog is unavailable.");
    return this._withSftp(sessionId, async (sftp) => {
      const attrs = await call(sftp, "stat", target);
      if (typeof attrs?.isDirectory === "function" && attrs.isDirectory()) throw new Error("Directory download is not available in this first File Manager version.");
      const size = Math.max(0, Number(attrs?.size) || 0);
      if (size > MAX_TRANSFER_BYTES) throw new Error("Remote file exceeds the transfer size limit.");
      const selected = await this.selectDownloadPath(path.posix.basename(target));
      if (!selected || selected.canceled || !selected.path) return { canceled: true };
      await call(sftp, "fastGet", target, selected.path);
      this.logger?.info("File downloaded through Core.", { sessionId, path: target, bytes: size });
      return { canceled: false, path: target, size };
    });
  }

  async downloadMany(sessionId, remotePaths) {
    const targets = this._normalizeSelection(remotePaths);
    if (typeof this.selectDownloadDirectory !== "function") throw new Error("Download directory dialog is unavailable.");
    const selected = await this.selectDownloadDirectory();
    if (!selected || selected.canceled || !selected.path) return { canceled: true, items: [] };
    return this._withSftp(sessionId, async (sftp) => {
      const state = { entries: 0, bytes: 0 };
      const items = [];
      for (const target of targets) {
        if (target === "/") throw new Error("Downloading the entire remote root is not allowed in one batch.");
        const localPath = path.join(selected.path, safeEntryName(path.posix.basename(target)));
        const result = await this._downloadRemoteEntry(sftp, target, localPath, state);
        items.push({ path: target, type: result.type, size: result.size });
      }
      this.logger?.info("Entries downloaded through Core.", { sessionId, entries: state.entries, bytes: state.bytes });
      return { canceled: false, items, entries: state.entries, size: state.bytes };
    });
  }

  async downloadArchive(sessionId, remotePaths, requestedFormat) {
    const targets = this._normalizeSelection(remotePaths);
    if (targets.some((target) => target === "/")) throw new Error("Archiving the entire remote root is not allowed.");
    const format = String(requestedFormat || "zip").toLowerCase() === "tgz" ? "tar.gz" : String(requestedFormat || "zip").toLowerCase();
    if (!ARCHIVE_FORMATS.has(format)) throw new Error("Supported archive formats are zip, tar and tar.gz.");
    if (typeof this.selectArchivePath !== "function") throw new Error("Archive save dialog is unavailable.");
    const baseName = targets.length === 1 ? safeEntryName(path.posix.basename(targets[0])) : "remote-selection";
    const selected = await this.selectArchivePath(`${baseName}.${format}`, format);
    if (!selected || selected.canceled || !selected.path) return { canceled: true };
    const temporaryRoot = await fs.promises.mkdtemp(path.join(os.tmpdir(), "chj-file-archive-"));
    try {
      const transfer = await this._withSftp(sessionId, async (sftp) => {
        const state = { entries: 0, bytes: 0 };
        for (const target of targets) {
          await this._downloadRemoteEntry(sftp, target, path.join(temporaryRoot, safeEntryName(path.posix.basename(target))), state);
        }
        return state;
      });
      const archiveSize = await this._createArchive(temporaryRoot, selected.path, format);
      this.logger?.info("Remote selection archived through Core.", { sessionId, format, entries: transfer.entries, sourceBytes: transfer.bytes, archiveBytes: archiveSize });
      return { canceled: false, path: selected.path, format, entries: transfer.entries, sourceSize: transfer.bytes, size: archiveSize };
    } finally {
      await fs.promises.rm(temporaryRoot, { recursive: true, force: true }).catch(() => {});
    }
  }

  _normalizeSelection(remotePaths) {
    const values = Array.isArray(remotePaths) ? remotePaths : [remotePaths];
    const targets = [...new Set(values.filter((value) => value !== undefined && value !== null).map(normalizeRemotePath))];
    if (!targets.length || targets.length > MAX_SELECTED_ENTRIES) throw new Error(`Select between 1 and ${MAX_SELECTED_ENTRIES} remote entries.`);
    return targets;
  }

  _countTransfer(state, bytes = 0) {
    state.entries += 1;
    state.bytes += Math.max(0, Number(bytes) || 0);
    if (state.entries > MAX_BATCH_ENTRIES) throw new Error(`Transfer exceeds the ${MAX_BATCH_ENTRIES} entry limit.`);
    if (state.bytes > MAX_TRANSFER_BYTES) throw new Error("Transfer exceeds the aggregate size limit.");
  }

  async _uploadLocalEntry(sftp, localPath, remotePath, state) {
    const attrs = await fs.promises.lstat(localPath);
    if (attrs.isSymbolicLink()) throw new Error("Uploading symbolic links is not supported.");
    if (attrs.isDirectory()) {
      this._countTransfer(state);
      try { await call(sftp, "mkdir", remotePath, { mode: 0o755 }); }
      catch (error) {
        const existing = await call(sftp, "stat", remotePath).catch(() => null);
        if (!existing || typeof existing.isDirectory !== "function" || !existing.isDirectory()) throw error;
      }
      for (const entry of await fs.promises.readdir(localPath, { withFileTypes: true })) {
        const name = safeEntryName(entry.name);
        await this._uploadLocalEntry(sftp, path.join(localPath, name), path.posix.join(remotePath, name), state);
      }
      return { type: "directory", size: 0 };
    }
    if (!attrs.isFile()) throw new Error("Only regular files and directories can be uploaded.");
    this._countTransfer(state, attrs.size);
    const temporary = path.posix.join(path.posix.dirname(remotePath), `.${path.posix.basename(remotePath)}.chj-upload-${crypto.randomBytes(6).toString("hex")}.tmp`);
    try {
      await call(sftp, "fastPut", localPath, temporary);
      await call(sftp, "rename", temporary, remotePath);
    } catch (error) {
      try { await call(sftp, "unlink", temporary); } catch {}
      throw error;
    }
    return { type: "file", size: attrs.size };
  }

  async _downloadRemoteEntry(sftp, remotePath, localPath, state) {
    const attrs = await call(sftp, "lstat", remotePath);
    if (typeof attrs?.isSymbolicLink === "function" && attrs.isSymbolicLink()) throw new Error(`Symbolic links are not included in recursive downloads: ${remotePath}`);
    if (typeof attrs?.isDirectory === "function" && attrs.isDirectory()) {
      this._countTransfer(state);
      await fs.promises.mkdir(localPath, { recursive: false, mode: 0o700 }).catch((error) => { if (error.code !== "EEXIST") throw error; });
      for (const entry of await call(sftp, "readdir", remotePath) || []) {
        const name = safeEntryName(entry.filename);
        await this._downloadRemoteEntry(sftp, path.posix.join(remotePath, name), path.join(localPath, name), state);
      }
      return { type: "directory", size: 0 };
    }
    const size = Math.max(0, Number(attrs?.size) || 0);
    this._countTransfer(state, size);
    await fs.promises.mkdir(path.dirname(localPath), { recursive: true, mode: 0o700 });
    const temporary = path.join(path.dirname(localPath), `.${path.basename(localPath)}.chj-download-${crypto.randomBytes(6).toString("hex")}.tmp`);
    try {
      await call(sftp, "fastGet", remotePath, temporary);
      await fs.promises.rename(temporary, localPath);
    } catch (error) {
      await fs.promises.unlink(temporary).catch(() => {});
      throw error;
    }
    return { type: "file", size };
  }

  async _removeRemoteEntry(sftp, remotePath, recursive, state) {
    const attrs = await call(sftp, "lstat", remotePath);
    this._countTransfer(state, Number(attrs?.size) || 0);
    if (typeof attrs?.isDirectory === "function" && attrs.isDirectory()) {
      if (recursive) for (const entry of await call(sftp, "readdir", remotePath) || []) await this._removeRemoteEntry(sftp, path.posix.join(remotePath, safeEntryName(entry.filename)), true, state);
      await call(sftp, "rmdir", remotePath);
    } else await call(sftp, "unlink", remotePath);
  }

  _createArchive(sourceRoot, destination, format) {
    return new Promise((resolve, reject) => {
      const output = fs.createWriteStream(destination, { flags: "w", mode: 0o600 });
      const archive = format === "zip" ? archiver("zip", { zlib: { level: 9 } }) : archiver("tar", { gzip: format === "tar.gz", gzipOptions: { level: 9 } });
      let settled = false;
      const fail = (error) => { if (settled) return; settled = true; try { archive.destroy(); } catch {} reject(error); };
      output.on("close", () => { if (!settled) { settled = true; resolve(Number(archive.pointer()) || 0); } });
      output.on("error", fail); archive.on("warning", fail); archive.on("error", fail);
      archive.pipe(output);
      archive.directory(sourceRoot, false);
      Promise.resolve(archive.finalize()).catch(fail);
    });
  }

  async _withSftp(sessionId, action) {
    const sftp = await this.sessionManager.openSftp(sessionId);
    try { return await action(sftp); }
    finally { try { sftp.end?.(); } catch {} }
  }
}

module.exports = { ARCHIVE_FORMATS, MAX_BATCH_ENTRIES, MAX_TEXT_BYTES, MAX_TRANSFER_BYTES, RemoteFileService, normalizeRemotePath, safeEntryName };
