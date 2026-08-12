"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const zlib = require("node:zlib");
const AdmZip = require("adm-zip");
const { MAX_TEXT_BYTES, RemoteFileService, normalizeRemotePath, safeEntryName } = require("../src/main/files/remoteFileService");

function attrs({ directory = false, size = 0, mtime = 0 } = {}) {
  return { size, mtime, mode: directory ? 0o40755 : 0o100644, isDirectory: () => directory, isSymbolicLink: () => false };
}

function fakeSftp() {
  const files = new Map([["/home/test/a.txt", Buffer.from("ahoj")]]);
  const calls = [];
  return {
    calls, files,
    readdir(_path, callback) { callback(null, [{ filename: "a.txt", attrs: attrs({ size: 4, mtime: 100 }) }, { filename: "folder", attrs: attrs({ directory: true }) }]); },
    stat(target, callback) { callback(null, attrs({ size: files.get(target)?.length || 0, mtime: 100 })); },
    lstat(target, callback) { callback(null, attrs({ directory: target.endsWith("folder") })); },
    readFile(target, callback) { callback(null, files.get(target)); },
    writeFile(target, data, options, callback) { calls.push(["writeFile", target, options.mode]); files.set(target, Buffer.from(data)); callback(null); },
    rename(from, to, callback) { calls.push(["rename", from, to]); files.set(to, files.get(from)); files.delete(from); callback(null); },
    unlink(target, callback) { calls.push(["unlink", target]); files.delete(target); callback(null); },
    rmdir(target, callback) { calls.push(["rmdir", target]); callback(null); },
    mkdir(target, options, callback) { calls.push(["mkdir", target, options.mode]); callback(null); },
    fastPut(localPath, target, callback) { calls.push(["fastPut", localPath, target]); files.set(target, fs.readFileSync(localPath)); callback(null); },
    fastGet(target, localPath, callback) { calls.push(["fastGet", target, localPath]); fs.writeFileSync(localPath, files.get(target)); callback(null); },
    end() { calls.push(["end"]); }
  };
}

test("remote file service lists, reads and atomically writes bounded UTF-8 files", async () => {
  const sftp = fakeSftp();
  const service = new RemoteFileService({ sessionManager: { openSftp: async () => sftp } });
  const entries = await service.list("session-1", "/home/test");
  assert.deepEqual(entries.map((entry) => [entry.name, entry.type]), [["folder", "directory"], ["a.txt", "file"]]);
  assert.equal((await service.readText("session-1", "/home/test/a.txt")).text, "ahoj");
  const saved = await service.writeText("session-1", "/home/test/a.txt", "nový obsah");
  assert.equal(saved.path, "/home/test/a.txt");
  assert.equal(sftp.files.get("/home/test/a.txt").toString("utf8"), "nový obsah");
  assert.ok(sftp.calls.some((entry) => entry[0] === "writeFile" && entry[1].includes(".chj-") && entry[2] === 0o644));
  assert.ok(sftp.calls.some((entry) => entry[0] === "rename" && entry[2] === "/home/test/a.txt"));
});

test("remote file service rejects unsafe paths, root removal and oversized editor content", async () => {
  const sftp = fakeSftp();
  const service = new RemoteFileService({ sessionManager: { openSftp: async () => sftp } });
  assert.equal(normalizeRemotePath("/home/test/../test/a.txt"), "/home/test/a.txt");
  assert.throws(() => normalizeRemotePath("relative/file"), /absolute/);
  assert.throws(() => safeEntryName("folder/file"), /safely/);
  await assert.rejects(() => service.remove("session-1", "/"), /root/);
  await assert.rejects(() => service.writeText("session-1", "/home/test/a.txt", "x".repeat(MAX_TEXT_BYTES + 1)), /limit/);
});

test("remote file service uploads batches atomically and exports zip, tar and tar.gz archives", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-remote-files-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const localUpload = path.join(root, "upload.txt"); fs.writeFileSync(localUpload, "upload-data");
  const archivePaths = { zip: path.join(root, "download.zip"), tar: path.join(root, "download.tar"), "tar.gz": path.join(root, "download.tar.gz") }; const sftp = fakeSftp();
  const service = new RemoteFileService({
    sessionManager: { openSftp: async () => sftp },
    selectUploadPath: async () => ({ canceled: false, paths: [localUpload] }),
    selectArchivePath: async (_suggestedName, format) => ({ canceled: false, path: archivePaths[format] })
  });

  const upload = await service.upload("session-1", "/home/test");
  assert.equal(upload.entries, 1); assert.equal(upload.size, 11);
  assert.equal(sftp.files.get("/home/test/upload.txt").toString(), "upload-data");
  assert.ok(sftp.calls.some((entry) => entry[0] === "fastPut" && entry[2].includes(".chj-upload-")));

  const zip = await service.downloadArchive("session-1", ["/home/test/a.txt"], "zip");
  assert.equal(zip.format, "zip"); assert.ok(zip.size > 0);
  assert.equal(new AdmZip(archivePaths.zip).readAsText("a.txt"), "ahoj");
  const tar = await service.downloadArchive("session-1", ["/home/test/a.txt"], "tar");
  assert.equal(tar.format, "tar"); assert.equal(fs.readFileSync(archivePaths.tar).subarray(257, 262).toString(), "ustar");
  const tarGz = await service.downloadArchive("session-1", ["/home/test/a.txt"], "tar.gz");
  assert.equal(tarGz.format, "tar.gz"); assert.equal(zlib.gunzipSync(fs.readFileSync(archivePaths["tar.gz"])).subarray(257, 262).toString(), "ustar");
});
