"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { RemoteFileService } = require("../src/main/files/remoteFileService");

const hash = (data) => crypto.createHash("sha256").update(data).digest("hex");
function fixture() {
  let content = Buffer.from("original");
  let baseline = { uid: 0, gid: 33, mode: 0o6754, mtimeNs: "1000000000", hash: hash(content), xattrs: { "user.test": "dGVzdA==" } };
  let finalError, uploadError, cleanupError;
  const calls = [], copies = new Map(), journals = new Map();
  const manager = {
    list: () => [{ sessionId: "s", state: "connected", host: "server", port: 22, username: "user", profileId: "p" }],
    openSftp: async () => ({
      writeFile(path, data, options, callback) {
        calls.push({ op: "upload", path, options });
        if (copies.has(path)) return callback(new Error("Exists"));
        if (uploadError) { copies.set(path, data.subarray(0, 2)); return callback(uploadError); }
        copies.set(path, Buffer.from(data)); callback(null);
      }, end() {}
    }),
    async remoteEditor(_session, request, authorization) {
      calls.push({ ...request, authorization });
      const path = "/srv/custom-home/ch-j-sm/." + request.id + ".tmp";
      if (request.operation === "read") return { data: content.toString("base64"), baseline: { ...baseline } };
      if (request.operation === "prepare") {
        journals.set(request.id, request);
        return { temporary: path, recoveryId: request.id, uid: 1001 };
      }
      if (request.operation === "finalize") {
        if (finalError) throw finalError;
        assert.equal(hash(copies.get(path)), request.hash);
        if (request.baseline.hash !== baseline.hash) { const e = new Error("Conflict"); e.code = "FILE_CONFLICT"; throw e; }
        content = copies.get(path); baseline = { ...baseline, hash: request.hash };
        return { status: "saved", hash: request.hash, baseline: { ...baseline } };
      }
      if (request.operation === "cleanup") {
        if (cleanupError) throw cleanupError;
        copies.delete(path); journals.delete(request.id); return { status: "confirmed" };
      }
      if (request.operation === "list") return { items: [...journals.keys()].map((recoveryId) => ({ recoveryId })) };
      if (request.operation === "inspect") return { data: copies.get(path).toString("base64"), hash: hash(copies.get(path)), complete: true, status: "recovery-available", recoveryId: request.id };
      throw new Error("Unexpected operation");
    }
  };
  return { service: new RemoteFileService({ sessionManager: manager }), manager, calls, copies, journals,
    get content() { return content.toString(); }, get baseline() { return baseline; },
    set finalError(value) { finalError = value; }, set uploadError(value) { uploadError = value; }, set cleanupError(value) { cleanupError = value; },
    change() { content = Buffer.from("external change"); baseline = { ...baseline, hash: hash(content) }; } };
}

test("editor captures a baseline, stages privately in actual home and finalizes once before cleanup", async () => {
  const f = fixture();
  const opened = await f.service.readText("s", "/etc/test config");
  assert.equal(opened.text, "original");
  assert.equal(opened.metadata.uid, 0);
  const result = await f.service.writeText("s", "/etc/test config", "modified", { editId: opened.editId, sudo: true, sudoPassword: "secret" });
  assert.equal(result.status, "saved");
  assert.equal(f.content, "modified");
  assert.deepEqual(f.calls.map((call) => call.operation || call.op), ["read", "prepare", "upload", "finalize", "cleanup"]);
  const upload = f.calls[2];
  assert.match(upload.path, /^\/srv\/custom-home\/ch-j-sm\/\.[a-f0-9]{32}\.tmp$/);
  assert.deepEqual(upload.options, { flag: "wx", mode: 0o600 });
  assert.equal(f.calls[3].baseline.mode, 0o6754);
  assert.equal(f.calls[3].baseline.gid, 33);
  assert.equal(f.calls[3].authorization.sudoPassword, "secret");
  assert.equal(f.copies.size, 0);
});

for (const code of ["FILE_SUDO_FAILED", "FILE_PERMISSION_DENIED", "FILE_CONFLICT", "FILE_REMOTE_IO_FAILED", "FILE_NOT_FOUND", "FILE_METADATA_UNSUPPORTED"]) {
  test(code + " preserves original and complete recovery copy", async () => {
    const f = fixture(); await f.service.readText("s", "/etc/config");
    f.finalError = Object.assign(new Error("failure"), { code });
    const result = await f.service.saveText("s", "/etc/config", "modified");
    assert.equal(result.ok, false); assert.equal(result.error.code, code);
    assert.equal(f.content, "original"); assert.equal([...f.copies.values()][0].toString(), "modified");
    assert.equal(f.calls.some((c) => c.operation === "cleanup"), false);
    assert.equal((await f.service.listRecovery("s")).items.length, 1);
    assert.equal((await f.service.readRecovery("s", result.error.recoveryId)).text, "modified");
  });
}

test("upload failure leaves target intact, partial copy discoverable and never finalizes", async () => {
  const f = fixture(); await f.service.readText("s", "/var/www/config");
  f.uploadError = new Error("Disk full");
  const result = await f.service.saveText("s", "/var/www/config", "modified");
  assert.equal(result.error.code, "FILE_UPLOAD_FAILED"); assert.equal(f.content, "original");
  assert.equal(f.calls.some((c) => c.operation === "finalize"), false);
  assert.equal(f.copies.size, 1);
});

test("stalled SFTP upload times out without finalization and closes late channels", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const f = fixture(); await f.service.readText("s", "/etc/config");
  let finishOpen, ended = 0;
  f.manager.openSftp = () => new Promise((resolve) => { finishOpen = resolve; });
  const saving = f.service.saveText("s", "/etc/config", "modified");
  await new Promise((resolve) => setImmediate(resolve));
  t.mock.timers.tick(60000);
  const result = await saving;
  assert.equal(result.error.code, "FILE_UPLOAD_TIMEOUT"); assert.equal(f.content, "original");
  assert.equal(f.calls.some((c) => c.operation === "finalize"), false);
  finishOpen({ end() { ended++; } });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(ended, 1);
});

test("lost final confirmation retains recovery and prevents automatic repeat, including after reconnect", async () => {
  const f = fixture(); await f.service.readText("s", "/etc/config");
  f.finalError = Object.assign(new Error("disconnected"), { code: "FILE_RESULT_UNKNOWN" });
  const result = await f.service.saveText("s", "/etc/config", "modified");
  assert.equal(result.error.status, "unknown");
  assert.equal((await f.service.saveText("s", "/etc/config", "modified")).error.code, "FILE_RESULT_UNKNOWN");
  assert.equal(f.calls.filter((c) => c.operation === "finalize").length, 1);
  const reconnected = new RemoteFileService({ sessionManager: f.manager });
  assert.equal((await reconnected.listRecovery("s")).items[0].recoveryId, result.error.recoveryId);
  assert.equal((await reconnected.readRecovery("s", result.error.recoveryId)).text, "modified");
});

test("unexpected remote failures remain unknown and never enable automatic repetition", async () => {
  const f = fixture(); await f.service.readText("s", "/etc/config");
  f.finalError = Object.assign(new Error("Unexpected exit"), { code: "FILE_UNEXPECTED_EXIT" });
  const result = await f.service.saveText("s", "/etc/config", "modified");
  assert.equal(result.error.code, "FILE_RESULT_UNKNOWN"); assert.equal(result.error.status, "unknown");
  assert.equal(f.copies.size, 1);
});

test("simultaneous saves of one document are rejected while the first upload is pending", async () => {
  const f = fixture(); const opened = await f.service.readText("s", "/etc/config");
  let finishUpload;
  const open = f.manager.openSftp;
  f.manager.openSftp = async () => {
    const sftp = await open(); const write = sftp.writeFile;
    sftp.writeFile = (...args) => { finishUpload = () => write(...args); };
    return sftp;
  };
  const first = f.service.writeText("s", "/etc/config", "first", { editId: opened.editId });
  await new Promise((resolve) => setImmediate(resolve));
  const second = await f.service.saveText("s", "/etc/config", "second", { editId: opened.editId });
  assert.equal(second.ok, false); assert.equal(f.calls.filter((c) => c.operation === "prepare").length, 1);
  finishUpload(); await first;
  assert.equal(f.content, "first");
});

test("editor preserves a trailing space in a filename", async () => {
  const f = fixture(); await f.service.readText("s", "/etc/config ");
  await f.service.writeText("s", "/etc/config ", "modified");
  assert.equal(f.calls.find((c) => c.operation === "finalize").path, "/etc/config ");
});

test("confirmed save stays successful when cleanup cannot be confirmed", async () => {
  const f = fixture(); await f.service.readText("s", "/etc/config"); f.cleanupError = new Error("disconnected");
  const saved = await f.service.writeText("s", "/etc/config", "modified");
  assert.equal(saved.status, "saved"); assert.equal(saved.recoveryAvailable, true); assert.equal(f.copies.size, 1);
});

test("independent editor baselines detect concurrent changes and temporary names never collide", async () => {
  const f = fixture(); const one = await f.service.readText("s", "/etc/config"); const two = await f.service.readText("s", "/etc/config");
  await f.service.writeText("s", "/etc/config", "first", { editId: one.editId });
  const result = await f.service.saveText("s", "/etc/config", "second", { editId: two.editId });
  assert.equal(result.error.code, "FILE_CONFLICT"); assert.equal(f.content, "first");
  const paths = f.calls.filter((c) => c.op === "upload").map((c) => c.path);
  assert.equal(new Set(paths).size, 2);
});

test("legacy calls cannot silently choose a baseline when multiple documents share a path", async () => {
  const f = fixture(); const one = await f.service.readText("s", "/etc/config"); const two = await f.service.readText("s", "/etc/config");
  const ambiguous = await f.service.saveText("s", "/etc/config", "modified");
  assert.equal(ambiguous.error.code, "FILE_EDIT_ID_REQUIRED"); assert.equal(f.content, "original");
  f.service.closeText(one.editId);
  const result = await f.service.writeText("s", "/etc/config", "modified");
  assert.equal(result.editId, two.editId);
});

test("editor rejects traversal and cross-plugin/cross-server baseline reuse", async () => {
  const f = fixture();
  await assert.rejects(() => f.service.readText("s", "/etc/../etc/passwd"), /traversal/);
  const opened = await f.service.readText("s", "/etc/config", {}, "plugin-a");
  await assert.rejects(() => f.service.writeText("s", "/etc/config", "x", { editId: opened.editId }, "plugin-b"), /baseline/);
  f.manager.list = () => [{ sessionId: "s", state: "connected", host: "other", username: "user" }];
  await assert.rejects(() => f.service.writeText("s", "/etc/config", "x", { editId: opened.editId }, "plugin-a"), /baseline/);
});

test("ordinary writable saves work with legacy arguments after opening; document handles can be released", async () => {
  const f = fixture(); const opened = await f.service.readText("s", "/home/user/config");
  await f.service.writeText("s", "/home/user/config", "modified");
  assert.deepEqual(f.calls.find((c) => c.operation === "finalize").authorization, {});
  assert.equal(f.service.closeText(opened.editId).closed, true);
  await assert.rejects(() => f.service.writeText("s", "/home/user/config", "x"), /baseline/);
});
