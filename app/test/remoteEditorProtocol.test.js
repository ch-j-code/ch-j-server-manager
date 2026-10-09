"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { SessionManager } = require("../src/main/sessions/sessionManager");
const marker = "\x1eCHJ_EDITOR_START\n";

function fixture({ username = "user", stdout = marker + JSON.stringify({ ok: true, value: { status: "saved" } }), code = 0, stderr = "" } = {}) {
  const commands = [], input = [];
  const manager = new SessionManager({});
  manager.sessions.set("s", { sessionId: "s", username, state: "connected", stream: {}, client: {
    exec(command, callback) {
      commands.push(command);
      const stream = new EventEmitter(); stream.stderr = new EventEmitter(); stream.end = (value) => input.push(value);
      callback(null, stream);
      queueMicrotask(() => { stream.emit("data", Buffer.from(stdout)); stream.stderr.emit("data", Buffer.from(stderr)); stream.emit("close", code); });
    }
  } });
  return { manager, commands, input };
}

test("editor sudo supports passwordless, password stdin and root without exposing credentials in commands", async () => {
  const request = { operation: "finalize", path: "/etc/test 'quoted' ; $(echo unsafe)" };
  const password = "sudo-secret-'$value";
  const f = fixture(); await f.manager.remoteEditor("s", request, { sudo: true, sudoPassword: password });
  assert.match(f.commands[0], /^sudo -S -p '' -- sh -c /);
  assert.equal(f.commands[0].includes(password), false); assert.deepEqual(f.input, [password + "\n"]);
  const passwordless = fixture(); await passwordless.manager.remoteEditor("s", request, { sudo: true });
  assert.match(passwordless.commands[0], /^sudo -n -- sh -c /);
  const root = fixture({ username: "root" }); await root.manager.remoteEditor("s", request, { sudo: true });
  assert.match(root.commands[0], /^sh -c /); assert.doesNotMatch(root.commands[0], /^sudo/);
  const plain = fixture(); await plain.manager.remoteEditor("s", request);
  assert.match(plain.commands[0], /^printf /); assert.doesNotMatch(plain.commands[0], /^sudo/);
  await assert.rejects(() => f.manager.remoteEditor("s", request, { sudoPassword: password }), { code: "FILE_SUDO_AUTHORIZATION_REQUIRED" });
});

test("sudo denial is distinguished from an uncertain command failure after sudo authorization", async () => {
  const denied = fixture({ stdout: "", code: 1, stderr: "sudo-secret: unauthorized" });
  await assert.rejects(() => denied.manager.remoteEditor("s", { operation: "finalize" }, { sudo: true, sudoPassword: "sudo-secret" }), (error) => {
    assert.equal(error.code, "FILE_SUDO_FAILED"); assert.doesNotMatch(error.message, /sudo-secret/); return true;
  });
  const started = fixture({ stdout: marker, code: 1 });
  await assert.rejects(() => started.manager.remoteEditor("s", { operation: "finalize" }, { sudo: true }), { code: "FILE_RESULT_UNKNOWN" });
  const noPython = fixture({ stdout: marker, code: 127 });
  await assert.rejects(() => noPython.manager.remoteEditor("s", { operation: "read" }), { code: "FILE_DEPENDENCY_UNAVAILABLE" });
});

test("invalid replies and missing remote exit status fail closed", async () => {
  for (const stdout of ["", "{}", marker + "null", marker + "unexpected"]) {
    const f = fixture({ stdout });
    await assert.rejects(() => f.manager.remoteEditor("s", { operation: "finalize" }));
  }
  const f = fixture({ code: null });
  await assert.rejects(() => f.manager.remoteEditor("s", { operation: "finalize" }), { code: "FILE_RESULT_UNKNOWN" });
});

test("synchronous exec failure releases timers and pending requests", async () => {
  const manager = new SessionManager({}); const record = { client: { exec() { throw new Error("Disconnected"); } } };
  await assert.rejects(() => manager._execFixed(record, "true", 5000));
  assert.equal(record.pendingExec.size, 0);
  await assert.rejects(() => manager._execSudo(record, "true", "", 5000));
  assert.equal(record.pendingExec.size, 0);
});

test("SSH loss settles a pending editor save as unknown immediately", async () => {
  const f = fixture(); const record = f.manager.sessions.get("s");
  record.decoder = { end: () => "" }; record.client.end = () => {}; record.client.exec = () => {};
  const pending = assert.rejects(() => f.manager.remoteEditor("s", { operation: "finalize" }), { code: "FILE_RESULT_UNKNOWN" });
  await f.manager.disconnect("s"); await pending;
  assert.equal(record.pendingExec.size, 0);
});

test("host shell receives hostile paths as an exact JSON argument with no expansion", async (t) => {
  const fs = require("node:fs"), os = require("node:os"), path = require("node:path"), { execFile } = require("node:child_process");
  if (process.platform === "win32") { t.skip("POSIX quoting belongs to the Linux server shell"); return; }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-editor-shell-")); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(path.join(root, "python3"), '#!' + process.execPath + '\nconst value=JSON.parse(process.argv.at(-1)); process.stdout.write(JSON.stringify({ok:true,value}));\n', { mode: 0o700 });
  const request = { operation: "read", path: "/etc/trailing ' ; $(touch " + root + "/EXPANDED) `echo bad` \\" };
  const manager = new SessionManager({});
  const record = { state: "connected", stream: {}, client: {} }; manager.sessions.set("s", record);
  // The real shell parses exactly the fixed command handed to ssh2.exec.
  manager._execFixed = (_record, command) => new Promise((resolve, reject) => {
    execFile("/bin/sh", ["-c", command], { shell: false, env: { ...process.env, PATH: root + ":" + process.env.PATH }, maxBuffer: 1024 * 1024 }, (error, stdout, stderr) => error ? reject(error) : resolve({ stdout, stderr }));
  });
  assert.deepEqual(await manager.remoteEditor("s", request), request);
  assert.equal(fs.existsSync(path.join(root, "EXPANDED")), false);
});
