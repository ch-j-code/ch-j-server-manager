"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { PassThrough } = require("node:stream");
const { UpdateInstallerLauncher } = require("../src/main/updates/updateInstallerLauncher");

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-linux-installer-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const artifactPath = path.join(root, "verified update;not-a-command.deb");
  fs.writeFileSync(artifactPath, "deb fixture", { mode: 0o400 });
  return { root, artifactPath };
}

function fakeChild(onStart) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = () => true;
  process.nextTick(() => onStart(child));
  return child;
}

test("Linux installs only the verified deb with fixed pkexec and apt-get arguments", async (t) => {
  const { artifactPath } = fixture(t);
  let invocation;
  const launcher = new UpdateInstallerLauncher({
    platform: "linux",
    pkexecPath: "/usr/bin/true",
    aptGetPath: "/usr/bin/true",
    spawnImpl(command, args, options) {
      invocation = { command, args, options };
      return fakeChild((child) => child.emit("close", 0, null));
    }
  });

  assert.deepEqual(await launcher.install(artifactPath), {
    launched: true,
    installed: true,
    restartApplication: true
  });
  assert.equal(invocation.command, "/usr/bin/true");
  assert.deepEqual(invocation.args, [
    "/usr/bin/true",
    "install",
    "--reinstall",
    "--yes",
    artifactPath
  ]);
  assert.equal(invocation.options.shell, false);
  assert.deepEqual(invocation.options.stdio, ["ignore", "pipe", "pipe"]);
});

test("Linux refuses relative, non-deb, missing, and symlink package paths", async (t) => {
  const { root, artifactPath } = fixture(t);
  const launcher = new UpdateInstallerLauncher({
    platform: "linux",
    pkexecPath: "/usr/bin/true",
    aptGetPath: "/usr/bin/true",
    spawnImpl() { throw new Error("must not spawn"); }
  });
  await assert.rejects(() => launcher.install("relative.deb"), { code: "UPDATE_INSTALL_UNSAFE_PATH" });
  await assert.rejects(() => launcher.install(path.join(root, "update.exe")), { code: "UPDATE_INSTALL_UNSUPPORTED_PACKAGE" });
  await assert.rejects(() => launcher.install(path.join(root, "missing.deb")), { code: "UPDATE_INSTALL_FILE_MISSING" });
  const symlink = path.join(root, "linked.deb");
  fs.symlinkSync(artifactPath, symlink);
  await assert.rejects(() => launcher.install(symlink), { code: "UPDATE_INSTALL_UNSAFE_PATH" });
});

test("Linux fails closed when authorization is denied or installation fails", async (t) => {
  const { artifactPath } = fixture(t);
  for (const [exitCode, expectedCode] of [[126, "UPDATE_INSTALL_AUTHORIZATION_DENIED"], [100, "UPDATE_INSTALL_FAILED"]]) {
    const launcher = new UpdateInstallerLauncher({
      platform: "linux",
      pkexecPath: "/usr/bin/true",
      aptGetPath: "/usr/bin/true",
      spawnImpl() { return fakeChild((child) => child.emit("close", exitCode, null)); }
    });
    await assert.rejects(() => launcher.install(artifactPath), { code: expectedCode });
  }
});

test("macOS and Windows retain the native installer handoff", async (t) => {
  const { artifactPath } = fixture(t);
  let opened = null;
  const launcher = new UpdateInstallerLauncher({
    platform: "win32",
    shell: { async openPath(value) { opened = value; return ""; } },
    spawnImpl() { throw new Error("must not spawn"); }
  });
  assert.deepEqual(await launcher.install(artifactPath), {
    launched: true,
    installed: false,
    restartApplication: false
  });
  assert.equal(opened, artifactPath);
});
