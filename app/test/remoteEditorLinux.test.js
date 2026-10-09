"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const scenarios = ["metadata", "move-failure", "disk-full", "post-rename-disconnect", "conflict", "upload-incomplete",
  "target-symlink", "target-hardlink", "target-fifo", "workspace-symlink", "temporary-symlink", "metadata-failure",
  "concurrent-target-replacement", "cross-filesystem-strategy", "acl", "existing-temporary"];
for (const scenario of scenarios) {
  test("Linux remote editor filesystem: " + scenario, { skip: process.platform !== "linux" ? "Requires Linux and Python 3; no remote SSH server configured." : false }, (t) => {
    const result = spawnSync("python3", [path.join(__dirname, "fixtures/remoteEditorLinux.py"),
      path.join(__dirname, "../src/main/files/remoteEditor.py"), scenario], { encoding: "utf8", timeout: 10000 });
    assert.ifError(result.error);
    if (result.status === 77) { t.skip(result.stdout.trim()); return; }
    assert.equal(result.status, 0, result.stderr + result.stdout);
    assert.equal(result.stdout.trim(), "ok");
  });
}
