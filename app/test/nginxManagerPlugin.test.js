"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..", "..", "plugins", "nginx-manager");

test("NGINX Manager declares bounded capabilities and complete UI actions", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
  const html = fs.readFileSync(path.join(root, "ui", "index.html"), "utf8");
  const script = fs.readFileSync(path.join(root, "ui", "index.js"), "utf8");
  assert.equal(manifest.id, "chj.nginx-manager");
  assert.deepEqual(manifest.permissions, ["session.read", "nginx.read", "nginx.manage"]);
  assert.ok(!manifest.permissions.includes("remote.exec"));
  for (const id of ["sessionSelect", "sudoPassword", "configList", "configEditor", "testButton", "saveButton", "reloadButton", "commandOutput"]) {
    assert.match(html, new RegExp(`id="${id}"`));
  }
  for (const operation of ["inspect", "readConfig", "dumpConfig", "testConfig", "saveConfig", "reload"]) {
    assert.match(script, new RegExp(`api\\.nginx\\.${operation}`));
  }
  assert.match(html, /nginx -t/);
  assert.match(html, /automaticky vrátí ze zálohy/);
  assert.match(html, /nginx\.org\/en\/docs\/control\.html/);
});
