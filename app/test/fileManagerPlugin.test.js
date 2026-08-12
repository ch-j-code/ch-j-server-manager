"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { validateManifest } = require("../src/main/plugins/pluginRegistry");

test("file manager declares only bounded SFTP capabilities and complete UI hooks", () => {
  const root = path.join(__dirname, "..", "..", "plugins", "file-manager");
  const manifest = validateManifest(JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8")));
  const html = fs.readFileSync(path.join(root, "ui", "index.html"), "utf8");
  const script = fs.readFileSync(path.join(root, "ui", "index.js"), "utf8");

  assert.equal(manifest.id, "chj.file-manager");
  assert.deepEqual(manifest.permissions, ["session.read", "files.read", "files.write", "files.transfer"]);
  assert.ok(!manifest.permissions.includes("remote.exec"));
  for (const id of ["sessionSelect", "breadcrumbs", "pathInput", "filesBody", "filterInput", "editorHost", "contextMenu", "uploadButton", "downloadButton", "zipButton", "saveEditorButton"]) {
    assert.match(html, new RegExp(`id="${id}"`));
  }
  for (const operation of ["list", "readText", "writeText", "createFile", "mkdir", "rename", "removeMany", "upload", "download", "downloadMany", "downloadArchive"]) {
    assert.match(script, new RegExp(`api\\.files\\.${operation}`));
  }
  assert.match(html, /vendor\/monaco\/vs\/loader\.js/);
  assert.ok(fs.statSync(path.join(root, "ui", "vendor", "monaco", "vs", "loader.js")).isFile());
  assert.ok(fs.statSync(path.join(root, "ui", "vendor", "monaco", "vs", "base", "browser", "ui", "codicons", "codicon", "codicon.woff")).isFile());
  assert.ok(!fs.existsSync(path.join(root, "ui", "vendor", "monaco", "vs", "base", "browser", "ui", "codicons", "codicon", "codicon.ttf")));
  assert.match(fs.readFileSync(path.join(root, "ui", "vendor", "monaco", "vs", "editor", "editor.main.css"), "utf8"), /codicon\.woff\) format\("woff"\)/);
  assert.match(script, /vs\/editor\/editor\.main/);
  assert.match(script, /preferScriptTags: true/);
  assert.match(script, /aktualizujte aplikaci/);
});
