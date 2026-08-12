"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { cleanDownloadCache, removeCachedFile } = require("../src/main/storage/downloadCache");

test("download cache removes a package and prunes its empty release directories", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-cache-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const cache = path.join(root, "plugins", ".downloads");
  const packagePath = path.join(cache, "chj.test", "0.0.1-release", "test.chjplugin");
  fs.mkdirSync(path.dirname(packagePath), { recursive: true });
  fs.writeFileSync(packagePath, "package");

  assert.equal(removeCachedFile(cache, packagePath).removed, true);
  assert.equal(fs.existsSync(packagePath), false);
  assert.equal(fs.existsSync(path.join(cache, "chj.test")), false);
});

test("download cache rejects paths outside its root and can clear abandoned files", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-cache-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const cache = path.join(root, "updates", "downloads");
  const outside = path.join(root, "keep.txt");
  const abandoned = path.join(cache, "0.0.1-release", "installer.dmg");
  fs.mkdirSync(path.dirname(abandoned), { recursive: true });
  fs.writeFileSync(outside, "keep");
  fs.writeFileSync(abandoned, "installer");

  assert.throws(() => removeCachedFile(cache, outside), /outside its cache/);
  assert.equal(cleanDownloadCache(cache).cleaned, true);
  assert.equal(fs.existsSync(abandoned), false);
  assert.equal(fs.existsSync(cache), true);
  assert.equal(fs.readFileSync(outside, "utf8"), "keep");
});

test("download cache does not follow a parent symlink outside its root", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-cache-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const cache = path.join(root, "cache");
  const outside = path.join(root, "outside");
  fs.mkdirSync(cache);
  fs.mkdirSync(outside);
  fs.writeFileSync(path.join(outside, "keep.chjplugin"), "keep");
  fs.symlinkSync(outside, path.join(cache, "redirect"), "dir");

  assert.throws(
    () => removeCachedFile(cache, path.join(cache, "redirect", "keep.chjplugin")),
    /resolves outside its cache/
  );
  assert.equal(fs.readFileSync(path.join(outside, "keep.chjplugin"), "utf8"), "keep");
});
