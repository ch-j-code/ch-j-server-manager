"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const packageJson = require("../package.json");

test("Ubuntu release is a clickable x64 Debian package", () => {
  assert.equal(packageJson.scripts["dist:linux"], "electron-builder --linux deb --x64");
  assert.deepEqual(packageJson.build.linux.target, ["deb"]);
  assert.equal(packageJson.homepage, "https://www.sm.ch-j.de");
  assert.equal(packageJson.desktopName, "ch-j-server-manager");
  assert.equal(packageJson.build.linux.syncDesktopName, true);
  assert.match(packageJson.build.linux.maintainer, /<[^>]+@[^>]+>$/);
});
