"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const packageJson = require("../package.json");

test("one manifest defines the macOS, Windows and Linux builds", () => {
  assert.equal(packageJson.scripts["build:mac"], "electron-builder --mac && npm run package:mac:installer");
  assert.equal(packageJson.scripts["build:win"], "electron-builder --win");
  assert.equal(packageJson.scripts["build:linux"], "electron-builder --linux");
  assert.equal(packageJson.scripts["dist:mac"], "npm run build:mac");
  assert.equal(packageJson.scripts["dist:win"], "npm run build:win");
  assert.equal(packageJson.scripts["dist:linux"], "npm run build:linux");
  assert.deepEqual(packageJson.build.mac.target, [{ target: "dmg", arch: ["arm64"] }]);
  assert.deepEqual(packageJson.build.win.target, [{ target: "nsis", arch: ["x64"] }]);
  assert.deepEqual(packageJson.build.linux.target, [{ target: "deb", arch: ["x64"] }]);
});

test("Ubuntu release remains a clickable x64 Debian package", () => {
  assert.equal(packageJson.homepage, "https://www.sm.ch-j.de");
  assert.equal(packageJson.desktopName, "ch-j-server-manager");
  assert.equal(packageJson.build.linux.syncDesktopName, true);
  assert.match(packageJson.build.linux.maintainer, /<[^>]+@[^>]+>$/);
});
