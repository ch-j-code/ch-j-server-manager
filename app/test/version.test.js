"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { compareVersions, parseVersion } = require("../src/shared/version");

test("version parser accepts application versions", () => {
  assert.deepEqual(parseVersion("v0.0.1").numbers, [0, 0, 1, 0]);
  assert.equal(parseVersion("1.2.3-alpha.1+build").prerelease.join("."), "alpha.1");
});

test("version comparison handles stable and prerelease versions", () => {
  assert.equal(compareVersions("0.0.2", "0.0.1"), 1);
  assert.equal(compareVersions("1.0.0-alpha.2", "1.0.0-alpha.10"), -1);
  assert.equal(compareVersions("1.0.0", "1.0.0-beta.1"), 1);
  assert.equal(compareVersions("1.0", "1.0.0"), 0);
});

test("invalid version is rejected", () => {
  assert.throws(() => parseVersion("latest"), /Invalid version/);
});
