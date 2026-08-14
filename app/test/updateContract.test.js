"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  assertSupportedUpdateTarget,
  serverChannel,
  validateReleaseListResponse,
  validateReleaseResponse
} = require("../src/shared/updateContract");

function payload(overrides = {}) {
  return {
    update_available: true,
    release: {
      id: "release-1",
      type: "app",
      name: "CH-J Server Manager",
      version: "0.0.2",
      platform: "win",
      arch: "x64",
      channel: "alpha",
      mandatory: false,
      notes: "Alpha update",
      sha512: "a".repeat(128),
      size: 123,
      filename: "CH-J-Server-Manager.exe",
      download_url: "https://192.168.10.154/files/apps/win/update.exe",
      signature_url: "https://192.168.10.154/files/apps/win/update.exe.asc",
      ...overrides
    }
  };
}

const expected = { currentVersion: "0.0.1", platform: "win32", arch: "x64", channel: "alpha" };

test("valid PHP release response is normalized", () => {
  const result = validateReleaseResponse(payload(), expected);
  assert.equal(result.updateAvailable, true);
  assert.equal(result.release.version, "0.0.2");
  assert.equal(result.release.sha512.length, 128);
});

test("client independently rejects same or older release", () => {
  assert.equal(validateReleaseResponse(payload({ version: "0.0.1" }), expected).updateAvailable, false);
  assert.equal(validateReleaseResponse(payload({ version: "0.0.0" }), expected).updateAvailable, false);
});

test("wrong platform, channel and hash are rejected", () => {
  assert.throws(() => validateReleaseResponse(payload({ platform: "mac", arch: "arm64" }), expected), /platform/);
  assert.throws(() => validateReleaseResponse(payload({ channel: "stable" }), expected), /channel/);
  assert.throws(() => validateReleaseResponse(payload({ sha512: "abcd" }), expected), /SHA-512/);
});

test("application and server use identical update channel names", () => {
  assert.equal(serverChannel("alpha"), "alpha");
  assert.equal(serverChannel("beta"), "beta");
  assert.equal(serverChannel("stable"), "stable");
  assert.throws(() => serverChannel("dev"), /Unsupported update channel/);
});

test("macOS updates support ARM64 only", () => {
  assert.deepEqual(assertSupportedUpdateTarget("darwin", "arm64"), { platform: "mac", arch: "arm64" });
  assert.throws(() => assertSupportedUpdateTarget("mac", "x64"), /Unsupported update architecture/);
  assert.throws(() => assertSupportedUpdateTarget("mac", "universal"), /Unsupported update architecture/);
});

test("catalog keeps equal versions separate and sorts them by publication time", () => {
  const first = payload({ id: "older-build", version: "0.0.1", published_at: "2026-08-07T15:00:00Z" }).release;
  const second = payload({ id: "newer-build", version: "0.0.1", published_at: "2026-08-07T16:00:00Z" }).release;
  const result = validateReleaseListResponse({ releases: [first, second] }, expected);
  assert.deepEqual(result.releases.map((release) => release.id), ["newer-build", "older-build"]);
  assert.throws(() => validateReleaseListResponse({ releases: [first, first] }, expected), /Duplicate release id/);
});
