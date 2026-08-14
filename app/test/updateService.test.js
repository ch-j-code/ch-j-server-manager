"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { UpdateService } = require("../src/main/updates/updateService");

function release(id, publishedAt) {
  return {
    id,
    version: "0.0.1",
    publishedAt,
    filename: `${id}.dmg`,
    size: 10,
    sha512: "a".repeat(128)
  };
}

test("service exposes and selects distinct builds with the installed version", async () => {
  const older = release("build-older", "2026-08-07T15:00:00Z");
  const newer = release("build-newer", "2026-08-07T16:00:00Z");
  const provider = {
    async listReleases() { return { releases: [newer, older], sourceBaseUrl: "https://192.168.10.154/" }; },
    async downloadAndVerify(selected) {
      return {
        path: `/tmp/${selected.filename}`,
        signaturePath: `/tmp/${selected.filename}.asc`,
        filename: selected.filename,
        size: selected.size,
        sha512: selected.sha512,
        reused: false,
        signatureVerified: true,
        primaryFingerprint: "0".repeat(40),
        signingFingerprints: ["1".repeat(40)]
      };
    }
  };
  const service = new UpdateService({
    appVersion: "0.0.1",
    platform: "darwin",
    arch: "arm64",
    configStore: { get: () => ({ updates: { channel: "alpha", lastLaunchedRelease: null } }) },
    providerFactory: () => provider
  });

  const checked = await service.check();
  assert.equal(checked.releases.length, 2);
  assert.equal(checked.selectedReleaseId, "build-newer");
  assert.equal(checked.releaseRelation, "sameVersionNewerRelease");

  const selected = service.select("build-older");
  assert.equal(selected.selectedReleaseId, "build-older");
  assert.equal(selected.releaseRelation, "sameVersionOlderRelease");
  const downloaded = await service.download();
  assert.equal(downloaded.downloaded.releaseId, "build-older");
  assert.throws(() => service.select("missing"), /not available/);
});

test("service compares same-version releases with the last launched installer by publication time", async () => {
  const current = release("build-current", "2026-08-07T15:00:00Z");
  const newer = release("build-newer", "2026-08-07T16:00:00Z");
  const older = release("build-older", "2026-08-07T14:00:00Z");
  newer.sha512 = "b".repeat(128);
  older.sha512 = "c".repeat(128);
  const config = { updates: { channel: "alpha", lastLaunchedRelease: current } };
  const service = new UpdateService({
    appVersion: "0.0.1",
    platform: "darwin",
    arch: "arm64",
    configStore: { get: () => config },
    providerFactory: () => ({
      async listReleases() { return { releases: [newer, current, older], sourceBaseUrl: "https://192.168.10.154/" }; }
    })
  });

  assert.equal((await service.check()).releaseRelation, "sameVersionNewerRelease");
  assert.equal(service.select("build-current").releaseRelation, "sameVersionCurrentRelease");
  assert.equal(service.select("build-older").releaseRelation, "sameVersionOlderRelease");
});

test("embedded build identity marks the exact repository release as current", async () => {
  const current = { ...release("repository-release", "2026-08-08T15:35:00Z"), buildId: "core-20260808T153400Z-a1b2c3d4e5f6" };
  const service = new UpdateService({
    appVersion: "0.0.1",
    buildId: current.buildId,
    platform: "darwin",
    arch: "arm64",
    configStore: { get: () => ({ updates: { channel: "alpha", lastLaunchedRelease: null } }) },
    providerFactory: () => ({
      async listReleases() { return { releases: [current], sourceBaseUrl: "https://192.168.10.154/" }; }
    })
  });

  const state = await service.check();
  assert.equal(state.releaseRelation, "sameVersionCurrentRelease");
  assert.equal(state.updateAvailable, false);
  assert.equal(state.currentBuildId, current.buildId);
});
