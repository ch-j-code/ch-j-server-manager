"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { HashUrlProvider } = require("../src/main/updates/hashUrlProvider");

const baseUrl = "https://192.168.10.154/";

function releasePayload(bytes) {
  return {
    update_available: true,
    current_version: "0.0.1",
    release: {
      id: "alpha-002",
      type: "app",
      name: "CH-J Server Manager",
      version: "0.0.2",
      platform: "mac",
      arch: "arm64",
      channel: "alpha",
      mandatory: false,
      notes: "Test",
      sha512: crypto.createHash("sha512").update(bytes).digest("hex"),
      size: bytes.length,
      filename: "CH-J.dmg",
      download_url: `${baseUrl}files/apps/mac/0.0.2-arm64/CH-J.dmg`,
      signature_url: `${baseUrl}files/apps/mac/0.0.2-arm64/CH-J.dmg.asc`,
      published_at: "2026-08-07T17:30:00+02:00"
    }
  };
}

test("provider checks PHP API and independently validates release", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-updates-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bytes = Buffer.from("release-bytes");
  const provider = new HashUrlProvider({
    baseUrls: [baseUrl],
    downloadRoot: root,
    fetchImpl: async (url) => {
      assert.match(url.toString(), /api\/latest\.php/);
      assert.equal(url.searchParams.get("channel"), "alpha");
      assert.equal(url.searchParams.get("arch"), "arm64");
      return new Response(JSON.stringify(releasePayload(bytes)), { status: 200, headers: { "content-type": "application/json" } });
    }
  });
  const result = await provider.checkForUpdates({ currentVersion: "0.0.1", platform: "darwin", arch: "arm64", channel: "alpha" });
  assert.equal(result.updateAvailable, true);
  assert.equal(result.release.version, "0.0.2");
});

test("provider lists every compatible build and keeps same-version releases distinct", async () => {
  const bytes = Buffer.from("release-bytes");
  const newest = releasePayload(bytes).release;
  newest.id = "same-version-newer";
  newest.version = "0.0.1";
  newest.published_at = "2026-08-07T18:00:00+02:00";
  const older = { ...newest, id: "same-version-older", published_at: "2026-08-07T17:00:00+02:00" };
  const provider = new HashUrlProvider({
    baseUrls: [baseUrl],
    downloadRoot: os.tmpdir(),
    fetchImpl: async (url) => {
      assert.match(url.toString(), /api\/releases\.php/);
      assert.equal(url.searchParams.get("platform"), "mac");
      assert.equal(url.searchParams.get("arch"), "arm64");
      assert.equal(url.searchParams.get("channel"), "alpha");
      return new Response(JSON.stringify({ releases: [older, newest] }), { status: 200 });
    }
  });
  const result = await provider.listReleases({ currentVersion: "0.0.1", platform: "darwin", arch: "arm64", channel: "alpha" });
  assert.deepEqual(result.releases.map((release) => release.id), ["same-version-newer", "same-version-older"]);
});

test("all update channels are fetched separately and merged locally", async () => {
  const bytes = Buffer.from("release-bytes");
  const requestedChannels = [];
  const provider = new HashUrlProvider({
    baseUrls: [baseUrl],
    downloadRoot: os.tmpdir(),
    fetchImpl: async (url) => {
      const channel = url.searchParams.get("channel");
      requestedChannels.push(channel);
      const release = releasePayload(bytes).release;
      release.id = `${channel}-release`;
      release.channel = channel;
      return new Response(JSON.stringify({ releases: [release] }), { status: 200 });
    }
  });
  const result = await provider.listReleases({ currentVersion: "0.0.1", platform: "darwin", arch: "arm64", channel: "all" });
  assert.deepEqual(requestedChannels, ["alpha", "beta", "stable"]);
  assert.deepEqual(new Set(result.releases.map((release) => release.channel)), new Set(["alpha", "beta", "stable"]));
});

test("provider rejects unsupported macOS x64 target before contacting server", async () => {
  let contacted = false;
  const provider = new HashUrlProvider({
    baseUrls: [baseUrl],
    downloadRoot: os.tmpdir(),
    fetchImpl: async () => {
      contacted = true;
      return new Response(null, { status: 404 });
    }
  });
  await assert.rejects(
    () => provider.checkForUpdates({ currentVersion: "0.0.1", platform: "darwin", arch: "x64", channel: "alpha" }),
    /Unsupported update architecture/
  );
  assert.equal(contacted, false);
});

test("provider downloads exact bytes and verifies SHA-512", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-updates-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bytes = Buffer.from("verified release bytes");
  const payload = releasePayload(bytes);
  const provider = new HashUrlProvider({
    baseUrls: [baseUrl],
    downloadRoot: root,
    signatureVerifier: {
      async verifyFile() {
        return { valid: true, primaryFingerprint: "0".repeat(40), signingFingerprints: ["1".repeat(40)] };
      }
    },
    fetchImpl: async (url) => String(url).endsWith(".asc")
      ? new Response("test-signature", { status: 200 })
      : new Response(bytes, { status: 200, headers: { "content-length": String(bytes.length) } })
  });
  const release = {
    ...payload.release,
    downloadUrl: payload.release.download_url,
    signatureUrl: payload.release.signature_url
  };
  const result = await provider.downloadAndVerify(release);
  assert.equal(fs.readFileSync(result.path, "utf8"), bytes.toString("utf8"));
  assert.equal(result.sha512, payload.release.sha512);
});

test("provider deletes staging file when SHA-512 does not match", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-updates-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const expected = Buffer.from("expected");
  const actual = Buffer.from("modified");
  const payload = releasePayload(expected);
  payload.release.size = actual.length;
  const provider = new HashUrlProvider({
    baseUrls: [baseUrl],
    downloadRoot: root,
    signatureVerifier: { async verifyFile() { throw new Error("must not be reached"); } },
    fetchImpl: async () => new Response(actual, { status: 200 })
  });
  await assert.rejects(() => provider.downloadAndVerify({
    ...payload.release,
    downloadUrl: payload.release.download_url,
    signatureUrl: payload.release.signature_url
  }), /SHA-512/);
  const remaining = fs.readdirSync(path.dirname(path.join(root, `${payload.release.version}-${payload.release.id}`, payload.release.filename)));
  assert.equal(remaining.some((name) => name.endsWith(".part")), false);
});

test("provider removes an artifact when mandatory OpenPGP verification fails", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-updates-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bytes = Buffer.from("unsigned release bytes");
  const payload = releasePayload(bytes);
  const provider = new HashUrlProvider({
    baseUrls: [baseUrl],
    downloadRoot: root,
    signatureVerifier: { async verifyFile() { throw new Error("invalid signature"); } },
    fetchImpl: async (url) => String(url).endsWith(".asc")
      ? new Response("bad-signature", { status: 200 })
      : new Response(bytes, { status: 200 })
  });
  const release = {
    ...payload.release,
    downloadUrl: payload.release.download_url,
    signatureUrl: payload.release.signature_url
  };
  await assert.rejects(() => provider.downloadAndVerify(release), /invalid signature/);
  const destination = path.join(root, `${release.version}-${release.id}`, release.filename);
  assert.equal(fs.existsSync(destination), false);
  assert.equal(fs.existsSync(`${destination}.asc`), false);
});

test("provider re-hashes the same private-cache artifact immediately before installation", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-updates-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bytes = Buffer.from("verified release bytes");
  const payload = releasePayload(bytes);
  const signatureVerifier = {
    calls: 0,
    async verifyFile() {
      this.calls += 1;
      return { valid: true, primaryFingerprint: "0".repeat(40), signingFingerprints: ["1".repeat(40)] };
    }
  };
  const provider = new HashUrlProvider({
    baseUrls: [baseUrl],
    downloadRoot: root,
    signatureVerifier,
    fetchImpl: async (url) => String(url).endsWith(".asc")
      ? new Response("test-signature", { status: 200 })
      : new Response(bytes, { status: 200 })
  });
  const release = {
    ...payload.release,
    downloadUrl: payload.release.download_url,
    signatureUrl: payload.release.signature_url
  };
  const downloaded = await provider.downloadAndVerify(release);
  fs.chmodSync(downloaded.path, 0o600);
  fs.writeFileSync(downloaded.path, Buffer.from("tampered release bytes"));
  await assert.rejects(() => provider.reverifyForInstall(downloaded, release), /changed after verification|size changed/);
  assert.equal(signatureVerifier.calls, 1, "tampered bytes must be rejected before the second OpenPGP pass");
});
