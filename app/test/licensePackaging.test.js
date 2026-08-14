"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const AdmZip = require("adm-zip");

const root = path.join(__dirname, "..");

test("application includes the complete project and dependency license texts", () => {
  const license = fs.readFileSync(path.join(root, "LICENSE"), "utf8");
  const notice = fs.readFileSync(path.join(root, "NOTICE"), "utf8");
  const thirdParty = fs.readFileSync(path.join(root, "THIRD_PARTY_NOTICES.txt"), "utf8");
  const packageJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  assert.match(license, /TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION/);
  assert.ok(license.length > 10000);
  assert.match(notice, /Copyright 2026 Josef Chudy/);
  assert.match(thirdParty, /isarray@1\.0\.0/);
  for (const filename of ["APPLICATION_LICENSE.txt", "NOTICE.txt", "THIRD_PARTY_NOTICES.txt", "THIRD_PARTY_LICENSES.zip", "ELECTRON_LICENSE.txt", "CHROMIUM_LICENSES.html"]) {
    assert.ok(packageJson.build.extraResources.some((entry) => entry.to === `licenses/${filename}`), filename);
  }
  assert.equal(packageJson.build.afterPack, "scripts/afterPack.js");
  const bundle = new AdmZip(path.join(root, "THIRD_PARTY_LICENSES.zip"));
  for (const filename of ["THIRD_PARTY_NOTICES.txt", "ELECTRON_LICENSE.txt", "CHROMIUM_LICENSES.html", "MONACO_LICENSE.txt", "MONACO_THIRD_PARTY_NOTICES.txt", "FB_TIGER_HASH_LICENSE.txt", "GOOGLE_CITYHASH_LICENSE.txt", "SHA512SUMS.txt"]) {
    assert.ok(bundle.getEntry(filename), filename);
  }
  for (const dependency of ["@noble/hashes@2.3.0", "farmhashjs@1.0.1", "hash-wasm@4.12.0", "highwayhasher@0.4.4", "fb-tiger-hash@1.0.0", "google-cityhash"]) {
    assert.match(thirdParty, new RegExp(dependency.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
});

test("license documents are accessible from the sandboxed renderer through narrow IPC", () => {
  const preload = fs.readFileSync(path.join(root, "src", "preload", "corePreload.js"), "utf8");
  const ipc = fs.readFileSync(path.join(root, "src", "main", "ipc", "registerCoreIpc.js"), "utf8");
  const html = fs.readFileSync(path.join(root, "src", "renderer", "index.html"), "utf8");
  assert.match(preload, /openLegalDocument/);
  assert.match(ipc, /handle\("legal:open"/);
  assert.match(html, /data-legal-document="thirdParty"/);
  assert.match(html, /data-legal-document="thirdPartyBundle"/);
});
