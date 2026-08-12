"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { assertAllowedUrl, normalizeBaseUrl } = require("../src/main/security/urlPolicy");

const bases = [
  "https://sm.ch-j.de/"
];

test("base URL normalization preserves the allowed root", () => {
  assert.equal(normalizeBaseUrl("https://sm.ch-j.de").toString(), bases[0]);
});

test("allowed API and file URLs pass", () => {
  assert.equal(
    assertAllowedUrl(`${bases[0]}api/latest.php`, bases, { pathSegment: "api/" }).hostname,
    "sm.ch-j.de"
  );
  assert.equal(
    assertAllowedUrl(`${bases[0]}files/apps/win/app.exe`, bases, { pathSegment: "files/" }).hostname,
    "sm.ch-j.de"
  );
});

test("foreign hosts, credentials and paths are rejected", () => {
  assert.throws(() => assertAllowedUrl("https://example.com/update.exe", bases), /allowlist/);
  assert.throws(() => assertAllowedUrl("https://admin@sm.ch-j.de/files/a", bases), /credentials/);
  assert.throws(() => assertAllowedUrl(`${bases[0]}admin.php`, bases, { pathSegment: "files/" }), /path/);
});

test("HTTP update origins are rejected", () => {
  assert.throws(() => normalizeBaseUrl("http://sm.ch-j.de/"), /HTTPS/);
});
