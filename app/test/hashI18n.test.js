"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { catalogs, createI18n } = require("../src/main/firstPartyPlugins/chj.hash-checksum/0.0.1/ui/i18n");
const { ALGORITHMS } = require("../src/main/hashing/hashAlgorithms");

const uiRoot = path.join(__dirname, "../src/main/firstPartyPlugins/chj.hash-checksum/0.0.1/ui");

test("hash translations cover all UI phrases, algorithm categories, and result states in CS/DE/EN", () => {
  const keys = Object.keys(catalogs.en).sort();
  for (const language of ["cs", "de", "en"]) {
    assert.deepEqual(Object.keys(catalogs[language]).sort(), keys);
    for (const key of keys) assert.ok(catalogs[language][key].trim(), `${language}: ${key}`);
    for (const algorithm of ALGORITHMS) assert.ok(catalogs[language][`category.${algorithm.category}`]);
    for (const status of ["queued", "running", "completed", "failed", "cancelled", "COMPLETED", "MATCH", "MISMATCH", "ERROR", "MISSING", "INVALID ENTRY"]) assert.ok(catalogs[language][status]);
  }
  const html = fs.readFileSync(path.join(uiRoot, "index.html"), "utf8");
  const script = fs.readFileSync(path.join(uiRoot, "index.js"), "utf8");
  const usedKeys = [
    ...[...html.matchAll(/data-i18n(?:-aria-label)?="([^"]+)"/g)].map((match) => match[1].replaceAll("&amp;", "&")),
    ...[...script.matchAll(/\bt\("([^"]+)"/g)].map((match) => match[1])
  ];
  for (const key of usedKeys) assert.ok(Object.hasOwn(catalogs.en, key), `Missing hash phrase: ${key}`);
});

test("hash language changes translate interpolation, IPC errors, and states", () => {
  const i18n = createI18n("cs-CZ");
  assert.equal(i18n.t("{count} file(s) completed", { count: 2 }), "Dokončeno souborů: 2");
  assert.equal(i18n.t("MATCH"), "SHODA");
  assert.equal(i18n.errorMessage(new Error("Error invoking remote method 'plugin:hashing:start': Error: HASH_INVALID_KEY: Invalid key")), catalogs.cs.HASH_INVALID_KEY);
  i18n.setLanguage("de-DE");
  assert.equal(i18n.t("COMPLETED"), "ABGESCHLOSSEN");
  assert.equal(i18n.t("HEX key ({bytes} bytes; zero key if blank)", { bytes: 32 }), "HEX-Schlüssel (32 Bytes; leer = Nullschlüssel)");
  assert.equal(i18n.errorMessage({ code: "ENOENT", message: "not found" }), catalogs.de.ENOENT);
  i18n.setLanguage("en");
  assert.equal(i18n.errorMessage({ code: "HASH_INVALID_KEY", message: "Invalid key" }), "Invalid key");
  assert.equal(i18n.setLanguage("__proto__"), "en");
  assert.equal(i18n.t("Unknown phrase"), "Unknown phrase");
});
