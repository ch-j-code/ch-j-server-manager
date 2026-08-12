"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { catalogs, createI18n, normalizeLanguage, supportedLanguages } = require("../src/renderer/i18n");

test("all i18n catalogs expose the same translation keys", () => {
  const expected = Object.keys(catalogs.cs).sort();
  assert.deepEqual(supportedLanguages, ["cs", "de", "en"]);
  for (const language of supportedLanguages) assert.deepEqual(Object.keys(catalogs[language]).sort(), expected);
});

test("i18n selects a supported language, interpolates values and falls back safely", () => {
  const i18n = createI18n("de-DE");
  assert.equal(i18n.getLanguage(), "de");
  assert.equal(i18n.t("updates.channel", { channel: "alpha" }), "Kanal alpha");
  assert.equal(i18n.t("missing.translation"), "missing.translation");
  assert.equal(i18n.setLanguage("../../en"), "cs");
  assert.equal(normalizeLanguage("en-US"), "en");
});

test("every translation key used by renderer markup exists in the catalogs", () => {
  const html = fs.readFileSync(path.join(__dirname, "..", "src", "renderer", "index.html"), "utf8");
  const keys = [...html.matchAll(/data-i18n(?:-placeholder|-aria-label)?="([^"]+)"/g)].map((match) => match[1]);
  assert.ok(keys.length > 50);
  for (const key of keys) assert.ok(key in catalogs.cs, `Missing renderer translation: ${key}`);
});

test("every literal dynamic translation key exists in the catalogs", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "src", "renderer", "app.js"), "utf8");
  const keys = [...source.matchAll(/\bt\("([^"]+)"/g)].map((match) => match[1]);
  assert.ok(keys.length > 25);
  for (const key of keys) assert.ok(key in catalogs.cs, `Missing dynamic translation: ${key}`);
});
