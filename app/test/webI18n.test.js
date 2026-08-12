"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const portalRoot = path.join(__dirname, "..", "..", "php-update-server");
const read = (name) => fs.readFileSync(path.join(portalRoot, name), "utf8");

test("web localization catalogs expose the same complete key set", () => {
  const catalogs = Object.fromEntries(["cs", "de", "en"].map((language) => [
    language,
    JSON.parse(read(`locales/${language}.json`)),
  ]));
  const expectedKeys = Object.keys(catalogs.cs).sort();
  assert.ok(expectedKeys.length > 140);
  for (const [language, catalog] of Object.entries(catalogs)) {
    assert.deepEqual(Object.keys(catalog).sort(), expectedKeys, `${language} catalog keys differ`);
    for (const [key, value] of Object.entries(catalog)) {
      assert.equal(typeof value, "string", `${language}:${key} must be text`);
      assert.notEqual(value.trim(), "", `${language}:${key} must not be empty`);
    }
  }
});

test("web localization selects browser language and allows a persisted override", () => {
  const runtime = read("i18n.php");
  const bootstrap = read("bootstrap.php");
  const partials = read("partials.php");
  const script = read("assets/app.js");
  assert.match(runtime, /HTTP_ACCEPT_LANGUAGE/);
  assert.match(runtime, /WEB_LANGUAGE_COOKIE/);
  assert.match(runtime, /\$_GET\['lang'\]/);
  assert.match(runtime, /const WEB_LANGUAGES = \['cs', 'de', 'en'\]/);
  assert.match(bootstrap, /web_i18n_bootstrap\(\)/);
  assert.match(partials, /<html lang="<\?= h\(web_language\(\)\) \?>">/);
  assert.match(partials, /class="language-switcher"/);
  assert.match(partials, /id="chj-web-i18n" type="application\/json"/);
  assert.match(partials, /JSON_HEX_TAG/);
  assert.match(script, /JSON\.parse\(document\.querySelector\('#chj-web-i18n'\)/);
  assert.doesNotMatch(partials, /window\.CHJ_WEB_I18N/);
  assert.doesNotMatch(script, /\.innerHTML\s*=/);
});

test("localized home routes keep language in the URL path", () => {
  for (const language of ["cs", "de", "en"]) {
    const route = read(`${language}/index.php`);
    assert.match(route, new RegExp(`\\$_GET\\['lang'\\] = '${language}'`));
    assert.match(route, /CHJ_PRETTY_ROUTE.*home/s);
    assert.match(route, /index\.php/);
  }
  const runtime = read("i18n.php");
  const partials = read("partials.php");
  const index = read("index.php");
  assert.match(runtime, /CHJ_PRETTY_ROUTE.*home/s);
  assert.match(runtime, /rawurlencode\(\$language\).*'\/'/s);
  assert.match(partials, /\$languageHomePath/);
  assert.match(partials, /\$languageWikiPath/);
  assert.match(index, /str_ends_with\(\$requestedHost, '\.ch-j\.cz'\)/);
  assert.match(index, /str_ends_with\(\$requestedHost, '\.ch-j\.eu'\)/);
  assert.match(index, /Location: \/.*rawurlencode\(\$routeLanguage\)/s);
});

test("every literal template translation key exists in all catalogs", () => {
  const catalog = JSON.parse(read("locales/en.json"));
  const templates = ["partials.php", "index.php", "releases.php", "login.php", "admin.php", "upload.php", "action.php", "functions.php", "analytics.php", "i18n.php", "wiki.php", "faq.php", "community.php", "community-action.php", "privacy.php"]
    .map(read)
    .join("\n");
  const keys = [...templates.matchAll(/web_t\('([^']+)'/g)].map((match) => match[1]);
  for (const key of keys) {
    const exists = key.endsWith('.')
      ? Object.keys(catalog).some((catalogKey) => catalogKey.startsWith(key))
      : key in catalog;
    assert.ok(exists, `Missing translation key: ${key}`);
  }
});
