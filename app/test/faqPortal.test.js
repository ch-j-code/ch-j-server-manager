"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..", "..", "php-update-server");
const read = (name) => fs.readFileSync(path.join(root, name), "utf8");

test("FAQ uses native accessible disclosure elements and verified structured data", () => {
  const faq = read("faq.php");
  const partials = read("partials.php");
  assert.match(faq, /<details id=/);
  assert.match(faq, /<summary>/);
  assert.match(faq, /'@type' => 'FAQPage'/);
  assert.match(faq, /'@type' => 'Question'/);
  assert.match(faq, /'@type' => 'Answer'/);
  assert.match(faq, /'text' => web_t\('faq\.' \. \$key \. '\.answer'\)/);
  assert.equal((faq.match(/<h1>/g) || []).length, 1);
  assert.doesNotMatch(faq, /<script|onclick|onload/i);
  assert.match(partials, /web_t\('nav\.faq'\)/);
  assert.match(partials, /\$languageFaqPath/);
});

test("localized FAQ routes and language switching preserve clean paths", () => {
  const i18n = read("i18n.php");
  const partials = read("partials.php");
  for (const language of ["cs", "de", "en"]) {
    const route = read(`${language}/faq/index.php`);
    assert.match(route, new RegExp(`\\$_GET\\['lang'\\] = '${language}'`));
    assert.match(route, /CHJ_PRETTY_ROUTE.*faq/s);
    assert.match(route, /faq\.php/);
  }
  assert.match(i18n, /CHJ_PRETTY_ROUTE.*faq/s);
  assert.match(i18n, /rawurlencode\(\$language\).*faq/s);
  assert.match(partials, /'faq' => 'meta\.description\.faq'/);
  assert.match(partials, /\$pagePath === 'faq'/);
});

test("FAQ has the same complete question set in all three languages", () => {
  const languages = ["cs", "de", "en"];
  const catalogs = languages.map((language) => JSON.parse(read(`locales/${language}.json`)));
  const faqKeys = (catalog) => Object.keys(catalog).filter((key) => key.startsWith("faq.")).sort();
  const expected = faqKeys(catalogs[0]);
  assert.equal(expected.filter((key) => key.endsWith(".question")).length, 16);
  assert.equal(expected.filter((key) => key.endsWith(".answer")).length, 16);
  for (const catalog of catalogs) assert.deepEqual(faqKeys(catalog), expected);
});

test("sitemap lists every canonical FAQ URL with language alternates", () => {
  const sitemap = read("sitemap.xml");
  for (const language of ["cs", "de", "en"]) {
    assert.match(sitemap, new RegExp(`https://www\\.sm\\.ch-j\\.de/${language}/faq/`));
    assert.match(sitemap, new RegExp(`hreflang="${language}" href="https://www\\.sm\\.ch-j\\.de/${language}/faq/"`));
  }
});
