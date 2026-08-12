"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const webRoot = path.join(__dirname, "..", "..", "php-update-server");
const read = (name) => fs.readFileSync(path.join(webRoot, name), "utf8");

test("public web exposes a real robots file and multilingual sitemap", () => {
  const robots = read("robots.txt");
  const sitemap = read("sitemap.xml");
  assert.match(robots, /^User-agent: \*/m);
  assert.match(robots, /Sitemap: https:\/\/www\.sm\.ch-j\.de\/sitemap\.xml/);
  assert.match(robots, /Disallow: \/admin\.php/);
  assert.doesNotMatch(robots, /<!doctype html>/i);
  assert.match(sitemap, /<urlset[^>]+sitemaps\.org\/schemas\/sitemap/);
  assert.match(sitemap, /https:\/\/www\.sm\.ch-j\.de\/cs\//);
  assert.match(sitemap, /https:\/\/www\.sm\.ch-j\.de\/de\//);
  assert.match(sitemap, /https:\/\/www\.sm\.ch-j\.de\/en\//);
  assert.doesNotMatch(sitemap, /www\.sm\.ch-j\.de\/\?lang=(?:cs|de|en)/);
  assert.match(sitemap, /https:\/\/www\.sm\.ch-j\.de\/cs\/servermanager\//);
  assert.match(sitemap, /https:\/\/www\.sm\.ch-j\.de\/de\/servermanager\//);
  assert.match(sitemap, /https:\/\/www\.sm\.ch-j\.de\/en\/servermanager\//);
  assert.match(sitemap, /https:\/\/www\.sm\.ch-j\.de\/cs\/faq\//);
  assert.match(sitemap, /https:\/\/www\.sm\.ch-j\.de\/de\/faq\//);
  assert.match(sitemap, /https:\/\/www\.sm\.ch-j\.de\/en\/faq\//);
  assert.doesNotMatch(sitemap, /https:\/\/sm\.ch-j\.de\//);
  assert.match(sitemap, /hreflang="x-default"/);
  assert.doesNotMatch(sitemap, /admin\.php|login\.php|api\//);
  assert.equal((sitemap.match(/<url>/g) || []).length, 21);
});

test("public templates publish canonical, language, social and structured metadata", () => {
  const partials = read("partials.php");
  assert.match(partials, /rel="canonical"/);
  assert.match(partials, /rel="alternate" hreflang=/);
  assert.match(partials, /hreflang="x-default"/);
  assert.match(partials, /property="og:title"/);
  assert.match(partials, /name="twitter:card"/);
  assert.match(partials, /application\/ld\+json/);
  assert.match(partials, /SoftwareApplication/);
  assert.match(partials, /CH-J ServerManager/);
  assert.match(partials, /X-Robots-Tag: noindex, nofollow, noarchive/);
  assert.match(partials, /noindex, nofollow, noarchive/);
});

test("SEO image is a real PNG and localized descriptions are complete", () => {
  const icon = fs.readFileSync(path.join(webRoot, "assets", "app-icon.png"));
  assert.deepEqual([...icon.subarray(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10]);
  for (const language of ["cs", "de", "en"]) {
    const catalog = JSON.parse(read(`locales/${language}.json`));
    for (const page of ["index", "releases", "wiki", "faq", "community", "privacy", "license"]) {
      assert.ok(catalog[`meta.description.${page}`], `${language} is missing ${page} SEO description`);
    }
  }
});
