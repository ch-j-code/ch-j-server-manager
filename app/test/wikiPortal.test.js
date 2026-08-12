"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.join(__dirname, "..", "..", "php-update-server");
const read = (name) => fs.readFileSync(path.join(root, name), "utf8");

test("wiki remains documentation and links to the standalone community", () => {
  const partials = read("partials.php");
  const wiki = read("wiki.php");
  assert.match(partials, /\$languageWikiPath/);
  assert.match(partials, /href="\/community\.php"/);
  assert.match(partials, /web_t\('nav\.community'\)/);
  assert.match(wiki, /wiki\.overview\.title/);
  assert.match(wiki, /wiki\.install\.title/);
  assert.match(wiki, /preferred_app_installer/);
  assert.match(wiki, /install-manuals/);
  assert.match(wiki, /tracked_download_url/);
  assert.match(wiki, /wiki\.features\.title/);
  assert.match(wiki, /wiki\.plugins\.title/);
  assert.match(wiki, /wiki\.security\.title/);
  assert.match(wiki, /wiki\.updates\.title/);
  assert.match(wiki, /wiki\.community\.open/);
  assert.doesNotMatch(wiki, /load_community_messages|<form[^>]+community-action/);
});

test("localized Server Manager routes render the wiki in a fixed language", () => {
  for (const language of ["cs", "en", "de"]) {
    const route = read(`${language}/servermanager/index.php`);
    assert.match(route, new RegExp(`\\$_GET\\['lang'\\] = '${language}'`));
    assert.match(route, /CHJ_PRETTY_ROUTE/);
    assert.match(route, /wiki\.php/);
  }
  const partials = read("partials.php");
  const i18n = read("i18n.php");
  assert.match(partials, /'servermanager'/);
  assert.match(partials, /rawurlencode\(\$language\).*servermanager/s);
  assert.match(i18n, /servermanager/);
});

test("community supports topics, replies and escaped public output", () => {
  const community = read("community.php");
  assert.match(community, /load_community_messages\(\)/);
  assert.match(community, /\$replies\[\$parentId\]/);
  assert.match(community, /name="parent_id" value="<\?= h\(\$threadId\)/);
  assert.match(community, /nl2br\(h\(\$thread\['message'\]/);
  assert.match(community, /nl2br\(h\(\$reply\['message'\]/);
  assert.match(community, /data-confirm=/);
  assert.match(community, /community-action\.php/);
});

test("community writes use CSRF, honeypot, rate limiting and atomic storage", () => {
  const handler = read("community-action.php");
  const functions = read("functions.php");
  const nginx = read("nginx-site.conf");
  assert.match(handler, /verify_csrf\(\)/);
  assert.match(handler, /\$_POST\['website'\]/);
  assert.match(handler, /add_community_message/);
  assert.match(handler, /require_login\(\)/);
  assert.match(handler, /\^\[a-f0-9\]\{24\}\$/);
  assert.match(functions, /hash_hmac\('sha256', "community-message/);
  assert.match(functions, /count\(\$actorTimes\) >= 5/);
  assert.match(functions, /COMMUNITY_MESSAGES_FILE/);
  assert.match(functions, /COMMUNITY_MESSAGES_LOCK_FILE/);
  assert.match(functions, /tempnam\(dirname\(COMMUNITY_MESSAGES_FILE\)/);
  assert.match(functions, /rename\(\$temporary, COMMUNITY_MESSAGES_FILE\)/);
  assert.match(functions, /\$message\['parent_id'\] = null/);
  assert.match(functions, /\$rootParentId/);
  assert.match(nginx, /location \^~ \/data\//);
});

test("community and wiki translations exist in Czech, English and German", () => {
  const catalogs = ["cs", "en", "de"].map((language) => JSON.parse(read(`locales/${language}.json`)));
  const selected = (catalog) => Object.keys(catalog).filter((key) => key === "nav.wiki" || key === "nav.community" || key.startsWith("wiki.") || key.startsWith("community.")).sort();
  const expected = selected(catalogs[0]);
  assert.ok(expected.length > 80);
  for (const catalog of catalogs) assert.deepEqual(selected(catalog), expected);
});

test("public portal exposes the project license in every language", () => {
  const partials = read("partials.php");
  const license = read("license.php");
  const notice = read("LICENSE.txt");
  const copyrightNotice = read("NOTICE.txt");
  const thirdParty = read("THIRD_PARTY_NOTICES.txt");
  const sitemap = read("sitemap.xml");
  assert.match(partials, /href="\/license\.php"/);
  assert.match(partials, /web_t\('nav\.license'\)/);
  assert.match(license, /SPDX-License-Identifier: Apache-2\.0/);
  assert.match(license, /LICENSE\.txt/);
  assert.match(license, /license\.third_party\.text/);
  assert.match(license, /THIRD_PARTY_LICENSES\.zip/);
  assert.match(notice, /Apache License, Version 2\.0/);
  assert.match(notice, /TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION/);
  assert.match(copyrightNotice, /Copyright 2026 Josef Chudy/);
  assert.match(thirdParty, /isarray@1\.0\.0/);
  assert.match(sitemap, /https:\/\/www\.sm\.ch-j\.de\/license\.php/);
  for (const language of ["cs", "en", "de"]) {
    const catalog = JSON.parse(read(`locales/${language}.json`));
    for (const key of ["nav.license", "license.title", "license.core.text", "license.core.notice", "license.third_party.text", "license.third_party.open", "license.third_party.bundle", "license.warranty.text"]) {
      assert.equal(typeof catalog[key], "string", `${language}:${key}`);
    }
  }
});
