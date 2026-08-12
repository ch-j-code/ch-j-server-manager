"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createTestHttpsFetch } = require("../src/main/security/testHttpsFetch");

test("test HTTPS transport rejects HTTP and foreign HTTPS origins before connecting", async () => {
  const testFetch = createTestHttpsFetch({ allowedBaseUrls: ["https://sm.ch-j.de/"] });
  await assert.rejects(() => testFetch("http://sm.ch-j.de/api/releases.php"), /outside/);
  await assert.rejects(() => testFetch("https://example.com/api/releases.php"), /outside/);
});

test("test HTTPS transport refuses automatic redirects", async () => {
  const testFetch = createTestHttpsFetch({ allowedBaseUrls: ["https://sm.ch-j.de/"] });
  await assert.rejects(
    () => testFetch("https://sm.ch-j.de/api/releases.php", { redirect: "follow" }),
    /must not follow redirects/
  );
});

test("the temporary CA exception is restricted to the single configured HTTPS domain", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "src", "main", "security", "testHttpsFetch.js"), "utf8");
  const bootstrap = fs.readFileSync(path.join(__dirname, "..", "src", "main", "index.js"), "utf8");
  const config = fs.readFileSync(path.join(__dirname, "..", "src", "main", "config", "configStore.js"), "utf8");
  assert.match(source, /rejectUnauthorized:\s*!insecureOrigins\.has\(url\.origin\)/);
  assert.match(source, /insecure test origin must also be explicitly allowed/i);
  assert.match(source, /minVersion:\s*"TLSv1\.2"/);
  assert.match(source, /maxVersion:\s*"TLSv1\.3"/);
  assert.match(bootstrap, /insecureBaseUrls:\s*\["https:\/\/sm\.ch-j\.de\/"\]/);
  assert.match(config, /https:\/\/www\.sm\.ch-j\.de\//);
  assert.match(config, /https:\/\/sm\.ch-j\.de\//);
  assert.doesNotMatch(config, /192\.168\.10\.154/);
  assert.throws(() => createTestHttpsFetch({
    allowedBaseUrls: ["https://sm.ch-j.de/"],
    insecureBaseUrls: ["https://example.com/"]
  }), /must also be explicitly allowed/);
});
