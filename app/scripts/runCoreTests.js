"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const testRoot = path.join(__dirname, "..", "test");
const workspaceOnlyTests = new Set([
  "faqPortal.test.js",
  "fileManagerPlugin.test.js",
  "nginxManagerPlugin.test.js",
  "systemMonitorPlugin.test.js",
  "updatePortal.test.js",
  "visitorCounter.test.js",
  "webI18n.test.js",
  "webSeo.test.js",
  "wikiPortal.test.js"
]);
const coreTests = fs.readdirSync(testRoot, { withFileTypes: true })
  .filter((entry) => entry.isFile() && entry.name.endsWith(".test.js") && !workspaceOnlyTests.has(entry.name))
  .map((entry) => path.join(testRoot, entry.name))
  .sort();

if (!coreTests.length) throw new Error("No Core test files found.");

const result = spawnSync(process.execPath, ["--test", ...coreTests], { stdio: "inherit" });
if (result.error) throw result.error;
process.exit(result.status ?? 1);
