"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { LogService, MAX_LIMIT, normalizeLimit } = require("../src/main/logging/logService");

test("log service returns a bounded tail without a partial first record", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-log-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const logPath = path.join(root, "core.log");
  fs.writeFileSync(logPath, "first-record\nsecond-record\nthird-record\n");
  const result = await new LogService(logPath).readTail({ maxBytes: 29 });
  assert.equal(result.text, "second-record\nthird-record\n");
  assert.equal(result.truncated, true);
  assert.equal(result.size, 40);
  assert.match(result.readAt, /^\d{4}-\d{2}-\d{2}T/);
});

test("log service handles a missing log and caps read limits", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chj-log-missing-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  assert.equal(normalizeLimit(Number.MAX_SAFE_INTEGER), MAX_LIMIT);
  assert.equal((await new LogService(path.join(root, "missing.log")).readTail()).text, "");
});
