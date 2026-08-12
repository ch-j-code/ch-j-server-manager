"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

test("system monitor declares and renders CPU, swap and network metrics", () => {
  const root = path.join(__dirname, "..", "..", "plugins", "system-monitor");
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
  const html = fs.readFileSync(path.join(root, "ui", "index.html"), "utf8");
  const script = fs.readFileSync(path.join(root, "ui", "index.js"), "utf8");
  assert.deepEqual(manifest.permissions, ["session.read", "system.metrics.read"]);
  for (const id of ["cpu", "cpuBar", "cpuModel", "cpuTopology", "cpuTypes", "swap", "swapBar", "swapDetail", "networkSummary", "networkInterfaces"]) {
    assert.match(html, new RegExp(`id="${id}"`));
  }
  assert.match(script, /cpu\?\.usagePercent/);
  assert.match(script, /cpu\?\.logicalCores/);
  assert.match(script, /metrics\.swap\?\.total/);
  assert.match(script, /metrics\.swap\?\.used/);
  assert.match(script, /network\?\.interfaces/);
  assert.match(script, /rxBytes/);
  assert.match(script, /txBytes/);
});
