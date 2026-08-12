"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const builtAt = new Date().toISOString();
const compactTime = builtAt.replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
const generatedId = `core-${compactTime}-${crypto.randomBytes(6).toString("hex")}`;
const buildId = String(process.env.CHJ_BUILD_ID || generatedId).trim();
if (!/^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/.test(buildId)) {
  throw new Error("CHJ_BUILD_ID must contain 8-128 safe identifier characters.");
}

const target = path.join(__dirname, "..", "src", "shared", "buildInfo.json");
fs.writeFileSync(target, `${JSON.stringify({ buildId, builtAt }, null, 2)}\n`, { mode: 0o600 });
process.stdout.write(`Stamped build ${buildId} (${builtAt})\n`);
