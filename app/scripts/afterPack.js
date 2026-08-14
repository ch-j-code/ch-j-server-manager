"use strict";

const fs = require("node:fs");
const path = require("node:path");

function assertFile(filePath, pattern, minimumSize = 1) {
  const stat = fs.statSync(filePath, { throwIfNoEntry: false });
  if (!stat?.isFile() || stat.size < minimumSize) throw new Error(`Required license file is missing or incomplete: ${filePath}`);
  if (pattern && !pattern.test(fs.readFileSync(filePath, "utf8"))) throw new Error(`Unexpected license content: ${filePath}`);
}

module.exports = async function afterPack(context) {
  const resources = context.electronPlatformName === "darwin"
    ? path.join(context.appOutDir, `${context.packager.appInfo.productFilename}.app`, "Contents", "Resources")
    : path.join(context.appOutDir, "resources");
  const licenses = path.join(resources, "licenses");
  assertFile(path.join(licenses, "APPLICATION_LICENSE.txt"), /TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION/, 10000);
  assertFile(path.join(licenses, "NOTICE.txt"), /Copyright 2026 Josef Chudy/);
  assertFile(path.join(licenses, "THIRD_PARTY_NOTICES.txt"), /isarray@1\.0\.0/);
  assertFile(path.join(licenses, "THIRD_PARTY_LICENSES.zip"), null, 1000000);
  assertFile(path.join(licenses, "ELECTRON_LICENSE.txt"), /Copyright \(c\) Electron contributors/i);
  assertFile(path.join(licenses, "CHROMIUM_LICENSES.html"), /Chromium/, 1000000);
  assertFile(
    path.join(resources, "signing", "ch-j-signing-public.asc"),
    /-----BEGIN PGP PUBLIC KEY BLOCK-----/,
    1000
  );
};
