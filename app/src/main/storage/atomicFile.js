"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

function atomicWriteFile(filePath, content, options = {}) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tempPath = `${filePath}.tmp-${crypto.randomBytes(6).toString("hex")}`;
  const backupPath = `${filePath}.replace-backup`;
  fs.writeFileSync(tempPath, content, { mode: options.mode || 0o600, encoding: options.encoding });
  try {
    if (process.platform === "win32" && fs.existsSync(filePath)) {
      try { fs.unlinkSync(backupPath); } catch {}
      fs.renameSync(filePath, backupPath);
      try {
        fs.renameSync(tempPath, filePath);
        fs.unlinkSync(backupPath);
      } catch (error) {
        try { fs.renameSync(backupPath, filePath); } catch {}
        throw error;
      }
    } else {
      fs.renameSync(tempPath, filePath);
    }
  } catch (error) {
    try { fs.unlinkSync(tempPath); } catch {}
    throw error;
  }
}

function atomicWriteJson(filePath, value) {
  atomicWriteFile(filePath, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

module.exports = { atomicWriteFile, atomicWriteJson };
