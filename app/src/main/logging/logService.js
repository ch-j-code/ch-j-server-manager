"use strict";

const fs = require("node:fs");

const DEFAULT_LIMIT = 256 * 1024;
const MAX_LIMIT = 1024 * 1024;

function normalizeLimit(value) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) return DEFAULT_LIMIT;
  return Math.min(parsed, MAX_LIMIT);
}

class LogService {
  constructor(logPath) {
    this.logPath = String(logPath || "");
    if (!this.logPath) throw new Error("Log path is required.");
  }

  async readTail(payload = {}) {
    const maxBytes = normalizeLimit(payload.maxBytes);
    let handle;
    try {
      const stat = await fs.promises.stat(this.logPath);
      if (!stat.isFile()) throw new Error("Application log is not a file.");
      const length = Math.min(stat.size, maxBytes);
      const offset = Math.max(0, stat.size - length);
      const buffer = Buffer.alloc(length);
      handle = await fs.promises.open(this.logPath, "r");
      const { bytesRead } = await handle.read(buffer, 0, length, offset);
      let text = buffer.subarray(0, bytesRead).toString("utf8");
      if (offset > 0) {
        const firstNewline = text.indexOf("\n");
        text = firstNewline >= 0 ? text.slice(firstNewline + 1) : "";
      }
      return {
        text,
        truncated: offset > 0,
        size: stat.size,
        readAt: new Date().toISOString()
      };
    } catch (error) {
      if (error?.code === "ENOENT") {
        return { text: "", truncated: false, size: 0, readAt: new Date().toISOString() };
      }
      throw error;
    } finally {
      await handle?.close().catch(() => {});
    }
  }
}

module.exports = { DEFAULT_LIMIT, LogService, MAX_LIMIT, normalizeLimit };
