"use strict";

const fs = require("node:fs");
const path = require("node:path");

const SENSITIVE_KEYS = /pass(word|phrase)?|private.?key|secret|token|credential/i;

function sanitize(value, depth = 0) {
  if (depth > 5) return "[depth-limit]";
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => sanitize(item, depth + 1));
  if (!value || typeof value !== "object") return value;
  const result = {};
  for (const [key, entry] of Object.entries(value)) {
    result[key] = SENSITIVE_KEYS.test(key) ? "[redacted]" : sanitize(entry, depth + 1);
  }
  return result;
}

class Logger {
  constructor(rootDir) {
    this.logDir = path.join(rootDir, "logs");
    this.logPath = path.join(this.logDir, "core.log");
    fs.mkdirSync(this.logDir, { recursive: true });
  }

  write(level, message, data = {}) {
    const record = {
      timestamp: new Date().toISOString(),
      level,
      message: String(message || ""),
      data: sanitize(data)
    };
    const line = `${JSON.stringify(record)}\n`;
    try { fs.appendFileSync(this.logPath, line, { encoding: "utf8", mode: 0o600 }); } catch {}
    const output = level === "error" ? console.error : level === "warn" ? console.warn : console.log;
    output(`[${level.toUpperCase()}] ${record.message}`, record.data);
  }

  info(message, data) { this.write("info", message, data); }
  warn(message, data) { this.write("warn", message, data); }
  error(message, data) { this.write("error", message, data); }
}

module.exports = { Logger, sanitize };
