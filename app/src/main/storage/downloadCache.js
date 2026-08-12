"use strict";

const fs = require("node:fs");
const path = require("node:path");

function resolvedCacheRoot(rootDir) {
  const raw = String(rootDir || "").trim();
  if (!raw) throw new Error("Download cache root is required.");
  const resolved = path.resolve(raw);
  if (resolved === path.parse(resolved).root) throw new Error("Refusing to use a filesystem root as a download cache.");
  return resolved;
}

function cleanDownloadCache(rootDir) {
  const root = resolvedCacheRoot(rootDir);
  const existed = fs.existsSync(root);
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  return { cleaned: existed, root };
}

function removeCachedFile(rootDir, filePath) {
  const root = resolvedCacheRoot(rootDir);
  const target = path.resolve(String(filePath || ""));
  const relative = path.relative(root, target);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("Downloaded package path is outside its cache.");
  }
  if (!fs.existsSync(target)) return { removed: false, path: target };
  if (!fs.lstatSync(target).isFile()) throw new Error("Downloaded package is not a regular file.");
  const realRoot = fs.realpathSync(root);
  const realTarget = fs.realpathSync(target);
  const realRelative = path.relative(realRoot, realTarget);
  if (!realRelative || realRelative.startsWith("..") || path.isAbsolute(realRelative)) {
    throw new Error("Downloaded package resolves outside its cache.");
  }
  fs.unlinkSync(target);

  let current = path.dirname(target);
  while (current !== root) {
    try { fs.rmdirSync(current); }
    catch (error) {
      if (error?.code === "ENOTEMPTY" || error?.code === "EEXIST" || error?.code === "ENOENT") break;
      throw error;
    }
    current = path.dirname(current);
  }
  return { removed: true, path: target };
}

module.exports = { cleanDownloadCache, removeCachedFile, resolvedCacheRoot };
