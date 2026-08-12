"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const AdmZip = require("adm-zip");

const projectRoot = path.resolve(__dirname, "..");
const lock = JSON.parse(fs.readFileSync(path.join(projectRoot, "package-lock.json"), "utf8"));
const outputPath = path.join(projectRoot, "THIRD_PARTY_NOTICES.txt");
const packages = new Map();

function declaredLicense(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(declaredLicense).filter(Boolean).join(" OR ");
  if (value && typeof value === "object") return String(value.type || value.name || "See included text");
  return "See included text";
}

function readLicense(directory) {
  const entries = fs.readdirSync(directory, { withFileTypes: true });
  const candidates = entries
    .filter((entry) => entry.isFile() && /^(licen[cs]e|copying|notice)(\..*)?$/i.test(entry.name))
    .sort((left, right) => left.name.localeCompare(right.name));
  if (candidates.length) {
    return candidates.map((entry) => ({ source: entry.name, text: fs.readFileSync(path.join(directory, entry.name), "utf8").trim() }));
  }
  const readme = entries.find((entry) => entry.isFile() && /^readme(?:\..*)?$/i.test(entry.name));
  if (readme) {
    const text = fs.readFileSync(path.join(directory, readme.name), "utf8");
    const match = text.match(/^#{1,3}\s+licen[cs]e\s*$[\s\S]*/im);
    if (match) return [{ source: `${readme.name} (License section)`, text: match[0].trim() }];
  }
  return [];
}

for (const [relative, metadata] of Object.entries(lock.packages || {})) {
  if (!relative.startsWith("node_modules/") || metadata.dev === true) continue;
  const directory = path.join(projectRoot, relative);
  const packagePath = path.join(directory, "package.json");
  if (!fs.statSync(packagePath, { throwIfNoEntry: false })?.isFile()) continue;
  const manifest = JSON.parse(fs.readFileSync(packagePath, "utf8"));
  const key = `${manifest.name}@${manifest.version}`;
  if (packages.has(key)) continue;
  const texts = readLicense(directory);
  if (!texts.length) throw new Error(`No distributable license text found for ${key}.`);
  packages.set(key, { key, license: declaredLicense(manifest.license || metadata.license), texts });
}

const separator = "=".repeat(78);
const sections = [...packages.values()]
  .sort((left, right) => left.key.localeCompare(right.key))
  .map((entry) => {
    const body = entry.texts.map((item) => `Source: ${item.source}\n\n${item.text}`).join("\n\n");
    return `${separator}\n${entry.key}\nDeclared license: ${entry.license}\n${separator}\n\n${body}`;
  });
const header = [
  "CH-J Server Manager — Third-Party Notices",
  "",
  "This file lists license texts for production Node.js dependencies bundled",
  "with the application. Electron and Chromium license files are distributed",
  "separately in the application's resources/licenses directory.",
  ""
].join("\n");
fs.writeFileSync(outputPath, `${header}\n${sections.join("\n\n")}\n`, "utf8");

const bundleDocuments = [
  { name: "THIRD_PARTY_NOTICES.txt", path: outputPath, description: "Production Node.js dependency licenses" },
  { name: "ELECTRON_LICENSE.txt", path: path.join(projectRoot, "node_modules", "electron", "dist", "LICENSE"), description: "Electron license" },
  { name: "CHROMIUM_LICENSES.html", path: path.join(projectRoot, "node_modules", "electron", "dist", "LICENSES.chromium.html"), description: "Chromium and embedded component licenses" }
];
for (const document of bundleDocuments) {
  if (!fs.statSync(document.path, { throwIfNoEntry: false })?.isFile()) throw new Error(`Missing third-party license document: ${document.path}`);
  document.data = fs.readFileSync(document.path);
  document.sha512 = crypto.createHash("sha512").update(document.data).digest("hex");
}
const bundleReadme = [
  "CH-J Server Manager — Complete Third-Party License Package",
  "",
  "This archive contains the license texts and notices for third-party software",
  "distributed by CH-J Server Manager Core.",
  "The project itself is licensed separately under Apache License 2.0.",
  "",
  "Contents:",
  ...bundleDocuments.map((document) => `- ${document.name}: ${document.description}`),
  ""
].join("\n");
const checksums = bundleDocuments.map((document) => `${document.sha512}  ${document.name}`).join("\n") + "\n";
const zip = new AdmZip();
for (const document of [
  { name: "README.txt", data: Buffer.from(bundleReadme, "utf8") },
  { name: "SHA512SUMS.txt", data: Buffer.from(checksums, "utf8") },
  ...bundleDocuments
]) {
  zip.addFile(document.name, document.data, "", 0o644);
  const entry = zip.getEntry(document.name);
  if (entry) entry.header.time = new Date("2000-01-01T00:00:00Z");
}
const bundlePath = path.join(projectRoot, "THIRD_PARTY_LICENSES.zip");
zip.writeZip(bundlePath);
console.log(`Generated ${path.basename(outputPath)} for ${sections.length} package versions and ${path.basename(bundlePath)} with ${bundleDocuments.length} complete license documents.`);
