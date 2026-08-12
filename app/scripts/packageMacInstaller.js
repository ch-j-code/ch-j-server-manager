"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawn, spawnSync } = require("node:child_process");
const { signAsync } = require("@electron/osx-sign");

const projectRoot = path.resolve(__dirname, "..");
const packageJson = require(path.join(projectRoot, "package.json"));
const productName = packageJson.build?.productName || packageJson.productName;
const appPath = path.join(projectRoot, "dist", "mac-arm64", `${productName}.app`);
const outputPath = path.join(projectRoot, "dist", `${productName}-${packageJson.version}-arm64.app.zip`);

function run(command, args, options = {}) {
  return execFileSync(command, args, { encoding: "utf8", stdio: options.capture ? "pipe" : "inherit" });
}

function signatureIsValid(bundlePath) {
  try {
    run("codesign", ["--verify", "--deep", "--strict", "--verbose=2", bundlePath], { capture: true });
    return true;
  } catch (_) {
    return false;
  }
}

function signatureDescription(bundlePath) {
  const result = spawnSync("codesign", ["-dv", "--verbose=4", bundlePath], { encoding: "utf8" });
  return `${result.stdout || ""}\n${result.stderr || ""}`;
}

async function ensureValidSignature() {
  if (signatureIsValid(appPath)) {
    const description = signatureDescription(appPath);
    if (description.includes("Authority=Developer ID Application")) return "developer-id";
    if (description.includes("Signature=adhoc") && !description.includes("runtime)")) return "adhoc";
  }

  const identities = run("security", ["find-identity", "-v", "-p", "codesigning"], { capture: true });
  const hasDeveloperId = identities.includes("Developer ID Application:");
  const options = {
    app: appPath,
    platform: "darwin",
    preAutoEntitlements: false,
    preEmbedProvisioningProfile: false,
  };
  if (!hasDeveloperId) {
    options.identity = "-";
    options.identityValidation = false;
    options.optionsForFile = () => ({
      hardenedRuntime: false,
      signatureFlags: [],
      timestamp: "none",
    });
  }
  await signAsync(options);
  if (!signatureIsValid(appPath)) throw new Error("Kontrola codesign po podepsání .app selhala.");
  return hasDeveloperId ? "developer-id" : "adhoc";
}

async function smokeTestApp(bundlePath) {
  const executable = path.join(bundlePath, "Contents", "MacOS", productName);
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "chj-mac-smoke-data-"));
  try {
    await new Promise((resolve, reject) => {
      let output = "";
      const smokeEnvironment = {
        ...process.env,
        CHJ_BUILD_SMOKE_USER_DATA_DIR: userDataDir,
        ELECTRON_ENABLE_LOGGING: "1",
      };
      delete smokeEnvironment.ELECTRON_RUN_AS_NODE;
      delete smokeEnvironment.NODE_OPTIONS;
      const child = spawn(executable, [], {
        env: smokeEnvironment,
        stdio: ["ignore", "pipe", "pipe"],
      });
      child.stdout.on("data", (chunk) => { output += chunk; });
      child.stderr.on("data", (chunk) => { output += chunk; });
      const timeout = setTimeout(() => {
        child.kill("SIGTERM");
        reject(new Error(`Aplikace nedokončila smoke test do 12 sekund.\n${output.trim()}`));
      }, 12000);
      child.once("error", (error) => {
        clearTimeout(timeout);
        reject(error);
      });
      child.once("exit", (code, signal) => {
        clearTimeout(timeout);
        if (code === 0 && output.includes("CHJ_BUILD_SMOKE_READY")) resolve();
        else reject(new Error(`Aplikace nedokončila smoke test (code=${code}, signal=${signal}).\n${output.trim()}`));
      });
    });
  } finally {
    fs.rmSync(userDataDir, { recursive: true, force: true });
  }
}

async function main() {
  if (process.platform !== "darwin") throw new Error("macOS instalační ZIP lze vytvářet pouze na macOS.");
  if (!productName || !fs.statSync(appPath, { throwIfNoEntry: false })?.isDirectory()) {
    throw new Error(`Chybí sestavená aplikace ${appPath}. Nejdřív spusťte macOS build.`);
  }

  const signature = await ensureValidSignature();
  fs.rmSync(outputPath, { force: true });
  run("ditto", ["-c", "-k", "--sequesterRsrc", "--keepParent", appPath, outputPath]);

  const verifyRoot = fs.mkdtempSync(path.join(os.tmpdir(), "chj-mac-installer-"));
  try {
    run("ditto", ["-x", "-k", outputPath, verifyRoot]);
    const extractedApp = path.join(verifyRoot, `${productName}.app`);
    if (!fs.statSync(extractedApp, { throwIfNoEntry: false })?.isDirectory() || !signatureIsValid(extractedApp)) {
      throw new Error("Výsledný ZIP neobsahuje kompletní aplikaci s platným podpisem bundle.");
    }
    await smokeTestApp(extractedApp);
  } finally {
    fs.rmSync(verifyRoot, { recursive: true, force: true });
  }

  console.log(`Instalační balíček: ${outputPath}`);
  console.log(`Podpis: ${signature}`);
  if (signature !== "developer-id") {
    console.warn("VAROVÁNÍ: Jde o testovací ad-hoc sestavení. Pro bezobslužnou instalaci z webu je nutný Developer ID podpis a Apple notarizace.");
  }
}

main().catch((error) => {
  console.error(error.message || error);
  process.exitCode = 1;
});
