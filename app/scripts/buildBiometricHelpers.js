"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const appRoot = path.resolve(__dirname, ".."), out = path.join(appRoot, "build", "biometrics"), source = path.join(appRoot, "src/main/security/biometrics/native");
fs.mkdirSync(out, { recursive: true });
if (process.platform === "darwin") {
  const compiler = fs.existsSync("/Library/Developer/CommandLineTools/usr/bin/swiftc") ? "/Library/Developer/CommandLineTools/usr/bin/swiftc" : "/usr/bin/swiftc";
  const sdk = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk";
  const target = `${process.arch === "arm64" ? "arm64" : "x86_64"}-apple-macos12.0`;
  execFileSync(compiler, [...(fs.existsSync(sdk) ? ["-sdk", sdk] : []), "-target", target, "-O", "-framework", "Security", "-framework", "LocalAuthentication", path.join(source, "mac.swift"), "-o", path.join(out, "chj-biometric")], { stdio: "inherit" });
} else if (process.platform === "win32") {
  const vswhere = path.join(process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)", "Microsoft Visual Studio", "Installer", "vswhere.exe");
  const installation = execFileSync(vswhere, ["-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], { encoding: "utf8" }).trim();
  if (!installation) throw new Error("Biometric helper requires Visual Studio C++ Build Tools and Windows SDK with C++/WinRT.");
  const batch = path.join(out, "compile.cmd");
  fs.writeFileSync(batch, `@echo off\r\ncall "${installation}\\VC\\Auxiliary\\Build\\vcvars64.bat" >nul\r\nif errorlevel 1 exit /b 1\r\ncd /d "${out}"\r\ncl.exe /nologo /std:c++17 /EHsc /O2 /DUNICODE /D_UNICODE "${path.join(source, "windows.cpp")}" /Fe:"${path.join(out, "chj-biometric.exe")}" /link windowsapp.lib crypt32.lib advapi32.lib user32.lib\r\nexit /b %errorlevel%\r\n`);
  try { execFileSync(process.env.ComSpec || "cmd.exe", ["/d", "/c", batch], { stdio: "inherit" }); } finally { fs.unlinkSync(batch); }
  for (const name of ["windows.obj", "chj-biometric.pdb"]) { try { fs.unlinkSync(path.join(out, name)); } catch {} }
} else if (process.platform === "linux") {
  fs.copyFileSync(path.join(source, "linux.py"), path.join(out, "linux.py"));
} else throw new Error("Biometric helpers are not supported on this platform.");
console.log(`Biometric helper prepared for ${process.platform}/${process.arch}.`);
