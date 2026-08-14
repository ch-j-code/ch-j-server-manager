"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");

const PKEXEC_PATH = "/usr/bin/pkexec";
const APT_GET_PATH = "/usr/bin/apt-get";
const DEFAULT_INSTALL_TIMEOUT_MS = 30 * 60 * 1000;
const MAX_OUTPUT_CHARS = 32 * 1024;

class UpdateInstallError extends Error {
  constructor(message, code = "UPDATE_INSTALL_FAILED", options = {}) {
    super(message, options);
    this.name = "UpdateInstallError";
    this.code = code;
  }
}

function assertSafeRegularFile(filePath, label) {
  if (!path.isAbsolute(filePath)) {
    throw new UpdateInstallError(`${label} path must be absolute.`, "UPDATE_INSTALL_UNSAFE_PATH");
  }
  let stat;
  try {
    stat = fs.lstatSync(filePath);
  } catch (error) {
    throw new UpdateInstallError(`${label} is missing.`, "UPDATE_INSTALL_FILE_MISSING", { cause: error });
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size <= 0) {
    throw new UpdateInstallError(`${label} must be a non-empty regular file.`, "UPDATE_INSTALL_UNSAFE_PATH");
  }
  return stat;
}

function assertTrustedSystemExecutable(filePath) {
  const stat = assertSafeRegularFile(filePath, "System installer executable");
  if (typeof stat.uid === "number" && stat.uid !== 0) {
    throw new UpdateInstallError("System installer executable is not owned by root.", "UPDATE_INSTALL_UNSAFE_EXECUTABLE");
  }
  if ((stat.mode & 0o111) === 0) {
    throw new UpdateInstallError("System installer executable is not executable.", "UPDATE_INSTALL_UNSAFE_EXECUTABLE");
  }
  if ((stat.mode & 0o022) !== 0) {
    throw new UpdateInstallError("System installer executable is writable by an untrusted account.", "UPDATE_INSTALL_UNSAFE_EXECUTABLE");
  }
}

function appendBounded(current, chunk) {
  const next = `${current}${String(chunk || "")}`;
  return next.length > MAX_OUTPUT_CHARS ? next.slice(-MAX_OUTPUT_CHARS) : next;
}

class UpdateInstallerLauncher {
  constructor(options = {}) {
    this.platform = options.platform || process.platform;
    this.shell = options.shell;
    this.spawnImpl = options.spawnImpl || spawn;
    this.logger = options.logger;
    this.installTimeoutMs = Number(options.installTimeoutMs || DEFAULT_INSTALL_TIMEOUT_MS);
    this.pkexecPath = options.pkexecPath || PKEXEC_PATH;
    this.aptGetPath = options.aptGetPath || APT_GET_PATH;
    if (!Number.isFinite(this.installTimeoutMs) || this.installTimeoutMs <= 0) {
      throw new Error("The update installation timeout is invalid.");
    }
  }

  async install(filePath) {
    if (this.platform === "linux") return this._installDeb(filePath);
    if (!this.shell?.openPath) throw new UpdateInstallError("System installer integration is unavailable.");
    const error = await this.shell.openPath(filePath);
    if (error) throw new UpdateInstallError(`The installer could not be opened: ${error}`);
    return { launched: true, installed: false, restartApplication: false };
  }

  async _installDeb(filePath) {
    if (!path.isAbsolute(filePath)) {
      throw new UpdateInstallError("Verified Debian update package path must be absolute.", "UPDATE_INSTALL_UNSAFE_PATH");
    }
    const artifactPath = path.resolve(filePath);
    if (path.extname(artifactPath).toLowerCase() !== ".deb") {
      throw new UpdateInstallError("Linux updates must use a Debian package.", "UPDATE_INSTALL_UNSUPPORTED_PACKAGE");
    }
    assertSafeRegularFile(artifactPath, "Verified Debian update package");
    assertTrustedSystemExecutable(this.pkexecPath);
    assertTrustedSystemExecutable(this.aptGetPath);

    // Both executables and all options are fixed by the main process. The only
    // variable argument is the private-cache artifact that was re-hashed and
    // OpenPGP-verified immediately before this method is called.
    const args = [this.aptGetPath, "install", "--reinstall", "--yes", artifactPath];
    this.logger?.info("Starting privileged Debian update installation.", {
      filename: path.basename(artifactPath)
    });

    return new Promise((resolve, reject) => {
      let stdout = "";
      let stderr = "";
      let settled = false;
      let child;
      let timer;
      const finish = (callback) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        callback();
      };

      try {
        child = this.spawnImpl(this.pkexecPath, args, {
          shell: false,
          windowsHide: true,
          stdio: ["ignore", "pipe", "pipe"]
        });
      } catch (error) {
        reject(new UpdateInstallError("The privileged installer could not be started.", "UPDATE_INSTALL_LAUNCH_FAILED", { cause: error }));
        return;
      }

      child.stdout?.on("data", (chunk) => { stdout = appendBounded(stdout, chunk); });
      child.stderr?.on("data", (chunk) => { stderr = appendBounded(stderr, chunk); });
      child.once("error", (error) => finish(() => reject(new UpdateInstallError(
        "The privileged installer could not be started.",
        "UPDATE_INSTALL_LAUNCH_FAILED",
        { cause: error }
      ))));
      child.once("close", (code, signal) => finish(() => {
        if (code === 0) {
          this.logger?.info("Debian update installation completed.", { filename: path.basename(artifactPath) });
          resolve({ launched: true, installed: true, restartApplication: true });
          return;
        }
        const authorizationDenied = code === 126 || code === 127;
        const failure = new UpdateInstallError(
          authorizationDenied
            ? "Administrator authorization for the update was canceled or denied."
            : "The Debian update installation failed.",
          authorizationDenied ? "UPDATE_INSTALL_AUTHORIZATION_DENIED" : "UPDATE_INSTALL_FAILED"
        );
        this.logger?.warn("Debian update installation failed.", {
          code,
          signal: signal || null,
          output: `${stdout}\n${stderr}`.trim().slice(-4096)
        });
        reject(failure);
      }));

      timer = setTimeout(() => {
        try { child.kill("SIGTERM"); } catch {}
        finish(() => reject(new UpdateInstallError(
          "The Debian update installation timed out.",
          "UPDATE_INSTALL_TIMEOUT"
        )));
      }, this.installTimeoutMs);
      timer.unref?.();
    });
  }
}

module.exports = {
  APT_GET_PATH,
  PKEXEC_PATH,
  UpdateInstallError,
  UpdateInstallerLauncher,
  assertSafeRegularFile
};
