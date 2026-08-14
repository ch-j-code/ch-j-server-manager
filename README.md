# CH-J Server Manager

CH-J Server Manager is a desktop application for securely administering Linux servers over SSH. It combines server profiles, an interactive terminal, file management, monitoring, log inspection, user administration, and NGINX management in one Electron application.

The project is currently in **alpha**. It is suitable for testing, but some planned features and production distribution requirements are not complete yet. The internal name "Core" refers to the current application architecture; the product name remains CH-J Server Manager.

## Download

Download the latest alpha build for your platform:

| Platform | Architecture | Package |
| --- | --- | --- |
| macOS | Apple Silicon (`arm64`) | [Download for macOS](https://www.sm.ch-j.de/download.php?channel=alpha&platform=mac&arch=arm64) |
| Windows | `x64` | [Download for Windows](https://www.sm.ch-j.de/download.php?channel=alpha&platform=win&arch=x64) |
| Ubuntu/Debian | `x64` | [Download for Ubuntu](https://www.sm.ch-j.de/download.php?channel=alpha&platform=ubuntu&arch=x64) |

Additional builds and release channels are available on the [CH-J Server Manager website](https://www.sm.ch-j.de/de/servermanager/).

Alpha distribution notes:

- macOS builds currently target Apple Silicon only. Test builds may be ad hoc signed and can require manual approval in **Privacy & Security** until Developer ID signing and notarization are enabled.
- Windows builds use an NSIS installer.
- Ubuntu/Debian builds use a `.deb` package. For an initial installation, use `sudo apt install ./<downloaded-file>.deb` if the graphical software center rejects the package as coming from an unknown publisher.
- Back up important connection details before testing an alpha update.

## Features

- encrypted local vault using scrypt and AES-256-GCM;
- server profiles with password and private-key SSH authentication;
- mandatory SHA-256 SSH host-key verification and explicit handling of changed host keys;
- multiple SSH sessions and an interactive terminal;
- file browsing, editing, upload, download, deletion, and ZIP/TAR/TAR.GZ export through a restricted SFTP interface;
- Czech, German, and English user interfaces;
- installable first-party plugins for System Monitor, Key Generator, Log Viewer, Users, File Manager, and NGINX Manager;
- a bundled local Hash & Checksum plugin for calculation, verification, comparison, and checksum manifests;
- sandboxed plugin windows with capability-based access to Core services;
- alpha, beta, and stable update channels;
- application updates protected by size checks, SHA-512, and mandatory detached OpenPGP signatures.

## Hash & Checksum

The bundled first-party **Hash & Checksum** plugin calculates and verifies hashes for individual files, batches, and recursive directories. It also compares files by digest and reads or creates GNU, BSD, and SFV checksum manifests.

All processing is local. File contents and calculated digests are not sent to a server. Core opens the native file picker and gives the sandboxed plugin only opaque, plugin-owned selection tokens; the renderer receives neither unrestricted filesystem access nor raw local paths. Hashing runs in worker threads and streams files instead of loading them entirely into memory.

The plugin supports 49 algorithms across SHA-2, SHA-3, SHAKE, BLAKE2, BLAKE3, KangarooTwelve, RIPEMD-160, Whirlpool, Tiger, Tiger2, xxHash, MurmurHash3, CityHash, FarmHash, HighwayHash, SipHash-2-4, FNV, CRC, and Adler-32 families. MD5 and SHA-1 are available only for legacy compatibility. Fast hashes and checksums are not cryptographic integrity proofs.

## Security

Update verification is performed in the Electron main process and fails closed. The application downloads the selected artifact and its detached `.asc` signature, checks the expected size and SHA-512 hash, and verifies the signature with the bundled CH-J public key. Immediately before installation, it re-checks the same private-cache files to reduce time-of-check/time-of-use risk. The renderer cannot supply an artifact path, public key, fingerprint, or a forged verification result.

The long-term update trust anchor is the primary OpenPGP fingerprint:

```text
0D92 778A D8EC F85C 80E3  9248 48F2 433A D9CD F453
```

Valid signing subkeys may be rotated as long as they remain cryptographically bound to this primary key and are valid for signing. Revoked, expired, unknown, malformed, or otherwise invalid keys and signatures block installation.

The alpha service is still undergoing distribution hardening. In particular, standard CA verification for the explicitly allowlisted update host is temporarily relaxed in test mode, and macOS production signing/notarization is not yet enabled. OpenPGP verification remains mandatory for application update artifacts, but alpha builds should not be treated as production releases.

When connecting to a server for the first time, verify the displayed SSH host-key fingerprint through another trusted channel. If a known host key changes, verify both the old and new fingerprints before accepting the replacement.

## Getting started

On first launch, choose the interface language and create a vault master password. Then add a profile under **Servers** and connect from **Terminal**.

The vault password cannot be recovered. **Forgot password / reset vault** deletes encrypted server profiles, saved SSH passwords, trusted host fingerprints, and other encrypted data. Update settings and installed plugins are preserved.

Private-key passphrases are intentionally not stored and must be entered for each connection. An SSH account password can optionally be stored in the encrypted vault.

## Current limitations

The following features are planned but not yet available:

- migration of data from older application versions;
- resumable SFTP transfer queues and sudo-assisted saves;
- remote archive extraction;
- SSH jump hosts and port forwarding;
- Safe Mode and additional tools.

This list is not exhaustive. Behavior and data formats may still change during the alpha phase.

## Repository boundary

The complete desktop application source tree lives in `app/`. Dependency installation, tests, development startup, and supported platform builds run from that directory without requiring source files or tooling from sibling projects.

An update service, independently distributed plugin packages, and release tooling may integrate with the application through public APIs, package formats, or build artifacts, but they are not application runtime, test, or build dependencies. Bundled first-party plugins under `app/src/main/firstPartyPlugins/` and the internal Core plugin framework under `app/src/main/plugins/` are part of the application itself.

## Development

Requirements:

- Node.js 18 or newer;
- npm;
- the native toolchain required by Electron dependencies on the host platform.

Use a separate `node_modules` installation on each operating system:

```bash
git clone https://github.com/ch-j-code/ch-j-server-manager.git
cd ch-j-server-manager/app
npm ci
npm test
npm start
```

The repository uses one shared `package.json` and one shared `package-lock.json` for all supported platforms. Build on the target operating system with:

```bash
npm run build:mac
npm run build:win
npm run build:linux
```

The configured outputs are a macOS DMG (`arm64`), a Windows NSIS installer (`x64`), and a Debian package (`x64`). The macOS build also creates an application ZIP for initial website distribution. Generated packages are written to `app/dist/` and are not committed.

## License

CH-J Server Manager is licensed under the Apache License 2.0. Third-party notices and license texts are included in the repository and packaged distributions.
