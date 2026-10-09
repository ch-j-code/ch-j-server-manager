# CH-J Server Manager

CH-J Server Manager is a desktop SSH and SFTP client for Linux server administration and a local file hash calculator and checksum verification tool for Windows, macOS, and Linux. It combines server profiles, an interactive terminal, file management, monitoring, log inspection, user administration, NGINX management, and 49 hashing algorithms in one Electron application.

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

## Latest alpha changes

This release adds the integrated Server Diagnostics workspace (CS/DE/EN), reliable Monaco remote-file saves with recovery and conflict detection, and separate SSH RTT and ICMP measurements. Hash & Checksum, plugin windows and existing server profiles remain supported. See [remote editor and latency details](app/docs/remote-editor-latency.md) and [diagnostics capabilities and limits](app/docs/server-diagnostics.md).

All platform packages use build ID `core-20261009T160026Z-b5497107`. Detached `.asc` signatures are produced with the CH-J signing subkey on a YubiKey; [SHA512SUMS](https://www.sm.ch-j.de/files/apps/builds/core-20261009T160026Z-b5497107/SHA512SUMS) and its [OpenPGP signature](https://www.sm.ch-j.de/files/apps/builds/core-20261009T160026Z-b5497107/SHA512SUMS.asc) cover all four artifacts.

## Features

- encrypted local vault using scrypt and AES-256-GCM;
- server profiles with password and private-key SSH authentication;
- mandatory SHA-256 SSH host-key verification and explicit handling of changed host keys;
- multiple SSH sessions and an interactive terminal;
- file browsing, editing, upload, download, deletion, and ZIP/TAR/TAR.GZ export through a restricted SFTP interface;
- Czech, German, and English user interfaces;
- installable first-party plugins for System Monitor, Key Generator, Log Viewer, Users, File Manager, and NGINX Manager;
- integrated Server Diagnostics: ICMP, traceroute, DNS, HTTP/1.1/2/3 capability tests, server timings, compression, TLS, TCP ports, local history and JSON/CSV/TXT exports;
- a bundled local Hash & Checksum tool in the sidebar for calculation, verification, comparison, and checksum manifests;
- sandboxed plugin windows with capability-based access to Core services;
- dark title bars on Windows and Linux, plugin windows kept above the main window, and a bottom bar for collapsed plugins;
- alpha, beta, and stable update channels;
- application updates protected by size checks, SHA-512, and mandatory detached OpenPGP signatures.

## Server Diagnostics

Open **Server Diagnostics** between **Plugins** and **Hash & Checksum**. Enter a hostname, IPv4, IPv6 or HTTP(S)/WS(S) URL, choose Auto / IPv4 / IPv6 / Both, and run the overview or an individual tool. No SSH connection or external plugin is required. Results update while probes run, and individual tools or the entire run can be stopped.

The module includes per-packet ICMP graphs/statistics, progressive traceroute, twelve DNS record types with TTL and consistency observations, independently negotiated HTTP versions, request phase timings and warm/cold connections, verified gzip/deflate/Brotli (and runtime-supported zstd), TLS 1.2/1.3 certificate inspection, bounded TCP port tests, an SSH host-key handshake without authentication, security-header/redirect checks and an optional WebSocket handshake. It supports Czech, German and English and local light/dark/system themes.

HTTP/3 requires a separately available curl build with HTTP3/QUIC and `--http3-only` (7.88+). Success requires an actual HTTP/3 result over UDP/443; otherwise the UI reports unavailable, unsupported or error with a reason. `Alt-Svc` and HTTP/2 fallback never establish HTTP/3 support. DNSSEC is explicitly **not validated**; DS/DNSKEY records are observations. ICMP failures do not label a server offline.

History stays in the application's local data directory. JSON/CSV/TXT reports omit bodies, cookies, authentication metadata and URL queries. Import JSON, reopen or compare saved runs from History. No new npm dependencies are required; OS ping/traceroute tools and optional HTTP3-enabled curl provide the platform-specific capabilities.

See [implementation, IPC, limits and verification](app/docs/server-diagnostics.md). Run `npm test` for deterministic network tests and `npm run test:diagnostics:ui` for the Electron UI smoke test (requires a graphical desktop).

## Hash & Checksum

Calculate file hashes, verify checksums, and compare local files with 49 algorithms, including SHA-256, SHA-512, SHA-3, BLAKE3, and xxHash. The built-in hashing tool supports HEX and Base64 output and GNU, BSD, and SFV checksum manifests.

Open **Hash & Checksum** from the left sidebar, directly below **Server Diagnostics**, after unlocking the vault. The tool is bundled with the application, opens in its own window, and does not appear in the installed-plugin list.

The interface follows the application's saved language setting: **Czech, German, or English**. Saving a language change updates an already open Hash window, including controls, progress, result statuses, errors, and native file-dialog labels, while preserving selected files, algorithms, parameters, and results.

Available functions:

- **Calculate:** hash a single file, multiple files, or a directory, optionally including subdirectories. Use the recommended selection (SHA-256, SHA-512, and BLAKE3), select individual algorithms, or select all 49 at once. Directory symlinks are skipped.
- **Output and parameters:** display digests as lowercase HEX, uppercase HEX, or Base64. Configure output length for SHAKE and KangarooTwelve, seeds for xxHash and MurmurHash3, and hexadecimal keys for SipHash and HighwayHash. An empty key field uses an all-zero key.
- **Verify:** compare a file with an expected HEX or Base64 digest using a selected fixed-length algorithm. HEX comparison ignores letter case and surrounding whitespace. Suggested algorithms based on HEX length are hints, not definitive identification.
- **Compare Files:** compare the calculated digests of two files using one or more fixed-length algorithms.
- **Manifests:** generate and verify GNU, BSD, and SFV checksum lists with relative paths. Generation requires a fixed-length algorithm without a key or seed; SFV requires CRC32. Verification supports automatic algorithm detection or a manual override when the digest length is ambiguous.
- **Progress and results:** view processed bytes, percentage, throughput, elapsed time, estimated remaining time, and per-file statuses; cancel a running job; copy an individual digest or all results; export results to a text file.

### Supported algorithms

The complete list of **49 supported algorithms** is shown below. Algorithm IDs match the result table and exported results.

| Algorithm | ID | Output size (bits) |
| --- | --- | --- |
| SHA-224 | `sha224` | 224 |
| SHA-256 | `sha256` | 256 |
| SHA-384 | `sha384` | 384 |
| SHA-512 | `sha512` | 512 |
| SHA-512/224 | `sha512-224` | 224 |
| SHA-512/256 | `sha512-256` | 256 |
| SHA3-224 | `sha3-224` | 224 |
| SHA3-256 | `sha3-256` | 256 |
| SHA3-384 | `sha3-384` | 384 |
| SHA3-512 | `sha3-512` | 512 |
| SHAKE128 | `shake128` | Variable (default 256) |
| SHAKE256 | `shake256` | Variable (default 512) |
| BLAKE2b-512 | `blake2b-512` | 512 |
| BLAKE2s-256 | `blake2s-256` | 256 |
| BLAKE3 | `blake3` | 256 |
| KangarooTwelve | `kangaroo-twelve` | Variable (default 256) |
| RIPEMD-160 | `ripemd160` | 160 |
| Whirlpool | `whirlpool` | 512 |
| Tiger | `tiger` | 192 |
| Tiger2 | `tiger2` | 192 |
| MD5 | `md5` | 128 |
| SHA-1 | `sha1` | 160 |
| XXH32 | `xxh32` | 32 |
| XXH64 | `xxh64` | 64 |
| XXH3-64 | `xxh3-64` | 64 |
| XXH3-128 | `xxh3-128` | 128 |
| MurmurHash3 x86 32 | `murmur3-x86-32` | 32 |
| MurmurHash3 x86 128 | `murmur3-x86-128` | 128 |
| MurmurHash3 x64 128 | `murmur3-x64-128` | 128 |
| CityHash32 | `cityhash32` | 32 |
| CityHash64 | `cityhash64` | 64 |
| CityHash128 | `cityhash128` | 128 |
| FarmHash32 | `farmhash32` | 32 |
| FarmHash64 | `farmhash64` | 64 |
| FarmHash128 | `farmhash128` | 128 |
| HighwayHash64 | `highwayhash64` | 64 |
| HighwayHash128 | `highwayhash128` | 128 |
| HighwayHash256 | `highwayhash256` | 256 |
| SipHash-2-4 | `siphash-2-4` | 64 |
| FNV-1 32 | `fnv1-32` | 32 |
| FNV-1 64 | `fnv1-64` | 64 |
| FNV-1a 32 | `fnv1a-32` | 32 |
| FNV-1a 64 | `fnv1a-64` | 64 |
| CRC-16/CCITT-FALSE | `crc16-ccitt-false` | 16 |
| CRC-32/ISO-HDLC | `crc32` | 32 |
| CRC-32C/Castagnoli | `crc32c` | 32 |
| CRC-64/ECMA-182 | `crc64-ecma` | 64 |
| CRC-64/XZ | `crc64-xz` | 64 |
| Adler-32 | `adler32` | 32 |

SHAKE128, SHAKE256, and KangarooTwelve allow an output length of **16–1024 bytes**. Their defaults are 32, 64, and 32 bytes respectively. BLAKE3 currently produces a fixed 256-bit digest.

MD5 and SHA-1 are included only for legacy compatibility. xxHash, MurmurHash3, CityHash, FarmHash, HighwayHash, SipHash, FNV, CRC, and Adler-32 are not offered as cryptographic integrity proofs.

All processing is local. File contents and calculated digests are not sent to a server. Core opens the native file picker and gives the sandboxed plugin only opaque, plugin-owned selection tokens; the renderer receives neither unrestricted filesystem access nor raw local paths. Hashing runs in worker threads and streams files instead of loading them entirely into memory.

The plugin supports 49 algorithms across SHA-2, SHA-3, SHAKE, BLAKE2, BLAKE3, KangarooTwelve, RIPEMD-160, Whirlpool, Tiger, Tiger2, xxHash, MurmurHash3, CityHash, FarmHash, HighwayHash, SipHash-2-4, FNV, CRC, and Adler-32 families. MD5 and SHA-1 are available only for legacy compatibility. Fast hashes and checksums are not cryptographic integrity proofs.

## Security

Update verification is performed in the Electron main process and fails closed. The application downloads the selected artifact and its detached `.asc` signature, checks the expected size and SHA-512 hash, and verifies the signature with the bundled CH-J public key. Immediately before installation, it re-checks the same private-cache files to reduce time-of-check/time-of-use risk. The renderer cannot supply an artifact path, public key, fingerprint, or a forged verification result.

The long-term update trust anchor is the primary OpenPGP fingerprint:

```text
0D92 778A D8EC F85C 80E3  9248 48F2 433A D9CD F453
```

To verify a download manually, obtain the bundled [public key](app/ch-j-signing-public.asc), check that its primary fingerprint matches the value above, and import it with `gpg --import ch-j-signing-public.asc`. Verify the downloaded manifest with `gpg --verify SHA512SUMS.asc SHA512SUMS`, then check the files with `shasum -a 512 -c SHA512SUMS` (macOS) or `sha512sum -c SHA512SUMS` (Linux). Windows PowerShell provides `Get-FileHash -Algorithm SHA512 <file>`. Each installer also has a detached `.asc` signature that can be checked with `gpg --verify <file>.asc <file>`.

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

- Node.js 24 LTS (24.18 or newer);
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

## Topics

[#ssh](https://github.com/topics/ssh) · [#sftp](https://github.com/topics/sftp) · [#server-management](https://github.com/topics/server-management) · [#hash-calculator](https://github.com/topics/hash-calculator) · [#checksum](https://github.com/topics/checksum) · [#file-integrity](https://github.com/topics/file-integrity) · [#sha256](https://github.com/topics/sha256) · [#sha512](https://github.com/topics/sha512) · [#sha3](https://github.com/topics/sha3) · [#blake3](https://github.com/topics/blake3) · [#xxhash](https://github.com/topics/xxhash) · [#electron](https://github.com/topics/electron) · [#linux](https://github.com/topics/linux) · [#macos](https://github.com/topics/macos) · [#windows](https://github.com/topics/windows)

## License

CH-J Server Manager is licensed under the Apache License 2.0. Third-party notices and license texts are included in the repository and packaged distributions.
