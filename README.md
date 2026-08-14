# CH-J Server Manager

CH-J Server Manager is a desktop application for managing Linux servers from macOS, Windows, and Ubuntu. It combines secure SSH sessions, an interactive terminal, server profiles, an encrypted local vault, updates, and a sandboxed plugin system in one Electron application.

## Download

Get the latest alpha build for your platform:

- [macOS for Apple Silicon](https://www.sm.ch-j.de/download.php?channel=alpha&platform=mac&arch=arm64)
- [Windows x64](https://www.sm.ch-j.de/download.php?channel=alpha&platform=win&arch=x64)
- [Ubuntu x64](https://www.sm.ch-j.de/download.php?channel=alpha&platform=ubuntu&arch=x64)

More versions and release channels are available at [sm.ch-j.de](https://www.sm.ch-j.de/de/servermanager/).

## Features

- encrypted local vault for profiles, credentials, and trusted SSH host keys;
- multiple SSH sessions with password and private-key authentication;
- interactive terminal, system metrics, user management, logs, and NGINX tools;
- restricted SFTP file management with editing, transfers, and archive export;
- platform- and integrity-checked application updates;
- sandboxed plugins with explicit, narrowly scoped permissions;
- Czech, English, and German user interface.

## Hash & Checksum

The bundled first-party **Hash & Checksum** plugin calculates and verifies hashes for files on the computer running CH-J Server Manager. It supports single files, batches, recursive directories, digest-based file comparison, and GNU, BSD, and SFV checksum manifests.

All file processing is local: file contents and calculated digests are not sent to a server. Files can be accessed only after an explicit system file-picker selection. The plugin remains sandboxed and does not receive Node.js filesystem access or raw local paths.

Supported families include SHA-2, SHA-3, SHAKE, BLAKE2, BLAKE3, KangarooTwelve, RIPEMD-160, Whirlpool, Tiger, Tiger2, xxHash, MurmurHash3, CityHash, FarmHash, HighwayHash, SipHash-2-4, FNV, CRC, and Adler-32.

MD5 and SHA-1 are provided only for compatibility with old checksums because they are cryptographically broken. xxHash, MurmurHash, CityHash, FarmHash, HighwayHash, SipHash, FNV, CRC, and Adler-32 must not be treated as cryptographic integrity or security proofs.

## Security model

Plugin windows run with Electron sandboxing enabled, context isolation enabled, Node integration disabled, and a restrictive Content Security Policy. Core grants capabilities from each validated plugin manifest and keeps local filesystem access, network access, and remote server access separated.

Always confirm a new SSH host-key fingerprint through a second trusted channel. If a known key changes, the application blocks the connection until both the previous and replacement fingerprints are explicitly reviewed.

## Development

Requirements: a current Node.js release compatible with Electron 43 and npm.

```bash
cd app
npm ci
npm test
npm start
```

Platform packaging commands are:

```bash
npm run dist:mac
npm run dist:win
npm run dist:linux
```

Builds are produced for macOS ARM64, Windows x64, and Debian/Ubuntu x64. Platform signing and installer requirements still apply when creating distributable production artifacts.

## License

CH-J Server Manager is licensed under the [Apache License 2.0](app/LICENSE). Third-party notices and complete bundled dependency license texts are included with the application.
