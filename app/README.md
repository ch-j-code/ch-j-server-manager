# CH-J Server Manager Core

A new implementation of CH-J Server Manager. The user-facing application name remains unchanged; “Core” refers only to the new architecture.

## Current implementation scope

- secure Electron bootstrap;
- a single restricted preload bridge;
- atomic non-sensitive configuration;
- plugin manifests and an installed-plugin registry;
- `HashUrlProvider` for the PHP channels `alpha`, `beta`, and `stable`, including the combined `all` view;
- platform, architecture, version, size, and SHA-512 validation;
- downloads to internal staging without automatic execution;
- encrypted vault (scrypt + AES-256-GCM) with manual locking;
- server profile creation and editing;
- an optional SSH password stored separately in the encrypted vault and used automatically when the login field is empty;
- multi-session SSH `SessionManager` with password/private-key authentication;
- preliminary DNS resolution of SSH hostnames, a precise error for missing records, and IPv4 preference when both A and AAAA records exist;
- mandatory SHA-256 SSH host-key verification, first-key confirmation, and explicit confirmation of a verified replacement when a key changes;
- interactive terminal with input and resizing;
- restricted SFTP transport in Core with absolute paths, an editor for files up to 25 MiB, multi-file upload/download transfers up to 16 GiB, and ZIP/TAR/TAR.GZ export;
- i18n runtime with complete Czech, German, and English catalogs;
- web catalog, SHA-512-verified installation, sandboxed execution, and removal of `.chjplugin` packages;
- bundled local Hash & Checksum plugin with streaming batch processing, verification, digest comparison, and GNU/BSD/SFV manifests;
- System Monitor (including CPU/RAM/swap/disk/network metrics), Key Generator, Log Viewer, Users, File Manager, and NGINX Manager plugins as separate installable packages;
- shell UI and automated tests.

Migration of data from older versions, SFTP transfer queue/resume/sudo save, remote archive extraction, jump hosts/forwarding, Safe Mode, and other planned Tools are not yet implemented. A verified Core installer can be handed off to the platform manually; fully unattended installation is not enabled yet. An SSH password can optionally be stored in the vault; private-key passphrases are not stored and must be entered for each connection. Platform and release status is documented in `../PROJECT-STATUS.md`.

## Development

```bash
npm install
npm test
npm start
```

On first launch, the application asks you to create a vault master password between 4 and 64 characters long. Then create a profile under **Servers** and connect under **Terminal**. Always verify the first host-key fingerprint through another trusted channel as well.

If a known SSH host key changes, Core blocks the connection first and displays both the original and new SHA-256 fingerprints. The new fingerprint can be saved only through a separate warning that requires confirmation of both values; confirm it only after verifying them through another trusted channel.

The lock screen provides **Forgot password / reset vault**. Because the data cannot be decrypted without the original password, resetting removes server profiles, trusted host fingerprints, and other encrypted data. Update settings and installed plugins are preserved.

The language can be changed directly on the lock screen or under **Settings**. The `cs`, `de`, or `en` selection is stored in non-sensitive local configuration and applied on the next launch.

The alpha updater uses only the HTTPS endpoint `https://sm.ch-j.de/`, defined in the main process. The public server already has a valid Let’s Encrypt certificate, but in temporary test mode Core still accepts any certificate from this single explicitly allowed host. HTTPS and the allowlist remain mandatory, but standard CA verification must be re-enabled as soon as possible. SHA-512 verifies the exact artifact contents, not the publisher’s identity.

The channels use the same names in the application and on the PHP server: `alpha`, `beta`, and `stable`. The historical `dev` channel is not an alias and is rejected. Core updates and the plugin catalog store their channel selections separately. The `all` option is only a client-side view that safely loads and merges all three real channels. macOS distributions and updates are built only for Apple Silicon (`arm64`), not Intel (`x64`).

`npm run dist:mac` creates two separate artifacts: a DMG for automatic updates and `*.app.zip` for initial installation from the website. The ZIP preserves the macOS bundle structure, and the build step verifies `codesign` both before and after packaging. Without a Developer ID Application certificate, only an ad hoc signed test build is produced, which may need to be allowed manually in Privacy & Security settings. For unattended web installation, the `.app` must be signed with Developer ID, use the hardened runtime, and be notarized by Apple.

The Updates screen loads the complete compatible catalog for the current platform, architecture, and channel. Each release is distinguished by the server-provided `id` and `published_at`, so another build with the same version number can also be selected, downloaded, verified, and launched manually. Launching the installer is always manual and becomes available only after successful SHA-512 verification.

The Plugin Manager loads the catalog only from the allowed origin `https://sm.ch-j.de/`; Core does not permit HTTP, direct IP addresses, or legacy QNAP addresses. In alpha mode, CA verification is temporarily disabled only for this origin. A size or SHA-512 mismatch is treated as a security error and the package is not used. Standalone `.chjplugin` packages are safely extracted to staging and atomically installed in the user directory. An installed plugin can be removed; Core closes its window before deleting all installed versions. This does not delete the vault or Core configuration. Plugin windows have their own sandbox, fixed preload, and capabilities derived from the verified manifest. The current Plugin API is `1.2.0`; older plugins requiring `^1.0.0` or `^1.1.0` remain compatible. The alpha catalog publishes `chj.system-monitor`, `chj.key-generator`, `chj.log-viewer`, `chj.users`, `chj.file-manager`, and `chj.nginx-manager`.

Hash & Checksum is a bundled first-party plugin using only the narrow `local.hash` capability. Native dialogs in Core issue opaque, plugin-owned selection tokens; the renderer never receives or submits arbitrary local paths. Files are streamed through worker threads, and multiple incremental algorithms share one read pass where technically possible. The plugin performs no SSH/SFTP hashing and has no network access. MD5 and SHA-1 are compatibility-only; fast hashes and checksums are explicitly marked as non-cryptographic.

NGINX Manager uses only `session.read`, `nginx.read`, and `nginx.manage`. It supports inventory and restricted configuration reading, `nginx -T`, editing files up to 512 KiB with timestamped backups, `nginx -t`, automatic rollback, and a confirmed graceful reload. It requires Plugin API `^1.1.0`, so older Core versions do not display it in the catalog.

File Manager uses an existing verified SSH session, but receives only the `files.read`, `files.write`, and `files.transfer` capabilities instead of a general-purpose remote shell. It provides interactive multiple selection, sorting, filtering, breadcrumbs, a context menu, keyboard shortcuts, and a bundled offline Monaco Editor with a 25 MiB limit. Core provides atomic writes, multi-upload of files and folders, recursive batch downloads, confirmed recursive deletion, and export of selected items as ZIP, TAR, or TAR.GZ. Because alpha builds currently share version `0.0.1`, the plugin detects older Core builds without the extended `files.*` API, requests an application update, and safely disables its controls. Sudo save, remote archive extraction, transfer queues, and resume are not yet implemented.

Installed plugins are not compared by manifest version alone. The registry also stores the server release ID and SHA-512, allowing a newer alpha build with the same version to be offered and atomically reinstalled—for example, an updated `chj.key-generator` 0.0.1 build.

An SSH profile can use either an IP address or a DNS hostname. Core first tries the system resolver and, if it fails, performs direct A/AAAA DNS queries; `ssh2` then receives the selected numeric address. When both record types are available, the current configuration prefers IPv4. The host-key database, UI, and audit log continue to use the original DNS name, so resolution does not weaken server identity verification. Only a DNS name without a usable record returns `SSH_DNS_RESOLUTION_FAILED`.
