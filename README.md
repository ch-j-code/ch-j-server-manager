# CH-J Server Manager Core

A new implementation of CH-J Server Manager. The user-facing application name remains unchanged; "Core" refers only to the new architecture.

## Download

Get the latest release for your platform:

- **macOS (ARM64)**: [Download](https://www.sm.ch-j.de/download.php?channel=alpha&platform=mac&arch=arm64)
- **Windows**: [Download](https://www.sm.ch-j.de/download.php?channel=alpha&platform=win&arch=x64)
- **Ubuntu**: [Download](https://www.sm.ch-j.de/download.php?channel=alpha&platform=ubuntu&arch=x64)

For more versions and channels, visit [sm.ch-j.de](https://www.sm.ch-j.de/de/servermanager/)

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
- System Monitor (including CPU/RAM/swap/disk/network metrics), Key Generator, Log Viewer, Users, File Manager, and NGINX Manager plugins as separate installable packages;
- shell UI and automated tests.

Migration of data from older versions, SFTP transfer queue/resume/sudo save, remote archive extraction, jump hosts/forwarding, Safe Mode, and other planned Tools are not yet implemented. A verifie[...]

## Development

```bash
npm install
npm test
npm start
```

On first launch, the application asks you to create a vault master password between 4 and 64 characters long. Then create a profile under **Servers** and connect under **Terminal**. Always verify [...]

If a known SSH host key changes, Core blocks the connection first and displays both the original and new SHA-256 fingerprints. The new fingerprint can be saved only through a separate warning that[...]

The lock screen provides **Forgot password / reset vault**. Because the data cannot be decrypted without the original password, resetting removes server profiles, trusted host fingerprints, and ot[...]

The language can be changed directly on the lock screen or under **Settings**. The `cs`, `de`, or `en` selection is stored in non-sensitive local configuration and applied on the next launch.

The alpha updater uses only the HTTPS endpoint `https://sm.ch-j.de/`, defined in the main process. The public server already has a valid Let's Encrypt certificate, but in temporary test mode Cor[...]

The channels use the same names in the application and on the PHP server: `alpha`, `beta`, and `stable`. The historical `dev` channel is not an alias and is rejected. Core updates and the plugin c[...]

`npm run dist:mac` creates two separate artifacts: a DMG for automatic updates and `*.app.zip` for initial installation from the website. The ZIP preserves the macOS bundle structure, and the buil[...]

The Updates screen loads the complete compatible catalog for the current platform, architecture, and channel. Each release is distinguished by the server-provided `id` and `published_at`, so anoth[...]

The Plugin Manager loads the catalog only from the allowed origin `https://sm.ch-j.de/`; Core does not permit HTTP, direct IP addresses, or legacy QNAP addresses. In alpha mode, CA verification is[...]

NGINX Manager uses only `session.read`, `nginx.read`, and `nginx.manage`. It supports inventory and restricted configuration reading, `nginx -T`, editing files up to 512 KiB with timestamped backu[...]

File Manager uses an existing verified SSH session, but receives only the `files.read`, `files.write`, and `files.transfer` capabilities instead of a general-purpose remote shell. It provides inte[...]

Installed plugins are not compared by manifest version alone. The registry also stores the server release ID and SHA-512, allowing a newer alpha build with the same version to be offered and atomi[...]

An SSH profile can use either an IP address or a DNS hostname. Core first tries the system resolver and, if it fails, performs direct A/AAAA DNS queries; `ssh2` then receives the selected numeric [...]
