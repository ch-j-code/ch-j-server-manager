# Optional system authentication and Vault locking

Create or unlock the Vault with its master password first. Open **Settings → Security**, check the provider status, and enable biometric unlock. Enrollment requests fresh system authentication. Afterwards the login overlay offers Touch ID, Windows Hello or fingerprint unlock alongside the master-password form. **Disable and remove enrollment** removes this application's cached key, never the operating system's registered fingerprints.

Keep the master password: cancellation, timeout, unavailable hardware/keyring and invalidated enrollment all require password fallback. Biometric enrollment is local to this user, device and Vault. It is not a recovery mechanism or a backup. Resetting the Vault revokes enrollment and deletes existing encrypted profiles and host fingerprints only after the existing `SMAZAT` confirmation.

| Platform | Authentication and storage | Requirements and limits |
| --- | --- | --- |
| macOS Apple Silicon | Native LocalAuthentication / Touch ID; Security.framework Keychain item with `biometryCurrentSet` and `WhenUnlockedThisDeviceOnly` | Enrolled Touch ID, available sensor and a usable login Keychain. Fingerprint changes invalidate the item. Use stable Developer ID signing for production updates; ad hoc alpha signing can disrupt Keychain trust and local-network permission tracking. |
| Windows x64 | Native WinRT Windows Hello desktop interop attached to the main HWND; current-user DPAPI encrypted key in Windows Credential Manager | Configured Hello fingerprint, face **or PIN**. This is convenience unlock: Hello approval is enforced by the app, while DPAPI itself is not biometric gated. Other code running as the same user may decrypt the credential. |
| Ubuntu x64 | Current user's enrolled fingerprint through fprintd D-Bus; explicit libsecret / Secret Service credential storage | Supported reader, enrolled fingerprint, running desktop Secret Service and default keyring. Convenience unlock: the keyring credential is not cryptographically bound to fingerprint verification. No `basic_text` or plaintext-file fallback. |

On Ubuntu the optional runtime packages are `python3-gi`, `gir1.2-secret-1`, `gnome-keyring` (or another compatible Secret Service) and `fprintd`. Install missing packages using the normal OS package manager, then enroll a fingerprint in OS settings. Authentication uses the current user and does not require root or change PAM. A headless SSH session without a desktop keyring reports unavailable; it does not silently store a key elsewhere.

## Locking rules

Automatic locking is off for existing installations. Enabling it selects **15 minutes** by default; supported values are Never, 1, 5, 10, 15, 30 and 60 minutes. Keyboard and mouse input in application windows count as activity; incoming SSH output does not. Optional focus locking treats the application's plugin windows as part of the app and allows an in-progress system authentication prompt to finish. Changing these rules requires the master password.

**Every Vault lock, including inactivity and focus locking, disconnects active SSH sessions, closes plugins and stops diagnostics.** Save remote edits before locking. This preserves the existing manual-lock behavior; no SSH credentials remain available to background plugins after a lock.

The optional sensitive-operation policy requests fresh system authentication for profile deletion, plugin installation/removal, installer launch and reset of an unlocked Vault. Remote terminal commands and plugin file edits are outside this policy. The policy does not replace SSH server authorization. If the provider stops working, unlock with the master password and change the policy using that password. Reset remains available from the locked recovery screen after its destructive confirmation.

## Vault and IPC design

The existing v1 Vault remains AES-256-GCM with scrypt; enrollment does not rewrite its files or change its schema. Only a copy of its **derived 32-byte key** goes to OS credential storage. The plaintext master password is never stored. Local enrollment metadata contains random credential ID, provider and a SHA-256 binding to the Vault's immutable metadata. A recovered key must pass authenticated decryption before a session is opened. Main-process buffers are cleared after use; native protocol strings are transient process memory, not a claim of complete memory erasure in managed runtimes.

The helper communicates through bounded private stdin/stdout pipes, accepts no shell commands, has authentication timeouts and returns sanitized error codes. Helpers are packaged outside ASAR in `resources/biometrics`; they are standalone native executables, so no Electron ABI native module is required. The Linux helper uses system Python and GI. Native objects and derived keys never cross the renderer/plugin bridge. Biometric IPC validates the live main window and its main frame; plugins cannot invoke it. Explicit locking cancels pending biometric and password unlock work so late approval cannot reopen the Vault. Removing enrollment revokes its local binding even if the OS store is offline; an unreachable store may retain an unusable orphaned credential.

## Build and verification

`npm run biometrics:build` prepares the host-platform helper; development start and release preparation invoke it automatically. macOS requires Swift/Apple SDK with Security and LocalAuthentication; Windows requires Visual Studio C++ Build Tools, Windows SDK and C++/WinRT; Linux copies the Python helper. No new npm dependencies are added. Build natively on each target OS. The macOS helper is included in recursive bundle signing; it needs no App Sandbox entitlement because this desktop app is not sandboxed. Production macOS distribution still requires Developer ID signing and notarization, independent of OpenPGP release signatures.

Run `npm test`, `npm run test:biometrics:ui` and `npm run test:diagnostics:ui`. Biometric Node tests and the isolated UI smoke test use a **mock OS adapter** to cover success, rejection/cancellation, wrong keys, missing hardware/enrollment, reset, timeout and late results, unavailable Linux keyrings, OS credential failures, Windows PIN-approved responses, macOS enrollment changes, existing Vault compatibility, IPC isolation and SSH cleanup. This does not establish successful hardware authentication.

Native compilation was verified on macOS arm64 and Windows x64. macOS reports Touch ID available; the Windows VM reports Hello unavailable. Fingerprint/face/PIN enrollment, actual protected-key retrieval, OS dialog cancellation and enrollment-change invalidation still require interactive hardware testing on each supported system. Linux's helper must additionally be tested on a desktop with a supported fprintd reader; a headless VM cannot establish that verification.

Platform references: [Apple biometric access control](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset), [Windows desktop Hello interop](https://learn.microsoft.com/en-us/windows/win32/api/userconsentverifierinterop/nf-userconsentverifierinterop-iuserconsentverifierinterop-requestverificationforwindowasync), [fprintd device lifecycle](https://fprint.freedesktop.org/fprintd-dev/Device.html), [Secret Service specification](https://specifications.freedesktop.org/secret-service/latest/).

## macOS SSH local-network access

If every local SSH profile fails with `connect EHOSTUNREACH` but the same connection works in Terminal, check **System Settings → Privacy & Security → Local Network → CH-J Server Manager**, allow access, fully quit the app and reopen it. If already enabled, toggle its permission and restart. Also check routing, Wi-Fi/Ethernet and VPN: the error alone is not proof of a privacy denial. Do not reset the Vault or discard trusted SSH fingerprints for this error.

The app declares `NSLocalNetworkUsageDescription` and supplies localized guidance for macOS network permission/route errors. It cannot grant itself permission. Apple recommends an Apple-issued signing identity so macOS can track network privacy reliably across builds; current ad hoc alpha builds retain that limitation. See [Apple's local-network privacy guidance](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy).

## Ubuntu application icon

Debian packages install the existing CH-J icon at standard hicolor sizes (16–512 px), with a matching desktop entry and Electron window class. The main window also receives the icon when recreated. After updating an already pinned old launcher, unpin it and pin the newly installed application; a desktop logout/login can refresh a stale GNOME launcher cache.
