# Remote editor saving and latency monitoring

## Root causes

The previous editor uploaded its working file into the target's parent directory,
which often cannot be written by the SSH account under `/etc` or `/var`. SFTP
rename supplied no authorized sudo path, baseline conflict check, security
metadata verification or reliable overwrite semantics. Its error handler deleted
the temporary copy, removing recovery material even when completion was uncertain.

Session status previously exposed only the connection state. There was no ICMP or
authenticated SSH response measurement feeding the terminal indicator.

## Save protocol

1. A fixed SSH helper opens a regular, single-link file using descriptor-relative
   operations and `O_NOFOLLOW` for every path component. It captures the content,
   SHA-256 hash, device/inode, UID, GID, complete permission bits, nanosecond
   modification/change times and all readable extended attributes. Core verifies
   the hash and decodes strict UTF-8, preserving a BOM. Each document gets an
   opaque `editId`, scoped to its plugin, terminal session and server identity.
2. An unprivileged preparation operation resolves the authenticated account's
   home through `pwd.getpwuid(os.getuid())`, creates `$HOME/ch-j-sm/` with mode
   `0700`, and creates a private, exclusive recovery journal. An unsafe home,
   symlink workspace, or workspace owned by another account is rejected.
3. Core uploads a hidden, random 128-bit `.tmp` working file through SFTP with
   exclusive creation (`wx`), mode `0600` and a sixty-second channel/upload timeout.
   The journal contains the target,
   original baseline and expected working hash; it contains no credentials.
4. **One SSH exec performs the entire finalization**, optionally through the
   existing sudo executor. The helper safely opens and hashes the private working
   copy and flushes it. It locks the original inode, checks its baseline, creates
   an exclusive destination file beside the target, writes all content, applies
   and verifies metadata, checks the original again, and flushes the replacement.
5. A same-directory `os.replace` atomically replaces the target. The parent
   directory is flushed and the final path, hash, inode and metadata are verified.
   The original path remains available until replacement. The working file is
   never moved across filesystems and is never removed by finalization.
6. After Core receives a verified success, a separate cleanup rechecks the final
   content and security metadata before removing the working file and journal.
   Cleanup failure still reports a confirmed save with `recoveryAvailable: true`.

A failed upload, failed sudo, conflict, metadata error or failed replacement keeps
the original and any staged material. Incomplete uploads are identified as such
and cannot be recovered as a complete edited document. Lost SSH communication,
missing exit status, timeouts and unexpected finalization results are reported as
**unknown**, never as saved. Core blocks another save on an uncertain document;
there is no automatic replacement retry.

## Metadata, privileges and safety boundaries

The helper preserves and verifies UID, GID and all POSIX permission bits, including
executable, setuid, setgid and sticky bits. It reproduces Linux extended attributes
byte for byte, including POSIX ACLs, capabilities and SELinux labels. Ownership
and file content are set before security attributes, because writes/chown can
clear capabilities or special permission bits. Inherited destination attributes
that are absent on the original are removed. Modification time reflects the new
write and is not copied from the original.

An unreadable or unrepresentable attribute aborts the operation; metadata is not
silently dropped. IMA/EVM signatures are explicitly rejected because copying
content/inode-bound integrity signatures would invalidate them. Symlinks in the
target or home path, hard-linked files and nonregular files are rejected. No
in-place or weaker SFTP overwrite fallback is used.

Ordinary writable saves run as the SSH account. Protected saves require explicit
`{ sudo: true }`; a sudo password is optional for passwordless sudo. Passwords are
validated and passed only on channel stdin, never inside the command, journal,
working file, logger or remote error. Root SSH sessions use the existing direct
root executor. Failed authorization leaves the original and working copy intact.
All saves executed as root (direct root SSH or sudo) also reject target
directories/ancestors owned or writable by other accounts, or carrying an access
ACL, rather than trusting a privileged pathname controlled by another account.

The fixed helper runs with `python3 -I -B`: it ignores user Python paths, the
working directory and user site packages, and writes no bytecode. Paths and JSON
arguments are shell-quoted in Core. Plugins never receive arbitrary SSH exec or
SFTP handles. Existing sandbox, CSP, manifest permissions, host-key verification
and update verification remain in use.

## Plugin API and remaining Monaco integration

**The separately distributed Monaco/File Manager UI is absent from this
checkout. Its UI integration, sudo prompt, dirty-buffer handling and translations
could not be implemented or tested here.** The bundled plugin source is the Hash
& Checksum plugin. No substitute File Manager source was invented.

The existing methods remain available. Additive methods/options are exposed by
the sandboxed preload and permission-checked runtime:

```js
const opened = await chjPlugin.files.readText(sessionId, path);
// For a protected read, explicitly pass { sudo: true, sudoPassword }.

const result = await chjPlugin.files.saveText(sessionId, path, editor.getValue(), {
  editId: opened.editId,
  sudo: true,           // Include only after the user authorizes elevation.
  sudoPassword         // Omit for passwordless sudo; never persist this value.
});

if (result.ok && result.value.status === "saved") {
  // Mark this exact submitted editor version as saved. Later edits stay dirty.
} else {
  // Keep the Monaco model dirty. Translate result.error.code/status.
  // result.error.recoveryId/recoveryPath identify retained working material.
}

await chjPlugin.files.closeText(opened.editId);
const recovery = await chjPlugin.files.listRecovery(sessionId);
const copy = await chjPlugin.files.readRecovery(sessionId, recoveryId);
// Review copy.status and copy.text; open a fresh document before another save.
await chjPlugin.files.cleanupRecovery(sessionId, recoveryId);
// Cleanup rejects anything whose target is not currently confirmed.
```

Recovery methods accept an optional final `{ sudo: true, sudoPassword }` argument
when inspecting a target requires elevation. They retain the authenticated user's
workspace even when executed through sudo. Journals survive app restart and SSH
reconnect; recovery never automatically repeats finalization. Review a recovered
buffer against a freshly opened target before explicitly saving it.

`files.read` guards reads, inspection and handle release. `files.write` guards
saves and recovery cleanup. `writeText` still rejects on failure for existing
plugins; `saveText` returns a structured `{ ok, value/error }` envelope because
Electron drops custom properties on rejected Error objects. A legacy three-argument
`writeText` can use the baseline of a single open document. Multiple live documents
for the same path require `editId`; ambiguous legacy calls fail safely instead of
choosing another document's baseline. Plugins should release unused handles.

The external UI must display saving immediately, keep buffers dirty on failure,
offer sudo only after permission/authentication failures, show conflicts without
overwriting, and offer recovery after connection loss or an unknown outcome. It
must translate these states in Czech, German and English. Suggested state copy:

| State | Czech | German | English |
| --- | --- | --- | --- |
| Saving | Ukládání… | Wird gespeichert… | Saving… |
| Confirmed | Uloženo | Gespeichert | Saved |
| Failure | Uložení selhalo | Speichern fehlgeschlagen | Save failed |
| Sudo required | Vyžadováno oprávnění sudo | sudo-Autorisierung erforderlich | Sudo authorization required |
| Conflict | Původní soubor byl změněn | Originaldatei wurde geändert | Original file changed |
| Disconnected | Spojení bylo přerušeno | Verbindung unterbrochen | Connection lost |
| Unknown | Výsledek uložení není znám | Speicherergebnis unbekannt | Save result unknown |
| Recovery | Obnova je dostupná | Wiederherstellung verfügbar | Recovery available |

## Latency definitions and lifecycle

**Ping** is the latency reported by an actual client-side ICMP echo reply to the
resolved IP used by SSH. Core invokes the platform ping executable asynchronously
with a fixed argument array, without a shell or administrator startup requirement.
Linux, macOS (including `ping6`) and Windows arguments are selected separately.
Blocked ICMP, a missing executable, a timeout, invalid output or an upper-bound-only
Windows reply such as `<1ms` produce an unavailable value, not an invented number.

**SSH RTT** is the monotonic `performance.now()` duration of a fixed `true` exec
request over the existing authenticated SSH client. It includes channel setup,
server processing and response delivery; it is not pure network RTT or SSH login
duration. The translated indicator tooltip explains this distinction.

Monitoring starts as soon as the terminal connects. Probes run concurrently and
asynchronously, with a five-second request/process timeout. The next sample is
scheduled twelve seconds after the previous sample completes, preventing overlap.
Disconnect aborts ICMP, clears timers, cancels pending SSH work and clears values.
Record identity checks prevent a prior connection from publishing after reconnect.
ICMP failure never changes SSH connection state.

Latency travels inside the existing `state` event / `ssh:state` IPC payload:

```js
latency: { pingMs: 24.1, sshRttMs: 31.25, measuredAt: "…" }
```

Unavailable numbers are `null`. The compact terminal indicator uses milliseconds,
localized unavailable text and Czech/German/English labels. It hides on disconnect.
No additional renderer execution capability or IPC request was needed.

## Validation and operational limits

- Run from `app/`: `npm ci`, then `npm test`.
- Final local result: **179 tests; 163 passed, 0 failed, 16 skipped**. All skips
  are the Linux filesystem cases on this macOS host. `npm ci`, Python syntax
  compilation and `git diff --check` completed successfully.
- The tests cover Core saves/recovery, sudo protocol and password redaction,
  real POSIX shell quoting of hostile paths, conflicts, uploads, failed cleanup,
  uncertain outcomes, concurrent documents, IPC permissions and latency lifecycle.
- Linux filesystem tests exercise the shipped Python entry point, using a private
  test account-home lookup: ownership/mode/xattrs, POSIX ACLs, symlinks/hardlinks,
  FIFOs, upload and metadata failures, replacement failures, target races, unknown
  post-replacement outcomes and recovery. Cross-filesystem staging uses `/dev/shm`
  and another filesystem when available. These tests skip on non-Linux hosts;
  missing ACL/separate-filesystem facilities are explicitly skipped.
- The added Linux GitHub Actions job runs the complete suite and repeats filesystem
  cases as root. This workflow has not been dispatched from this working tree.
- Local validation was on macOS. Python source syntax was checked with the direct
  Command Line Tools Python executable. A real macOS loopback ICMP smoke check
  returned `0.071 ms`. No live remote SSH server, Windows runtime, Linux runtime,
  SELinux deployment or external Monaco UI was tested locally.
- Remote text editing now requires Linux and Python 3 with descriptor-relative
  filesystem/xattr support. A missing interpreter fails explicitly. This Core
  intentionally refuses unsafe metadata, links and directory configurations.
- Locking is advisory: noncooperating processes can still race in the narrow
  interval between the last baseline check and atomic rename. Linux supplies no
  general atomic content-hash compare-and-replace operation. Checks detect changes
  before that interval; retained working copies support recovery afterward.
- Recovery data remains on the remote account until a confirmed cleanup. Incomplete,
  conflicted and uninspectable journals are never silently discarded. There is no
  automatic recovery-file expiration and no forced overwrite option.
- `npm ci` reported 17 dependency audit findings (9 moderate, 8 high). This change
  does not change dependencies or the application's update trust model.

The user requested retaining changes in the existing working tree, currently
`feature/hash-checksum-plugin`; no branch switch or unrelated cleanup was performed.

## Files changed for this task

- `src/main/files/remoteFileService.js`
- `src/main/files/remoteEditor.py` (new)
- `src/main/sessions/sessionManager.js`
- `src/main/sessions/latencyMonitor.js` (new)
- `src/main/plugins/pluginRuntime.js`
- `src/preload/pluginPreload.js`
- `src/renderer/app.js`
- `src/renderer/index.html`
- `src/renderer/styles.css`
- `src/renderer/i18n.js`
- `test/remoteFileService.test.js`
- `test/sessionManager.test.js`
- `test/pluginRuntime.test.js`
- `test/remoteEditor.test.js` (new)
- `test/remoteEditorProtocol.test.js` (new)
- `test/remoteEditorLinux.test.js` (new)
- `test/fixtures/remoteEditorLinux.py` (new)
- `test/latencyMonitor.test.js` (new)
- `README.md`
- `docs/remote-editor-latency.md` (this file)
- `../.github/workflows/remote-editor-tests.yml` (new)
