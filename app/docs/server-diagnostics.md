# Server Diagnostics

Integrated into the Core sidebar, in the order Plugins → Server Diagnostics → Hash & Checksum. It requires no SSH session or downloaded plugin. All runtime code, tests and fixtures live in `app/`; the module has no dependency on sibling repositories. The repository has no `doc.md`, so this document and both READMEs describe the implementation.

## User workflow

Enter a hostname, IPv4, IPv6 or HTTP(S)/WS(S) URL. Bare hostnames/IPs default to HTTPS; explicit URLs retain their path, query and port during the request. Credentials in URLs, unsupported schemes, whitespace/control characters and shell-like hostnames are rejected. IPv6 literals are bracketed automatically; scoped/link-local zone identifiers are not supported by the URL parser.

Choose Auto (prefer IPv4, otherwise IPv6), IPv4, IPv6 or Both. Resolve addresses to choose a particular current answer. The overview displays all resolved answers; probes test the selected address or one address per requested family. Both families are measured independently. AAAA presence alone never implies working IPv6 connectivity.

Run Diagnostics runs DNS, ping, traceroute, HTTP, compression, TLS and the selected TCP ports. WebSocket is opt-in. Each tool also has a separate Run/Stop control. One diagnostic run may be active at once. A completed run means the tools have finished, not that every probe succeeded. There is no blanket “server offline” verdict.

Timeout, packet count, repetitions, maximum hops, DNS resolver, protocol selection, warm connection and HTTP/HTTPS comparison are configurable. Changing the target clears a previously selected IP. History can reopen, compare two reports, delete, import JSON, copy or export JSON/CSV/TXT through native Core dialogs. Light/dark/system theme applies to the diagnostics section and is saved in the existing UI configuration. CZ/DE/EN follows the application language immediately.

## Components and protocol behavior

| Component | Implementation and interpretation |
| --- | --- |
| `common.js` | Validates targets/options, limits and enum values; IDNA conversion; numeric statistics exclude unknown values. |
| `dnsDiagnostics.js` | System address resolution uses `dns.lookup` to honor OS configuration and hosts files. Record queries use bounded UDP DNS with TCP fallback for truncated responses against `dns.getServers()`, or the explicitly chosen custom/public resolver. No implicit switch to public DNS. |
| `processTools.js` | Executes OS ping/traceroute with an argument array and `shell: false`, bounded output, explicit timeout and abort/kill cleanup. Parses packet replies and hops, rather than treating process duration as RTT. |
| `httpDiagnostics.js` | Native Node HTTP/HTTPS for HTTP/1.1, native HTTP/2 sessions with forced h2 ALPN (h2c prior knowledge for cleartext), and optional external curl for HTTP/3. Each version is independently requested; the actual version is recorded. |
| `socketDiagnostics.js` | Explicit TLS version probes, bounded TCP connects/passive banners, pre-authentication SSH host-key observation using the existing ssh2 dependency, and optional RFC 6455 Upgrade validation. |
| `diagnosticsService.js` | Runs and cancels tools, selects/validates addresses, streams progress, preserves partial measurements and owns the run deadline. |
| `historyStore.js` | Versioned bounded local history, redaction, schema-checked imports and measured-data exports. |

### ICMP and routes

Ping defaults to four individually executed ICMP echo requests. Results contain per-packet measured RTT, received/sent counts, loss, min/average/max, population standard deviation, mean absolute difference between consecutive measured RTTs (jitter), TTL/Hop Limit when printed, and timestamps. A `<1 ms` reply is counted as received with an upper bound, rather than inventing a numeric RTT. Unknown RTTs are excluded from latency statistics. Statistics use the retained window of at most 500 packets; sent/received/loss counts cover the whole run. Graphs show the last 200 observations, with distinct symbols for replies, sub-resolution replies, missing replies and explicit request/process timeouts.

A missing reply can reflect ICMP filtering, packet loss or timeout; these observations cannot identify a firewall conclusively. Missing executables, local permission failures and invalid tool invocations are separate tool errors, not packet loss or server unavailability. No privilege escalation is requested.

Traceroute streams hops, addresses, individual probes, means and observed unanswered-probe percentages. Reverse DNS is resolved after the route, using the selected resolver. Repetitions compare observed hop-address sequences; differences can reflect load balancing. Unanswered intermediate hops do not establish a broken route. Raw probe metadata and method appear in expandable details. macOS requires integer-second traceroute waits; the effective rounded timeout is recorded.

### DNS

The twelve record types are A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA, PTR, DS and DNSKEY. DNS wire parsing checks transaction/question identity, record sizes, compression-pointer loops and message limits. Answers preserve record TTLs, query timing, resolver and NXDOMAIN/NODATA/SERVFAIL/refused/timeout states. OS address lookups cannot supply TTL; the separate record query can.

CNAME following is bounded to eight links with cycle detection. Consistency repeats A/AAAA answers from the selected resolver, and performs forward-confirmed PTR for IP-literal DNS tests. Changed answers are observations, not proof of a DNS fault. Queries for SRV use the target name as given; enter a service name such as `_service._tcp.example.org` when needed. DNSSEC is always **not validated**. DS/DNSKEY presence and even a resolver's AD flag are never treated as independent validation.

### HTTP, performance and compression

HTTP/1.1 accepts that version as supported only when it was actually returned. HTTPS HTTP/2 requires negotiated h2; no fallback is relabeled. Cleartext HTTP/2 uses prior knowledge, not an HTTP/1.1 Upgrade probe. TLS verification remains strict for every HTTP/WebSocket request.

Manual redirects are limited to eight; loops, invalid destinations and excessive redirects fail explicitly. The full chain records cross-domain changes and HTTPS downgrades; schemes and www changes are visible in the source/destination URLs. Credentials and non-HTTP(S) redirect schemes are rejected. Each cross-host redirect is resolved independently through the selected resolver and requested IP family.

Measurements include DNS (when performed), TCP, TLS, final-response TTFB, overall TTFB including DNS/redirects, download, redirect and total wall time, actual entity bytes, transfer speed, status, response headers, actual server address/port, ALPN and verified connection reuse. DNS/TCP/TLS phases not performed on a pinned or reused connection are `N/A`, not fake zeros. QUIC has no TCP phase; its handshake is separately recorded. Header-transfer or full wire overhead is not asserted as entity-byte measurement. These are server/network timings, not page rendering or Lighthouse scores.

Each selected protocol uses the same target and repetitions. IPv4/IPv6 and HTTP/HTTPS are explicit comparison options. The alternate scheme uses its default port. Cold native requests create fresh connections; warm native requests use HTTP agents or an HTTP/2 session cache. Actual reuse is reported, never assumed. HTTP/3 starts a separate curl process per sample and does not claim reuse. Total-time statistics include min/average/median/max/nearest-rank P95 and a separate transport/protocol error rate; HTTP status codes remain visible even when a server successfully returns a 4xx/5xx response.

Compression sends identity, gzip, deflate, br and (when the runtime supports it) zstd as separate Accept-Encoding requests. Content-Encoding must match, and bounded decompression must succeed. A ratio is calculated only if the decoded body hash, final URL and status match the identity baseline. Ignored encodings are unsupported; changing/dynamic bodies have no ratio. This is an observation for that URL/status, not universal server support.

Security-header checks show presence and value of HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and X-Frame-Options. A CSP frame-ancestors directive can supersede the latter. Presence does not establish that the policy is correctly configured or that the website is secure.

### HTTP/3 requirements and proof

The selected `curl`/`curl.exe` executable must advertise `HTTP3` in its Features and support `--http3-only` (curl 7.88+). Requests use HTTPS on UDP/443, pin the resolved address, disable curl config/proxies, use explicit timeout/body limits and strict certificate verification, and do not enable Alt-Svc caches or automatic protocol fallback.

A successful process is insufficient: curl JSON metrics must say `http_version = 3`. Any other negotiated version is rejected as `HTTP3_FALLBACK_REJECTED`. Merely receiving `Alt-Svc: h3` proves nothing. Missing/insufficient curl reports **HTTP/3 testing unavailable** with the capability reason; other negotiation/network/certificate failures remain explicit errors. Chromium's opportunistic negotiation is not used as a forced-protocol measurement API.

References: [curl --http3-only documentation](https://curl.se/docs/manpage.html#--http3-only) and [curl HTTP/3 support](https://curl.se/docs/http3.html).

### TLS, ports and SSH

TLS 1.2 and TLS 1.3 are independently forced. The inspection-only socket can collect an invalid certificate chain but sends no application payload. A valid result requires BOTH OpenSSL chain/date/signature authorization AND explicit hostname/IP verification (IP SAN matching uses X509.checkIP, including IPv6). The scoped inspection flag is never reused for HTTP, WebSocket or the updater; no environment/global verification setting is modified.

Details include subject, issuer, SAN, validity dates, days remaining, chain, SHA-256 fingerprint, public-key type/available size, signature algorithm (OID when the runtime lacks a friendly name), negotiated version, cipher, ALPN and SNI. Trust failures, mismatches and expired/self-signed certificates stay visible. A trusted certificate expiring within 30 days is a warning. Revocation, certificate transparency and deprecated TLS versions are not independently audited.

TCP presets cover all sixteen requested standard ports, with a maximum of sixteen ports per test and four concurrent connects per address. Standard service names are labels, not proof of the running service. Passive banners are limited to 512 bytes and known plaintext greeting protocols, with no credentials or arbitrary payloads. For an open port 22, ssh2 observes the handshake host key and immediately stops before authentication; the key is neither trusted nor added to known hosts. WebSocket tests verify status/Upgrade/Connection and the Sec-WebSocket-Accept hash, then close without reading messages.

## Core IPC

Preload exposes only `window.chjCore.diagnostics`; all handlers retain the existing main-window sender check and network work stays in main. Results use `{ ok: true, value }` or `{ ok: false, error: { code, message } }`.

| Channel / preload method | Payload / result |
| --- | --- |
| `diagnostics:resolve` / `resolve(options)` | Validated target/settings → target and resolved addresses. At most two concurrent resolution requests. |
| `diagnostics:start` / `start(options)` | Validated target/settings/tool selection → opaque job ID and initial report. |
| `diagnostics:cancel` / `cancel(id, tool?)` | Cancel one active/queued tool or the entire run. |
| `diagnostics:get` / `get(id)` | Snapshot of a known run or saved report. |
| `diagnostics:history` / `history()` | Local history summaries. |
| `diagnostics:removeHistory` / `removeHistory(id)` | Remove the selected history item. |
| `diagnostics:copy` / `copy(id, format)` | Main writes a redacted known report to clipboard. |
| `diagnostics:export` / `export(id, format)` | JSON/CSV/TXT via native save dialog; renderer cannot supply a filesystem path. |
| `diagnostics:import` / `import()` | Native file picker, size/schema/depth validation and redaction before storing. |
| `diagnostics:progress` / `onProgress(callback)` | Resolved addresses, tool starts/completions, packets, hops, HTTP samples and completion; returns an unsubscribe callback. |

No generic shell, filesystem or network API is exposed. Context isolation, sandbox, disabled Node integration and the existing renderer CSP remain enabled. Existing plugin contracts and updater verification/exceptions are unchanged.

## Budgets and local data

- One run, two active tools, at most two IP-family probes per tool; TCP additionally limits each address to four connections.
- Per-operation timeout 250–30000 ms; 1–100 packets, 1–20 repetitions, 1–40 hops, 1–16 ports. Regular runs stop at five minutes; continuous ping at thirty minutes. The traceroute subprocess has a further 180-second cap.
- Process output normally 256 KiB; HTTP entity body 2 MiB; decompressed body 8 MiB; HTTP headers bounded; no response bodies enter history.
- Retain at most 500 packets/progress events, five in-memory runs, thirty history reports and 10 MiB of history. History uses the existing private atomic writer at `<userData>/diagnostics/history.json` (mode 0600).
- Imports are at most 2 MiB, schema 1, with bounded nesting and validated result collections. CSV cells are escaped and formula prefixes neutralized. URL queries/fragments, credentials, cookies, authentication headers and raw bodies are excluded from stored/copied/exported reports. Raw details show measured structured data, not a packet capture or retained response body.
- No cloud synchronization, automatic login, server configuration changes or aggressive/unbounded scanning. The user explicitly chooses target/ports/resolver.

## Platform requirements and verification

| Platform | ICMP | Route | Other protocols |
| --- | --- | --- | --- |
| Windows 10/11 | `ping.exe -4/-6` | `tracert.exe -4/-6`, ICMP | Node native APIs; optional HTTP3-enabled curl.exe. Localized RTT fields do not depend on the word “time”. |
| macOS | `/sbin/ping`, `/sbin/ping6` | `/usr/sbin/traceroute`, `/usr/sbin/traceroute6`, UDP; integer-second waits | Node native APIs; system curl often lacks HTTP3. |
| Ubuntu/Linux | iputils `ping -4/-6` | standard `traceroute -4/-6`, UDP | Missing tools/capabilities are reported; optional HTTP3-enabled curl. |

No new npm dependency was added. The implementation uses Node built-ins and the application's existing ssh2. It neither installs system tools nor requests administrative rights. Firewalls and UDP restrictions can prevent a test from establishing support; they cannot be inferred from a timeout alone.

Automated coverage is in `diagnosticsCore.test.js`, `diagnosticsNetwork.test.js`, `diagnosticsHttp.test.js` and `diagnosticsIpc.test.js`: validation/IPv6 literals, native/local DNS UDP+TCP fixtures, missing/dual-family answers and resolver errors, CNAME/consistency, OS argument/parsing fixtures, bounded real child processes, blocked ICMP observations, real local HTTP/1.1 and TLS h2, redirects/body limits/timeouts/reuse, compression enabled/ignored, HTTP3 capabilities/success-result parsing/fallback rejection, local CA trust/mismatch/expiration and real IPv6 HTTP/HTTPS, TCP connect/refused/mock timeout, real WebSocket and SSH pre-authentication handshakes, cancellation/cleanup/partial results, offline state, private history round-trip/import rejection/exports, trusted IPC and preload subscriptions.

`npm test` runs deterministic tests without public test servers. `npm run test:diagnostics:ui` runs `scripts/smokeDiagnostics.js` in a graphical Electron desktop, using production UI/preload/IPC and real local HTTP/compression probes. Unrelated services are stubbed/offline only in this test harness. It checks navigation order, protocol outcomes, persistence, CZ/DE/EN, both themes, narrow-window overflow and sandbox preferences. If the shell sets ELECTRON_RUN_AS_NODE, unset it for this command.

Verification on macOS: 205 tests, 189 passed, 16 existing Linux-only tests skipped; Electron smoke passed. Real IPv4/IPv6 loopback ICMP and traceroute passed. The installed curl 8.7.1 advertises HTTP2 but no HTTP3; the unavailable path was checked with the real executable. Successful HTTP3 parsing and rejection of HTTP2 fallback were checked with deterministic curl fixtures, **not a live QUIC server**. Windows/Linux command builders and output cases were tested here, but live Windows/Linux runs and packaging were not executed.

Explicit optional limits: no independent DNSSEC validation (requires a complete validating resolver/trust-anchor lifecycle), no Lighthouse audit (server/network timing only), no deprecated TLS audit or revocation/CT service, no HTTP3 warm-reuse claim, and no live HTTP3 verification in this environment. Unsupported capabilities are displayed rather than simulated.

## Files in this change

Created: the seven service files in `src/main/diagnostics/`; `src/renderer/diagnostics.js`, `diagnosticsI18n.js`, `diagnostics.css`; the four `test/diagnostics*.test.js` files; five files under `test/fixtures/diagnostics/`; `scripts/smokeDiagnostics.js`; this document.

Integrated/updated: `src/main/index.js`, `src/main/ipc/registerCoreIpc.js`, `src/preload/corePreload.js`, `src/renderer/index.html`, `app.js`, `i18n.js`, `package.json`, `app/README.md`, root `README.md`, `.gitignore` (four public fixture exceptions), and the root gitleaks allowlist narrowly naming the deliberately public TLS test-key fixture. The signing CA private key was discarded; the fixture is never used by the application runtime.
