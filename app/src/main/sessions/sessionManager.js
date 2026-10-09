"use strict";

const fs = require("node:fs");
const dns = require("node:dns").promises;
const net = require("node:net");
const { EventEmitter } = require("node:events");
const { StringDecoder } = require("node:string_decoder");
const { Client } = require("ssh2");
const path = require("node:path");
const { LatencyMonitor } = require("./latencyMonitor");
const REMOTE_EDITOR = fs.readFileSync(path.join(__dirname, "../files/remoteEditor.py"), "utf8");
const EDITOR_STARTED = "\x1eCHJ_EDITOR_START\n";

const SESSION_ID_PATTERN = /^[A-Za-z0-9._-]{1,80}$/;
const MAX_INPUT_LENGTH = 64 * 1024;
const MAX_KEY_BYTES = 2 * 1024 * 1024;
const MAX_COMMAND_OUTPUT = 512 * 1024;
const MAX_NGINX_CONFIG_BYTES = 512 * 1024;
const USERNAME_PATTERN = /^[a-z_][a-z0-9_-]{0,31}$/;
const USER_ACTIONS = new Set(["create", "delete", "lock", "unlock", "grantAdmin", "revokeAdmin"]);
const METRICS_COMMAND = String.raw`LC_ALL=C
platform=$(uname -s 2>/dev/null || echo unknown)
kernel=$(uname -r 2>/dev/null || echo unknown)
host=$(hostname 2>/dev/null || echo unknown)
cpu_arch=$(uname -m 2>/dev/null || echo unknown)
cpu_usage=0
cpu_logical=0
cpu_physical=0
cpu_sockets=0
cpu_model=unknown
cpu_core_types=
network_default=

if [ -r /proc/uptime ]; then
  uptime_s=$(awk '{print int($1)}' /proc/uptime)
else
  boot_epoch=$(sysctl -n kern.boottime 2>/dev/null | awk -F'[=,]' '{gsub(/[^0-9]/,"",$2); print $2}')
  now_epoch=$(date +%s 2>/dev/null || echo 0)
  if [ -n "$boot_epoch" ] && [ "$now_epoch" -ge "$boot_epoch" ] 2>/dev/null; then uptime_s=$((now_epoch-boot_epoch)); else uptime_s=0; fi
fi
if [ -r /proc/loadavg ]; then load1=$(awk '{print $1}' /proc/loadavg); else load1=$(uptime | sed -E 's/.*load averages?:[[:space:]]*([0-9.]+).*/\1/'); fi

if [ -r /proc/meminfo ]; then
  mem_total=$(awk '/^MemTotal:/{print $2*1024}' /proc/meminfo)
  mem_avail=$(awk '/^MemAvailable:/{print $2*1024}' /proc/meminfo)
  swap_total=$(awk '/^SwapTotal:/{print $2*1024}' /proc/meminfo)
  swap_free=$(awk '/^SwapFree:/{print $2*1024}' /proc/meminfo)
  cpu_first=$(awk '/^cpu /{idle=$5+$6; total=0; for(i=2;i<=9 && i<=NF;i++)total+=$i; printf "%.0f:%.0f",idle,total; exit}' /proc/stat)
  sleep 0.2
  cpu_second=$(awk '/^cpu /{idle=$5+$6; total=0; for(i=2;i<=9 && i<=NF;i++)total+=$i; printf "%.0f:%.0f",idle,total; exit}' /proc/stat)
  cpu_usage=$(awk -v first="$cpu_first" -v second="$cpu_second" 'BEGIN{split(first,a,":");split(second,b,":");total=b[2]-a[2];idle=b[1]-a[1];if(total>0)printf "%.2f",100*(total-idle)/total;else print 0}')
  cpu_logical=$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || awk '/^processor[[:space:]]*:/{n++}END{print n+0}' /proc/cpuinfo)
  cpu_model=$(awk -F: '/^(model name|Processor|Hardware)[[:space:]]*:/{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2);if($2!=""){print $2;exit}}' /proc/cpuinfo)
  if command -v lscpu >/dev/null 2>&1; then
    cpu_physical=$(lscpu -p=Core,Socket 2>/dev/null | awk -F, '!/^#/&&$1~/^[0-9]+$/{seen[$1":"$2]=1}END{for(k in seen)n++;print n+0}')
    cpu_sockets=$(lscpu -p=Socket 2>/dev/null | awk -F, '!/^#/&&$1~/^[0-9]+$/{seen[$1]=1}END{for(k in seen)n++;print n+0}')
  fi
  [ "$cpu_physical" -gt 0 ] 2>/dev/null || cpu_physical=$cpu_logical
  [ "$cpu_sockets" -gt 0 ] 2>/dev/null || cpu_sockets=1
  if ls /sys/devices/system/cpu/cpu*/topology/core_type >/dev/null 2>&1; then
    core_type_records=$(for type_file in /sys/devices/system/cpu/cpu*/topology/core_type; do topology=$(dirname "$type_file"); type=$(cat "$type_file" 2>/dev/null); core=$(cat "$topology/core_id" 2>/dev/null); package=$(cat "$topology/physical_package_id" 2>/dev/null); printf '%s:%s:%s\n' "$type" "$package" "$core"; done | sort -u)
    efficiency_cores=$(printf '%s\n' "$core_type_records" | awk -F: '$1==1{n++}END{print n+0}')
    performance_cores=$(printf '%s\n' "$core_type_records" | awk -F: '$1==2{n++}END{print n+0}')
    [ "$performance_cores" -gt 0 ] && cpu_core_types="P-core:$performance_cores"
    if [ "$efficiency_cores" -gt 0 ]; then [ -n "$cpu_core_types" ] && separator=, || separator=; cpu_core_types=$(printf '%s%sE-core:%s' "$cpu_core_types" "$separator" "$efficiency_cores"); fi
  fi
  if command -v ip >/dev/null 2>&1; then network_default=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}'); fi
else
  mem_total=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
  page_size=$(vm_stat 2>/dev/null | awk '/page size of/{print $8}')
  [ -n "$page_size" ] || page_size=4096
  mem_avail=$(vm_stat 2>/dev/null | awk -v page="$page_size" '/Pages (free|inactive|speculative):/{gsub(/\./,"",$3);pages+=$3}END{printf "%.0f",pages*page}')
  swap_total=0
  swap_free=0
  cpu_logical=$(sysctl -n hw.logicalcpu 2>/dev/null || echo 0)
  cpu_physical=$(sysctl -n hw.physicalcpu 2>/dev/null || echo "$cpu_logical")
  cpu_sockets=1
  cpu_model=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || sysctl -n hw.model 2>/dev/null || echo unknown)
  cpu_usage=$(top -l 1 -n 0 2>/dev/null | awk '/CPU usage:/{idle=$7;gsub(/%/,"",idle)}END{if(idle!="")printf "%.2f",100-idle;else print 0}')
  for level in 0 1 2; do
    count=$(sysctl -n "hw.perflevel$level.physicalcpu" 2>/dev/null || echo 0)
    if [ "$count" -gt 0 ] 2>/dev/null; then
      name=$(sysctl -n "hw.perflevel$level.name" 2>/dev/null || echo "Cluster $level")
      [ -n "$cpu_core_types" ] && separator=, || separator=
      cpu_core_types=$(printf '%s%s%s:%s' "$cpu_core_types" "$separator" "$name" "$count")
    fi
  done
  network_default=$(route -n get default 2>/dev/null | awk '/interface:/{print $2;exit}')
fi

[ -n "$cpu_model" ] || cpu_model=unknown
cpu_model=$(printf '%s' "$cpu_model" | tr '\r\n|\036' '    ')
cpu_core_types=$(printf '%s' "$cpu_core_types" | tr '\r\n|\036' '    ')
disk=$(df -Pk / 2>/dev/null | awk 'NR==2{print $2*1024":"$3*1024":"$4*1024}')
printf 'platform=%s\nkernel=%s\nhostname=%s\nuptimeSeconds=%s\nload1=%s\nmemoryTotal=%s\nmemoryAvailable=%s\nswapTotal=%s\nswapFree=%s\ndisk=%s\ncpuUsage=%s\ncpuArchitecture=%s\ncpuModel=%s\ncpuLogical=%s\ncpuPhysical=%s\ncpuSockets=%s\ncpuCoreTypes=%s\nnetworkDefault=%s\n' "$platform" "$kernel" "$host" "$uptime_s" "$load1" "$mem_total" "$mem_avail" "$swap_total" "$swap_free" "$disk" "$cpu_usage" "$cpu_arch" "$cpu_model" "$cpu_logical" "$cpu_physical" "$cpu_sockets" "$cpu_core_types" "$network_default"

if [ -d /sys/class/net ]; then
  for iface_path in /sys/class/net/*; do
    [ -e "$iface_path" ] || continue
    iface=$(basename "$iface_path")
    [ "$iface" = lo ] && continue
    state=$(cat "$iface_path/operstate" 2>/dev/null || echo unknown)
    mac=$(cat "$iface_path/address" 2>/dev/null || true)
    rx=$(cat "$iface_path/statistics/rx_bytes" 2>/dev/null || echo 0)
    tx=$(cat "$iface_path/statistics/tx_bytes" 2>/dev/null || echo 0)
    if command -v ip >/dev/null 2>&1; then addresses=$(ip -o addr show dev "$iface" scope global 2>/dev/null | awk '{print $4}' | paste -sd, -); else addresses=; fi
    printf 'networkInterface=%s|%s|%s|%s|%s|%s\n' "$iface" "$state" "$mac" "$rx" "$tx" "$addresses"
  done
elif command -v ifconfig >/dev/null 2>&1; then
  for iface in $(ifconfig -l 2>/dev/null); do
    [ "$iface" = lo0 ] && continue
    state=$(ifconfig "$iface" 2>/dev/null | awk '/status:/{print $2;exit}')
    mac=$(ifconfig "$iface" 2>/dev/null | awk '/ether /{print $2;exit}')
    addresses=$(ifconfig "$iface" 2>/dev/null | awk '/^[[:space:]]+inet /{print $2}/^[[:space:]]+inet6 /{print $2}' | paste -sd, -)
    counters=$(netstat -ibn -I "$iface" 2>/dev/null | awk 'NR==2{print $7":"$10;exit}')
    rx=$(printf '%s' "$counters" | cut -d: -f1); tx=$(printf '%s' "$counters" | cut -d: -f2)
    [ -n "$state" ] || state=unknown; [ -n "$rx" ] || rx=0; [ -n "$tx" ] || tx=0
    printf 'networkInterface=%s|%s|%s|%s|%s|%s\n' "$iface" "$state" "$mac" "$rx" "$tx" "$addresses"
  done
fi`;
const USERS_COMMAND = String.raw`LC_ALL=C; getent passwd | awk -F: '$1=="root" || ($3 >= 1000 && $3 != 65534)'; printf '\036CHJ_GROUPS\n'; getent group sudo 2>/dev/null || true; getent group wheel 2>/dev/null || true; printf '\036CHJ_STATUS\n'; for name in $(getent passwd | awk -F: '$1=="root" || ($3 >= 1000 && $3 != 65534) {print $1}'); do passwd -S "$name" 2>/dev/null || true; done`;
const NGINX_INSPECT_COMMAND = String.raw`LC_ALL=C
nginx_bin=$(command -v nginx 2>/dev/null || true)
if [ -z "$nginx_bin" ]; then printf 'installed=0\n'; exit 0; fi
printf 'installed=1\n'
printf 'binary=%s\n' "$nginx_bin"
version=$($nginx_bin -v 2>&1 | sed 's/^nginx version: //')
build=$($nginx_bin -V 2>&1 | tr '\n' ' ')
conf_path=$(printf '%s' "$build" | sed -n 's/.*--conf-path=\([^ ]*\).*/\1/p')
[ -n "$conf_path" ] || conf_path=/etc/nginx/nginx.conf
if command -v systemctl >/dev/null 2>&1; then service_state=$(systemctl is-active nginx 2>/dev/null || true); else service_state=$(pgrep -x nginx >/dev/null 2>&1 && echo active || echo inactive); fi
[ -n "$service_state" ] || service_state=unknown
printf 'version=%s\nconfigPath=%s\nserviceState=%s\n' "$version" "$conf_path" "$service_state"
for directory in /etc/nginx /etc/nginx/conf.d /etc/nginx/snippets /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/modules-available /etc/nginx/modules-enabled /etc/nginx/stream-conf.d /usr/local/etc/nginx /usr/local/etc/nginx/conf.d /opt/homebrew/etc/nginx /opt/homebrew/etc/nginx/servers; do
  [ -d "$directory" ] || continue
  find "$directory" -maxdepth 1 \( -type f -o -type l \) ! -name '*.chj-backup-*' -print 2>/dev/null | while IFS= read -r file; do
    [ -L "$file" ] && kind=symlink || kind=file
    printf 'config=%s|%s\n' "$kind" "$file"
  done
done`;

const NGINX_CONFIG_PATH_PATTERN = /^\/(?:etc\/nginx\/(?:nginx\.conf|(?:conf\.d|snippets|modules-(?:available|enabled)|stream-conf\.d)\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}|sites-(?:available|enabled)\/[A-Za-z0-9][A-Za-z0-9._-]{0,127})|usr\/local\/etc\/nginx\/(?:nginx\.conf|conf\.d\/[A-Za-z0-9][A-Za-z0-9._-]{0,127})|opt\/homebrew\/etc\/nginx\/(?:nginx\.conf|servers\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}))$/;

function normalizeNginxConfigPath(value) {
  const path = String(value || "").trim();
  if (!NGINX_CONFIG_PATH_PATTERN.test(path) || path.includes(".chj-backup-")) {
    throw new SessionError("NGINX_CONFIG_PATH_INVALID", "The NGINX configuration path is outside the managed directories.");
  }
  return path;
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'"'"'`)}'`;
}

function openExec(client, command, callback) {
  try { client.exec(command, callback); }
  catch (error) { callback(error); }
}

function normalizeSudoPassword(value) {
  const password = String(value || "");
  if (password.length > 1024 || /[\0\r\n]/.test(password)) throw new SessionError("SUDO_PASSWORD_INVALID", "Invalid sudo password.");
  return password;
}

function parseNginxInspectionOutput(stdout) {
  const result = { installed: false, binary: "", version: "", configPath: "", serviceState: "unknown", configs: [] };
  const seen = new Set();
  for (const line of String(stdout || "").split(/\r?\n/)) {
    if (line.startsWith("config=")) {
      const separator = line.indexOf("|", 7);
      if (separator < 0) continue;
      const kind = line.slice(7, separator) === "symlink" ? "symlink" : "file";
      try {
        const path = normalizeNginxConfigPath(line.slice(separator + 1));
        if (!seen.has(path)) { seen.add(path); result.configs.push({ path, kind, writable: kind === "file" }); }
      } catch {}
      continue;
    }
    const separator = line.indexOf("=");
    if (separator < 1) continue;
    const key = line.slice(0, separator);
    const value = line.slice(separator + 1).replace(/[\x00-\x1f\x7f]/g, " ").trim().slice(0, 512);
    if (key === "installed") result.installed = value === "1";
    else if (["binary", "version", "configPath", "serviceState"].includes(key)) result[key] = value;
  }
  result.configs.sort((left, right) => left.path.localeCompare(right.path));
  return result;
}

class SessionError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "SessionError";
    this.code = code;
    Object.assign(this, details);
  }

  toJSON() {
    const result = { code: this.code, message: this.message };
    for (const key of ["sessionId", "profileId", "host", "port", "fingerprint", "knownFingerprint"]) {
      if (this[key] !== undefined) result[key] = this[key];
    }
    return result;
  }
}

function normalizeTerminalSize(value, fallback, min, max) {
  const number = Number(value);
  return Number.isInteger(number) ? Math.max(min, Math.min(max, number)) : fallback;
}

function metricNumber(value, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(minimum, Math.min(maximum, number)) : minimum;
}

function metricText(value, fallback = "unknown", maximumLength = 240) {
  const normalized = String(value ?? "")
    .replace(/[\x00-\x1f\x7f|]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maximumLength);
  return normalized || fallback;
}

function parseCpuCoreTypes(value) {
  return String(value || "").split(",").slice(0, 16).map((entry) => {
    const separator = entry.lastIndexOf(":");
    if (separator <= 0) return null;
    const name = metricText(entry.slice(0, separator), "", 80);
    const count = Math.floor(metricNumber(entry.slice(separator + 1), 0, 4096));
    return name && count > 0 ? { name, count } : null;
  }).filter(Boolean);
}

function parseNetworkInterfaces(lines, defaultInterface) {
  return lines.filter((line) => line.startsWith("networkInterface=")).slice(0, 64).map((line) => {
    const fields = line.slice("networkInterface=".length).split("|");
    const name = metricText(fields[0], "unknown", 64);
    const state = metricText(fields[1], "unknown", 32).toLowerCase();
    const addresses = String(fields[5] || "").split(",").slice(0, 16)
      .map((address) => metricText(address, "", 128)).filter(Boolean);
    return {
      name,
      state,
      mac: metricText(fields[2], "", 64),
      rxBytes: metricNumber(fields[3]),
      txBytes: metricNumber(fields[4]),
      addresses,
      isDefault: name === defaultInterface
    };
  });
}

function parseSystemMetricsOutput(stdout, fallbackHostname = "unknown") {
  const lines = String(stdout || "").split(/\r?\n/).filter(Boolean);
  const values = Object.fromEntries(lines.filter((line) => !line.startsWith("networkInterface=")).map((line) => {
    const index = line.indexOf("=");
    return index > 0 ? [line.slice(0, index), line.slice(index + 1)] : [line, ""];
  }));
  const disk = String(values.disk || "0:0:0").split(":").map((value) => metricNumber(value));
  const memoryTotal = metricNumber(values.memoryTotal);
  const memoryAvailable = metricNumber(values.memoryAvailable, 0, memoryTotal);
  const swapTotal = metricNumber(values.swapTotal);
  const swapFree = metricNumber(values.swapFree, 0, swapTotal);
  const defaultInterface = metricText(values.networkDefault, "", 64);
  return {
    platform: metricText(values.platform),
    kernel: metricText(values.kernel),
    hostname: metricText(values.hostname, fallbackHostname),
    uptimeSeconds: metricNumber(values.uptimeSeconds),
    load1: metricNumber(values.load1),
    memory: { total: memoryTotal, available: memoryAvailable },
    swap: { total: swapTotal, used: Math.max(0, swapTotal - swapFree), free: swapFree },
    disk: {
      total: disk[0] || 0,
      used: Math.min(disk[0] || 0, disk[1] || 0),
      available: Math.min(disk[0] || 0, disk[2] || 0)
    },
    cpu: {
      usagePercent: metricNumber(values.cpuUsage, 0, 100),
      architecture: metricText(values.cpuArchitecture),
      model: metricText(values.cpuModel),
      logicalCores: Math.floor(metricNumber(values.cpuLogical, 0, 4096)),
      physicalCores: Math.floor(metricNumber(values.cpuPhysical, 0, 4096)),
      sockets: Math.floor(metricNumber(values.cpuSockets, 0, 256)),
      coreTypes: parseCpuCoreTypes(values.cpuCoreTypes)
    },
    network: {
      defaultInterface,
      interfaces: parseNetworkInterfaces(lines, defaultInterface)
    }
  };
}

class SessionManager extends EventEmitter {
  constructor(options) {
    super();
    this.profileService = options.profileService;
    this.logger = options.logger;
    this.clientFactory = options.clientFactory || (() => new Client());
    this.lookupHost = options.lookupHost || dns.lookup;
    this.resolve4 = options.resolve4 || dns.resolve4;
    this.resolve6 = options.resolve6 || dns.resolve6;
    this.latencyMonitor = options.latencyMonitor || new LatencyMonitor();
    this.sessions = new Map();
    this.pendingTrust = new Map();
  }

  list() {
    return [...this.sessions.values()].map((record) => this._publicStatus(record));
  }

  async connect(options = {}) {
    const sessionId = String(options.sessionId || "").trim();
    if (!SESSION_ID_PATTERN.test(sessionId)) throw new SessionError("INVALID_SESSION_ID", "Invalid terminal session ID.");
    await this.disconnect(sessionId, "reconnect");
    const profile = this.profileService.get(String(options.profileId || ""));
    const config = this._buildConnectConfig(profile, options);
    const resolvedHost = await this._resolveConnectionAddress(profile.host);
    config.host = resolvedHost.address;
    const knownFingerprint = this.profileService.getHostKey(profile.host, profile.port);
    const client = this.clientFactory();
    const record = {
      sessionId,
      profileId: profile.id,
      label: profile.label,
      host: profile.host,
      address: resolvedHost.address,
      port: profile.port,
      username: profile.username,
      authMethod: profile.authMethod,
      state: "connecting",
      client,
      stream: null,
      decoder: new StringDecoder("utf8"),
      finalized: false
    };
    this.sessions.set(sessionId, record);
    this.emit("state", this._publicStatus(record));

    let hostKeyIssue = null;
    config.hostHash = "sha256";
    config.hostVerifier = (fingerprint) => {
      const normalized = String(fingerprint || "").toLowerCase();
      if (!knownFingerprint) {
        hostKeyIssue = { code: "HOST_KEY_UNKNOWN", fingerprint: normalized };
        this.pendingTrust.set(sessionId, {
          sessionId,
          profileId: profile.id,
          host: profile.host,
          port: profile.port,
          fingerprint: normalized,
          knownFingerprint: null,
          expiresAt: Date.now() + 5 * 60 * 1000
        });
        return false;
      }
      if (knownFingerprint !== normalized) {
        hostKeyIssue = { code: "HOST_KEY_MISMATCH", fingerprint: normalized, knownFingerprint };
        this.pendingTrust.set(sessionId, {
          sessionId,
          profileId: profile.id,
          host: profile.host,
          port: profile.port,
          fingerprint: normalized,
          knownFingerprint,
          expiresAt: Date.now() + 5 * 60 * 1000
        });
        return false;
      }
      return true;
    };

    return new Promise((resolve, reject) => {
      let settled = false;
      const fail = (error) => {
        if (settled) {
          const normalized = this._normalizeConnectionError(error, record);
          this.emit("sessionError", normalized.toJSON());
          this._finalize(record, normalized.code);
          return;
        }
        settled = true;
        const normalized = hostKeyIssue
          ? new SessionError(hostKeyIssue.code, hostKeyIssue.code === "HOST_KEY_UNKNOWN" ? "The SSH host key is not trusted yet." : "The SSH host key changed.", {
            sessionId,
            profileId: profile.id,
            host: profile.host,
            port: profile.port,
            ...hostKeyIssue
          })
          : this._normalizeConnectionError(error, record);
        this.logger?.warn("SSH connection failed.", { sessionId, code: normalized.code, message: normalized.message, address: record.address, port: record.port });
        this._finalize(record, normalized.code);
        reject(normalized);
      };

      client.once("ready", () => {
        const cols = normalizeTerminalSize(options.cols, 100, 20, 500);
        const rows = normalizeTerminalSize(options.rows, 30, 5, 300);
        client.shell({ term: "xterm-256color", cols, rows }, (error, stream) => {
          if (error) { fail(error); return; }
          if (settled) { try { stream.close(); } catch {} return; }
          settled = true;
          record.stream = stream;
          record.state = "connected";
          this.pendingTrust.delete(sessionId);
          this._bindShell(record);
          this.profileService.markUsed(profile.id);
          this.logger?.info("SSH session connected.", {
            sessionId,
            profileId: profile.id,
            host: profile.host,
            port: profile.port,
            username: profile.username,
            authMethod: profile.authMethod
          });
          const status = this._publicStatus(record);
          this.emit("state", status);
          record.stopLatency = this.latencyMonitor.start(record,
            () => this._execFixed(record, "true", 5000),
            (latency) => {
              if (record.finalized || this.sessions.get(sessionId) !== record) return;
              record.latency = latency;
              this.emit("state", this._publicStatus(record));
            });
          resolve(status);
        });
      });
      client.on("error", fail);
      client.once("close", () => {
        if (!settled) fail(new Error("SSH connection closed before it became ready."));
        else this._finalize(record, "remote-close");
      });
      try { client.connect(config); } catch (error) { fail(error); }
    });
  }

  trustPending(options = {}) {
    const sessionId = String(options.sessionId || "");
    const pending = this.pendingTrust.get(sessionId);
    const fingerprint = String(options.fingerprint || "").toLowerCase();
    if (!pending || pending.expiresAt < Date.now()) {
      this.pendingTrust.delete(sessionId);
      throw new SessionError("HOST_KEY_CONFIRMATION_EXPIRED", "The host-key confirmation expired.");
    }
    if (pending.profileId !== options.profileId || pending.fingerprint !== fingerprint) {
      throw new SessionError("HOST_KEY_CONFIRMATION_INVALID", "The host-key confirmation does not match the pending connection.");
    }
    if (pending.knownFingerprint) {
      const confirmedKnownFingerprint = String(options.knownFingerprint || "").toLowerCase();
      if (options.replaceKnown !== true || confirmedKnownFingerprint !== pending.knownFingerprint) {
        throw new SessionError("HOST_KEY_REPLACEMENT_CONFIRMATION_REQUIRED", "Replacing a changed SSH host key requires explicit confirmation of both fingerprints.");
      }
      if (this.profileService.getHostKey(pending.host, pending.port) !== pending.knownFingerprint) {
        this.pendingTrust.delete(sessionId);
        throw new SessionError("HOST_KEY_REPLACEMENT_STALE", "The stored SSH host key changed while confirmation was pending.");
      }
    } else if (options.replaceKnown === true) {
      throw new SessionError("HOST_KEY_CONFIRMATION_INVALID", "A new host key cannot be confirmed as a replacement.");
    }
    const result = this.profileService.trustHostKey(pending.host, pending.port, pending.fingerprint);
    this.pendingTrust.delete(sessionId);
    const details = { host: pending.host, port: pending.port, fingerprint: pending.fingerprint, replacedFingerprint: pending.knownFingerprint };
    if (pending.knownFingerprint) this.logger?.warn("Changed SSH host key replaced by user confirmation.", details);
    else this.logger?.info("SSH host key trusted by user.", details);
    return result;
  }

  write(sessionId, data) {
    const record = this._requireConnected(sessionId);
    const text = String(data ?? "");
    if (Buffer.byteLength(text, "utf8") > MAX_INPUT_LENGTH) throw new SessionError("TERMINAL_INPUT_TOO_LARGE", "Terminal input is too large.");
    record.stream.write(text);
  }

  resize(sessionId, cols, rows) {
    const record = this._requireConnected(sessionId);
    const normalizedCols = normalizeTerminalSize(cols, 100, 20, 500);
    const normalizedRows = normalizeTerminalSize(rows, 30, 5, 300);
    record.stream.setWindow(normalizedRows, normalizedCols, 0, 0);
    return { cols: normalizedCols, rows: normalizedRows };
  }

  async readSystemMetrics(sessionId) {
    const record = this._requireConnected(sessionId);
    const output = await this._execFixed(record, METRICS_COMMAND, 10000);
    return {
      sessionId: record.sessionId,
      ...parseSystemMetricsOutput(output.stdout, record.host),
      collectedAt: new Date().toISOString()
    };
  }

  openSftp(sessionId) {
    const record = this._requireConnected(sessionId);
    return new Promise((resolve, reject) => record.client.sftp((error, sftp) => error ? reject(new SessionError("SFTP_OPEN_FAILED", error.message)) : resolve(sftp)));
  }

  // Internal fixed protocol only. Neither renderer nor plugin can supply code.
  async remoteEditor(sessionId, request, authorization = {}) {
    const record = this._requireConnected(sessionId);
    let password;
    try { password = normalizeSudoPassword(authorization.sudoPassword); }
    catch { throw new SessionError("FILE_SUDO_PASSWORD_INVALID", "Invalid sudo password."); }
    if (password && authorization.sudo !== true) throw new SessionError("FILE_SUDO_AUTHORIZATION_REQUIRED", "Explicit sudo authorization is required.");
    const command = `printf '\\036CHJ_EDITOR_START\\n'; exec python3 -I -B -c ${shellQuote(REMOTE_EDITOR)} ${shellQuote(JSON.stringify(request))}`;
    let output;
    try {
      output = authorization.sudo === true
        ? await this._execSudo(record, command, password, 60000, 36 * 1024 * 1024)
        : await this._execFixed(record, command, 60000, 36 * 1024 * 1024);
    } catch (error) {
      // Remote stderr and sudo diagnostics never become editor errors or logs.
      const definitiveSudoFailure = authorization.sudo === true && error.remoteExitCode === 1 && error.editorStarted === false;
      throw new SessionError(definitiveSudoFailure ? "FILE_SUDO_FAILED" : error.remoteExitCode === 127 ? "FILE_DEPENDENCY_UNAVAILABLE" : request.operation === "finalize" ? "FILE_RESULT_UNKNOWN" : "FILE_EXEC_FAILED",
        "Remote editor operation was not confirmed. Inspect recovery before retrying.");
    }
    let response;
    try {
      if (!output.stdout.startsWith(EDITOR_STARTED)) throw new Error("Missing editor marker");
      response = JSON.parse(output.stdout.slice(EDITOR_STARTED.length));
    }
    catch { throw new SessionError("FILE_RESULT_UNKNOWN", "Remote editor result could not be verified."); }
    if (!response || response.ok !== true || !response.value || typeof response.value !== "object") {
      const code = /^FILE_[A-Z_]+$/.test(response?.code) ? response.code : "FILE_PROTOCOL_ERROR";
      throw new SessionError(code, `${code}: Remote editor operation stopped; recoverable copies were retained.`);
    }
    return response.value;
  }

  async readUsers(sessionId) {
    const record = this._requireConnected(sessionId);
    const output = await this._execFixed(record, USERS_COMMAND, 10000);
    const [passwdText = "", groupText = "", statusText = ""] = output.stdout.split(/\x1eCHJ_(?:GROUPS|STATUS)\r?\n/);
    const adminMembers = new Set(["root"]);
    for (const line of groupText.split(/\r?\n/).filter(Boolean)) {
      const fields = line.split(":");
      if (fields[0] !== "sudo" && fields[0] !== "wheel") continue;
      for (const username of String(fields[3] || "").split(",").filter(Boolean)) adminMembers.add(username);
    }
    const statuses = new Map(statusText.split(/\r?\n/).filter(Boolean).map((line) => {
      const [username, state = ""] = line.trim().split(/\s+/, 3);
      return [username, state];
    }));
    return passwdText.split(/\r?\n/).filter(Boolean).map((line) => {
      const [username, , uid, gid, displayName, home, shell] = line.split(":");
      const passwordState = statuses.get(username) || "";
      return {
        username,
        uid: Number(uid) || 0,
        gid: Number(gid) || 0,
        displayName: String(displayName || "").split(",")[0],
        home: String(home || ""),
        shell: String(shell || ""),
        admin: adminMembers.has(username),
        locked: passwordState === "L" || passwordState === "LK",
        passwordState
      };
    }).sort((left, right) => left.uid - right.uid || left.username.localeCompare(right.username));
  }

  async manageUser(sessionId, payload = {}) {
    const record = this._requireConnected(sessionId);
    const action = String(payload.action || "");
    const username = String(payload.username || "").trim();
    if (!USER_ACTIONS.has(action)) throw new SessionError("USER_ACTION_INVALID", "Unsupported user-management action.");
    if (!USERNAME_PATTERN.test(username)) throw new SessionError("USERNAME_INVALID", "Username must use lowercase letters, numbers, underscore or hyphen.");
    if (username === "root" || username === record.username) {
      throw new SessionError("PROTECTED_USER", "Core will not modify root or the account used by the active SSH session.");
    }
    const sudoPassword = String(payload.sudoPassword || "");
    if (sudoPassword.length > 1024 || /[\0\r\n]/.test(sudoPassword)) throw new SessionError("SUDO_PASSWORD_INVALID", "Invalid sudo password.");
    const commands = {
      create: `useradd --create-home --shell /bin/bash -- ${username}${payload.admin === true ? ` && group=$(getent group sudo >/dev/null && echo sudo || echo wheel) && usermod --append --groups "$group" -- ${username}` : ""}`,
      delete: `userdel ${payload.removeHome === true ? "--remove " : ""}-- ${username}`,
      lock: `usermod --lock -- ${username}`,
      unlock: `usermod --unlock -- ${username}`,
      grantAdmin: `group=$(getent group sudo >/dev/null && echo sudo || echo wheel); usermod --append --groups "$group" -- ${username}`,
      revokeAdmin: `group=$(getent group sudo >/dev/null && echo sudo || echo wheel); gpasswd --delete ${username} "$group"`
    };
    await this._execSudo(record, commands[action], sudoPassword, 30000);
    this.logger?.warn("Remote user-management action completed.", { sessionId: record.sessionId, host: record.host, action, username });
    return { action, username, users: await this.readUsers(sessionId) };
  }

  async inspectNginx(sessionId) {
    const record = this._requireConnected(sessionId);
    const output = await this._execFixed(record, NGINX_INSPECT_COMMAND, 10000);
    return { sessionId: record.sessionId, ...parseNginxInspectionOutput(output.stdout), collectedAt: new Date().toISOString() };
  }

  async readNginxConfig(sessionId, payload = {}) {
    const record = this._requireConnected(sessionId);
    const path = normalizeNginxConfigPath(payload.path);
    const sudoPassword = normalizeSudoPassword(payload.sudoPassword);
    const command = `target=${shellQuote(path)}; [ -f "$target" ] || { echo 'NGINX configuration file was not found.' >&2; exit 41; }; size=$(wc -c < "$target"); [ "$size" -le ${MAX_NGINX_CONFIG_BYTES} ] || { echo 'NGINX configuration exceeds the 512 KiB editor limit.' >&2; exit 42; }; cat -- "$target"`;
    const output = sudoPassword
      ? await this._execSudo(record, command, sudoPassword, 10000)
      : await this._execFixed(record, command, 10000);
    return { path, text: output.stdout, size: Buffer.byteLength(output.stdout, "utf8") };
  }

  async dumpNginxConfig(sessionId, payload = {}) {
    const record = this._requireConnected(sessionId);
    const sudoPassword = normalizeSudoPassword(payload.sudoPassword);
    const output = await this._execSudo(record, "nginx -T 2>&1", sudoPassword, 20000);
    return { text: output.stdout, generatedAt: new Date().toISOString() };
  }

  async testNginxConfig(sessionId, payload = {}) {
    const record = this._requireConnected(sessionId);
    const sudoPassword = normalizeSudoPassword(payload.sudoPassword);
    const command = "set +e; output=$(nginx -t 2>&1); code=$?; printf '%s\\n' \"$output\"; printf '\\036CHJ_EXIT=%s\\n' \"$code\"; exit 0";
    const output = await this._execSudo(record, command, sudoPassword, 20000);
    const marker = output.stdout.match(/\x1eCHJ_EXIT=(\d+)\s*$/);
    const code = marker ? Number(marker[1]) : 1;
    return { ok: code === 0, output: output.stdout.replace(/\x1eCHJ_EXIT=\d+\s*$/, "").trim(), testedAt: new Date().toISOString() };
  }

  async saveNginxConfig(sessionId, payload = {}) {
    const record = this._requireConnected(sessionId);
    const path = normalizeNginxConfigPath(payload.path);
    const sudoPassword = normalizeSudoPassword(payload.sudoPassword);
    const text = String(payload.text ?? "");
    const bytes = Buffer.byteLength(text, "utf8");
    if (bytes <= 0 || bytes > MAX_NGINX_CONFIG_BYTES || text.includes("\0")) {
      throw new SessionError("NGINX_CONFIG_INVALID", "NGINX configuration must be UTF-8 text between 1 byte and 512 KiB.");
    }
    const encoded = Buffer.from(text, "utf8").toString("base64");
    const command = `target=${shellQuote(path)}; data=${shellQuote(encoded)}; [ -f "$target" ] || { echo 'NGINX configuration file was not found.' >&2; exit 41; }; [ ! -L "$target" ] || { echo 'Edit the corresponding sites-available file instead of replacing an enabled symlink.' >&2; exit 42; }; backup="$target.chj-backup-$(date +%Y%m%dT%H%M%S)"; temporary=$(mktemp "$target.chj-tmp.XXXXXX") || exit 43; cleanup(){ [ -z "$temporary" ] || rm -f -- "$temporary"; }; trap cleanup EXIT HUP INT TERM; if ! printf '%s' "$data" | base64 --decode > "$temporary" 2>/dev/null; then printf '%s' "$data" | base64 -d > "$temporary" || exit 44; fi; chmod --reference="$target" "$temporary"; chown --reference="$target" "$temporary"; cp -p -- "$target" "$backup"; mv -f -- "$temporary" "$target"; temporary=; test_output=$(nginx -t 2>&1); test_code=$?; if [ "$test_code" -ne 0 ]; then cp -p -- "$backup" "$target"; printf '%s\\nConfiguration was rolled back from %s.\\n' "$test_output" "$backup" >&2; exit 45; fi; printf '%s\\n\\036CHJ_BACKUP=%s\\n' "$test_output" "$backup"`;
    const output = await this._execSudo(record, command, sudoPassword, 30000);
    const marker = output.stdout.match(/\x1eCHJ_BACKUP=([^\r\n]+)\s*$/);
    const backupPath = marker ? marker[1].trim() : "";
    this.logger?.warn("Remote NGINX configuration saved after successful validation.", { sessionId: record.sessionId, host: record.host, path, backupPath });
    return { path, backupPath, size: bytes, testOutput: output.stdout.replace(/\x1eCHJ_BACKUP=[^\r\n]+\s*$/, "").trim(), savedAt: new Date().toISOString() };
  }

  async reloadNginx(sessionId, payload = {}) {
    const record = this._requireConnected(sessionId);
    const sudoPassword = normalizeSudoPassword(payload.sudoPassword);
    if (payload.confirm !== true) throw new SessionError("NGINX_RELOAD_CONFIRMATION_REQUIRED", "Reloading NGINX requires explicit confirmation.");
    const command = "test_output=$(nginx -t 2>&1) || { printf '%s\\n' \"$test_output\" >&2; exit 41; }; if command -v systemctl >/dev/null 2>&1; then systemctl reload nginx; elif command -v service >/dev/null 2>&1; then service nginx reload; else nginx -s reload; fi; printf '%s\\nNGINX configuration reloaded gracefully.\\n' \"$test_output\"";
    const output = await this._execSudo(record, command, sudoPassword, 30000);
    this.logger?.warn("Remote NGINX graceful reload completed.", { sessionId: record.sessionId, host: record.host });
    return { ok: true, output: output.stdout.trim(), reloadedAt: new Date().toISOString() };
  }

  async disconnect(sessionId, reason = "user") {
    const record = this.sessions.get(String(sessionId || ""));
    this.pendingTrust.delete(String(sessionId || ""));
    if (!record) return { disconnected: false };
    this._finalize(record, reason);
    return { disconnected: true };
  }

  async disconnectAll(reason = "lock") {
    const ids = [...this.sessions.keys()];
    for (const id of ids) await this.disconnect(id, reason);
    this.pendingTrust.clear();
    return { disconnected: ids.length };
  }

  _buildConnectConfig(profile, options) {
    const config = {
      host: profile.host,
      port: profile.port,
      username: profile.username,
      readyTimeout: 15000,
      keepaliveInterval: 15000,
      keepaliveCountMax: 3
    };
    if (profile.authMethod === "privateKey") {
      if (profile.privateKeyPath.toLowerCase().endsWith(".pub")) throw new SessionError("PUBLIC_KEY_SELECTED", "Select a private key, not a .pub file.");
      let stat;
      try { stat = fs.statSync(profile.privateKeyPath); } catch { throw new SessionError("PRIVATE_KEY_NOT_FOUND", "The private key file cannot be read."); }
      if (!stat.isFile() || stat.size <= 0 || stat.size > MAX_KEY_BYTES) throw new SessionError("PRIVATE_KEY_INVALID", "The private key file is invalid or too large.");
      config.privateKey = fs.readFileSync(profile.privateKeyPath);
      const passphrase = String(options.passphrase || "");
      if (passphrase) config.passphrase = passphrase;
    } else {
      const password = String(options.password || this.profileService.getStoredPassword?.(profile.id) || "");
      if (!password) throw new SessionError("PASSWORD_REQUIRED", "Enter the SSH password.");
      config.password = password;
    }
    return config;
  }

  _bindShell(record) {
    record.stream.on("data", (chunk) => this.emit("data", { sessionId: record.sessionId, data: record.decoder.write(chunk) }));
    record.stream.stderr?.on("data", (chunk) => this.emit("data", { sessionId: record.sessionId, data: record.decoder.write(chunk) }));
    record.stream.once("close", () => this._finalize(record, "shell-close"));
    record.stream.once("error", (error) => {
      this.emit("sessionError", { sessionId: record.sessionId, message: error?.message || String(error) });
      this._finalize(record, "shell-error");
    });
  }

  _requireConnected(sessionId) {
    const record = this.sessions.get(String(sessionId || ""));
    if (!record || record.state !== "connected" || !record.stream) throw new SessionError("SESSION_NOT_CONNECTED", "The terminal session is not connected.");
    return record;
  }

  _normalizeConnectionError(error, record) {
    const message = error?.message || String(error || "SSH connection failed.");
    let code = "SSH_CONNECTION_FAILED";
    if (process.platform === "darwin" && ["EPERM", "EACCES"].includes(error?.code)) code = "SSH_LOCAL_NETWORK_DENIED";
    else if (process.platform === "darwin" && ["EHOSTUNREACH", "ENETUNREACH"].includes(error?.code)) code = "SSH_MAC_NETWORK_UNREACHABLE";
    else if (error?.code === "ENOTFOUND" || error?.code === "EAI_AGAIN" || /getaddrinfo|name or service not known|nodename nor servname/i.test(message)) code = "SSH_DNS_RESOLUTION_FAILED";
    else if (/authentication/i.test(message)) code = "SSH_AUTHENTICATION_FAILED";
    else if (/timed?\s*out/i.test(message)) code = "SSH_TIMEOUT";
    else if (/refused/i.test(message)) code = "SSH_CONNECTION_REFUSED";
    return new SessionError(code, message, { sessionId: record.sessionId, profileId: record.profileId, host: record.host, port: record.port });
  }

  async _resolveConnectionAddress(host) {
    const literalFamily = net.isIP(host);
    if (literalFamily) return { address: host, family: literalFamily, source: "literal" };
    let addresses = [];
    let lookupError = null;
    try {
      addresses = await this.lookupHost(host, { all: true });
    } catch (error) {
      lookupError = error;
    }
    let normalized = (Array.isArray(addresses) ? addresses : [addresses]).filter((entry) => entry && net.isIP(entry.address) === Number(entry.family));
    let source = "system";
    if (!normalized.length) {
      const [ipv4, ipv6] = await Promise.allSettled([this.resolve4(host), this.resolve6(host)]);
      normalized = [
        ...(ipv4.status === "fulfilled" ? ipv4.value.map((address) => ({ address, family: 4 })) : []),
        ...(ipv6.status === "fulfilled" ? ipv6.value.map((address) => ({ address, family: 6 })) : [])
      ].filter((entry) => net.isIP(entry.address) === entry.family);
      source = "dns";
    }
    if (!normalized.length) {
      throw new SessionError("SSH_DNS_RESOLUTION_FAILED", `DNS name "${host}" could not be resolved.`, { host, causeCode: lookupError?.code });
    }
    const selected = normalized.find((entry) => entry.family === 4) || normalized[0];
    this.logger?.info("SSH hostname resolved.", { host, address: selected.address, addressFamily: selected.family, addressCount: normalized.length, source });
    return { ...selected, source };
  }

  _execFixed(record, command, timeoutMs, outputLimit = MAX_COMMAND_OUTPUT) {
    return new Promise((resolve, reject) => {
      let settled = false;
      let stdout = "";
      let stderr = "";
      let channel;
      const cancel = () => finish(new SessionError("SESSION_NOT_CONNECTED", "The SSH connection was lost."));
      record.pendingExec ||= new Set();
      record.pendingExec.add(cancel);
      const timer = setTimeout(() => {
        finish(new SessionError("REMOTE_COMMAND_TIMEOUT", "The remote command timed out."));
        try { channel?.close(); } catch {}
      }, timeoutMs);
      timer.unref?.();
      const finish = (error, result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        record.pendingExec.delete(cancel);
        if (error) reject(error); else resolve(result);
      };
      openExec(record.client, command, (error, stream) => {
        if (settled) { try { stream?.close(); } catch {} return; }
        if (error) { finish(new SessionError("REMOTE_COMMAND_FAILED", error.message)); return; }
        channel = stream;
        const append = (target, chunk) => {
          const next = target + chunk.toString("utf8");
          if (Buffer.byteLength(next, "utf8") > outputLimit) {
            try { stream.close(); } catch {}
            finish(new SessionError("REMOTE_OUTPUT_TOO_LARGE", "The system metrics response is too large."));
            return target;
          }
          return next;
        };
        stream.on("data", (chunk) => { stdout = append(stdout, chunk); });
        stream.stderr?.on("data", (chunk) => { stderr = append(stderr, chunk); });
        stream.once("error", (streamError) => finish(new SessionError("REMOTE_COMMAND_FAILED", streamError.message)));
        stream.once("close", (code) => {
          if (!Number.isInteger(code) || code !== 0) finish(new SessionError("REMOTE_COMMAND_FAILED", stderr.trim() || `Remote command exited with ${code}.`, { remoteExitCode: code, editorStarted: stdout.startsWith(EDITOR_STARTED) }));
          else finish(null, { stdout, stderr });
        });
      });
    });
  }

  _execSudo(record, command, sudoPassword, timeoutMs, outputLimit = MAX_COMMAND_OUTPUT) {
    return new Promise((resolve, reject) => {
      let settled = false; let stdout = ""; let stderr = "";
      let channel;
      const cancel = () => finish(new SessionError("SESSION_NOT_CONNECTED", "The SSH connection was lost."));
      record.pendingExec ||= new Set();
      record.pendingExec.add(cancel);
      const timer = setTimeout(() => {
        finish(new SessionError("REMOTE_COMMAND_TIMEOUT", "The remote command timed out."));
        try { channel?.close(); } catch {}
      }, timeoutMs);
      timer.unref?.();
      const finish = (error, result) => {
        if (settled) return;
        settled = true; clearTimeout(timer);
        record.pendingExec.delete(cancel);
        if (error) reject(error); else resolve(result);
      };
      const isRootSession = record.username === "root";
      const prefix = isRootSession ? "sh -c " : (sudoPassword ? "sudo -S -p '' -- sh -c " : "sudo -n -- sh -c ");
      const quoted = `'${String(command).replace(/'/g, `'"'"'`)}'`;
      openExec(record.client, prefix + quoted, (error, stream) => {
        if (settled) { try { stream?.close(); } catch {} return; }
        if (error) { finish(new SessionError("USER_ACTION_FAILED", error.message)); return; }
        channel = stream;
        const append = (target, chunk) => {
          const next = target + chunk.toString("utf8");
          if (Buffer.byteLength(next, "utf8") > outputLimit) {
            try { stream.close(); } catch {}
            finish(new SessionError("REMOTE_OUTPUT_TOO_LARGE", "The user-management response is too large."));
            return target;
          }
          return next;
        };
        stream.on("data", (chunk) => { stdout = append(stdout, chunk); });
        stream.stderr?.on("data", (chunk) => { stderr = append(stderr, chunk); });
        stream.once("error", (streamError) => finish(new SessionError("USER_ACTION_FAILED", streamError.message)));
        stream.once("close", (code) => {
          if (!Number.isInteger(code) || code !== 0) finish(new SessionError("USER_ACTION_FAILED", stderr.trim() || `User command exited with ${code}.`, { remoteExitCode: code, editorStarted: stdout.startsWith(EDITOR_STARTED) }));
          else finish(null, { stdout, stderr });
        });
        if (!isRootSession && sudoPassword) stream.end(`${sudoPassword}\n`); else stream.end();
      });
    });
  }

  _finalize(record, reason) {
    if (record.finalized) return;
    record.finalized = true;
    record.state = "disconnected";
    record.stopLatency?.();
    record.latency = null;
    for (const cancel of record.pendingExec || []) cancel();
    if (this.sessions.get(record.sessionId) === record) this.sessions.delete(record.sessionId);
    try { record.stream?.end(); } catch {}
    try { record.client?.end(); } catch {}
    const trailing = record.decoder.end();
    if (trailing) this.emit("data", { sessionId: record.sessionId, data: trailing });
    const status = { ...this._publicStatus(record), reason };
    this.emit("state", status);
    this.logger?.info("SSH session disconnected.", { sessionId: record.sessionId, profileId: record.profileId, reason });
  }

  _publicStatus(record) {
    return {
      sessionId: record.sessionId,
      profileId: record.profileId,
      label: record.label,
      host: record.host,
      port: record.port,
      username: record.username,
      authMethod: record.authMethod,
      state: record.state,
      latency: record.latency || { pingMs: null, sshRttMs: null, measuredAt: null }
    };
  }
}

module.exports = {
  MAX_NGINX_CONFIG_BYTES,
  METRICS_COMMAND,
  NGINX_INSPECT_COMMAND,
  SessionError,
  SessionManager,
  USERNAME_PATTERN,
  normalizeNginxConfigPath,
  normalizeTerminalSize,
  parseNginxInspectionOutput,
  parseSystemMetricsOutput
};
