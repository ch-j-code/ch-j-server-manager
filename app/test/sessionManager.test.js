"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { SessionManager, normalizeNginxConfigPath, parseNginxInspectionOutput, parseSystemMetricsOutput } = require("../src/main/sessions/sessionManager");
const lookupHost = async () => [{ address: "192.0.2.10", family: 4 }];

class FakeStream extends EventEmitter {
  constructor() {
    super();
    this.stderr = new EventEmitter();
    this.writes = [];
    this.window = null;
  }
  write(value) { this.writes.push(value); }
  setWindow(rows, cols) { this.window = { rows, cols }; }
  end() {}
}

class FakeClient extends EventEmitter {
  constructor(fingerprint) {
    super();
    this.fingerprint = fingerprint;
    this.stream = new FakeStream();
  }
  connect(config) {
    this.config = config;
    setImmediate(() => {
      if (!config.hostVerifier(this.fingerprint)) this.emit("error", new Error("Host key verification failed"));
      else this.emit("ready");
    });
  }
  shell(_options, callback) { setImmediate(() => callback(null, this.stream)); }
  end() {}
}

test("session manager requires host-key trust before opening a shell", async () => {
  const fingerprint = "cd".repeat(32);
  let knownFingerprint = null;
  let latestClient;
  const profile = { id: "profile-1", label: "Test", host: "server.local", port: 22, username: "root", authMethod: "password" };
  const profileService = {
    get: () => profile,
    getHostKey: () => knownFingerprint,
    trustHostKey: (_host, _port, value) => { knownFingerprint = value; return { fingerprint: value }; },
    markUsed: () => {}
  };
  const manager = new SessionManager({
    profileService,
    lookupHost,
    clientFactory: () => { latestClient = new FakeClient(fingerprint); return latestClient; }
  });

  await assert.rejects(
    () => manager.connect({ sessionId: "terminal-1", profileId: profile.id, password: "secret" }),
    { code: "HOST_KEY_UNKNOWN", fingerprint }
  );
  manager.trustPending({ sessionId: "terminal-1", profileId: profile.id, fingerprint });
  const connected = await manager.connect({ sessionId: "terminal-1", profileId: profile.id, password: "secret", cols: 120, rows: 40 });
  assert.equal(connected.state, "connected");

  let output = "";
  manager.on("data", (payload) => { output += payload.data; });
  latestClient.stream.emit("data", Buffer.from("ready\n"));
  manager.write("terminal-1", "uptime\r");
  assert.deepEqual(latestClient.stream.writes, ["uptime\r"]);
  assert.deepEqual(manager.resize("terminal-1", 140, 50), { cols: 140, rows: 50 });
  assert.deepEqual(latestClient.stream.window, { rows: 50, cols: 140 });
  assert.equal(output, "ready\n");
  assert.equal((await manager.disconnect("terminal-1")).disconnected, true);
});

test("session manager uses the encrypted stored password when no temporary password is entered", async () => {
  const fingerprint = "ab".repeat(32);
  let client;
  const profile = { id: "profile-1", label: "Saved", host: "server.local", port: 22, username: "root", authMethod: "password" };
  const manager = new SessionManager({
    profileService: {
      get: () => profile,
      getHostKey: () => fingerprint,
      getStoredPassword: () => "stored-secret",
      markUsed: () => {}
    },
    lookupHost,
    clientFactory: () => { client = new FakeClient(fingerprint); return client; }
  });
  assert.equal((await manager.connect({ sessionId: "terminal-1", profileId: profile.id })).state, "connected");
  assert.equal(client.config.password, "stored-secret");
  await manager.disconnect("terminal-1");
});

test("session manager replaces a changed host key only after explicit confirmation of both fingerprints", async () => {
  const known = "ab".repeat(32);
  const changed = "cd".repeat(32);
  let knownFingerprint = known;
  const profile = { id: "profile-1", label: "Test", host: "server.local", port: 22, username: "root", authMethod: "password" };
  const profileService = {
    get: () => profile,
    getHostKey: () => knownFingerprint,
    trustHostKey: (_host, _port, value) => { knownFingerprint = value; return { fingerprint: value }; },
    markUsed: () => {}
  };
  const manager = new SessionManager({ profileService, lookupHost, clientFactory: () => new FakeClient(changed) });

  await assert.rejects(
    () => manager.connect({ sessionId: "terminal-1", profileId: profile.id, password: "secret" }),
    { code: "HOST_KEY_MISMATCH", fingerprint: changed, knownFingerprint: known }
  );
  assert.throws(
    () => manager.trustPending({ sessionId: "terminal-1", profileId: profile.id, fingerprint: changed }),
    { code: "HOST_KEY_REPLACEMENT_CONFIRMATION_REQUIRED" }
  );
  assert.throws(
    () => manager.trustPending({ sessionId: "terminal-1", profileId: profile.id, fingerprint: changed, knownFingerprint: "ef".repeat(32), replaceKnown: true }),
    { code: "HOST_KEY_REPLACEMENT_CONFIRMATION_REQUIRED" }
  );
  manager.trustPending({ sessionId: "terminal-1", profileId: profile.id, fingerprint: changed, knownFingerprint: known, replaceKnown: true });
  assert.equal(knownFingerprint, changed);
  assert.equal((await manager.connect({ sessionId: "terminal-1", profileId: profile.id, password: "secret" })).state, "connected");
  await manager.disconnect("terminal-1");
});

test("session manager resolves DNS names, prefers IPv4 and reports missing DNS records", async () => {
  const fingerprint = "ef".repeat(32);
  let client;
  const profile = { id: "profile-dns", label: "DNS", host: "server.example.test", port: 22, username: "root", authMethod: "password" };
  const profileService = {
    get: () => profile,
    getHostKey: () => fingerprint,
    getStoredPassword: () => null,
    markUsed: () => {}
  };
  const manager = new SessionManager({
    profileService,
    lookupHost: async () => [{ address: "2001:db8::10", family: 6 }, { address: "192.0.2.10", family: 4 }],
    clientFactory: () => { client = new FakeClient(fingerprint); return client; }
  });
  await manager.connect({ sessionId: "terminal-dns", profileId: profile.id, password: "secret" });
  assert.equal(client.config.host, "192.0.2.10");
  await manager.disconnect("terminal-dns");

  const fallback = new SessionManager({
    profileService,
    lookupHost: async () => { const error = new Error("system resolver failed"); error.code = "ENOTFOUND"; throw error; },
    resolve4: async () => ["198.51.100.20"],
    resolve6: async () => ["2001:db8::20"],
    clientFactory: () => { client = new FakeClient(fingerprint); return client; }
  });
  await fallback.connect({ sessionId: "terminal-fallback", profileId: profile.id, password: "secret" });
  assert.equal(client.config.host, "198.51.100.20");
  await fallback.disconnect("terminal-fallback");

  const notFound = async () => { const error = new Error("not found"); error.code = "ENOTFOUND"; throw error; };
  const missing = new SessionManager({ profileService, lookupHost: notFound, resolve4: notFound, resolve6: notFound });
  await assert.rejects(() => missing.connect({ sessionId: "terminal-missing", profileId: profile.id, password: "secret" }), {
    code: "SSH_DNS_RESOLUTION_FAILED",
    host: profile.host
  });
});

test("system metrics use a fixed command on an existing SSH session", async () => {
  const manager = new SessionManager({ profileService: {} });
  const stream = new EventEmitter();
  stream.stderr = new EventEmitter();
  const client = {
    exec(command, callback) {
      assert.match(command, /\/proc\/meminfo/);
      assert.match(command, /\/proc\/stat/);
      assert.match(command, /\/sys\/class\/net/);
      assert.match(command, /hw\.logicalcpu/);
      assert.match(command, /networkInterface=/);
      callback(null, stream);
      queueMicrotask(() => {
        stream.emit("data", Buffer.from([
          "platform=Linux", "kernel=6.8", "hostname=test", "uptimeSeconds=3600", "load1=0.25",
          "memoryTotal=1000", "memoryAvailable=400", "swapTotal=800", "swapFree=300", "disk=2000:500:1500",
          "cpuUsage=37.5", "cpuArchitecture=x86_64", "cpuModel=AMD EPYC Test", "cpuLogical=8", "cpuPhysical=4",
          "cpuSockets=1", "cpuCoreTypes=P-core:2,E-core:2", "networkDefault=eth0",
          "networkInterface=eth0|up|aa:bb:cc:dd:ee:ff|1000|2000|192.168.10.54/24,fe80::1/64",
          "networkInterface=eth1|down||0|0|", ""
        ].join("\n")));
        stream.emit("close", 0);
      });
    }
  };
  manager.sessions.set("terminal-main", { sessionId: "terminal-main", profileId: "p1", host: "test", state: "connected", stream: {}, client });
  const metrics = await manager.readSystemMetrics("terminal-main");
  assert.equal(metrics.platform, "Linux");
  assert.equal(metrics.memory.available, 400);
  assert.deepEqual(metrics.swap, { total: 800, used: 500, free: 300 });
  assert.equal(metrics.disk.used, 500);
  assert.deepEqual(metrics.cpu, {
    usagePercent: 37.5,
    architecture: "x86_64",
    model: "AMD EPYC Test",
    logicalCores: 8,
    physicalCores: 4,
    sockets: 1,
    coreTypes: [{ name: "P-core", count: 2 }, { name: "E-core", count: 2 }]
  });
  assert.equal(metrics.network.defaultInterface, "eth0");
  assert.equal(metrics.network.interfaces.length, 2);
  assert.deepEqual(metrics.network.interfaces[0], {
    name: "eth0", state: "up", mac: "aa:bb:cc:dd:ee:ff", rxBytes: 1000, txBytes: 2000,
    addresses: ["192.168.10.54/24", "fe80::1/64"], isDefault: true
  });
});

test("legacy system metrics remain compatible without CPU and network fields", () => {
  const metrics = parseSystemMetricsOutput("platform=Linux\nhostname=legacy\nmemoryTotal=100\nmemoryAvailable=40\ndisk=200:50:150\n");
  assert.equal(metrics.cpu.logicalCores, 0);
  assert.equal(metrics.cpu.model, "unknown");
  assert.deepEqual(metrics.network, { defaultInterface: "", interfaces: [] });
});

test("user capability parses accounts and allows only bounded sudo actions", async () => {
  const manager = new SessionManager({ profileService: {} });
  const commands = [];
  const inputs = [];
  const usersOutput = [
    "root:x:0:0:root:/root:/bin/bash",
    "admin:x:1000:1000:Admin User:/home/admin:/bin/bash",
    "bob:x:1001:1001:Bob User:/home/bob:/bin/bash",
    "\x1eCHJ_GROUPS",
    "sudo:x:27:admin",
    "\x1eCHJ_STATUS",
    "root P 01/01/2026 0 99999 7 -1",
    "admin P 01/01/2026 0 99999 7 -1",
    "bob L 01/01/2026 0 99999 7 -1",
    ""
  ].join("\n");
  const client = {
    exec(command, callback) {
      commands.push(command);
      const stream = new EventEmitter();
      stream.stderr = new EventEmitter();
      stream.end = (input = "") => inputs.push(input);
      callback(null, stream);
      queueMicrotask(() => {
        if (!command.startsWith("sudo ")) stream.emit("data", Buffer.from(usersOutput));
        stream.emit("close", 0);
      });
    }
  };
  manager.sessions.set("terminal-users", { sessionId: "terminal-users", profileId: "p1", host: "server.test", username: "admin", state: "connected", stream: {}, client });
  const users = await manager.readUsers("terminal-users");
  assert.deepEqual(users.map((user) => [user.username, user.admin, user.locked]), [["root", true, false], ["admin", true, false], ["bob", false, true]]);
  const result = await manager.manageUser("terminal-users", { action: "unlock", username: "bob", sudoPassword: "sudo-secret" });
  assert.equal(result.users[2].username, "bob");
  assert.match(commands[1], /^sudo -S -p '' -- sh -c 'usermod --unlock -- bob'$/);
  assert.equal(inputs[0], "sudo-secret\n");
  await assert.rejects(() => manager.manageUser("terminal-users", { action: "delete", username: "admin" }), { code: "PROTECTED_USER" });
  await assert.rejects(() => manager.manageUser("terminal-users", { action: "lock", username: "bob;id" }), { code: "USERNAME_INVALID" });
});

test("NGINX capability restricts paths, validates before reload and hides configuration from shell syntax", async () => {
  assert.equal(normalizeNginxConfigPath("/etc/nginx/sites-enabled/default"), "/etc/nginx/sites-enabled/default");
  assert.throws(() => normalizeNginxConfigPath("/etc/nginx/../../etc/shadow"), { code: "NGINX_CONFIG_PATH_INVALID" });
  assert.throws(() => normalizeNginxConfigPath("/etc/nginx/sites-enabled/default;id"), { code: "NGINX_CONFIG_PATH_INVALID" });
  const parsed = parseNginxInspectionOutput("installed=1\nversion=nginx/1.24.0\nserviceState=active\nconfigPath=/etc/nginx/nginx.conf\nconfig=file|/etc/nginx/nginx.conf\nconfig=symlink|/etc/nginx/sites-enabled/default\n");
  assert.equal(parsed.installed, true);
  assert.deepEqual(parsed.configs.map((item) => [item.path, item.writable]), [["/etc/nginx/nginx.conf", true], ["/etc/nginx/sites-enabled/default", false]]);

  const manager = new SessionManager({ profileService: {} });
  const commands = [];
  const inputs = [];
  const client = {
    exec(command, callback) {
      commands.push(command);
      const stream = new EventEmitter();
      stream.stderr = new EventEmitter();
      stream.end = (input = "") => inputs.push(input);
      callback(null, stream);
      queueMicrotask(() => {
        let stdout = "";
        if (command.includes("nginx_bin=$(command -v nginx")) stdout = "installed=1\nversion=nginx/1.24.0\nserviceState=active\nconfigPath=/etc/nginx/nginx.conf\nconfig=file|/etc/nginx/nginx.conf\n";
        else if (command.includes("cat --")) stdout = "events {}\nhttp {}\n";
        else if (command.includes("CHJ_EXIT")) stdout = "nginx: configuration file test is successful\n\x1eCHJ_EXIT=0\n";
        else if (command.includes("CHJ_BACKUP")) stdout = "nginx: configuration file test is successful\n\x1eCHJ_BACKUP=/etc/nginx/nginx.conf.chj-backup-20260809T010203\n";
        else if (command.includes("systemctl reload nginx")) stdout = "nginx: configuration file test is successful\nNGINX configuration reloaded gracefully.\n";
        stream.emit("data", Buffer.from(stdout));
        stream.emit("close", 0);
      });
    }
  };
  manager.sessions.set("terminal-nginx", { sessionId: "terminal-nginx", profileId: "p1", host: "web.test", username: "admin", state: "connected", stream: {}, client });

  const inspection = await manager.inspectNginx("terminal-nginx");
  assert.equal(inspection.serviceState, "active");
  const config = await manager.readNginxConfig("terminal-nginx", { path: "/etc/nginx/nginx.conf" });
  assert.equal(config.text, "events {}\nhttp {}\n");
  assert.equal((await manager.testNginxConfig("terminal-nginx", { sudoPassword: "secret" })).ok, true);
  const source = "events {}\nhttp { server { listen 80; } }\n";
  const saved = await manager.saveNginxConfig("terminal-nginx", { path: "/etc/nginx/nginx.conf", text: source, sudoPassword: "secret" });
  assert.match(saved.backupPath, /\.chj-backup-/);
  assert.ok(!commands.at(-1).includes(source));
  assert.match(commands.at(-1), /base64 --decode/);
  assert.match(commands.at(-1), /nginx -t/);
  assert.match(commands.at(-1), /\[ ! -L/);
  await assert.rejects(() => manager.reloadNginx("terminal-nginx", { sudoPassword: "secret" }), { code: "NGINX_RELOAD_CONFIRMATION_REQUIRED" });
  assert.equal((await manager.reloadNginx("terminal-nginx", { sudoPassword: "secret", confirm: true })).ok, true);
  assert.equal(inputs.filter((value) => value === "secret\n").length, 3);
});

test("privileged bounded operations run directly in an authenticated root SSH session", async () => {
  const manager = new SessionManager({ profileService: {} });
  const commands = [];
  const client = { exec(command, callback) {
    commands.push(command);
    const stream = new EventEmitter(); stream.stderr = new EventEmitter(); stream.end = () => {};
    callback(null, stream);
    queueMicrotask(() => { stream.emit("data", Buffer.from("ok\n\x1eCHJ_EXIT=0\n")); stream.emit("close", 0); });
  } };
  manager.sessions.set("root-nginx", { sessionId: "root-nginx", host: "web.test", username: "root", state: "connected", stream: {}, client });
  assert.equal((await manager.testNginxConfig("root-nginx")).ok, true);
  assert.match(commands[0], /^sh -c /);
  assert.doesNotMatch(commands[0], /sudo/);
});
