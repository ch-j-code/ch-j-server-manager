"use strict";

const crypto = require("node:crypto");
const net = require("node:net");

const HOSTNAME_PATTERN = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$/;

function normalizeHost(value) {
  const host = String(value || "").trim();
  if (!host || (!net.isIP(host) && !HOSTNAME_PATTERN.test(host))) throw new Error("Invalid server host name or IP address.");
  return host.toLowerCase();
}

function normalizePort(value) {
  const port = Number(value || 22);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("SSH port must be between 1 and 65535.");
  return port;
}

function normalizeProfile(input, existing = null) {
  const host = normalizeHost(input.host);
  const username = String(input.username || "").trim();
  if (!username || username.length > 128 || /[\0\r\n]/.test(username)) throw new Error("Invalid SSH username.");
  const authMethod = input.authMethod === "privateKey" ? "privateKey" : "password";
  const privateKeyPath = String(input.privateKeyPath || "").trim();
  if (authMethod === "privateKey" && (!privateKeyPath || /[\0\r\n]/.test(privateKeyPath))) {
    throw new Error("Select a private key file.");
  }
  const now = new Date().toISOString();
  return {
    id: existing?.id || crypto.randomUUID(),
    label: String(input.label || host).trim().slice(0, 100) || host,
    host,
    port: normalizePort(input.port),
    username,
    authMethod,
    privateKeyPath: authMethod === "privateKey" ? privateKeyPath : "",
    tags: Array.isArray(input.tags) ? [...new Set(input.tags.map((tag) => String(tag).trim()).filter(Boolean))].slice(0, 20) : [],
    createdAt: existing?.createdAt || now,
    updatedAt: now,
    lastUsedAt: existing?.lastUsedAt || null
  };
}

function hostKeyId(host, port) {
  return `${normalizeHost(host)}:${normalizePort(port)}`;
}

function validateStoredPassword(value) {
  const password = String(value ?? "");
  if (!password || password.length > 1024 || password.includes("\0")) throw new Error("Stored SSH password is invalid.");
  return password;
}

function passwordStore(data) {
  if (!data.secrets || typeof data.secrets !== "object" || Array.isArray(data.secrets)) data.secrets = {};
  if (!data.secrets.profilePasswords || typeof data.secrets.profilePasswords !== "object" || Array.isArray(data.secrets.profilePasswords)) {
    data.secrets.profilePasswords = {};
  }
  return data.secrets.profilePasswords;
}

class ProfileService {
  constructor(vaultStore) {
    this.vaultStore = vaultStore;
  }

  list() {
    const data = this.vaultStore.getData();
    const passwords = passwordStore(data);
    return data.profiles
      .map((profile) => ({ ...profile, hasStoredPassword: typeof passwords[profile.id] === "string" }))
      .sort((left, right) => (right.lastUsedAt || right.updatedAt).localeCompare(left.lastUsedAt || left.updatedAt));
  }

  get(id) {
    const data = this.vaultStore.getData();
    const profile = data.profiles.find((item) => item.id === id);
    if (!profile) throw new Error("Server profile was not found.");
    return { ...profile, hasStoredPassword: typeof passwordStore(data)[profile.id] === "string" };
  }

  save(input) {
    let saved;
    this.vaultStore.update((data) => {
      const index = data.profiles.findIndex((item) => item.id === input.id);
      const existing = index >= 0 ? data.profiles[index] : null;
      saved = normalizeProfile(input, existing);
      if (index >= 0) data.profiles[index] = saved;
      else data.profiles.push(saved);
      const passwords = passwordStore(data);
      if (saved.authMethod !== "password" || input.storePassword === false) {
        delete passwords[saved.id];
      } else if (input.storePassword === true) {
        const password = String(input.password ?? "");
        if (password) passwords[saved.id] = validateStoredPassword(password);
        else if (typeof passwords[saved.id] !== "string") throw new Error("Enter the SSH password to store it in the vault.");
      }
    });
    return this.get(saved.id);
  }

  delete(id) {
    let removed = false;
    this.vaultStore.update((data) => {
      const length = data.profiles.length;
      data.profiles = data.profiles.filter((item) => item.id !== id);
      delete passwordStore(data)[id];
      removed = length !== data.profiles.length;
    });
    return { removed };
  }

  markUsed(id) {
    this.vaultStore.update((data) => {
      const profile = data.profiles.find((item) => item.id === id);
      if (profile) profile.lastUsedAt = new Date().toISOString();
    });
  }

  getHostKey(host, port) {
    return this.vaultStore.getData().hostKeys[hostKeyId(host, port)] || null;
  }

  getStoredPassword(profileId) {
    const data = this.vaultStore.getData();
    if (!data.profiles.some((profile) => profile.id === profileId)) throw new Error("Server profile was not found.");
    const password = passwordStore(data)[profileId];
    return typeof password === "string" ? password : null;
  }

  trustHostKey(host, port, fingerprint) {
    const normalized = String(fingerprint || "").trim();
    if (!/^[a-f0-9]{64}$/i.test(normalized)) throw new Error("Invalid SHA-256 host fingerprint.");
    this.vaultStore.update((data) => {
      data.hostKeys[hostKeyId(host, port)] = normalized.toLowerCase();
    });
    return { host: normalizeHost(host), port: normalizePort(port), fingerprint: normalized.toLowerCase() };
  }

  removeHostKey(host, port) {
    this.vaultStore.update((data) => { delete data.hostKeys[hostKeyId(host, port)]; });
    return { removed: true };
  }
}

module.exports = { ProfileService, hostKeyId, normalizeHost, normalizePort, normalizeProfile, validateStoredPassword };
