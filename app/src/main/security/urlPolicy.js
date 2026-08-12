"use strict";

function normalizeBaseUrl(value) {
  const url = new URL(String(value || ""));
  if (url.protocol !== "https:") throw new Error("Update URL must use HTTPS.");
  if (url.username || url.password || url.hash || url.search) throw new Error("Invalid update base URL.");
  url.pathname = `${url.pathname.replace(/\/+$/, "")}/`;
  return url;
}

function assertAllowedUrl(candidate, allowedBaseUrls, options = {}) {
  const raw = String(candidate || "").trim();
  if (!raw) throw new Error("Missing URL.");
  const bases = allowedBaseUrls.map(normalizeBaseUrl);

  if (raw.startsWith("/")) {
    if (!options.baseUrl) throw new Error("Relative URL requires a base URL.");
    return assertAllowedUrl(new URL(raw.replace(/^\/+/, ""), normalizeBaseUrl(options.baseUrl)).toString(), allowedBaseUrls, options);
  }

  const url = new URL(raw);
  if (url.username || url.password || url.hash) throw new Error("URL credentials and fragments are not allowed.");
  const matchedBase = bases.find((base) => (
    url.protocol === base.protocol
    && url.hostname === base.hostname
    && url.port === base.port
    && url.pathname.startsWith(base.pathname)
  ));
  if (!matchedBase) throw new Error("URL is outside the update allowlist.");

  if (options.pathSegment && !url.pathname.startsWith(`${matchedBase.pathname}${options.pathSegment}`)) {
    throw new Error("URL path is outside the allowed update area.");
  }
  return url;
}

module.exports = {
  assertAllowedUrl,
  normalizeBaseUrl
};
