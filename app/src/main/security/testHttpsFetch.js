"use strict";

const https = require("node:https");
const { Readable } = require("node:stream");

function normalizeOrigins(values) {
  return new Set((values || []).map((value) => {
    const url = new URL(String(value || ""));
    if (url.protocol !== "https:") throw new Error("Test update transport accepts HTTPS origins only.");
    return url.origin;
  }));
}

function responseHeaders(source) {
  const headers = new Headers();
  for (const [name, value] of Object.entries(source || {})) {
    if (Array.isArray(value)) {
      for (const item of value) headers.append(name, item);
    } else if (value != null) {
      headers.set(name, String(value));
    }
  }
  return headers;
}

function createTestHttpsFetch(options = {}) {
  const allowedOrigins = normalizeOrigins(options.allowedBaseUrls);
  const insecureOrigins = normalizeOrigins(options.insecureBaseUrls || []);
  if (allowedOrigins.size === 0) throw new Error("At least one test HTTPS origin is required.");
  for (const origin of insecureOrigins) {
    if (!allowedOrigins.has(origin)) throw new Error("An insecure test origin must also be explicitly allowed.");
  }

  return function testHttpsFetch(input, init = {}) {
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input?.url);
    if (url.protocol !== "https:" || !allowedOrigins.has(url.origin)) {
      return Promise.reject(new Error("Test HTTPS request is outside the allowed origins."));
    }
    if (init.redirect && init.redirect !== "manual") {
      return Promise.reject(new Error("Test HTTPS requests must not follow redirects automatically."));
    }

    return new Promise((resolve, reject) => {
      const signal = init.signal;
      if (signal?.aborted) {
        reject(signal.reason || new Error("Request aborted."));
        return;
      }

      // Dočasný alfa režim: výjimku lze explicitně zapnout pouze pro jediný
      // pevně povolený HTTPS origin. Před Stable vydáním se musí odstranit.
      const request = https.request(url, {
        method: init.method || "GET",
        headers: init.headers,
        rejectUnauthorized: !insecureOrigins.has(url.origin),
        minVersion: "TLSv1.2",
        maxVersion: "TLSv1.3"
      });
      const abort = () => request.destroy(signal.reason || new Error("Request aborted."));
      signal?.addEventListener("abort", abort, { once: true });
      request.once("error", reject);
      request.once("response", (incoming) => {
        incoming.once("close", () => signal?.removeEventListener("abort", abort));
        const bodyForbidden = init.method === "HEAD" || [204, 205, 304].includes(incoming.statusCode || 0);
        resolve(new Response(bodyForbidden ? null : Readable.toWeb(incoming), {
          status: incoming.statusCode || 500,
          statusText: incoming.statusMessage || "",
          headers: responseHeaders(incoming.headers)
        }));
      });
      request.end();
    });
  };
}

module.exports = { createTestHttpsFetch };
