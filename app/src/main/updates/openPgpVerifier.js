"use strict";

const fs = require("node:fs");
const { Readable } = require("node:stream");
const openpgp = require("openpgp");

const TRUSTED_PRIMARY_FINGERPRINT = "0D92778AD8ECF85C80E3924848F2433AD9CDF453";
const MAX_PUBLIC_KEY_BYTES = 128 * 1024;
const MAX_SIGNATURE_BYTES = 128 * 1024;
const DEFAULT_VERIFICATION_TIMEOUT_MS = 2 * 60 * 1000;

class SignatureVerificationError extends Error {
  constructor(message, code = "UPDATE_SIGNATURE_INVALID", options = {}) {
    super(message, options);
    this.name = "SignatureVerificationError";
    this.code = code;
  }
}

function normalizeFingerprint(value) {
  return String(value || "").replace(/[^0-9a-f]/gi, "").toUpperCase();
}

function assertRegularFile(filePath, label, maxBytes) {
  let stat;
  try {
    stat = fs.lstatSync(filePath);
  } catch (error) {
    throw new SignatureVerificationError(`${label} is missing.`, "UPDATE_SIGNATURE_FILE_MISSING", { cause: error });
  }
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new SignatureVerificationError(`${label} must be a regular file.`, "UPDATE_SIGNATURE_UNSAFE_FILE");
  }
  if (stat.size <= 0) {
    throw new SignatureVerificationError(`${label} is empty.`, "UPDATE_SIGNATURE_EMPTY");
  }
  if (maxBytes && stat.size > maxBytes) {
    throw new SignatureVerificationError(`${label} is too large.`, "UPDATE_SIGNATURE_TOO_LARGE");
  }
  return stat;
}

function withTimeout(operation, timeoutMs, onTimeout) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      try { onTimeout?.(); } catch {}
      reject(new SignatureVerificationError(
        "OpenPGP verification timed out.",
        "UPDATE_SIGNATURE_TIMEOUT"
      ));
    }, timeoutMs);
    timer.unref?.();
  });
  return Promise.race([Promise.resolve(operation), timeout]).finally(() => clearTimeout(timer));
}

function packetFromVerificationResult(signatureResult) {
  return Promise.resolve(signatureResult.signature).then((signature) => signature?.packets?.[0] || null);
}

class OpenPgpVerifier {
  constructor(options = {}) {
    this.publicKeyPath = options.publicKeyPath;
    this.trustedPrimaryFingerprint = normalizeFingerprint(
      options.trustedPrimaryFingerprint || TRUSTED_PRIMARY_FINGERPRINT
    );
    this.logger = options.logger;
    this.verificationTimeoutMs = Number(options.verificationTimeoutMs || DEFAULT_VERIFICATION_TIMEOUT_MS);
    this.openpgp = options.openpgpImpl || openpgp;

    if (!this.publicKeyPath) throw new Error("A bundled OpenPGP public key path is required.");
    if (!/^[0-9A-F]{40}$/.test(this.trustedPrimaryFingerprint)) {
      throw new Error("The trusted primary OpenPGP fingerprint is invalid.");
    }
    if (!Number.isFinite(this.verificationTimeoutMs) || this.verificationTimeoutMs <= 0) {
      throw new Error("The OpenPGP verification timeout is invalid.");
    }
  }

  async verifyFile(artifactPath, signaturePath) {
    this.logger?.info("OpenPGP update verification started.", {
      artifact: String(artifactPath || "").split(/[\\/]/).pop() || null
    });
    let source;
    try {
      assertRegularFile(artifactPath, "Update artifact");
      assertRegularFile(signaturePath, "Detached OpenPGP signature", MAX_SIGNATURE_BYTES);
      assertRegularFile(this.publicKeyPath, "Bundled OpenPGP public key", MAX_PUBLIC_KEY_BYTES);

      const operation = (async () => {
        const armoredKey = fs.readFileSync(this.publicKeyPath, "utf8");
        let publicKey;
        try {
          publicKey = await this.openpgp.readKey({ armoredKey });
        } catch (error) {
          throw new SignatureVerificationError(
            "Bundled OpenPGP public key is malformed.",
            "UPDATE_PUBLIC_KEY_INVALID",
            { cause: error }
          );
        }
        if (publicKey.isPrivate?.()) {
          throw new SignatureVerificationError("Bundled OpenPGP key contains private key material.");
        }

        const actualPrimaryFingerprint = normalizeFingerprint(publicKey.getFingerprint());
        this.logger?.info("Bundled OpenPGP public key loaded.", {
          primaryFingerprint: actualPrimaryFingerprint,
          trustedPrimaryFingerprint: this.trustedPrimaryFingerprint
        });
        if (actualPrimaryFingerprint !== this.trustedPrimaryFingerprint) {
          throw new SignatureVerificationError(
            "Bundled OpenPGP primary fingerprint does not match the trust anchor.",
            "UPDATE_PUBLIC_KEY_FINGERPRINT_MISMATCH"
          );
        }

        const verificationDate = new Date();
        try {
          await publicKey.verifyPrimaryKey(verificationDate);
        } catch (error) {
          throw new SignatureVerificationError(
            "Bundled OpenPGP primary key is revoked, expired, or invalid.",
            "UPDATE_PUBLIC_KEY_INVALID",
            { cause: error }
          );
        }
        this.logger?.info("Trusted OpenPGP primary fingerprint verified.", {
          trustedPrimaryFingerprint: this.trustedPrimaryFingerprint
        });

        const armoredSignature = fs.readFileSync(signaturePath, "utf8");
        let signature;
        try {
          signature = await this.openpgp.readSignature({ armoredSignature });
        } catch (error) {
          throw new SignatureVerificationError(
            "Detached OpenPGP signature is malformed.",
            "UPDATE_SIGNATURE_MALFORMED",
            { cause: error }
          );
        }

        source = fs.createReadStream(artifactPath);
        const message = await this.openpgp.createMessage({ binary: Readable.toWeb(source) });
        let verification;
        try {
          verification = await this.openpgp.verify({
            message,
            signature,
            verificationKeys: publicKey,
            expectSigned: true,
            format: "binary",
            date: verificationDate
          });
        } catch (error) {
          throw new SignatureVerificationError(
            "Detached OpenPGP signature verification failed.",
            "UPDATE_SIGNATURE_INVALID",
            { cause: error }
          );
        }

        if (!Array.isArray(verification.signatures) || verification.signatures.length === 0) {
          throw new SignatureVerificationError("Detached OpenPGP signature has no signer.");
        }

        // OpenPGP.js verifies streaming messages while their data is consumed.
        try {
          for await (const _chunk of verification.data) {}
        } catch (error) {
          throw new SignatureVerificationError(
            "Detached OpenPGP signature is not cryptographically valid.",
            "UPDATE_SIGNATURE_INVALID",
            { cause: error }
          );
        }

        const signers = [];
        for (const result of verification.signatures) {
          try {
            await result.verified;
          } catch (error) {
            throw new SignatureVerificationError(
              "Detached OpenPGP signature is not cryptographically valid.",
              "UPDATE_SIGNATURE_INVALID",
              { cause: error }
            );
          }

          let signingKey;
          try {
            signingKey = await publicKey.getSigningKey(result.keyID, verificationDate);
          } catch (error) {
            throw new SignatureVerificationError(
              "The signature was not made by a valid signing subkey of the trusted primary key.",
              "UPDATE_SIGNATURE_UNTRUSTED_SIGNER",
              { cause: error }
            );
          }

          const signingFingerprint = normalizeFingerprint(signingKey.getFingerprint());
          if (!signingFingerprint || signingFingerprint === actualPrimaryFingerprint) {
            throw new SignatureVerificationError(
              "Updates must be signed by a valid signing subkey of the trusted primary key.",
              "UPDATE_SIGNATURE_NOT_SIGNING_SUBKEY"
            );
          }

          const matchingSubkeys = publicKey.getSubkeys(result.keyID);
          const signingSubkey = matchingSubkeys.find(
            (subkey) => normalizeFingerprint(subkey.getFingerprint()) === signingFingerprint
          );
          if (!signingSubkey) {
            throw new SignatureVerificationError(
              "The signing subkey is not bound to the trusted primary key.",
              "UPDATE_SIGNATURE_UNTRUSTED_SIGNER"
            );
          }

          let bindingSignature;
          try {
            bindingSignature = await signingSubkey.verify(verificationDate);
          } catch (error) {
            throw new SignatureVerificationError(
              "The signing subkey is revoked, expired, or has an invalid binding.",
              "UPDATE_SIGNING_SUBKEY_INVALID",
              { cause: error }
            );
          }
          const keyFlags = bindingSignature?.keyFlags || [];
          const hasSigningCapability = [...keyFlags].some(
            (flags) => (flags & this.openpgp.enums.keyFlags.signData) !== 0
          );
          if (!hasSigningCapability) {
            throw new SignatureVerificationError(
              "The OpenPGP subkey does not have signing capability.",
              "UPDATE_SIGNING_SUBKEY_CAPABILITY_INVALID"
            );
          }

          const signaturePacket = await packetFromVerificationResult(result);
          signers.push({
            fingerprint: signingFingerprint,
            createdAt: signaturePacket?.created instanceof Date
              ? signaturePacket.created.toISOString()
              : null
          });
        }

        this.logger?.info("OpenPGP update signature verified.", {
          result: "valid",
          trustedPrimaryFingerprint: this.trustedPrimaryFingerprint,
          signingFingerprints: signers.map((signer) => signer.fingerprint)
        });
        return {
          valid: true,
          primaryFingerprint: actualPrimaryFingerprint,
          signingFingerprints: signers.map((signer) => signer.fingerprint),
          signatureCreatedAt: signers[0]?.createdAt || null
        };
      })();

      return await withTimeout(operation, this.verificationTimeoutMs, () => source?.destroy());
    } catch (error) {
      const failure = error instanceof SignatureVerificationError
        ? error
        : new SignatureVerificationError(
          "OpenPGP verification failed unexpectedly.",
          "UPDATE_SIGNATURE_ERROR",
          { cause: error }
        );
      this.logger?.warn("OpenPGP update verification failed.", {
        result: "invalid",
        code: failure.code,
        reason: failure.message,
        technicalReason: failure.cause?.message || null,
        trustedPrimaryFingerprint: this.trustedPrimaryFingerprint
      });
      throw failure;
    } finally {
      source?.destroy();
    }
  }
}

module.exports = {
  DEFAULT_VERIFICATION_TIMEOUT_MS,
  MAX_PUBLIC_KEY_BYTES,
  MAX_SIGNATURE_BYTES,
  OpenPgpVerifier,
  SignatureVerificationError,
  TRUSTED_PRIMARY_FINGERPRINT,
  normalizeFingerprint
};
