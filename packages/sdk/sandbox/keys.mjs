// Ephemeral local signing keys for the assurance sandbox.
//
// Adapted from examples/effect-assurance-demo/src/keys.mjs (PRs #449, #477).
// The demo derives its keys from public strings; the sandbox instead generates
// fresh random Ed25519 keys on every run. Every key is labelled
// `environment: "local"` and `trust_bearing: false`, and the loader refuses
// any key set that is not labelled exactly that way.
//
// Separation from production, by construction:
//   - this module never opens, derives from, or requests any production or
//     published sandbox key (it has no file path, URL or seed for one);
//   - the local key set has its own schema, which production verifiers
//     (`verify-proof`, the Go offline verifier, hosted verify) do not parse;
//   - production key sets never contain `environment: "local"` keys.

import { createPublicKey, generateKeyPairSync } from "node:crypto";
import { sha256Hex } from "./canonical.mjs";
import { isoMs } from "./time.mjs";

export const LOCAL_ENVIRONMENT = "local";
export const LOCAL_KEY_SET_SCHEMA = "intentrax.local.sandbox_key_set/0.1";
export const LOCAL_SIGNING_KEYS_SCHEMA = "intentrax.local.sandbox_signing_keys/0.1";
export const LOCAL_KEY_VALIDITY_SECONDS = 24 * 60 * 60;

export const ROLES = Object.freeze({
  PRINCIPAL: "PRINCIPAL",               // the local "organisation" issuing the root mandate
  DECISION_SERVICE: "DECISION_SERVICE", // local decision + bundle seal
  EXECUTOR: "EXECUTOR",                 // the executor shim (self-report only)
  EFFECT_VERIFIER: "EFFECT_VERIFIER",   // the sandbox's independent read-only check
});

// The identity each local key speaks for.
export const LOCAL_PRINCIPALS = Object.freeze({
  PRINCIPAL: "local:sandbox-principal",
  DECISION_SERVICE: "local:sandbox-decision-service",
  EXECUTOR: "local:sandbox-executor",
  EFFECT_VERIFIER: "local:sandbox-effect-verifier",
});

const WARNING =
  "LOCAL SANDBOX ONLY. These keys were generated on this machine for one sandbox run. They are not " +
  "trust-bearing, are not published by Intentrax, and must never be added to a production key set.";

function rawPublicKey(publicKey) {
  const spki = publicKey.export({ format: "der", type: "spki" });
  return spki.subarray(spki.length - 32);
}

export function publicKeyFromRaw(b64) {
  const raw = Buffer.from(String(b64), "base64url");
  if (raw.length !== 32) {
    throw new Error("ed25519 public key must be 32 bytes");
  }
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
  return createPublicKey({ key: spki, format: "der", type: "spki" });
}

function iso(ms) {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

// Generate one fresh Ed25519 key per role. Returns signers (holding private
// keys, in memory) and the PUBLIC local key set a verifier pins.
export function generateLocalSigners({ now }) {
  const validFrom = iso(Date.parse(now));
  const validUntil = iso(Date.parse(now) + LOCAL_KEY_VALIDITY_SECONDS * 1000);
  const signers = {};
  for (const role of Object.values(ROLES)) {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const publicKeyB64 = Buffer.from(rawPublicKey(publicKey)).toString("base64url");
    const keyId = "local-" + role.toLowerCase().replace(/_/g, "-") + "-" + sha256Hex(publicKeyB64).slice(0, 12);
    signers[role] = Object.freeze({
      key_id: keyId,
      role,
      principal: LOCAL_PRINCIPALS[role],
      privateKey,
      publicKey,
      public_key: publicKeyB64,
      valid_from: validFrom,
      valid_until: validUntil,
      environment: LOCAL_ENVIRONMENT,
      trust_bearing: false,
    });
  }
  return Object.freeze(signers);
}

function keyEntry(signer) {
  return {
    key_id: signer.key_id,
    alg: "Ed25519",
    role: signer.role,
    principal: signer.principal,
    public_key: signer.public_key,
    valid_from: signer.valid_from,
    valid_until: signer.valid_until,
    environment: LOCAL_ENVIRONMENT,
    trust_bearing: false,
  };
}

// The public key set for one run. Safe to share; useful only for
// re-verifying that run's bundle locally.
export function localKeySetDocument(signers) {
  return {
    schema_version: LOCAL_KEY_SET_SCHEMA,
    environment: LOCAL_ENVIRONMENT,
    trust_bearing: false,
    warning: WARNING,
    keys: Object.values(signers).map(keyEntry),
  };
}

// The private key material for one run (written under .intentrax/local/,
// which is gitignored). Never needed for verification.
export function localSigningKeysDocument(signers, generatedAt) {
  return {
    schema_version: LOCAL_SIGNING_KEYS_SCHEMA,
    environment: LOCAL_ENVIRONMENT,
    trust_bearing: false,
    generated_at: generatedAt,
    warning: WARNING + " Private keys: do not commit or share.",
    keys: Object.values(signers).map((s) => ({
      ...keyEntry(s),
      private_key_pkcs8: s.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64url"),
    })),
  };
}

export class LocalKeySetError extends Error {}

// Parse a local key set into the lookup the verifier uses. Fails closed on
// anything that is not an explicitly local, explicitly non-trust-bearing set,
// so a production or published key set can never be used here, and a local
// key can never be relabelled as trust-bearing.
export function loadLocalKeySet(doc) {
  if (!doc || typeof doc !== "object" || doc.schema_version !== LOCAL_KEY_SET_SCHEMA) {
    throw new LocalKeySetError(
      "not a local sandbox key set (expected schema_version " + LOCAL_KEY_SET_SCHEMA + "); " +
      "production and published key sets cannot be used with the sandbox verifier",
    );
  }
  if (doc.environment !== LOCAL_ENVIRONMENT || doc.trust_bearing !== false) {
    throw new LocalKeySetError("local key set must declare environment \"local\" and trust_bearing false");
  }
  if (!Array.isArray(doc.keys) || doc.keys.length === 0) {
    throw new LocalKeySetError("local key set has no keys");
  }
  const byId = new Map();
  for (const entry of doc.keys) {
    if (!entry || typeof entry !== "object") {
      throw new LocalKeySetError("local key set: malformed key entry");
    }
    if (entry.environment !== LOCAL_ENVIRONMENT || entry.trust_bearing !== false) {
      throw new LocalKeySetError("local key set: key " + entry.key_id + " is not labelled environment local / trust_bearing false");
    }
    if (byId.has(entry.key_id)) {
      throw new LocalKeySetError("local key set: duplicate key_id " + entry.key_id);
    }
    if (entry.alg !== "Ed25519" || !Object.values(ROLES).includes(entry.role)) {
      throw new LocalKeySetError("local key set: bad alg/role for " + entry.key_id);
    }
    // Strict, explicit-offset, non-inverted window (#491 parity): a NaN bound
    // would compare false and silently pass the signing-time check.
    const from = isoMs(entry.valid_from);
    const until = isoMs(entry.valid_until);
    if (from === null || until === null || from >= until) {
      throw new LocalKeySetError("local key set: bad validity window for " + entry.key_id);
    }
    let publicKey;
    try {
      publicKey = publicKeyFromRaw(entry.public_key);
    } catch {
      throw new LocalKeySetError("local key set: bad public key for " + entry.key_id);
    }
    byId.set(entry.key_id, Object.freeze({ ...entry, publicKey }));
  }
  return byId;
}
