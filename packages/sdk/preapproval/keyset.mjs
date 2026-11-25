// published_key_set/1.2 (spec 00 §5): per-key purpose and validity windows
// next to the 1.1 members. Port of the Go verifier (#569,
// keySetV12KeyInvalidFields and TrustedKeySet.EnvelopeKeys).
//
// - A 1.2 key needs an Intentrax-held purpose; times are strict RFC 3339;
//   valid_until after valid_from; revoked_at + revocation_reason go together,
//   exactly when status is REVOKED.
// - A 1.1 or 1.0 key must carry none of the 1.2 members, and is read as
//   AEP_RECORD.
// - AEP signers are pinned only by AEP_RECORD anchors: an AEP signer that
//   matches a key of another purpose is SIGNER_PURPOSE_MISMATCH (FAILED).
// - envelopeKeys(set, purpose) pins envelope signers (TENANT_KEY_DIRECTORY,
//   APPROVAL_SERVICE, …): trust-bearing keys of that purpose, never
//   AEP_RECORD; a REVOKED key without revoked_at is treated as compromised.
//
// verify-proof's key-set parser (cli/intentrax.mjs) is release-locked; it
// calls these in an SDK release.

import { PURPOSE, parseTime, pinnedKeys } from "../envelope/index.mjs";

export const PUBLISHED_KEY_SET_SCHEMA_VERSION_V12 = "intentrax.trust.published_key_set/1.2";
export const SIGNER_TRUST_PURPOSE_MISMATCH = "SIGNER_PURPOSE_MISMATCH";
const PUBLISHED_PURPOSES = new Set([PURPOSE.AEP_RECORD, PURPOSE.TENANT_KEY_DIRECTORY, PURPOSE.APPROVAL_SERVICE, PURPOSE.EXECUTOR_ATTESTATION, PURPOSE.EFFECT_VERIFIER]);
const REVOCATION_REASONS = new Set(["KEY_COMPROMISE", "SUPERSEDED", "CEASED"]);
const V12_MEMBERS = ["purpose", "valid_from", "valid_until", "revoked_at", "revocation_reason"];
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const present = (key, name) => own(key, name) && key[name] !== "";

// anchorPurpose: a 1.1/1.0 key is AEP_RECORD.
export const anchorPurpose = (key) => (present(key, "purpose") ? key.purpose : PURPOSE.AEP_RECORD);

// keySetV12KeyInvalidFields mirrors the Go function (prefix like "keys.0.").
export function keySetV12KeyInvalidFields(key, v12, prefix = "") {
  const fields = [];
  if (!v12) {
    if (V12_MEMBERS.some((n) => present(key, n))) fields.push(`${prefix}purpose`);
    return fields;
  }
  if (!PUBLISHED_PURPOSES.has(key.purpose)) fields.push(`${prefix}purpose`);
  const parsed = {};
  for (const name of ["valid_from", "valid_until", "revoked_at"]) {
    if (!present(key, name)) continue;
    try {
      parsed[name] = parseTime(key[name]);
    } catch {
      fields.push(`${prefix}${name}`);
    }
  }
  if (parsed.valid_from !== undefined && parsed.valid_until !== undefined && !(parsed.valid_until > parsed.valid_from)) fields.push(`${prefix}valid_until`);
  const revoked = present(key, "revoked_at") || present(key, "revocation_reason");
  if (revoked !== (key.status === "REVOKED") || (revoked && (!present(key, "revoked_at") || !REVOCATION_REASONS.has(key.revocation_reason)))) {
    fields.push(`${prefix}revocation_reason`);
  }
  return fields;
}

// envelopeKeys mirrors TrustedKeySet.EnvelopeKeys: a KeyResolver over the
// trust-bearing keys of one envelope purpose.
export function envelopeKeys(set, purpose) {
  const keys = [];
  if (purpose === PURPOSE.AEP_RECORD || set?.schema_version !== PUBLISHED_KEY_SET_SCHEMA_VERSION_V12) return null;
  for (const key of set.keys ?? []) {
    if (key.purpose !== purpose || key.trust_bearing !== true) continue;
    const pinned = { keyId: key.key_id, keyVersion: key.key_version, publicKeyHex: key.public_key_material, purpose: key.purpose, revocationReason: key.revocation_reason ?? "" };
    for (const [name, target] of [["valid_from", "validFrom"], ["valid_until", "validUntil"], ["revoked_at", "revokedAt"]]) {
      if (!present(key, name)) continue;
      try {
        pinned[target] = parseTime(key[name]);
      } catch {
        // invalid times fail the key-set parse; ignored here as in Go
      }
    }
    if (key.status === "REVOKED" && pinned.revokedAt === undefined) pinned.revocationReason = "KEY_COMPROMISE";
    keys.push(pinned);
  }
  return keys.length > 0 ? pinnedKeys(keys) : null;
}

// aepSignerPurposeMismatch: an AEP signer whose only matching anchors have a
// purpose other than AEP_RECORD (spec 00 §5).
export function aepSignerPurposeMismatch(matches) {
  return matches.length > 0 && matches.every((m) => anchorPurpose(m) !== PURPOSE.AEP_RECORD);
}
