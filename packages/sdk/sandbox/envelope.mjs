// Signed envelopes for the local assurance sandbox.
//
// Ported from examples/effect-assurance-demo/src/envelope.mjs (PRs #449,
// #477). Changes: a sandbox-specific signing domain (so a local signature can
// never be replayed as any other Intentrax envelope), the payload types the
// sandbox uses, and no revocation handling (local keys are never revoked;
// they simply expire with the run).
//
// { payload_type, payload, signatures: [{ key_id, alg, public_key, sig }] }
//
// The signed message is ALWAYS rebuilt by the verifier from `payload_type` and
// `payload`:  DOMAIN || canonical_json({ payload_type, payload }).
// `public_key` inside a signature entry is SELF-ASSERTED; it is used only to
// check record integrity when no pinned key matches and never establishes who
// signed.

import { sign as edSign, verify as edVerify } from "node:crypto";
import { canonicalJson, digest } from "./canonical.mjs";
import { publicKeyFromRaw, ROLES } from "./keys.mjs";
import { isoMs } from "./time.mjs";

const DOMAIN = "intentrax-local-sandbox-envelope/0.1\n";

export const PAYLOAD_TYPES = Object.freeze({
  MANDATE: "intentrax.mandate/0.1",
  DECISION: "intentrax.decision/0.1",
  EXECUTION_REPORT: "intentrax.execution_report/0.1",
  EFFECT_EVIDENCE: "intentrax.effect_evidence/0.1",
  BUNDLE_SEAL: "intentrax.local_bundle_seal/0.1",
});

export const SIGNING_TIME_FIELD = Object.freeze({
  [PAYLOAD_TYPES.MANDATE]: "issued_at",
  [PAYLOAD_TYPES.DECISION]: "decided_at",
  [PAYLOAD_TYPES.EXECUTION_REPORT]: "reported_at",
  [PAYLOAD_TYPES.EFFECT_EVIDENCE]: "attested_at",
  [PAYLOAD_TYPES.BUNDLE_SEAL]: "sealed_at",
});

export function expectedRole(payloadType) {
  switch (payloadType) {
    case PAYLOAD_TYPES.MANDATE:
      return ROLES.PRINCIPAL;
    case PAYLOAD_TYPES.DECISION:
    case PAYLOAD_TYPES.BUNDLE_SEAL:
      return ROLES.DECISION_SERVICE;
    case PAYLOAD_TYPES.EXECUTION_REPORT:
      return ROLES.EXECUTOR;
    case PAYLOAD_TYPES.EFFECT_EVIDENCE:
      return ROLES.EFFECT_VERIFIER;
    default:
      return null;
  }
}

function signingMessage(payloadType, payload) {
  return Buffer.from(DOMAIN + canonicalJson({ payload_type: payloadType, payload }), "utf8");
}

export function signEnvelope(payloadType, payload, signer) {
  const sig = edSign(null, signingMessage(payloadType, payload), signer.privateKey);
  return {
    payload_type: payloadType,
    payload,
    signatures: [{
      key_id: signer.key_id,
      alg: "Ed25519",
      public_key: signer.public_key,
      sig: sig.toString("base64url"),
    }],
  };
}

// Content digest of an envelope: binds payload_type + payload.
export function envelopeDigest(envelope) {
  return digest({ payload_type: envelope.payload_type, payload: envelope.payload });
}

// Verify one envelope. Returns a structured result; never throws on bad input.
//   integrity:    VERIFIED | FAILED
//   authenticity: VERIFIED | FAILED | INSUFFICIENT_EVIDENCE (signer unknown) | NOT_ASSESSED (no key set)
export function verifyEnvelope(envelope, { pinned = null } = {}) {
  const out = { integrity: "FAILED", authenticity: "FAILED", key_id: null, reasons: [] };
  const fail = (reason, which = "both") => {
    out.reasons.push(reason);
    if (which === "both" || which === "integrity") out.integrity = "FAILED";
    if (which === "both" || which === "authenticity") out.authenticity = "FAILED";
    return out;
  };
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) {
    return fail("ENVELOPE_MALFORMED");
  }
  if (Object.keys(envelope).sort().join(",") !== "payload,payload_type,signatures") {
    return fail("ENVELOPE_UNEXPECTED_FIELDS");
  }
  if (!Object.values(PAYLOAD_TYPES).includes(envelope.payload_type)) {
    return fail("ENVELOPE_UNKNOWN_PAYLOAD_TYPE");
  }
  if (!Array.isArray(envelope.signatures) || envelope.signatures.length !== 1) {
    return fail("ENVELOPE_REQUIRES_EXACTLY_ONE_SIGNATURE");
  }
  const s = envelope.signatures[0];
  if (!s || typeof s !== "object" || Object.keys(s).sort().join(",") !== "alg,key_id,public_key,sig" || s.alg !== "Ed25519") {
    return fail("SIGNATURE_ENTRY_MALFORMED");
  }
  out.key_id = s.key_id;
  let message;
  try {
    message = signingMessage(envelope.payload_type, envelope.payload);
  } catch {
    return fail("PAYLOAD_NOT_CANONICALIZABLE");
  }
  const sig = Buffer.from(String(s.sig), "base64url");
  const check = (publicKey) => {
    try {
      return edVerify(null, message, publicKey, sig);
    } catch {
      return false;
    }
  };

  const pinnedEntry = pinned ? pinned.get(s.key_id) : undefined;
  if (pinnedEntry) {
    if (s.public_key !== pinnedEntry.public_key) {
      return fail("EMBEDDED_KEY_DIFFERS_FROM_PINNED_KEY");
    }
    if (!check(pinnedEntry.publicKey)) {
      return fail("SIGNATURE_INVALID_FOR_PINNED_KEY");
    }
    out.integrity = "VERIFIED";
    const role = expectedRole(envelope.payload_type);
    if (pinnedEntry.role !== role) {
      return fail("SIGNER_ROLE_MISMATCH:" + pinnedEntry.role + "!=" + role, "authenticity");
    }
    const field = SIGNING_TIME_FIELD[envelope.payload_type];
    // Strict timestamps (explicit offset; #491 parity).
    const signedAt = isoMs(envelope.payload && envelope.payload[field]);
    if (signedAt === null) {
      return fail("SIGNING_TIME_MISSING", "authenticity");
    }
    // The loader guarantees the bounds parse (strict, explicit offset, from < until).
    if (signedAt < isoMs(pinnedEntry.valid_from) || signedAt >= isoMs(pinnedEntry.valid_until)) {
      return fail("SIGNER_KEY_NOT_VALID_AT_SIGNING_TIME", "authenticity");
    }
    out.authenticity = "VERIFIED";
    out.signer = {
      key_id: pinnedEntry.key_id,
      role: pinnedEntry.role,
      principal: pinnedEntry.principal,
      environment: pinnedEntry.environment,
      trust_bearing: pinnedEntry.trust_bearing,
    };
    return out;
  }

  let embedded;
  try {
    embedded = publicKeyFromRaw(String(s.public_key));
  } catch {
    return fail("SIGNATURE_UNVERIFIABLE_NO_KEY");
  }
  if (!check(embedded)) {
    return fail("SIGNATURE_INVALID_FOR_EMBEDDED_KEY");
  }
  out.integrity = "VERIFIED";
  if (pinned) {
    out.authenticity = "INSUFFICIENT_EVIDENCE";
    out.reasons.push("SIGNER_NOT_IN_PINNED_KEY_SET");
  } else {
    out.authenticity = "NOT_ASSESSED";
    out.reasons.push("NO_LOCAL_KEY_SET_SUPPLIED");
  }
  return out;
}
