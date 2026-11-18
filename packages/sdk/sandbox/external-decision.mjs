// External decision evidence for the local assurance sandbox (B3), VERIFIER
// SIDE ONLY.
//
// Ported from examples/effect-assurance-demo/src/external-decision.mjs (PR
// #481; docs/architecture/INTENTRAX_EXTERNAL_DECISION_EVIDENCE.md). The
// sandbox never issues or ingests external decisions itself: a bundle may
// carry them (`external_decisions`), and `sandbox verify` assesses them.
//
// A third party's signed authorization decision is EVIDENCE, never trust:
//   - the original decision bytes are kept verbatim inside an
//     `intentrax.external_decision_evidence/0.1` wrapper, sealed with the bundle;
//   - the signature is checked ONLY against an issuer key set the relying party
//     pinned out of band. This module has no network code at all: it never
//     fetches a key set, a JWKS or a revocation list;
//   - the result is its own optional dimension, EXTERNAL_AUTHORIZATION, with
//     provenance THIRD_PARTY_ATTESTED. It never changes AUTHORIZATION;
//   - the decision must bind the same tool, target, parameters digest and time
//     window as the local decision, otherwise UNBOUND_EXTERNAL_DECISION;
//   - an external DENY against a local ALLOW is CONTRADICTED.
//   - the sandbox ceiling still applies: a bundle with a genuinely signed,
//     bound, required external decision is still LOCAL_NON_TRUST_BEARING.
//
// Format profile: a generic Ed25519-over-JCS decision SHAPED LIKE an Open
// Agent Passport (OAP) decision, plus one profile extension (`action_binding`).
// Interoperability with genuine APort/OAP decisions is UNVERIFIED: this has
// never been run against a real signed APort decision. No APort compatibility
// is claimed.

import { verify as edVerify } from "node:crypto";
import { canonicalJson, digest, sha256Hex } from "./canonical.mjs";
import { publicKeyFromRaw } from "./keys.mjs";
import { actionDigest } from "./authority.mjs";
import { PROVENANCE } from "./model.mjs";
import { isoMs } from "./time.mjs";

export const EXTERNAL_EVIDENCE_SCHEMA = "intentrax.external_decision_evidence/0.1";

// The relying party's pinned issuer key set, as the sandbox reads it. Same
// document shape as the demo's `intentrax.demo.pinned_external_issuers/0.1`,
// under a sandbox schema id. Kept separate from the local key set: external
// issuers never sign Intentrax records, and local keys never sign external
// decisions.
export const ISSUER_KEY_SET_SCHEMA = "intentrax.local.sandbox_pinned_external_issuers/0.1";

// Profile id. Deliberately NOT named "oap" or "aport": it is our reading of the
// published shape, not a tested implementation of it.
export const PROFILE_ED25519_JCS_OAP_SHAPED = "intentrax.ext_profile.ed25519_jcs_oap_shaped/0.1";
export const SUPPORTED_PROFILES = Object.freeze([PROFILE_ED25519_JCS_OAP_SHAPED]);

export const WRAPPER_FIELDS = Object.freeze([
  "bound_to",
  "decision_bytes_b64",
  "decision_digest",
  "evidence_id",
  "ingested_at",
  "issuer",
  "issuer_key_set_digest",
  "kid",
  "profile",
  "schema_version",
]);

// Fields the profile requires in the decision object (OAP prose field list,
// 2026-10-12, not decision-schema.json, which cannot be satisfied as published).
const REQUIRED_STRINGS = ["decision_id", "policy_id", "agent_id", "owner_id", "assurance_level", "passport_digest", "kid"];

export class IssuerKeySetError extends Error {}

function isObj(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

// Strict timestamps (RFC 3339 with an explicit offset): the shared parser in
// time.mjs, used everywhere the verifier compares a time.

// Parse a pinned issuer key set. Fails closed on anything malformed, including
// a missing, malformed or inverted validity window (Date.parse() of a bad
// value is NaN, every NaN comparison is false, and the signing-time checks
// would otherwise silently pass). The returned digest is what wrappers record
// as `issuer_key_set_digest`.
export function loadPinnedIssuerKeySet(doc) {
  const fail = (msg) => {
    throw new IssuerKeySetError("pinned issuer key set: " + msg);
  };
  if (!isObj(doc) || doc.schema_version !== ISSUER_KEY_SET_SCHEMA || !Array.isArray(doc.issuers)) {
    fail("unsupported or malformed document (expected schema_version " + ISSUER_KEY_SET_SCHEMA + ")");
  }
  const byIssuer = new Map();
  const kidOwner = new Map();
  for (const entry of doc.issuers) {
    if (!isObj(entry) || typeof entry.issuer !== "string" || !entry.issuer || byIssuer.has(entry.issuer)) {
      fail("missing or duplicate issuer");
    }
    if (!SUPPORTED_PROFILES.includes(entry.profile) || !Array.isArray(entry.keys) || entry.keys.length === 0) {
      fail("bad profile/keys for " + entry.issuer);
    }
    const keys = new Map();
    for (const k of entry.keys) {
      if (!isObj(k) || k.alg !== "Ed25519" || typeof k.kid !== "string" || !k.kid || kidOwner.has(k.kid)) {
        fail("bad alg or duplicate kid " + (isObj(k) ? k.kid : k));
      }
      const from = isoMs(k.valid_from);
      const until = isoMs(k.valid_until);
      if (from === null || until === null || from >= until) {
        fail("missing or invalid validity window for " + k.kid);
      }
      if (k.revoked_at !== undefined && isoMs(k.revoked_at) === null) {
        fail("invalid revoked_at for " + k.kid);
      }
      let publicKey;
      try {
        publicKey = publicKeyFromRaw(k.public_key);
      } catch {
        fail("bad public key for " + k.kid);
      }
      keys.set(k.kid, Object.freeze({ ...k, publicKey }));
      kidOwner.set(k.kid, entry.issuer);
    }
    byIssuer.set(entry.issuer, { profile: entry.profile, keys });
  }
  let setDigest;
  try {
    setDigest = digest(doc);
  } catch {
    fail("not canonicalizable");
  }
  return Object.freeze({ digest: setDigest, byIssuer, kidOwner });
}

// The profile's binding extension, derived from a local decision request.
export function actionBindingFor({ operation, resource, params }) {
  return { tool: operation, target: resource, parameters_digest: digest(params) };
}

// Signed message: RFC 8785 JCS of the decision object WITHOUT its `signature`
// member. OAP says only "signature over JCS-canonicalized decision payload";
// which members that payload excludes is not specified (UNVERIFIED).
export function externalSigningBytes(decisionWithoutSignature) {
  return Buffer.from(canonicalJson(decisionWithoutSignature), "utf8");
}

function decodeBytes(wrapper) {
  const s = wrapper.decision_bytes_b64;
  if (typeof s !== "string") return null;
  const bytes = Buffer.from(s, "base64");
  return bytes.toString("base64") === s ? bytes : null;
}

// Record-integrity checks on the wrapper (shape, digest of the carried bytes,
// and that the wrapper names THIS local decision). Returns reason codes.
export function wrapperIntegrityReasons(wrapper, d, i) {
  const where = ":" + i;
  if (!isObj(wrapper) || Object.keys(wrapper).sort().join(",") !== WRAPPER_FIELDS.join(",")
    || wrapper.schema_version !== EXTERNAL_EVIDENCE_SCHEMA || !isObj(wrapper.bound_to)) {
    return ["EXTERNAL_EVIDENCE_MALFORMED" + where];
  }
  const reasons = [];
  const bytes = decodeBytes(wrapper);
  if (!bytes || "sha256:" + sha256Hex(bytes) !== wrapper.decision_digest) {
    reasons.push("EXTERNAL_DECISION_DIGEST_MISMATCH" + where);
  }
  if (wrapper.bound_to.intentrax_decision_id !== d.decision_id || wrapper.bound_to.action_digest !== actionDigest(d.request)) {
    reasons.push("EXTERNAL_EVIDENCE_BINDING_MISMATCH" + where);
  }
  return reasons;
}

// ---- verification ---------------------------------------------------------

export const EXTERNAL_LIMITATION_TEXT = Object.freeze({
  EXTERNAL_ISSUER_POLICY_UNKNOWN:
    "Intentrax cannot re-evaluate the external issuer's policy; the decision shows what the issuer concluded, not that it was right.",
  EXTERNAL_ISSUER_REVOCATION_NOT_REQUERIED:
    "Passport or key suspension/revocation after issuance is not re-queried offline; only the pinned key set's validity window is applied.",
  EXTERNAL_AGENT_IDENTITY_NOT_MAPPED:
    "The issuer's agent_id/owner_id are not mapped to the sandbox agent; the binding covers tool, target, parameters and time only.",
  EXTERNAL_PROFILE_INTEROP_UNVERIFIED:
    "The OAP-shaped profile follows the published OAP text; it has not been tested against a genuine signed APort decision. No APort compatibility is claimed.",
  EXTERNAL_SIGNING_TIME_SELF_ASSERTED:
    "The external decision's created_at is asserted by its issuer; key validity and expiry are judged against it.",
  ISSUER_KEY_SET_CHANGED_SINCE_INGESTION:
    "The relying party's pinned issuer key set differs from the one recorded at ingestion; the verifier used its own pinned set.",
});

const BASE_LIMITATIONS = [
  "EXTERNAL_ISSUER_POLICY_UNKNOWN",
  "EXTERNAL_ISSUER_REVOCATION_NOT_REQUERIED",
  "EXTERNAL_AGENT_IDENTITY_NOT_MAPPED",
  "EXTERNAL_PROFILE_INTEROP_UNVERIFIED",
  "EXTERNAL_SIGNING_TIME_SELF_ASSERTED",
];

const SIG_RE = /^ed25519:[A-Za-z0-9+/]+={0,2}$/;

// Assess one wrapped decision. Never throws.
//   ctx: { d (local decision payload), reports, effectConfirmed, issuerKeys }
function assessOne(wrapper, ctx) {
  const { d, reports, effectConfirmed, issuerKeys } = ctx;
  const out = {
    evidence_id: wrapper.evidence_id,
    issuer: wrapper.issuer,
    kid: wrapper.kid,
    profile: wrapper.profile,
    result: "INSUFFICIENT_EVIDENCE",
    reasons: [],
    signature: "NOT_CHECKED",
    bound: null,
    outcome: null,
    created_at: null,
    expires_at: null,
    key_set_digest_matches: issuerKeys ? wrapper.issuer_key_set_digest === issuerKeys.digest : null,
  };
  const done = (result, ...reasons) => {
    out.result = result;
    out.reasons.push(...reasons);
    return out;
  };

  if (!SUPPORTED_PROFILES.includes(wrapper.profile)) return done("INSUFFICIENT_EVIDENCE", "UNSUPPORTED_EXTERNAL_PROFILE");
  let decision;
  try {
    decision = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(decodeBytes(wrapper)));
  } catch {
    return done("FAILED", "EXTERNAL_DECISION_MALFORMED");
  }
  if (!isObj(decision)) return done("FAILED", "EXTERNAL_DECISION_MALFORMED");
  if (decision.kid !== wrapper.kid) return done("FAILED", "EXTERNAL_KID_MISMATCH");

  // -- signature, against the pinned issuer key set only --
  if (!issuerKeys) return done("NOT_ASSESSED", "NO_PINNED_ISSUER_KEY_SET");
  const owner = issuerKeys.kidOwner.get(wrapper.kid);
  if (owner === undefined) return done("INSUFFICIENT_EVIDENCE", "EXTERNAL_ISSUER_KEY_NOT_PINNED");
  if (owner !== wrapper.issuer) return done("INSUFFICIENT_EVIDENCE", "KID_PINNED_FOR_DIFFERENT_ISSUER");
  const pinnedIssuer = issuerKeys.byIssuer.get(owner);
  if (pinnedIssuer.profile !== wrapper.profile) return done("INSUFFICIENT_EVIDENCE", "PROFILE_NOT_PINNED_FOR_ISSUER");
  const key = pinnedIssuer.keys.get(wrapper.kid);
  const { signature, ...unsigned } = decision;
  if (typeof signature !== "string" || !SIG_RE.test(signature)) return done("FAILED", "EXTERNAL_SIGNATURE_MALFORMED");
  const sig = Buffer.from(signature.slice("ed25519:".length), "base64");
  let message;
  try {
    message = externalSigningBytes(unsigned);
  } catch {
    // The sandbox's JCS covers integers only; a decision with other numbers
    // cannot be checked here (RFC 8785 number serialization not implemented).
    return done("INSUFFICIENT_EVIDENCE", "EXTERNAL_DECISION_NOT_CANONICALIZABLE");
  }
  let valid = false;
  try {
    valid = sig.length === 64 && edVerify(null, message, key.publicKey, sig);
  } catch {
    valid = false;
  }
  if (!valid) {
    out.signature = "INVALID";
    return done("FAILED", "EXTERNAL_SIGNATURE_INVALID_FOR_PINNED_KEY");
  }
  out.signature = "VALID_PINNED_KEY";

  // -- shape (profile) --
  const bad = REQUIRED_STRINGS.filter((f) => typeof decision[f] !== "string");
  if (typeof decision.allow !== "boolean") bad.push("allow");
  if (!Array.isArray(decision.reasons) || !decision.reasons.length || !decision.reasons.every((r) => isObj(r) && typeof r.code === "string")) {
    bad.push("reasons");
  }
  const created = isoMs(decision.created_at);
  if (created === null) bad.push("created_at");
  if (!Number.isSafeInteger(decision.expires_in) || decision.expires_in < 0) bad.push("expires_in");
  if (bad.length) return done("INSUFFICIENT_EVIDENCE", ...bad.map((f) => "EXTERNAL_DECISION_SHAPE_INVALID:" + f));
  out.outcome = decision.allow ? "ALLOW" : "DENY";
  out.created_at = decision.created_at;
  const expires = created + decision.expires_in * 1000;
  out.expires_at = new Date(expires).toISOString().replace(/\.\d{3}Z$/, "Z");

  // -- key validity at the (self-asserted) signing time --
  if (created < isoMs(key.valid_from) || created >= isoMs(key.valid_until)) {
    return done("INSUFFICIENT_EVIDENCE", "EXTERNAL_KEY_NOT_VALID_AT_SIGNING_TIME");
  }
  if (key.revoked_at !== undefined && created >= isoMs(key.revoked_at)) {
    return done("INSUFFICIENT_EVIDENCE", "EXTERNAL_KEY_REVOKED_AT_SIGNING_TIME");
  }

  // -- binding: same tool, target, parameters digest, time window --
  const unbound = [];
  const b = decision.action_binding;
  if (!isObj(b)) {
    unbound.push("UNBOUND_EXTERNAL_DECISION:NO_ACTION_BINDING");
  } else {
    if (b.tool !== d.request.operation) unbound.push("UNBOUND_EXTERNAL_DECISION:tool");
    if (b.target !== d.request.resource) unbound.push("UNBOUND_EXTERNAL_DECISION:target");
    if (b.parameters_digest !== digest(d.request.params)) unbound.push("UNBOUND_EXTERNAL_DECISION:parameters_digest");
  }
  // The action happens at the first execution start, or (no execution) at the
  // local decision. The external decision must precede it...
  // Strict (explicit offset), and no `??` fallback: a report whose
  // started_at is missing or unparseable fails closed instead of silently
  // using the decision time (demo #490/#491 parity).
  const actionAt = isoMs(reports.length ? reports[0].started_at : d.decided_at);
  if (actionAt === null || created > actionAt) unbound.push("UNBOUND_EXTERNAL_DECISION:issued_after_action");
  out.bound = unbound.length === 0;
  if (unbound.length) return done("INSUFFICIENT_EVIDENCE", ...unbound);
  // ...and still be in force when it happens.
  if (actionAt >= expires) return done("INSUFFICIENT_EVIDENCE", "EXTERNAL_DECISION_EXPIRED");

  // -- conflict rules --
  if (out.outcome === "DENY" && d.outcome === "ALLOW") {
    return done("CONTRADICTED", "EXTERNAL_DENY_INTENTRAX_ALLOW",
      ...(reports.length ? ["EXECUTED_DESPITE_EXTERNAL_DENY"] : []));
  }
  // Informational cross-checks: the external decision is genuine and bound,
  // so the dimension stays VERIFIED, but the report says what happened next.
  if (out.outcome === "ALLOW" && d.outcome === "DENY") out.reasons.push("EXTERNAL_ALLOW_INTENTRAX_DENY");
  if (out.outcome === "ALLOW" && effectConfirmed === "CONTRADICTED") out.reasons.push("EXTERNAL_ALLOW_BUT_EFFECT_CONTRADICTED");
  out.result = "VERIFIED";
  return out;
}

// Assess every wrapped decision and aggregate into one EXTERNAL_AUTHORIZATION
// assessment body: { result, provenance, reasons, limitations, evidence_digests, detail }.
//   authorizationIssuers: issuers the relying party's assurance profile names.
//   Empty = EXTERNAL_AUTHORIZATION is informational (non-required) and any
//   pinned issuer's VERIFIED decision counts as VERIFIED.
export function assessExternalAuthorization({
  wrappers, d, reports, effectConfirmed, issuerKeys, authorizationIssuers = [],
}) {
  const per = wrappers.map((w) => assessOne(w, { d, reports, effectConfirmed, issuerKeys }));
  const limitations = [...BASE_LIMITATIONS];
  if (per.some((p) => p.key_set_digest_matches === false)) limitations.push("ISSUER_KEY_SET_CHANGED_SINCE_INGESTION");
  const reasons = [...new Set(per.flatMap((p) => p.reasons))];
  const results = per.map((p) => p.result);
  let result;
  if (!per.length) {
    result = "INSUFFICIENT_EVIDENCE";
    reasons.push("NO_EXTERNAL_DECISION_IN_BUNDLE");
  } else if (results.includes("FAILED")) {
    result = "FAILED";
  } else if (results.includes("CONTRADICTED")) {
    result = "CONTRADICTED";
  } else {
    const eligible = per.filter((p) => p.result === "VERIFIED"
      && (!authorizationIssuers.length || authorizationIssuers.includes(p.issuer)));
    if (eligible.length) {
      result = "VERIFIED";
    } else if (results.includes("VERIFIED")) {
      result = "INSUFFICIENT_EVIDENCE";
      reasons.push("EXTERNAL_ISSUER_NOT_NAMED_BY_PROFILE");
    } else {
      result = results.every((r) => r === "NOT_ASSESSED") ? "NOT_ASSESSED" : "INSUFFICIENT_EVIDENCE";
    }
  }
  return {
    result,
    provenance: PROVENANCE.THIRD_PARTY_ATTESTED,
    reasons,
    limitations,
    evidence_digests: wrappers.map((w) => w.decision_digest),
    detail: {
      substitutes_for_authorization: false,
      profile_names_issuers: authorizationIssuers,
      pinned_issuer_key_set_digest: issuerKeys ? issuerKeys.digest : null,
      decisions: per,
    },
  };
}
