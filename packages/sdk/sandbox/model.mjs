// Evidence-quality model for the local assurance sandbox.
//
// Ported from examples/effect-assurance-demo/src/model.mjs (PRs #449, #477;
// INTENTRAX_ASSURANCE_GAP_ANALYSIS.md §5). The eight dimensions, the
// profiles and the §5.4 verdict rule are unchanged. The sandbox adds ONE
// thing: a verdict ceiling. Every bundle the sandbox can produce is signed by
// ephemeral local keys that are not trust-bearing, so the strongest verdict a
// local bundle can ever receive is LOCAL_NON_TRUST_BEARING, never
// VERIFIED_FOR_SCOPE, whatever key set the user pins.

export const DIMENSIONS = Object.freeze([
  "RECORD_INTEGRITY",
  "SIGNER_AUTHENTICITY",
  "AUTHORIZATION",
  "EXECUTION_REPORTED",
  "EXECUTION_ATTESTED",
  "EFFECT_OBSERVED",
  "EFFECT_CONFIRMED",
  "CAUSAL_CHAIN",
]);

// Optional dimensions (B3, INTENTRAX_EXTERNAL_DECISION_EVIDENCE.md; ported from
// the demo, PR #481). Not in DIMENSIONS: a report carries one only when the
// bundle has the evidence it assesses or the relying party requires it, so
// ordinary sandbox reports keep exactly the eight core dimensions.
// EXTERNAL_AUTHORIZATION: a third party's signed authorization decision,
// verified against a relying-party-pinned issuer key set. Provenance is always
// THIRD_PARTY_ATTESTED; it never stands in for the local AUTHORIZATION.
export const OPTIONAL_DIMENSIONS = Object.freeze(["EXTERNAL_AUTHORIZATION"]);

// §5.2, plus OBSERVED for the EFFECT_OBSERVED dimension.
export const RESULTS = Object.freeze([
  "VERIFIED",
  "REPORTED",
  "ATTESTED",
  "OBSERVED",
  "CONFIRMED",
  "CONTRADICTED",
  "PENDING",
  "INSUFFICIENT_EVIDENCE",
  "NOT_ASSESSED",
  "NOT_APPLICABLE",
  "FAILED",
]);

export const PROVENANCE = Object.freeze({
  SELF_REPORTED: "SELF_REPORTED",
  INTENTRAX_DECISION: "INTENTRAX_DECISION",
  ENFORCEMENT_ATTESTED: "ENFORCEMENT_ATTESTED",
  AUTHORITATIVE_SOURCE: "AUTHORITATIVE_SOURCE",
  THIRD_PARTY_ATTESTED: "THIRD_PARTY_ATTESTED",
  VERIFIER_COMPUTED: "VERIFIER_COMPUTED",
});

// Assurance profiles, weakest first. EXECUTION_REPORTED is deliberately never
// required: a self-report can never satisfy a profile.
export const PROFILES = Object.freeze({
  DECISION_RECORD: ["RECORD_INTEGRITY", "SIGNER_AUTHENTICITY", "AUTHORIZATION"],
  AUTHORIZED_AND_ATTESTED: ["RECORD_INTEGRITY", "SIGNER_AUTHENTICITY", "AUTHORIZATION", "EXECUTION_ATTESTED"],
  EFFECT_CONFIRMED: ["RECORD_INTEGRITY", "SIGNER_AUTHENTICITY", "AUTHORIZATION", "EFFECT_OBSERVED", "EFFECT_CONFIRMED"],
  CAUSAL_CHAIN: [
    "RECORD_INTEGRITY", "SIGNER_AUTHENTICITY", "AUTHORIZATION", "EFFECT_OBSERVED", "EFFECT_CONFIRMED", "CAUSAL_CHAIN",
  ],
});

export const PROFILE_STRENGTH = Object.freeze({
  DECISION_RECORD: 0,
  AUTHORIZED_AND_ATTESTED: 1,
  EFFECT_CONFIRMED: 2,
  CAUSAL_CHAIN: 3,
});

export function strongerProfile(a, b) {
  return PROFILE_STRENGTH[a] >= PROFILE_STRENGTH[b] ? a : b;
}

export const VERDICTS = Object.freeze({
  VERIFICATION_FAILED: "VERIFICATION_FAILED",
  INTEGRITY_ONLY: "INTEGRITY_ONLY",
  CONFLICTING_EVIDENCE: "CONFLICTING_EVIDENCE",
  PENDING_FINALITY: "PENDING_FINALITY",
  INSUFFICIENT_EVIDENCE: "INSUFFICIENT_EVIDENCE",
  // Sandbox-only. The ceiling for anything signed by local keys: every check
  // that the bundle can carry passed, but no signer is trust-bearing, so this
  // is never production assurance.
  LOCAL_NON_TRUST_BEARING: "LOCAL_NON_TRUST_BEARING",
  VERIFIED_FOR_SCOPE: "VERIFIED_FOR_SCOPE",
});

// Rule precedence, first-matching rule = 0. LOCAL_NON_TRUST_BEARING sits
// directly below VERIFIED_FOR_SCOPE: the ceiling removes the positive claim
// but never hides a negative finding (a contradiction stays a contradiction).
export const VERDICT_PRECEDENCE = Object.freeze({
  VERIFICATION_FAILED: 0,
  INTEGRITY_ONLY: 1,
  CONFLICTING_EVIDENCE: 2,
  PENDING_FINALITY: 3,
  INSUFFICIENT_EVIDENCE: 4,
  LOCAL_NON_TRUST_BEARING: 5,
  VERIFIED_FOR_SCOPE: 6,
});

export const LOCAL_VERDICT_CEILING = VERDICTS.LOCAL_NON_TRUST_BEARING;

const WEAK = new Set(["REPORTED", "INSUFFICIENT_EVIDENCE", "NOT_ASSESSED"]);
const SATISFYING = new Set(["VERIFIED", "ATTESTED", "OBSERVED", "CONFIRMED"]);

// §5.4 order, with the V-1 change (CONTRADICTED anywhere -> CONFLICTING_EVIDENCE).
// `assessments` is { [dimension]: result }.
// A required dimension that is missing or NOT_APPLICABLE counts as
// INSUFFICIENT_EVIDENCE (never a bare VALID).
// `extraRequired`: dimensions the relying party adds to the profile (e.g.
// EXTERNAL_AUTHORIZATION when it names an external issuer). Additive only: it
// can make a verdict weaker, never stronger.
export function deriveVerdict(assessments, profile, { extraRequired = [] } = {}) {
  if (!PROFILES[profile]) {
    throw new Error("unknown assurance profile " + profile);
  }
  const required = [...new Set([...PROFILES[profile], ...extraRequired])];
  const all = Object.values(assessments);
  const req = required.map((d) => assessments[d] ?? "INSUFFICIENT_EVIDENCE");
  if (all.includes("FAILED")) return VERDICTS.VERIFICATION_FAILED;
  if (assessments.SIGNER_AUTHENTICITY !== "VERIFIED") return VERDICTS.INTEGRITY_ONLY;
  // V-1 (honest verdicts): a CONTRADICTED result in ANY dimension, required by
  // the profile or not, is a conflict and never a pass. Mirrors the demo,
  // Go DeriveAssuranceVerdict and the TS SDK deriveAssuranceVerdict.
  if (all.includes("CONTRADICTED")) return VERDICTS.CONFLICTING_EVIDENCE;
  if (req.includes("PENDING")) return VERDICTS.PENDING_FINALITY;
  if (req.some((r) => WEAK.has(r) || !SATISFYING.has(r))) return VERDICTS.INSUFFICIENT_EVIDENCE;
  return VERDICTS.VERIFIED_FOR_SCOPE;
}

// The sandbox ceiling: the weaker of the derived verdict and
// LOCAL_NON_TRUST_BEARING. Applied unconditionally to every local bundle.
export function applyLocalCeiling(verdict) {
  if (!Object.prototype.hasOwnProperty.call(VERDICT_PRECEDENCE, verdict)) {
    throw new Error("unknown verdict " + verdict);
  }
  return VERDICT_PRECEDENCE[verdict] > VERDICT_PRECEDENCE[LOCAL_VERDICT_CEILING] ? LOCAL_VERDICT_CEILING : verdict;
}

// Limitations every local sandbox bundle carries.
export const GLOBAL_LIMITATIONS = Object.freeze([
  {
    code: "LOCAL_KEYS_NOT_TRUST_BEARING",
    text: "Every signature was made by an ephemeral key generated on this machine (environment: local, " +
      "trust_bearing: false). Anyone can generate such keys; this is not production assurance.",
  },
  {
    code: "PREVIEW_FORMAT_NOT_PRODUCTION_AEP",
    text: "The bundle uses the preview effect-assurance format (intentrax.effect_evidence/0.1), not the " +
      "production AEP export; production verifiers, hosted verify and the Verification Mark do not accept it.",
  },
  {
    code: "SIGNING_TIME_SELF_ASSERTED",
    text: "Signing times are asserted by each local signer; there is no trusted timestamp authority.",
  },
  {
    code: "COMPLETENESS_NOT_ESTABLISHED",
    text: "Nothing proves every consequential agent action was routed through Intentrax.",
  },
  {
    code: "EXECUTION_NOT_ATTESTED",
    text: "No trusted in-path enforcement component observed the call; execution is self-reported.",
  },
  {
    code: "NO_REVOCATION_OR_BUDGET_IN_SANDBOX",
    text: "The mandate is minted for this run only; the sandbox has no revocation registry and no budget ledger.",
  },
]);
