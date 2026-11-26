// Verification assessment for proofs that carry the pre-approval members
// (admission_binding/0.1, policy_binding/1.2). Port of the Go offline
// verifier (engine/internal/verificationinfra/offlineproof/assessment.go,
// authorizationAssessment and buildVerificationAssessment, PR #564), with the
// same results, reasons, limitation codes and texts, in the same order.
//
// Honest verdicts:
//   - Under 1.2 a SATISFIED or REJECTED constraint counts as checked only when
//     its approval evidence verified (spec 02 §5); otherwise it is reported
//     APPROVAL_EVIDENCE_NOT_SUPPLIED:<id> and AUTHORIZATION stays REPORTED at
//     best. Unknown or absent approvals never upgrade anything.
//   - ENFORCED follows spec 03 §6.6: an authentic, re-checked refusal is
//     VERIFIED (never CONTRADICTED); without a re-check it is REPORTED.
//   - A DENIED admission record authorised nothing to run: execution and
//     effect dimensions are NOT_APPLICABLE, decision_outcome is DENY.
//   - Every ADMITTED record carries EXECUTE_RECHECK_NOT_ATTESTED (spec 01
//     §4.3, §8.6) until a spec 05 statement attests the re-check.
//
// For a proof with neither member, buildPreapprovalAssessment returns exactly
// what buildLegacyVerificationAssessment returns.

import {
  ASSURANCE_LIMITATION_TEXT,
  ASSURANCE_PROFILES,
  LEGACY_DECISION_RECORD_LIMITATIONS,
  VERIFICATION_ASSESSMENT_SCHEMA_VERSION,
  deriveAssuranceVerdict,
  signerAuthenticityAssessment,
} from "../index.js";
import { POLICY_BINDING_PROFILE_V12 } from "./policy-binding.mjs";
import { decisionOutcome } from "./admission.mjs";
import { APPROVAL_EVIDENCE, DIRECTORY_TRUST, approvalEvidenceReason } from "./approvals.mjs";

export const PREAPPROVAL_LIMITATION_TEXT = Object.freeze({
  POLICY_ENFORCED_AT_ADMISSION: "The decision was enforced at Intentrax admission: a request this policy does not allow receives no admitted record. Whether the action could run without an admitted record depends on the gate in front of the tool; see EXECUTION_ATTESTED.",
  EXECUTE_RECHECK_NOT_ATTESTED: "This record admits only a call whose arguments hash to the sealed arguments_hash, and the gate in front of the tool must recompute that hash at execution time and refuse on a mismatch. The record cannot show that the gate did so; only an execution statement (EXECUTION_ATTESTED) can.",
  APPROVER_IDENTITY_ATTESTED_BY_INTENTRAX: "The approval was signed by the Intentrax approval service on behalf of an approver who signed in with an external identity provider. Intentrax attests who approved; the approver did not sign with their own key.",
  APPROVER_KEY_VOUCHED_BY_INTENTRAX: "The approver's key is trusted because the Intentrax tenant key directory lists it. The relying party did not pin the tenant's approver keys itself.",
  POLICY_FACTS_DERIVED_FROM_ADMITTED_ARGUMENTS: "The verifier re-derived the policy facts from the admitted arguments and the tenant's fact map, and re-ran the published policy over them. That the tool later received those arguments is shown only by EXECUTION_ATTESTED.",
  APPROVAL_EVIDENCE_NOT_CHECKED: "A constraint is sealed as approved or rejected, but the approval evidence was not supplied with the proof or could not be re-checked. The sealed status is Intentrax's statement; this verifier did not check who approved or rejected the request.",
});

const LIMITATION_TEXT = Object.freeze({ ...ASSURANCE_LIMITATION_TEXT, ...PREAPPROVAL_LIMITATION_TEXT });
const POLICY_BOUND_LIMITATIONS = ["POLICY_EVALUATION_NOT_RECHECKABLE", "POLICY_DECISION_NOT_ENFORCED"];
const RECHECKED_POLICY_LIMITATIONS = ["POLICY_EVENT_SELF_REPORTED", "POLICY_DECISION_NOT_ENFORCED"];

// authorizationAssessment mirrors the Go function of the same name.
// evidence is the checkApprovalEvidence result (one check per 1.2 SATISFIED
// or REJECTED constraint); a constraint without a check is NOT_SUPPLIED.
// VERIFIED evidence counts as checked; INVALID makes AUTHORIZATION FAILED;
// anything else is only stated and never upgrades the result.
export function authorizationAssessment(binding, reevaluation = null, admission = null, evidence = []) {
  if (binding === null || binding === undefined) {
    return { result: "NOT_ASSESSED", provenance: "INTENTRAX_DECISION", reasons: ["DECISION_NOT_REEVALUATED_OFFLINE"], limitations: ["POLICY_BINDING_SYNTHETIC"] };
  }
  const v12 = binding.binding_profile === POLICY_BINDING_PROFILE_V12;
  const enforced = binding.enforcement === "ENFORCED";
  const denied = admission !== null && admission.admission_status === "DENIED";
  const rechecked = reevaluation !== null && reevaluation !== undefined && reevaluation.status === "MATCH";
  const checks = new Map(evidence.map((c) => [c.constraint_id, c]));
  const unchecked = [];
  const unevidenced = [];
  const evidenceReasons = [];
  let invalid = false;
  let attestedByIntentrax = false;
  let vouchedByIntentrax = false;
  for (const c of binding.constraints) {
    if (c.status === "NOT_EVALUATED") {
      unchecked.push(c.constraint_id);
    } else if (v12) {
      const check = checks.get(c.constraint_id) ?? { constraint_id: c.constraint_id, status: APPROVAL_EVIDENCE.NOT_SUPPLIED };
      evidenceReasons.push(approvalEvidenceReason(check));
      if (check.status === APPROVAL_EVIDENCE.VERIFIED) {
        for (const a of check.approvals) {
          if (a.identity_method === "INTENTRAX_ATTESTED_OIDC") attestedByIntentrax = true;
          else if (check.directory_trust === DIRECTORY_TRUST.VOUCHED_BY_INTENTRAX) vouchedByIntentrax = true;
        }
      } else {
        if (check.status === APPROVAL_EVIDENCE.INVALID) invalid = true;
        unevidenced.push(c.constraint_id);
      }
    }
  }
  let result = "INSUFFICIENT_EVIDENCE";
  const reasons = [];
  if (binding.decision === "COMPLIANT") reasons.push("POLICY_DECISION_COMPLIANT");
  else if (binding.decision === "NON_COMPLIANT") reasons.push("POLICY_DECISION_NON_COMPLIANT");
  else reasons.push("POLICY_DECISION_ERROR");
  if (enforced && denied) {
    result = rechecked && unevidenced.length === 0 ? "VERIFIED" : "REPORTED";
    reasons.push("POLICY_DECISION_REFUSED_AS_ENFORCED");
  } else if (enforced) {
    result = rechecked && unchecked.length === 0 && unevidenced.length === 0 ? "VERIFIED" : "REPORTED";
    reasons.push("POLICY_DECISION_ENFORCED");
  } else if (binding.decision === "COMPLIANT") {
    result = rechecked && unchecked.length === 0 && unevidenced.length === 0 ? "VERIFIED" : "REPORTED";
  } else if (binding.decision === "NON_COMPLIANT") {
    result = "CONTRADICTED";
  }
  // The record bound bad approval evidence (spec 02 §5.2).
  if (invalid) result = "FAILED";
  let provenance = "INTENTRAX_DECISION";
  let limitations = [...POLICY_BOUND_LIMITATIONS];
  if (rechecked) {
    provenance = "VERIFIER_COMPUTED";
    limitations = [...RECHECKED_POLICY_LIMITATIONS];
    reasons.push("POLICY_EVALUATION_RECHECKED");
    // The request facts were re-derived from the admitted arguments and the
    // tenant's fact map (spec 03 §6.5, §6.7).
    if (reevaluation.facts_rederived === true) {
      reasons.push("FACTS_REDERIVED");
      limitations = limitations.map((code) => (code === "POLICY_EVENT_SELF_REPORTED" ? "POLICY_FACTS_DERIVED_FROM_ADMITTED_ARGUMENTS" : code));
    }
  } else {
    reasons.push("POLICY_EVALUATION_NOT_RECHECKED_OFFLINE");
    if (reevaluation && typeof reevaluation.reason === "string" && reevaluation.reason !== "") reasons.push(`POLICY_REEVALUATION_${reevaluation.reason}`);
  }
  if (enforced) limitations = limitations.map((code) => (code === "POLICY_DECISION_NOT_ENFORCED" ? "POLICY_ENFORCED_AT_ADMISSION" : code));
  for (const id of unchecked) reasons.push(`POLICY_CONSTRAINT_NOT_EVALUATED:${id}`);
  reasons.push(...evidenceReasons);
  if (unchecked.length > 0) limitations.push("POLICY_CONSTRAINT_NOT_EVALUATED");
  if (unevidenced.length > 0 && !invalid) limitations.push("APPROVAL_EVIDENCE_NOT_CHECKED");
  if (attestedByIntentrax) limitations.push("APPROVER_IDENTITY_ATTESTED_BY_INTENTRAX");
  if (vouchedByIntentrax) limitations.push("APPROVER_KEY_VOUCHED_BY_INTENTRAX");
  return { result, provenance, reasons, limitations };
}

// buildPreapprovalAssessment mirrors buildVerificationAssessment.
export function buildPreapprovalAssessment({ signerTrust, keySetSupplied, policyBinding = null, policyReevaluation = null, admissionBinding = null, approvalEvidence = [] } = {}) {
  // An AEP signer that matches only a key pinned for another purpose, or
  // whose 1.2 validity window excludes the record's sealed signing time, is
  // FAILED (spec 00 §5: authenticity FAILED).
  const signer = (signerTrust === "SIGNER_PURPOSE_MISMATCH" || signerTrust === "SIGNER_KEY_NOT_VALID_AT_SIGNING_TIME") && keySetSupplied === true
    ? { result: "FAILED", reasons: [signerTrust] }
    : signerAuthenticityAssessment(signerTrust, keySetSupplied === true);
  const authorization = authorizationAssessment(policyBinding, policyReevaluation, admissionBinding, approvalEvidence);
  const signerVerified = signer.result === "VERIFIED";
  const row = (dimension, result, provenance, reasons, limitations) => ({ dimension, result, provenance, reasons, limitations });
  const assessments = [
    row("RECORD_INTEGRITY", "VERIFIED", "VERIFIER_COMPUTED", [], []),
    row("SIGNER_AUTHENTICITY", signer.result, "VERIFIER_COMPUTED", signer.reasons, signerVerified ? [] : ["SIGNER_AUTHENTICITY_REQUIRES_PINNED_ANCHORS"]),
    row("AUTHORIZATION", authorization.result, authorization.provenance, authorization.reasons, authorization.limitations),
    row("EXECUTION_REPORTED", "NOT_ASSESSED", null, ["NO_EXECUTION_REPORT_IN_PROOF"], []),
    row("EXECUTION_ATTESTED", "NOT_ASSESSED", null, ["NO_IN_PATH_ENFORCEMENT_ATTESTATION"], ["EXECUTION_NOT_ATTESTED"]),
    row("EFFECT_OBSERVED", "NOT_ASSESSED", null, ["NO_EFFECT_EVIDENCE"], ["EFFECT_NOT_VERIFIED"]),
    row("EFFECT_CONFIRMED", "NOT_ASSESSED", null, ["NO_EFFECT_EVIDENCE"], ["EFFECT_NOT_VERIFIED"]),
    row("CAUSAL_CHAIN", "NOT_ASSESSED", null, ["NO_DELEGATION_CHAIN_IN_PROOF"], []),
  ];
  const outcome = decisionOutcome(admissionBinding);
  if (outcome === "ALLOW") {
    assessments.find((a) => a.dimension === "EXECUTION_ATTESTED").limitations.push("EXECUTE_RECHECK_NOT_ATTESTED");
  }
  if (outcome === "DENY") {
    for (const a of assessments) {
      if (["EXECUTION_REPORTED", "EXECUTION_ATTESTED", "EFFECT_OBSERVED", "EFFECT_CONFIRMED"].includes(a.dimension)) {
        a.result = "NOT_APPLICABLE";
        a.reasons = ["ADMISSION_DENIED"];
        a.limitations = [];
      }
    }
  }
  const verdict = deriveAssuranceVerdict(Object.fromEntries(assessments.map((a) => [a.dimension, a.result])), "LEGACY_DECISION_RECORD");
  const codes = [
    ...LEGACY_DECISION_RECORD_LIMITATIONS.flatMap((code) => (code === "POLICY_BINDING_SYNTHETIC" ? authorization.limitations : [code])),
    ...(signerVerified ? [] : ["SIGNER_AUTHENTICITY_REQUIRES_PINNED_ANCHORS"]),
    ...(outcome === "ALLOW" ? ["EXECUTE_RECHECK_NOT_ATTESTED"] : []),
  ];
  return {
    schema_version: VERIFICATION_ASSESSMENT_SCHEMA_VERSION,
    assurance_profile: "LEGACY_DECISION_RECORD",
    required_dimensions: [...ASSURANCE_PROFILES.LEGACY_DECISION_RECORD],
    verdict,
    // Omitted for every proof that is not an admission decision record.
    ...(outcome === "" ? {} : { decision_outcome: outcome }),
    assessments,
    limitations: codes.map((code) => ({ code, text: LIMITATION_TEXT[code] })),
  };
}
