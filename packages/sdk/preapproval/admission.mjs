// aep.admission_binding (intentrax.aep.admission_binding/0.1) and the
// admission consistency check, for verify-proof.
//
// Specs: docs/architecture/specs/01-admission-request-v1.1.md §3.4 and §8
// (approved 2026-11-21; execute-time re-check amendment 2026-11-22),
// 02-approval-record.md §5.1, 03-enforce-mode-and-policy-facts.md §6.2–§6.3.
//
// Port of the Go verifier (engine/internal/registrylayer/persistence/
// admission_binding.go and engine/internal/verificationinfra/offlineproof/
// admission.go): same member rules, same invalid-field names, same
// consistency codes and the same statement wording. A present member that is
// malformed or out of contract fails verification closed, even under genuine
// signatures (spec 00 §9.7). Proofs without the member are unaffected.

import { parseEnvelope, parseTime, validHash } from "../envelope/index.mjs";

export const ADMISSION_BINDING_PROFILE = "intentrax.aep.admission_binding/0.1";
export const EXECUTE_RECHECK_PROFILE = "intentrax.execute_recheck/0.1";
export const ADMISSION_EXECUTION_ID_PREFIX = "runtime-admission-";
export const CALLER_STATEMENT_PAYLOAD_TYPE = "intentrax.caller_statement/0.1";

export const ADMISSION_STATUS = Object.freeze({ ADMITTED: "ADMITTED", DENIED: "DENIED" });
export const ADMISSION_REASON = Object.freeze({
  CONTRACT_SATISFIED: "ADMISSION_CONTRACT_SATISFIED",
  POLICY_NON_COMPLIANT: "POLICY_NON_COMPLIANT",
  POLICY_EVALUATION_ERROR: "POLICY_EVALUATION_ERROR",
  CONSTRAINT_TYPE_NOT_ENFORCEABLE: "CONSTRAINT_TYPE_NOT_ENFORCEABLE",
  APPROVAL_MISSING: "APPROVAL_MISSING",
  APPROVAL_REJECTED: "APPROVAL_REJECTED",
});

const ADMISSION_REASONS = new Set([
  ...Object.values(ADMISSION_REASON),
  "THIRD_PARTY_TOOLS_NOT_ENABLED", "SERVER_NOT_REGISTERED", "TOOL_DEFINITION_NOT_PINNED",
  "CALLER_SIGNATURE_REQUIRED", "CALLER_SIGNATURE_INVALID",
  // v1.0 reasons (engine/internal/runtime/agentadmission).
  "ADAPTER_MISMATCH", "ACTION_NOT_ALLOWED", "REQUIRED_EVIDENCE_REFS_MISSING", "REQUIRED_PROOF_REFS_MISSING",
  "ADAPTER_BOUNDARY_INVALID", "GATEWAY_POLICY_BOUNDARY_INVALID",
]);

// Consistency codes (offlineproof/admission.go).
export const ADMISSION_INCONSISTENT = Object.freeze({
  EXECUTION_ID: "ADMISSION_EXECUTION_ID_INCONSISTENT",
  LANE: "ADMISSION_LANE_INCONSISTENT",
  ENFORCED: "ENFORCED_WITHOUT_ADMISSION_BINDING",
  ENFORCED_ADMITTED: "ENFORCED_ADMITTED_NOT_COMPLIANT_AND_SATISFIED",
  ENFORCED_DENIED: "ENFORCED_DENIED_REASON_INCONSISTENT",
  REJECTED: "REJECTED_CONSTRAINT_NOT_DENIED_AS_APPROVAL_REJECTED",
  EVIDENCE_UNBOUND: "APPROVAL_EVIDENCE_WITHOUT_ADMISSION_BINDING",
  DIRECTORY_HEAD: "APPROVAL_EVIDENCE_INVALID:DIRECTORY_HEAD_NOT_SEALED",
});

const REQUIRED = ["admission_reason", "admission_request_hash", "admission_status", "arguments_hash_source", "binding_profile", "decided_at", "disclosure", "hash_algorithm", "idempotency_key_hash"];
const OPTIONAL = new Set(["arguments_hash", "caller_attestation", "execute_before", "execute_recheck", "tenant_key_directory_head", "tenant_settings_hash", "tool", "tool_commitment"]);
const STRING_MEMBERS = ["admission_reason", "admission_request_hash", "admission_status", "arguments_hash", "arguments_hash_source", "binding_profile", "decided_at", "disclosure", "execute_before", "execute_recheck", "hash_algorithm", "idempotency_key_hash", "tenant_key_directory_head", "tenant_settings_hash", "tool_commitment"];
const TOOL_REQUIRED = ["server_id", "server_id_verification", "tool_name"];
const TOOL_OPTIONAL = new Set(["server_origin", "tool_definition_digest", "tool_manifest_digest"]);
const SERVER_ID = /^[A-Za-z0-9.-]+\/[A-Za-z0-9._-]+$/;
const TOOL_NAME = /^[A-Za-z0-9_.-]{1,128}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

class BindingError extends Error {}
const malformed = (message) => { throw new BindingError(message); };

function checkMembers(object, required, optional, what) {
  if (!isObject(object)) malformed(`${what} is not a JSON object`);
  for (const k of required) if (!own(object, k)) malformed(`${what} member "${k}" is required`);
  for (const k of Object.keys(object).sort()) {
    if (!required.includes(k) && !optional.has(k)) malformed(`${what} member "${k}" is not allowed`);
  }
}

const nonEmptyString = (v) => typeof v === "string" && v !== "";

// validServerOrigin accepts exactly https://host[:port] (spec 01 §3.1): no
// credentials, path, query or fragment. A regex, not new URL(): WHATWG URL
// parsing lowercases the host and drops ":443", which would accept origins
// the Go verifier (url.Parse, host kept verbatim) compares differently.
const SERVER_ORIGIN = /^https:\/\/(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?$/;
export function validServerOrigin(origin) {
  return typeof origin === "string" && SERVER_ORIGIN.test(origin);
}

const tryTime = (s) => {
  try {
    return parseTime(s);
  } catch {
    return null;
  }
};

// sealedAdmissionBinding extracts aep.admission_binding from the verified
// canonical AEP. Returns {binding: null, invalid: []} when absent, the
// normalised binding when valid, or {binding: null, invalid: [...]} with Go's
// invalid-field names (or a parse message) when present and malformed.
export function sealedAdmissionBinding(canonicalAEPJSON) {
  let aep;
  try {
    aep = JSON.parse(canonicalAEPJSON);
  } catch {
    return { binding: null, invalid: [] };
  }
  if (!isObject(aep) || !own(aep, "admission_binding")) return { binding: null, invalid: [] };
  try {
    const b = aep.admission_binding;
    checkMembers(b, REQUIRED, OPTIONAL, "aep admission_binding");
    for (const k of STRING_MEMBERS) {
      if (own(b, k) && !nonEmptyString(b[k])) malformed(`aep admission_binding.${k} is not a non-empty string`);
    }
    if (own(b, "tool")) parseTool(b.tool);
    if (own(b, "caller_attestation")) parseCallerAttestation(b.caller_attestation);
    const invalid = admissionBindingInvalidFields(b, "admission_binding");
    if (invalid.length > 0) return { binding: null, invalid };
    return { binding: Object.freeze(structuredClone(b)), invalid: [] };
  } catch (err) {
    if (err instanceof BindingError) return { binding: null, invalid: [err.message] };
    throw err;
  }
}

function parseTool(tool) {
  checkMembers(tool, TOOL_REQUIRED, TOOL_OPTIONAL, "aep admission_binding.tool");
  for (const k of ["server_id", "server_origin", "tool_definition_digest", "tool_manifest_digest", "tool_name"]) {
    if (own(tool, k) && !nonEmptyString(tool[k])) malformed(`aep admission_binding.tool.${k} is not a non-empty string`);
  }
  const v = tool.server_id_verification;
  if (!isObject(v)) malformed("aep admission_binding.tool.server_id_verification is not a JSON object");
  for (const k of Object.keys(v)) {
    if (!["method", "registration_hash", "verified_at"].includes(k)) malformed(`aep admission_binding.tool.server_id_verification member "${k}" is not allowed`);
    if (!nonEmptyString(v[k])) malformed(`aep admission_binding.tool.server_id_verification.${k} is not a non-empty string`);
  }
}

function parseCallerAttestation(attestation) {
  checkMembers(attestation, ["envelope", "key_entry_hash"], new Set(), "aep admission_binding.caller_attestation");
  if (!nonEmptyString(attestation.key_entry_hash)) malformed("aep admission_binding.caller_attestation.key_entry_hash is not a non-empty string");
  let envelope;
  try {
    envelope = parseEnvelope(JSON.stringify(attestation.envelope));
  } catch (err) {
    malformed(`aep admission_binding.caller_attestation.envelope: ${err.message}`);
  }
  if (envelope.payloadType !== CALLER_STATEMENT_PAYLOAD_TYPE) {
    malformed(`aep admission_binding.caller_attestation.envelope payload_type "${envelope.payloadType}" is not ${CALLER_STATEMENT_PAYLOAD_TYPE}`);
  }
}

// admissionBindingInvalidFields mirrors ProofAdmissionBindingInvalidFields.
export function admissionBindingInvalidFields(b, prefix) {
  const fields = [];
  const has = (k) => own(b, k) && b[k] !== "";
  if (b.binding_profile !== ADMISSION_BINDING_PROFILE) fields.push(`${prefix}.binding_profile`);
  if (b.hash_algorithm !== "SHA-256") fields.push(`${prefix}.hash_algorithm`);
  if (!validHash(b.admission_request_hash)) fields.push(`${prefix}.admission_request_hash`);
  if (!validHash(b.idempotency_key_hash)) fields.push(`${prefix}.idempotency_key_hash`);
  if (!ADMISSION_REASONS.has(b.admission_reason)) fields.push(`${prefix}.admission_reason`);
  const admitted = b.admission_status === ADMISSION_STATUS.ADMITTED;
  if (b.admission_status === ADMISSION_STATUS.ADMITTED) {
    if (b.admission_reason !== ADMISSION_REASON.CONTRACT_SATISFIED) fields.push(`${prefix}.admission_reason`);
  } else if (b.admission_status === ADMISSION_STATUS.DENIED) {
    if (b.admission_reason === ADMISSION_REASON.CONTRACT_SATISFIED) fields.push(`${prefix}.admission_reason`);
  } else {
    fields.push(`${prefix}.admission_status`);
  }
  if (b.arguments_hash_source !== "ENGINE_COMPUTED" && b.arguments_hash_source !== "CALLER_DECLARED") fields.push(`${prefix}.arguments_hash_source`);
  const decidedAt = tryTime(b.decided_at);
  if (decidedAt === null) fields.push(`${prefix}.decided_at`);
  if (admitted !== has("execute_before")) {
    fields.push(`${prefix}.execute_before`);
  } else if (admitted) {
    const executeBefore = tryTime(b.execute_before);
    if (executeBefore === null || (decidedAt !== null && !(executeBefore > decidedAt))) fields.push(`${prefix}.execute_before`);
  }
  if (admitted !== has("execute_recheck") || (admitted && b.execute_recheck !== EXECUTE_RECHECK_PROFILE)) fields.push(`${prefix}.execute_recheck`);
  if (b.disclosure === "PLAINTEXT") {
    if (!validHash(b.arguments_hash)) fields.push(`${prefix}.arguments_hash`);
    if (!own(b, "tool")) fields.push(`${prefix}.tool`);
    else fields.push(...toolInvalidFields(b.tool, `${prefix}.tool`));
    if (has("tool_commitment")) fields.push(`${prefix}.tool_commitment`);
  } else if (b.disclosure === "COMMITTED") {
    if (!validHash(b.tool_commitment)) fields.push(`${prefix}.tool_commitment`);
    if (has("arguments_hash")) fields.push(`${prefix}.arguments_hash`);
    if (own(b, "tool")) fields.push(`${prefix}.tool`);
  } else {
    fields.push(`${prefix}.disclosure`);
  }
  if (own(b, "caller_attestation")) {
    if (!validHash(b.caller_attestation.key_entry_hash)) fields.push(`${prefix}.caller_attestation.key_entry_hash`);
    if (!has("tenant_key_directory_head")) fields.push(`${prefix}.tenant_key_directory_head`);
  }
  if (has("tenant_key_directory_head") && !validHash(b.tenant_key_directory_head)) fields.push(`${prefix}.tenant_key_directory_head`);
  if (has("tenant_settings_hash") && !validHash(b.tenant_settings_hash)) fields.push(`${prefix}.tenant_settings_hash`);
  return [...new Set(fields)].sort();
}

function toolInvalidFields(tool, prefix) {
  const fields = [];
  if (tool.server_id.length > 200 || !SERVER_ID.test(tool.server_id)) fields.push(`${prefix}.server_id`);
  if (!TOOL_NAME.test(tool.tool_name)) fields.push(`${prefix}.tool_name`);
  if (own(tool, "server_origin") && !validServerOrigin(tool.server_origin)) fields.push(`${prefix}.server_origin`);
  if (own(tool, "tool_definition_digest") && !DIGEST.test(tool.tool_definition_digest)) fields.push(`${prefix}.tool_definition_digest`);
  if (own(tool, "tool_manifest_digest") && !DIGEST.test(tool.tool_manifest_digest)) fields.push(`${prefix}.tool_manifest_digest`);
  const v = tool.server_id_verification;
  const at = `${prefix}.server_id_verification`;
  if (v.method === "DNS_TXT" || v.method === "MCP_REGISTRY") {
    if (!validHash(v.registration_hash)) fields.push(`${at}.registration_hash`);
    if (tryTime(v.verified_at) === null) fields.push(`${at}.verified_at`);
  } else if (v.method === "TENANT_DECLARED") {
    if (own(v, "registration_hash") || own(v, "verified_at")) fields.push(at);
  } else {
    fields.push(`${at}.method`);
  }
  return fields;
}

// ---------------------------------------------------------------- consistency

function signedExecutionID(canonicalAEPJSON) {
  try {
    const aep = JSON.parse(canonicalAEPJSON);
    return isObject(aep) && typeof aep.execution_id === "string" ? aep.execution_id : "";
  } catch {
    return "";
  }
}

// checkAdmissionConsistency mirrors offlineproof.CheckAdmissionConsistency.
// admission and policy are the sealed members (null when absent). Returns ""
// when consistent, otherwise the fail-closed code.
export function checkAdmissionConsistency(canonicalAEPJSON, admission, policy) {
  const admissionID = signedExecutionID(canonicalAEPJSON).startsWith(ADMISSION_EXECUTION_ID_PREFIX);
  if (admissionID !== (admission !== null)) return ADMISSION_INCONSISTENT.EXECUTION_ID;
  if (policy === null) return "";
  const admissionLane = isObject(policy.evaluated_facts) && policy.evaluated_facts.lane === "ADMISSION";
  if (admissionLane !== (admission !== null)) return ADMISSION_INCONSISTENT.LANE;
  const enforced = policy.enforcement === "ENFORCED";
  if (enforced && admission === null) return ADMISSION_INCONSISTENT.ENFORCED;
  const v12 = policy.binding_profile === "intentrax.aep.policy_binding/1.2";
  let rejected = false;
  let evidenced = false;
  let notEvaluatedApproval = false;
  let otherType = false;
  for (const c of policy.constraints) {
    if (c.status === "REJECTED") {
      rejected = true;
      evidenced = true;
    } else if (c.status === "SATISFIED") {
      if (v12) evidenced = true;
    } else if (c.status === "NOT_EVALUATED" && c.type === "REQUIRE_APPROVAL") {
      notEvaluatedApproval = true;
    }
    if (c.type !== "REQUIRE_APPROVAL") otherType = true;
  }
  if (evidenced) {
    if (admission === null) return ADMISSION_INCONSISTENT.EVIDENCE_UNBOUND;
    if (!own(admission, "tenant_key_directory_head") || admission.tenant_key_directory_head === "") return ADMISSION_INCONSISTENT.DIRECTORY_HEAD;
  }
  if (rejected && (admission.admission_status !== ADMISSION_STATUS.DENIED || admission.admission_reason !== ADMISSION_REASON.APPROVAL_REJECTED)) {
    return ADMISSION_INCONSISTENT.REJECTED;
  }
  if (!enforced) return "";
  if (admission.admission_status === ADMISSION_STATUS.ADMITTED) {
    if (policy.decision !== "COMPLIANT") return ADMISSION_INCONSISTENT.ENFORCED_ADMITTED;
    if (policy.constraints.some((c) => c.status !== "SATISFIED")) return ADMISSION_INCONSISTENT.ENFORCED_ADMITTED;
    return "";
  }
  const expected = new Set();
  if (policy.decision === "NON_COMPLIANT") expected.add(ADMISSION_REASON.POLICY_NON_COMPLIANT);
  else if (policy.decision === "ERROR") expected.add(ADMISSION_REASON.POLICY_EVALUATION_ERROR);
  else if (policy.decision === "COMPLIANT") {
    if (rejected) expected.add(ADMISSION_REASON.APPROVAL_REJECTED);
    else {
      if (otherType) expected.add(ADMISSION_REASON.CONSTRAINT_TYPE_NOT_ENFORCEABLE);
      if (notEvaluatedApproval) expected.add(ADMISSION_REASON.APPROVAL_MISSING);
    }
  }
  return expected.has(admission.admission_reason) ? "" : ADMISSION_INCONSISTENT.ENFORCED_DENIED;
}

// decisionOutcome is ALLOW for ADMITTED, DENY for DENIED, "" for other proofs.
export function decisionOutcome(admission) {
  if (admission === null) return "";
  return admission.admission_status === ADMISSION_STATUS.DENIED ? "DENY" : "ALLOW";
}

// ---------------------------------------------------------------- words

export function serverVerificationWords(method) {
  switch (method) {
    case "DNS_TXT": return "namespace verified by a DNS TXT record";
    case "MCP_REGISTRY": return "namespace verified by the official MCP Registry (a third-party statement)";
    case "TENANT_DECLARED": return "declared by the tenant, not verified";
    default: return "verification method unknown";
  }
}

// admissionBindingStatement mirrors persistence.AdmissionBindingStatement.
export function admissionBindingStatement(b) {
  let s = `Admission ${b.admission_status} (${b.admission_reason}) decided at ${b.decided_at} by the Intentrax engine clock.`;
  if (b.admission_status === ADMISSION_STATUS.ADMITTED) {
    s += ` Execute before ${b.execute_before}; the gate must re-check the arguments hash at execution (${b.execute_recheck}).`;
  }
  s += b.arguments_hash_source === "ENGINE_COMPUTED"
    ? " The arguments hash was computed by the engine from the arguments it received."
    : " The arguments hash was declared by the caller; the engine did not see the arguments.";
  if (own(b, "tool")) {
    s += ` Tool ${b.tool.tool_name} on server ${b.tool.server_id} (${serverVerificationWords(b.tool.server_id_verification.method)}).`;
  } else {
    s += " The tool and arguments hash are sealed as a commitment (COMMITTED disclosure).";
  }
  if (own(b, "caller_attestation")) s += " The record carries a caller-signed request statement.";
  return s;
}
