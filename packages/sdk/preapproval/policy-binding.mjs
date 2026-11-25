// aep.policy_binding 1.2 (docs/architecture/specs/03-enforce-mode-and-policy-facts.md §3,
// approved 2026-11-21): ENFORCED, the ADMISSION lane, request facts
// (plaintext or withheld as commitments), the fact source, fact_map_hash and
// the REJECTED constraint status (spec 02 §4).
//
// Port of the Go verifier (engine/internal/registrylayer/persistence/
// policy_binding.go, profile 1.2 branch): same member rules and the same
// invalid-field names. Profile 1.1 stays with verify-proof's existing parser,
// unchanged; this module handles 1.2 only.

import { validHash } from "../envelope/index.mjs";

export const POLICY_BINDING_PROFILE_V12 = "intentrax.aep.policy_binding/1.2";
export const FACT_SOURCE = Object.freeze({ RUNTIME_RECEIPT: "RUNTIME_RECEIPT", ENGINE_DERIVED_FROM_ARGUMENTS: "ENGINE_DERIVED_FROM_ARGUMENTS" });
export const REQUEST_FACT_KEYS = Object.freeze({
  "eeo.request.amount_minor": "amount_minor",
  "eeo.request.currency": "currency",
  "eeo.request.environment": "environment",
  "eeo.request.resource": "resource",
  "eeo.request.tool": "tool",
});
// The tenant request-event profile a policy on the admission lane may
// reference (spec 03 §7, TenantRequestEventFields). Never eeo.commitment_salt.
export const ADMISSION_REQUEST_EVENT_FIELDS = Object.freeze([
  "eeo.execution_domain.lane",
  "eeo.execution_domain.mutation_performed",
  ...Object.keys(REQUEST_FACT_KEYS),
]);

const REQUIRED = ["binding_profile", "compiled_policy_hash", "constraints", "decision", "enforcement", "evaluation_hash", "execution_event_hash", "hash_algorithm", "policy_id", "policy_version", "rule_id", "source_policy_hash"];
const OPTIONAL = new Set(["evaluated_facts", "fact_map_hash", "mandate_hash"]);
const FACTS_ALLOWED = new Set(["event_salt_commitment", "lane", "mutation_performed", "request", "source", "withheld"]);
const CONSTRAINT_MEMBERS = ["constraint_id", "status", "type"];
const DECISIONS = new Set(["COMPLIANT", "NON_COMPLIANT", "ERROR"]);
const CURRENCY = /^[A-Z]{3}$/;
const TOOL = /^[A-Za-z0-9_.-]{1,128}$/;

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const nonEmptyString = (v) => typeof v === "string" && v !== "";

class BindingError extends Error {}
const malformed = (message) => { throw new BindingError(message); };

// sealedPolicyBindingV12 parses a policy_binding object whose binding_profile
// is 1.2. Returns {binding} or {binding: null, invalid: [...]}.
export function sealedPolicyBindingV12(b) {
  try {
    if (!isObject(b)) malformed("aep policy_binding is not a JSON object");
    const keys = Object.keys(b).sort();
    const required = keys.filter((k) => !OPTIONAL.has(k));
    if (required.join(",") !== REQUIRED.join(",")) malformed(`aep policy_binding members invalid: ${keys.join(",")}`);
    const constraints = parseConstraints(b.constraints);
    for (const k of keys) {
      if (k !== "constraints" && k !== "evaluated_facts" && typeof b[k] !== "string") malformed(`aep policy_binding.${k} is not a string`);
    }
    for (const k of ["fact_map_hash", "mandate_hash"]) if (own(b, k) && b[k] === "") malformed(`aep policy_binding invalid: policy_binding.${k}`);
    const facts = own(b, "evaluated_facts") ? parseFacts(b.evaluated_facts) : null;
    const binding = { ...b, constraints, ...(facts ? { evaluated_facts: facts } : {}) };
    const invalid = policyBindingV12InvalidFields(binding, "policy_binding");
    if (invalid.length > 0) return { binding: null, invalid };
    return { binding: Object.freeze(binding), invalid: [] };
  } catch (err) {
    if (err instanceof BindingError) return { binding: null, invalid: [err.message] };
    throw err;
  }
}

function parseConstraints(value) {
  if (!Array.isArray(value)) malformed("aep policy_binding.constraints is not a JSON array");
  return value.map((c, i) => {
    if (!isObject(c)) malformed(`aep policy_binding.constraints[${i}] is not a JSON object`);
    const expected = own(c, "evidence_hash") ? [...CONSTRAINT_MEMBERS, "evidence_hash"].sort() : CONSTRAINT_MEMBERS;
    if (Object.keys(c).sort().join(",") !== expected.join(",")) malformed(`aep policy_binding.constraints[${i}] members invalid`);
    for (const k of expected) if (typeof c[k] !== "string") malformed(`aep policy_binding.constraints[${i}].${k} is not a string`);
    // A present evidence_hash is never empty (Go policyConstraintsFromJSON):
    // NOT_EVALUATED forbids the member, it does not accept it blank.
    if (own(c, "evidence_hash") && c.evidence_hash === "") malformed(`aep policy_binding invalid: policy_binding.constraints[${i}].evidence_hash`);
    return { ...c };
  });
}

function parseFacts(f) {
  if (!isObject(f)) malformed("aep policy_binding.evaluated_facts is not a JSON object");
  for (const k of Object.keys(f)) if (!FACTS_ALLOWED.has(k)) malformed(`aep policy_binding.evaluated_facts member "${k}" is not allowed`);
  for (const k of ["lane", "mutation_performed", "source"]) if (!own(f, k)) malformed(`aep policy_binding.evaluated_facts.${k} is required`);
  for (const k of ["lane", "source", "event_salt_commitment"]) {
    if (own(f, k) && !nonEmptyString(f[k])) malformed(`aep policy_binding.evaluated_facts.${k} is not a non-empty string`);
  }
  if (typeof f.mutation_performed !== "boolean") malformed("aep policy_binding.evaluated_facts.mutation_performed is not a boolean");
  const out = { lane: f.lane, mutation_performed: f.mutation_performed, source: f.source };
  if (own(f, "event_salt_commitment")) out.event_salt_commitment = f.event_salt_commitment;
  if (own(f, "request")) {
    if (!isObject(f.request)) malformed("aep policy_binding.evaluated_facts.request is not a JSON object");
    const request = {};
    for (const [k, v] of Object.entries(f.request)) {
      if (k === "amount_minor") {
        if (!Number.isSafeInteger(v)) malformed("aep policy_binding.evaluated_facts.request.amount_minor: not an integer in the safe-integer range");
      } else if (["currency", "environment", "resource", "tool"].includes(k)) {
        if (!nonEmptyString(v)) malformed(`aep policy_binding.evaluated_facts.request.${k} is not a non-empty string`);
      } else {
        malformed(`aep policy_binding.evaluated_facts.request member "${k}" is not allowed`);
      }
      request[k] = v;
    }
    out.request = request;
  }
  if (own(f, "withheld")) {
    if (!Array.isArray(f.withheld)) malformed("aep policy_binding.evaluated_facts.withheld is not a JSON array");
    out.withheld = f.withheld.map((w, i) => {
      if (!isObject(w) || Object.keys(w).sort().join(",") !== "commitment,field" || !nonEmptyString(w.commitment) || !nonEmptyString(w.field)) {
        malformed(`aep policy_binding.evaluated_facts.withheld[${i}]: members must be exactly commitment,field`);
      }
      return { commitment: w.commitment, field: w.field };
    });
  }
  return out;
}

// policyBindingV12InvalidFields mirrors ProofPolicyBindingInvalidFields for 1.2.
export function policyBindingV12InvalidFields(b, prefix) {
  const fields = [];
  if (b.binding_profile !== POLICY_BINDING_PROFILE_V12) fields.push(`${prefix}.binding_profile`);
  if (!validHash(b.compiled_policy_hash)) fields.push(`${prefix}.compiled_policy_hash`);
  b.constraints.forEach((c, i) => {
    const at = `${prefix}.constraints[${i}]`;
    if (c.constraint_id === "" || (i > 0 && c.constraint_id <= b.constraints[i - 1].constraint_id)) fields.push(`${at}.constraint_id`);
    if (c.type === "") fields.push(`${at}.type`);
    if (c.status === "SATISFIED" || c.status === "REJECTED") {
      if (!validHash(c.evidence_hash)) fields.push(`${at}.evidence_hash`);
    } else if (c.status === "NOT_EVALUATED") {
      if (own(c, "evidence_hash")) fields.push(`${at}.evidence_hash`);
    } else {
      fields.push(`${at}.status`);
    }
  });
  if (!DECISIONS.has(b.decision)) fields.push(`${prefix}.decision`);
  if (b.enforcement !== "RECORD_ONLY" && b.enforcement !== "ENFORCED") fields.push(`${prefix}.enforcement`);
  fields.push(...factsInvalidFields(b, prefix));
  if (!validHash(b.evaluation_hash)) fields.push(`${prefix}.evaluation_hash`);
  if (!validHash(b.execution_event_hash)) fields.push(`${prefix}.execution_event_hash`);
  if (b.hash_algorithm !== "SHA-256") fields.push(`${prefix}.hash_algorithm`);
  if (own(b, "mandate_hash") && !validHash(b.mandate_hash)) fields.push(`${prefix}.mandate_hash`);
  for (const k of ["policy_id", "policy_version", "rule_id"]) if (b[k] === "") fields.push(`${prefix}.${k}`);
  if (!validHash(b.source_policy_hash)) fields.push(`${prefix}.source_policy_hash`);
  return [...new Set(fields)].sort();
}

function factsInvalidFields(b, prefix) {
  const at = `${prefix}.evaluated_facts`;
  const facts = b.evaluated_facts;
  const hasFactMap = own(b, "fact_map_hash") && b.fact_map_hash !== "";
  if (!facts) return hasFactMap ? [at, `${prefix}.fact_map_hash`] : [at];
  const fields = [];
  const admission = facts.lane === "ADMISSION";
  if (!["DRY_RUN", "LIVE_EXECUTE", "ADMISSION"].includes(facts.lane)) fields.push(`${at}.lane`);
  let wantSource = FACT_SOURCE.RUNTIME_RECEIPT;
  if (admission) {
    wantSource = FACT_SOURCE.ENGINE_DERIVED_FROM_ARGUMENTS;
    if (facts.mutation_performed) fields.push(`${at}.mutation_performed`);
  } else if (facts.request || (facts.withheld && facts.withheld.length > 0) || facts.event_salt_commitment) {
    fields.push(`${at}.request`);
  }
  if (facts.source !== wantSource) fields.push(`${at}.source`);
  if ((facts.source === FACT_SOURCE.ENGINE_DERIVED_FROM_ARGUMENTS) !== hasFactMap || (hasFactMap && !validHash(b.fact_map_hash))) fields.push(`${prefix}.fact_map_hash`);
  const plaintext = new Set();
  const r = facts.request;
  if (r) {
    if (own(r, "amount_minor")) plaintext.add("eeo.request.amount_minor");
    if (own(r, "currency")) {
      plaintext.add("eeo.request.currency");
      if (!CURRENCY.test(r.currency)) fields.push(`${at}.request.currency`);
    }
    if (own(r, "environment")) {
      plaintext.add("eeo.request.environment");
      if (!["PROD", "STAGING", "DEV"].includes(r.environment)) fields.push(`${at}.request.environment`);
    }
    if (own(r, "resource")) {
      plaintext.add("eeo.request.resource");
      if ([...r.resource].length > 256) fields.push(`${at}.request.resource`);
    }
    if (own(r, "tool")) {
      plaintext.add("eeo.request.tool");
      if (!TOOL.test(r.tool)) fields.push(`${at}.request.tool`);
    }
    if (plaintext.size === 0) fields.push(`${at}.request`);
  }
  const withheld = facts.withheld;
  if (withheld && withheld.length === 0) fields.push(`${at}.withheld`);
  (withheld ?? []).forEach((w, i) => {
    const item = `${at}.withheld[${i}]`;
    if (!own(REQUEST_FACT_KEYS, w.field) || plaintext.has(w.field) || (i > 0 && w.field <= withheld[i - 1].field)) fields.push(`${item}.field`);
    if (!validHash(w.commitment)) fields.push(`${item}.commitment`);
  });
  const hasSalt = own(facts, "event_salt_commitment") && facts.event_salt_commitment !== "";
  if (((withheld ?? []).length > 0) !== hasSalt || (hasSalt && !validHash(facts.event_salt_commitment))) fields.push(`${at}.event_salt_commitment`);
  return fields;
}

// admissionExecutionEvent rebuilds the admission-lane execution event (spec
// 03 §4.1) from plaintext facts plus opened withheld facts ({field: value})
// and the opened event salt ("" when none). Mirrors offlineproof.
export function admissionExecutionEvent(facts, opened = {}, salt = "") {
  const request = {};
  for (const [k, v] of Object.entries(facts.request ?? {})) request[k] = v;
  for (const w of facts.withheld ?? []) {
    if (!own(opened, w.field)) throw new Error(`withheld fact ${w.field} is not opened`);
    request[REQUEST_FACT_KEYS[w.field]] = opened[w.field];
  }
  const eeo = { execution_domain: { lane: facts.lane, mutation_performed: facts.mutation_performed } };
  if (Object.keys(request).length > 0) eeo.request = request;
  if (salt !== "") eeo.commitment_salt = salt;
  return { eeo };
}

// Statement wording (mirrors persistence.PolicyBindingStatement for 1.2).
export function policyBindingV12Statement(b) {
  const mode = b.enforcement === "ENFORCED" ? "enforced at Intentrax admission." : "recorded only, never enforced.";
  const head = `Policy ${b.policy_id}@${b.policy_version} evaluated ${b.decision} (rule ${b.rule_id}); ${mode}`;
  if (b.constraints.length === 0) return `${head} The matched rule has no constraints.`;
  return [head, ...b.constraints.map((c) => {
    if (c.status === "SATISFIED") return `Constraint ${c.constraint_id} (${c.type}): SATISFIED; evidence ${c.evidence_hash} is bound by this proof.`;
    if (c.status === "REJECTED") return `Constraint ${c.constraint_id} (${c.type}): REJECTED; evidence ${c.evidence_hash} of the rejection is bound by this proof.`;
    return `Constraint ${c.constraint_id} (${c.type}): NOT CHECKED (NOT_EVALUATED); this proof binds no evidence that it was met.`;
  })].join(" ");
}

// admissionPolicyEvent mirrors the Go verifier's ADMISSION branch of
// reconstructPolicyEvent: the event is rebuilt from plaintext facts and
// re-run with the tenant request-event profile. A binding that withholds
// facts is NOT_RECHECKED / FACTS_WITHHELD (spec 00 §7): never a pass, never a
// failure. An ADMISSION lane on a proof that is not an admission record
// throws (fails closed).
// opened is openDisclosures' {facts, salt}: with every withheld fact and the
// event salt opened, the event is rebuilt with them (Go #569).
export function admissionPolicyEvent(canonicalAEPJSON, binding, opened = { facts: {}, salt: "" }) {
  let executionID = "";
  try {
    const aep = JSON.parse(canonicalAEPJSON);
    if (aep && typeof aep.execution_id === "string") executionID = aep.execution_id;
  } catch {
    executionID = "";
  }
  if (!executionID.startsWith("runtime-admission-")) {
    throw new Error("policy_binding.evaluated_facts.lane ADMISSION on a proof that is not an admission record");
  }
  const withheld = binding.evaluated_facts.withheld ?? [];
  if (withheld.length > 0) {
    if (withheld.some((w) => !own(opened.facts, w.field)) || opened.salt === "") return { notRechecked: "FACTS_WITHHELD" };
    return { event: admissionExecutionEvent(binding.evaluated_facts, opened.facts, opened.salt), allowedEventFields: [...ADMISSION_REQUEST_EVENT_FIELDS] };
  }
  return { event: admissionExecutionEvent(binding.evaluated_facts), allowedEventFields: [...ADMISSION_REQUEST_EVENT_FIELDS] };
}
