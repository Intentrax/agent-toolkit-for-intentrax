// Approval evidence re-check (docs/architecture/specs/02-approval-record.md
// §5; human-only amendment P-6, 2026-11-22). Port of the Go verifier
// (engine/internal/verificationinfra/offlineproof/approvals.go, PR #569):
// the same matching rule, check order, outcomes, codes and statement.
//
// A policy_binding/1.2 constraint sealed SATISFIED or REJECTED names its
// approvals only by evidence_hash. The approvals, the approver set in force
// and the tenant key directory snapshot travel unsigned in the export. The
// verifier finds the approvals whose evidence hash equals the sealed one and
// re-checks every condition of §4.1 except single use (condition 6, checked
// across records by the sequence audit).
//
// Outcomes never raise anything the container could not prove:
//   - NOT_SUPPLIED: no attached set matches the sealed hash;
//   - NOT_RECHECKED: the approvals are there, but something needed to check
//     them is missing or untrusted, or the key was later revoked for
//     compromise;
//   - INVALID: the record bound bad evidence (AUTHORIZATION FAILED);
//   - VERIFIED.

import { PROFILE_INT, PURPOSE, digest, parseEnvelope, parseTime, verifyEnvelope } from "../envelope/index.mjs";
import { toText } from "../envelope/jcs.mjs";
import { approverPermits, approverSetHash, decodeApproverSet, findApprover, parseDirectoryDocument, selfAssertedDirectoryKeys } from "./directory.mjs";
import { POLICY_BINDING_PROFILE_V12 } from "./policy-binding.mjs";

export const APPROVAL_PAYLOAD_TYPE = "intentrax.approval/0.1";
export const DOMAIN_APPROVAL_EVIDENCE = "INTENTRAX_APPROVAL_EVIDENCE_V0_1";
const NS = 1_000_000_000n;
const CLOCK_SKEW_NS = 60n * NS;
const HARD_CAP_NS = 86_400n * NS;
const OIDC_MAX_AUTH_AGE_NS = 300n * NS;

export const APPROVAL_EVIDENCE = Object.freeze({ VERIFIED: "VERIFIED", NOT_SUPPLIED: "NOT_SUPPLIED", NOT_RECHECKED: "NOT_RECHECKED", INVALID: "INVALID" });
export const DIRECTORY_TRUST = Object.freeze({ PINNED_HEAD: "PINNED_HEAD", VOUCHED_BY_INTENTRAX: "VOUCHED_BY_INTENTRAX" });
export const APPROVAL_CODE = Object.freeze({
  MALFORMED: "MALFORMED",
  DECISION_MISMATCH: "DECISION_MISMATCH",
  TENANT_MISMATCH: "TENANT_MISMATCH",
  REQUEST_MISMATCH: "REQUEST_HASH_MISMATCH",
  ARGUMENTS_MISMATCH: "ARGUMENTS_HASH_MISMATCH",
  CONSTRAINT_MISMATCH: "CONSTRAINT_MISMATCH",
  POLICY_MISMATCH: "POLICY_MISMATCH",
  TIME_INVALID: "APPROVAL_TIME_INVALID",
  APPROVED_AFTER: "APPROVED_AFTER_DECISION",
  EXPIRED: "APPROVAL_EXPIRED",
  VALIDITY_TOO_LONG: "APPROVAL_VALIDITY_TOO_LONG",
  NOT_SINGLE_USE: "SINGLE_USE_REQUIRED",
  NOT_HUMAN: "APPROVER_NOT_HUMAN",
  KEY_PRINCIPAL_MISMATCH: "APPROVER_KEY_PRINCIPAL_MISMATCH",
  SIGNATURE_INVALID: "SIGNATURE_INVALID",
  SIGNER_NOT_TRUSTED: "SIGNER_NOT_TRUSTED",
  SET_NOT_IN_FORCE: "APPROVER_SET_NOT_IN_FORCE",
  NOT_LISTED: "APPROVER_NOT_LISTED",
  METHOD_NOT_PERMITTED: "IDENTITY_METHOD_NOT_PERMITTED",
  KEY_NOT_LISTED: "APPROVER_KEY_NOT_LISTED",
  NOT_AUTHORISED: "APPROVER_NOT_AUTHORISED",
  SEPARATION_OF_DUTIES: "SEPARATION_OF_DUTIES",
  OIDC_AUTH_TIME: "OIDC_AUTH_TIME_INVALID",
  QUORUM_NOT_MET: "QUORUM_NOT_MET",
  DUPLICATE: "APPROVAL_DUPLICATE",
  DIRECTORY_NOT_SUPPLIED: "TENANT_KEY_DIRECTORY_NOT_SUPPLIED",
  DIRECTORY_NOT_TRUSTED: "TENANT_KEY_DIRECTORY_NOT_TRUSTED",
  DIRECTORY_HEAD_NOT_FOUND: "TENANT_KEY_DIRECTORY_HEAD_NOT_IN_SNAPSHOT",
  APPROVER_SET_NOT_SUPPLIED: "APPROVER_SET_NOT_SUPPLIED",
  SERVICE_KEY_NOT_PINNED: "APPROVAL_SERVICE_KEY_NOT_PINNED",
  KEY_REVOKED_COMPROMISED: "APPROVER_KEY_REVOKED_COMPROMISED",
  TOOL_COMMITMENT_NOT_OPENED: "TOOL_COMMITMENT_NOT_OPENED",
  ATTACHMENTS_TOO_MANY: "APPROVAL_ATTACHMENTS_TOO_MANY",
});
const C = APPROVAL_CODE;

const APPROVAL_ID = /^apr_[0-9A-Z]{20,32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const str = (v) => typeof v === "string";

function exactMembers(value, required, optional = []) {
  if (!isObject(value)) return false;
  for (const n of required) if (!own(value, n)) return false;
  return Object.keys(value).every((n) => required.includes(n) || optional.includes(n));
}

// decodeApproval parses an attachment as an approval envelope with a strictly
// shaped payload. Returns null for any other (or malformed) attachment.
export function decodeApproval(raw) {
  let env;
  try {
    env = parseEnvelope(typeof raw === "string" || raw instanceof Uint8Array ? raw : JSON.stringify(raw));
  } catch {
    return null;
  }
  if (env.payloadType !== APPROVAL_PAYLOAD_TYPE) return null;
  const p = env.payload;
  if (!exactMembers(p, ["schema_version", "approval_id", "tenant_id", "decision", "subject", "approver", "approved_at", "not_after", "single_use"], ["reason_commitment"])) return null;
  if (![p.approval_id, p.tenant_id, p.decision, p.approved_at, p.not_after].every(str) || typeof p.single_use !== "boolean") return null;
  const s = p.subject;
  if (!exactMembers(s, ["admission_request_hash", "arguments_hash", "constraint_id", "policy"]) || ![s.admission_request_hash, s.arguments_hash, s.constraint_id].every(str)) return null;
  const pol = s.policy;
  if (!exactMembers(pol, ["policy_id", "policy_version", "rule_id", "source_policy_hash"]) || ![pol.policy_id, pol.policy_version, pol.rule_id, pol.source_policy_hash].every(str)) return null;
  const a = p.approver;
  if (!exactMembers(a, ["approver_set_hash", "identity_method", "principal_id", "principal_type", "subject_commitment"], ["oidc"])) return null;
  if (![a.approver_set_hash, a.identity_method, a.principal_id, a.principal_type, a.subject_commitment].every(str)) return null;
  if (!APPROVAL_ID.test(p.approval_id) || p.tenant_id === "" || a.principal_id === "" || (p.decision !== "APPROVE" && p.decision !== "REJECT")
    || !HEX64.test(s.admission_request_hash) || !HEX64.test(s.arguments_hash) || !HEX64.test(a.approver_set_hash) || !HEX64.test(a.subject_commitment)
    || s.constraint_id === "" || pol.policy_id === "" || pol.policy_version === "" || pol.rule_id === "" || !HEX64.test(pol.source_policy_hash)
    || (own(p, "reason_commitment") && !(str(p.reason_commitment) && HEX64.test(p.reason_commitment)))) {
    return null;
  }
  let authTime = "";
  if (a.identity_method === "TENANT_KEY") {
    if (own(a, "oidc")) return null;
  } else if (a.identity_method === "INTENTRAX_ATTESTED_OIDC") {
    if (!exactMembers(a.oidc, ["auth_time", "issuer"]) || !str(a.oidc.auth_time) || !str(a.oidc.issuer) || a.oidc.issuer === "") return null;
    authTime = a.oidc.auth_time;
  } else {
    // Closed set in v0.1 (amendment P-6): no automated approvers.
    return null;
  }
  return {
    // Keep the accepted envelope text: bytes are decoded (never serialised
    // as a byte container), in-memory values serialised (Codex review #571).
    raw: typeof raw === "string" || raw instanceof Uint8Array ? toText(raw) : JSON.stringify(raw),
    envelope: env,
    approvalId: p.approval_id, tenantId: p.tenant_id, decision: p.decision, approvedAt: p.approved_at, notAfter: p.not_after,
    singleUse: p.single_use, constraintId: s.constraint_id, requestHash: s.admission_request_hash, argsHash: s.arguments_hash,
    policy: { policy_id: pol.policy_id, policy_version: pol.policy_version, rule_id: pol.rule_id, source_policy_hash: pol.source_policy_hash },
    setHash: a.approver_set_hash, method: a.identity_method, principalId: a.principal_id, principalType: a.principal_type, authTime,
  };
}

// approvalEvidenceHash = D(INTENTRAX_APPROVAL_EVIDENCE_V0_1, {approval_envelope_hashes: sorted unique}).
export function approvalEvidenceHash(envelopeHashes) {
  const sorted = [...envelopeHashes].sort();
  for (let i = 1; i < sorted.length; i++) if (sorted[i] === sorted[i - 1]) throw new Error("duplicate approval envelope hash");
  return digest(DOMAIN_APPROVAL_EVIDENCE, { approval_envelope_hashes: sorted }, PROFILE_INT);
}

// reasonOf renders a check as an AUTHORIZATION reason code.
export function approvalEvidenceReason(check) {
  switch (check.status) {
    case APPROVAL_EVIDENCE.VERIFIED: return `APPROVAL_EVIDENCE_VERIFIED:${check.constraint_id}`;
    case APPROVAL_EVIDENCE.INVALID: return `APPROVAL_EVIDENCE_INVALID:${check.code}`;
    case APPROVAL_EVIDENCE.NOT_RECHECKED: return `APPROVAL_EVIDENCE_NOT_RECHECKED:${check.constraint_id}:${check.code}`;
    default: return `APPROVAL_EVIDENCE_NOT_SUPPLIED:${check.constraint_id}`;
  }
}

// checkApprovalEvidence re-checks every 1.2 constraint sealed SATISFIED or
// REJECTED. Returns [] for any other proof. inputs:
//   attachments: bare envelopes; approverSets, directories: disclosed docs;
//   directoryKeys: KeyResolver of pinned TENANT_KEY_DIRECTORY keys (or null);
//   pinnedDirectoryHeads: heads pinned out of band;
//   approvalServiceKeys: KeyResolver of pinned APPROVAL_SERVICE keys (or null).
// argumentsHash: the record's (PLAINTEXT, or opened from tool_commitment), or "".
export function checkApprovalEvidence(tenantID, admission, policy, argumentsHash, inputs = {}) {
  if (!admission || !policy || policy.binding_profile !== POLICY_BINDING_PROFILE_V12) return [];
  const attachments = approvalAttachments(inputs.attachments ?? []);
  const directory = new DirectoryContext(inputs, tenantID, admission.tenant_key_directory_head ?? "");
  const checks = [];
  for (const constraint of policy.constraints) {
    if (constraint.status !== "SATISFIED" && constraint.status !== "REJECTED") continue;
    const check = { constraint_id: constraint.constraint_id, sealed_status: constraint.status, status: "" };
    // The pool: every approval envelope that could belong to this
    // constraint. A payload that does not decode stays in the pool, so
    // bound but malformed evidence is INVALID, never NOT_SUPPLIED.
    const pool = attachments.filter((a) => a.approval === null || a.approval.constraintId === constraint.constraint_id);
    if (pool.length > MAX_EVIDENCE_POOL) {
      checks.push({ ...check, status: APPROVAL_EVIDENCE.NOT_RECHECKED, code: C.ATTACHMENTS_TOO_MANY });
      continue;
    }
    const matched = matchEvidence(pool, constraint.evidence_hash);
    if (matched === null) {
      checks.push({ ...check, status: APPROVAL_EVIDENCE.NOT_SUPPLIED, code: APPROVAL_EVIDENCE.NOT_SUPPLIED });
      continue;
    }
    if (matched.some((a) => a.approval === null)) {
      checks.push({ ...check, status: APPROVAL_EVIDENCE.INVALID, code: C.MALFORMED });
      continue;
    }
    checks.push(checkEvidenceSet(check, matched.map((a) => a.approval), tenantID, admission, policy, argumentsHash, directory));
  }
  return checks;
}

// At most this many candidate envelopes per constraint are searched (2^16 − 1
// subsets); more is NOT_RECHECKED, never a pass.
export const MAX_EVIDENCE_POOL = 16;

// approvalAttachments: every attachment that parses as a signed envelope of
// payload type intentrax.approval/0.1, deduped by envelope_hash, with its
// decoded approval (null when the payload is out of contract).
function approvalAttachments(raws) {
  const out = [];
  const seen = new Set();
  for (const raw of raws) {
    let env;
    try {
      env = parseEnvelope(typeof raw === "string" || raw instanceof Uint8Array ? raw : JSON.stringify(raw));
    } catch {
      continue;
    }
    if (env.payloadType !== APPROVAL_PAYLOAD_TYPE || seen.has(env.envelopeHash)) continue;
    seen.add(env.envelopeHash);
    out.push({ envelopeHash: env.envelopeHash, approval: decodeApproval(raw) });
  }
  return out;
}

// matchEvidence finds the subset of the pool whose approval evidence hash is
// the sealed one (smallest subsets first; a hash match is unique, so the
// order only affects cost). Extra attachments never hide the bound set.
function matchEvidence(pool, evidenceHash) {
  const n = pool.length;
  const pick = [];
  const search = (start, size) => {
    if (pick.length === size) {
      return approvalEvidenceHash(pick.map((a) => a.envelopeHash)) === evidenceHash ? [...pick] : null;
    }
    for (let i = start; i <= n - (size - pick.length); i++) {
      pick.push(pool[i]);
      const found = search(i + 1, size);
      pick.pop();
      if (found) return found;
    }
    return null;
  };
  for (let size = 1; size <= n; size++) {
    const found = search(0, size);
    if (found) return found;
  }
  return null;
}

class DirectoryContext {
  constructor(inputs, tenantID, head) {
    this.inputs = inputs;
    this.tenantID = tenantID;
    this.head = head;
    this.resolved = false;
    this.atHead = null;
    // Every authenticated snapshot that reaches the sealed head. A later
    // KEY_COMPROMISE revocation in ANY of them counts, whatever order the
    // documents were supplied in (Codex review #571).
    this.trusted = [];
    this.trust = "";
    this.code = "";
  }

  resolve() {
    if (this.resolved) return;
    this.resolved = true;
    const docs = this.inputs.directories ?? [];
    if (docs.length === 0) {
      this.code = C.DIRECTORY_NOT_SUPPLIED;
      return;
    }
    this.code = C.DIRECTORY_NOT_TRUSTED;
    for (const raw of docs) {
      const { snapshot, trust } = this.verify(raw);
      if (!snapshot) continue;
      let atHead;
      try {
        atHead = snapshot.at(this.head);
      } catch {
        this.code = C.DIRECTORY_HEAD_NOT_FOUND;
        continue;
      }
      this.trusted.push(snapshot);
      if (this.atHead === null || (trust === DIRECTORY_TRUST.PINNED_HEAD && this.trust !== DIRECTORY_TRUST.PINNED_HEAD)) {
        Object.assign(this, { atHead, trust, code: "" });
      }
    }
  }

  verify(raw) {
    const doc = typeof raw === "string" ? safeParse(raw) : raw;
    for (const pinned of this.inputs.pinnedDirectoryHeads ?? []) {
      try {
        const snapshot = parseDirectoryDocument(raw, selfAssertedDirectoryKeys(doc));
        if (snapshot.tenantID !== this.tenantID) break;
        const reached = snapshot.at(pinned);
        reached.at(this.head); // the record's head is at or before the pinned head
        return { snapshot: reached, trust: DIRECTORY_TRUST.PINNED_HEAD };
      } catch {
        // try the next pinned head
      }
    }
    if (!this.inputs.directoryKeys) return { snapshot: null, trust: "" };
    try {
      const snapshot = parseDirectoryDocument(raw, this.inputs.directoryKeys);
      if (snapshot.tenantID !== this.tenantID) return { snapshot: null, trust: "" };
      return { snapshot, trust: DIRECTORY_TRUST.VOUCHED_BY_INTENTRAX };
    } catch {
      return { snapshot: null, trust: "" };
    }
  }
}

function safeParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function checkEvidenceSet(check, set, tenantID, admission, policy, argumentsHash, directory) {
  const invalid = (code) => ({ ...check, status: APPROVAL_EVIDENCE.INVALID, code });
  const notRechecked = (code, extra = {}) => ({ ...check, ...extra, status: APPROVAL_EVIDENCE.NOT_RECHECKED, code });
  let expected = "APPROVE";
  if (check.sealed_status === "REJECTED") {
    expected = "REJECT";
    if (set.length !== 1) return invalid(C.MALFORMED);
  }
  const decidedAt = parseTime(admission.decided_at);
  const ids = new Set();
  for (const a of set) {
    const code = checkAgainstRecord(a, expected, tenantID, admission, policy, argumentsHash, decidedAt, check.constraint_id);
    if (code !== "") return invalid(code);
    if (ids.has(a.approvalId)) return invalid(C.DUPLICATE);
    ids.add(a.approvalId);
  }
  if (argumentsHash === "") return notRechecked(C.TOOL_COMMITMENT_NOT_OPENED);

  directory.resolve();
  if (directory.atHead === null) return notRechecked(directory.code);
  const trust = { directory_trust: directory.trust };
  const setHash = directory.atHead.approverSetHash;
  if (setHash === "") return { ...invalid(C.SET_NOT_IN_FORCE), ...trust };
  const approverSet = disclosedApproverSet(directory.inputs.approverSets ?? [], setHash, tenantID);
  if (approverSet === null) return notRechecked(C.APPROVER_SET_NOT_SUPPLIED, trust);
  const caller = callerPrincipal(admission);
  const principals = new Set();
  let compromised = false;
  for (const a of set) {
    const r = checkAuthority(a, directory, approverSet, setHash, caller);
    if (r.code !== "" && r.notChecked) return notRechecked(r.code, trust);
    if (r.code !== "") return { ...invalid(r.code), ...trust };
    compromised = compromised || r.revoked;
    if (principals.has(a.principalId) && expected === "APPROVE") return { ...invalid(C.QUORUM_NOT_MET), ...trust };
    principals.add(a.principalId);
  }
  if (expected === "APPROVE" && principals.size < approverSet.min_approvals) return { ...invalid(C.QUORUM_NOT_MET), ...trust };
  if (compromised) return notRechecked(C.KEY_REVOKED_COMPROMISED, trust);
  const approvals = [...set]
    .sort((x, y) => (x.envelope.envelopeHash < y.envelope.envelopeHash ? -1 : x.envelope.envelopeHash > y.envelope.envelopeHash ? 1 : 0))
    .map((a) => ({ approval_id: a.approvalId, envelope_hash: a.envelope.envelopeHash, decision: a.decision, identity_method: a.method, principal_id: a.principalId, approved_at: a.approvedAt, not_after: a.notAfter }));
  const verified = { ...check, status: APPROVAL_EVIDENCE.VERIFIED, ...trust, approvals };
  return { ...verified, statement: approvalEvidenceStatement(verified) };
}

// checkAgainstRecord: shape, decision, subject and times (§4.1 2–5), in the
// Go order, so compound negative cases report the same code.
function checkAgainstRecord(a, expected, tenantID, admission, policy, argumentsHash, decidedAt, constraintID) {
  if (!a.singleUse) return C.NOT_SINGLE_USE;
  if (a.decision !== expected) return C.DECISION_MISMATCH;
  if (a.tenantId !== tenantID) return C.TENANT_MISMATCH;
  if (a.principalType !== "HUMAN") return C.NOT_HUMAN;
  if (a.requestHash !== admission.admission_request_hash) return C.REQUEST_MISMATCH;
  if (argumentsHash !== "" && a.argsHash !== argumentsHash) return C.ARGUMENTS_MISMATCH;
  if (a.constraintId !== constraintID) return C.CONSTRAINT_MISMATCH;
  if (a.policy.policy_id !== policy.policy_id || a.policy.policy_version !== policy.policy_version || a.policy.rule_id !== policy.rule_id || a.policy.source_policy_hash !== policy.source_policy_hash) {
    return C.POLICY_MISMATCH;
  }
  let approvedAt;
  let notAfter;
  try {
    approvedAt = parseTime(a.approvedAt);
    notAfter = parseTime(a.notAfter);
  } catch {
    return C.TIME_INVALID;
  }
  if (!(notAfter > approvedAt)) return C.TIME_INVALID;
  if (notAfter - approvedAt > HARD_CAP_NS) return C.VALIDITY_TOO_LONG;
  if (approvedAt > decidedAt + CLOCK_SKEW_NS) return C.APPROVED_AFTER;
  if (!(decidedAt < notAfter)) return C.EXPIRED;
  if (a.method === "INTENTRAX_ATTESTED_OIDC") {
    let authTime;
    try {
      authTime = parseTime(a.authTime);
    } catch {
      return C.OIDC_AUTH_TIME;
    }
    if (authTime > approvedAt || approvedAt - authTime > OIDC_MAX_AUTH_AGE_NS) return C.OIDC_AUTH_TIME;
  }
  return "";
}

const APPROVAL_WANT = { payloadType: APPROVAL_PAYLOAD_TYPE, signingTimeField: "approved_at" };

// checkAuthority: signer (condition 1), human-only, authority under the set
// in force (7), separation of duties (8).
function checkAuthority(a, directory, set, setHash, caller) {
  let revoked = false;
  if (a.method === "TENANT_KEY") {
    let res;
    try {
      res = verifyEnvelope(a.raw, { ...APPROVAL_WANT, purpose: PURPOSE.APPROVER }, directory.atHead);
    } catch {
      return { code: C.TIME_INVALID };
    }
    if (!res.integrityOk) return { code: C.SIGNATURE_INVALID };
    if (!res.trusted) return { code: C.SIGNER_NOT_TRUSTED };
    const state = directory.atHead.keyState(a.envelope.signature.keyId, a.envelope.signature.keyVersion);
    if (state.key.principal_type !== "HUMAN") return { code: C.NOT_HUMAN };
    if (state.key.principal_id !== a.principalId) return { code: C.KEY_PRINCIPAL_MISMATCH };
    revoked = directory.trusted.some((snapshot) => snapshot.keyState(a.envelope.signature.keyId, a.envelope.signature.keyVersion)?.revocationReason === "KEY_COMPROMISE");
  } else if (a.method === "INTENTRAX_ATTESTED_OIDC") {
    const keys = directory.inputs.approvalServiceKeys;
    if (!keys) return { code: C.SERVICE_KEY_NOT_PINNED, notChecked: true };
    let res;
    try {
      res = verifyEnvelope(a.raw, { ...APPROVAL_WANT, purpose: PURPOSE.APPROVAL_SERVICE }, keys);
    } catch {
      return { code: C.TIME_INVALID };
    }
    if (!res.integrityOk) return { code: C.SIGNATURE_INVALID };
    if (res.code === "SIGNER_NOT_PINNED") return { code: C.SERVICE_KEY_NOT_PINNED, notChecked: true };
    if (!res.trusted) return { code: C.SIGNER_NOT_TRUSTED };
  }
  const done = (code) => ({ code, revoked });
  if (a.setHash !== setHash) return done(C.SET_NOT_IN_FORCE);
  const member = findApprover(set, a.principalId);
  if (!member) return done(C.NOT_LISTED);
  if (!member.identity_methods.includes(a.method)) return done(C.METHOD_NOT_PERMITTED);
  if (a.method === "TENANT_KEY" && !member.key_ids.includes(a.envelope.signature.keyId)) return done(C.KEY_NOT_LISTED);
  if (!approverPermits(member, a.constraintId, a.policy.policy_id)) return done(C.NOT_AUTHORISED);
  if (set.separation_of_duties.approver_must_differ_from_caller && caller !== "" && caller === a.principalId) return done(C.SEPARATION_OF_DUTIES);
  return done("");
}

function disclosedApproverSet(candidates, setHash, tenantID) {
  for (const raw of candidates) {
    try {
      const set = decodeApproverSet(typeof raw === "string" ? raw : JSON.stringify(raw));
      if (set.tenant_id === tenantID && approverSetHash(set) === setHash) return set;
    } catch {
      // not a valid set
    }
  }
  return null;
}

function callerPrincipal(admission) {
  if (!admission.caller_attestation) return "";
  try {
    const env = parseEnvelope(JSON.stringify(admission.caller_attestation.envelope));
    const id = env.payload.caller?.principal_id;
    return typeof id === "string" ? id : "";
  } catch {
    return "";
  }
}

// approvalEvidenceStatement mirrors the Go statement (spec 02 §5.5).
export function approvalEvidenceStatement(check) {
  const parts = check.approvals.map((a) => `${a.identity_method}, ${a.principal_id}, approved ${a.approved_at}, expires ${a.not_after}`);
  const noun = check.approvals.length === 1 ? "approval" : "approvals";
  return `Constraint ${check.constraint_id} (REQUIRE_APPROVAL): ${check.sealed_status} by ${check.approvals.length} ${noun} (${parts.join("; ")}).`;
}
