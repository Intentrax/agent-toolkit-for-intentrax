// Tenant key directory (`intentrax.trust.tenant_key_directory/0.1`, spec 00
// §5) and approver set (`intentrax.approver_set/0.1`, spec 02 §2), verifier
// half. Port of engine/internal/trustlayer/tenantkeydir (directory.go and
// approverset.go, #558): the same chain rules and codes.
//
// Chain rules: every entry signed by a trusted TENANT_KEY_DIRECTORY key;
// strict payload per op; tenant; contiguous entry_seq; prev_entry_hash links;
// non-decreasing recorded_at; REGISTER needs a valid proof of possession and a
// key_id/version and public key unused so far; RETIRE/REVOKE name the
// registered key exactly; a revoked key accepts only one more operation, a
// REVOKE that escalates a non-compromise revocation to KEY_COMPROMISE (the
// earlier revoked_at is kept).

import {
  CODE as ENVELOPE_CODE,
  PROFILE_ANY,
  PROFILE_INT,
  PURPOSE,
  digest,
  ed25519Verify,
  parseJson,
  parseTime,
  serialize,
  validHash,
  verifyEnvelope,
} from "../envelope/index.mjs";

export const ENTRY_SCHEMA_VERSION = "intentrax.trust.tenant_key_entry/0.1";
export const DIRECTORY_SCHEMA_VERSION = "intentrax.trust.tenant_key_directory/0.1";
export const APPROVER_SET_SCHEMA_VERSION = "intentrax.approver_set/0.1";
export const DOMAIN_APPROVER_SET = "INTENTRAX_APPROVER_SET_V0_1";
const KEY_POP_PREFIX = "INTENTRAX_KEY_POP_V0_1\n";

export const DIRECTORY_CODE = Object.freeze({
  ENTRY_MALFORMED: "TENANT_KEY_ENTRY_MALFORMED",
  ENTRY_SIGNATURE: "TENANT_KEY_ENTRY_SIGNATURE_INVALID",
  ENTRY_NOT_TRUSTED: "TENANT_KEY_ENTRY_SIGNER_NOT_TRUSTED",
  CHAIN_BROKEN: "TENANT_KEY_DIRECTORY_CHAIN_BROKEN",
  TENANT_MISMATCH: "TENANT_KEY_ENTRY_TENANT_MISMATCH",
  PROOF_OF_POSSESSION: "TENANT_KEY_PROOF_OF_POSSESSION_INVALID",
  KEY_ALREADY_REGISTERED: "TENANT_KEY_ALREADY_REGISTERED",
  KEY_NOT_REGISTERED: "TENANT_KEY_NOT_REGISTERED",
  KEY_STATE_INVALID: "TENANT_KEY_STATE_INVALID",
  HEAD_UNKNOWN: "TENANT_KEY_DIRECTORY_HEAD_UNKNOWN",
  APPROVER_SET_MALFORMED: "APPROVER_SET_MALFORMED",
  PURPOSE_NOT_ALLOWED: "TENANT_KEY_PURPOSE_NOT_ALLOWED",
});

export class DirectoryError extends Error {
  constructor(code, reason) {
    super(`${code}: ${reason}`);
    this.name = "DirectoryError";
    this.code = code;
  }
}
const fail = (code, reason) => { throw new DirectoryError(code, reason); };

const KEY_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const KEY_VERSION = /^[A-Za-z0-9._-]{1,32}$/;
const PRINCIPAL_ID = /^[A-Za-z0-9._:@/-]{1,256}$/;
const TENANT_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const REASON = /^[A-Z][A-Z0-9_]{0,63}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const TENANT_HELD = new Set([PURPOSE.CALLER_REQUEST, PURPOSE.APPROVER, PURPOSE.EXECUTOR_ATTESTATION]);
const KEY_MEMBERS = ["alg", "key_id", "key_version", "principal_id", "principal_type", "public_key_hex", "purpose"];
const COMMON_REQUIRED = ["schema_version", "tenant_id", "entry_seq", "op", "registered_by_hash", "recorded_at"];
const OP_RULES = {
  REGISTER: { required: ["key", "valid_from", "proof_of_possession_hex"], optional: ["valid_until"] },
  RETIRE: { required: ["key"], optional: ["valid_until"] },
  REVOKE: { required: ["key", "revoked_at", "revocation_reason"], optional: [] },
  SET_APPROVERS: { required: ["approver_set_hash"], optional: [] },
};

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const timeOr = (s, what) => {
  try {
    return parseTime(s);
  } catch (err) {
    fail(DIRECTORY_CODE.ENTRY_MALFORMED, `${what}: ${err.message}`);
  }
};

function validateKey(k) {
  if (!isObject(k) || Object.keys(k).sort().join(",") !== KEY_MEMBERS.join(",")) fail(DIRECTORY_CODE.ENTRY_MALFORMED, "key: members invalid");
  if (k.alg !== "ED25519") fail(DIRECTORY_CODE.ENTRY_MALFORMED, "key.alg must be ED25519");
  if (typeof k.key_id !== "string" || !KEY_ID.test(k.key_id)) fail(DIRECTORY_CODE.ENTRY_MALFORMED, "key.key_id invalid");
  if (typeof k.key_version !== "string" || !KEY_VERSION.test(k.key_version)) fail(DIRECTORY_CODE.ENTRY_MALFORMED, "key.key_version invalid");
  if (typeof k.principal_id !== "string" || !PRINCIPAL_ID.test(k.principal_id)) fail(DIRECTORY_CODE.ENTRY_MALFORMED, "key.principal_id invalid");
  if (!["HUMAN", "AGENT", "SYSTEM"].includes(k.principal_type)) fail(DIRECTORY_CODE.ENTRY_MALFORMED, "key.principal_type must be HUMAN, AGENT or SYSTEM");
  if (typeof k.public_key_hex !== "string" || !/^[0-9a-f]{64}$/.test(k.public_key_hex)) fail(DIRECTORY_CODE.ENTRY_MALFORMED, "key.public_key_hex must be 64 lowercase hex digits");
  if (!TENANT_HELD.has(k.purpose)) fail(DIRECTORY_CODE.PURPOSE_NOT_ALLOWED, `key.purpose ${JSON.stringify(k.purpose)} is not a tenant-held purpose`);
}

// decodeEntryPayload mirrors tenantkeydir.DecodeEntryPayload.
export function decodeEntryPayload(p) {
  if (!isObject(p)) fail(DIRECTORY_CODE.ENTRY_MALFORMED, "payload is not an object");
  const rules = OP_RULES[p.op];
  if (typeof p.op !== "string" || !rules) fail(DIRECTORY_CODE.ENTRY_MALFORMED, `op ${JSON.stringify(p.op)} unknown`);
  const allowed = new Set(["prev_entry_hash", ...COMMON_REQUIRED, ...rules.required, ...rules.optional]);
  for (const n of [...COMMON_REQUIRED, ...rules.required]) if (!own(p, n)) fail(DIRECTORY_CODE.ENTRY_MALFORMED, `${p.op} entry: member "${n}" is required`);
  for (const n of Object.keys(p)) if (!allowed.has(n)) fail(DIRECTORY_CODE.ENTRY_MALFORMED, `${p.op} entry: member "${n}" is not allowed`);
  for (const n of ["schema_version", "tenant_id", "prev_entry_hash", "op", "approver_set_hash", "valid_from", "valid_until", "revoked_at", "revocation_reason", "proof_of_possession_hex", "registered_by_hash", "recorded_at"]) {
    if (own(p, n) && typeof p[n] !== "string") fail(DIRECTORY_CODE.ENTRY_MALFORMED, `payload: ${n} must be a string`);
  }
  if (!Number.isSafeInteger(p.entry_seq)) fail(DIRECTORY_CODE.ENTRY_MALFORMED, "payload: entry_seq must be an integer");
  if (p.schema_version !== ENTRY_SCHEMA_VERSION) fail(DIRECTORY_CODE.ENTRY_MALFORMED, `schema_version must be ${ENTRY_SCHEMA_VERSION}`);
  if (!TENANT_ID.test(p.tenant_id)) fail(DIRECTORY_CODE.ENTRY_MALFORMED, "tenant_id invalid");
  if (p.entry_seq < 1) fail(DIRECTORY_CODE.ENTRY_MALFORMED, "entry_seq must be >= 1");
  if (own(p, "prev_entry_hash") !== (p.entry_seq > 1)) fail(DIRECTORY_CODE.ENTRY_MALFORMED, "prev_entry_hash is required after entry 1 and omitted for entry 1");
  if (p.entry_seq > 1 && !validHash(p.prev_entry_hash)) fail(DIRECTORY_CODE.ENTRY_MALFORMED, "prev_entry_hash invalid");
  if (!validHash(p.registered_by_hash)) fail(DIRECTORY_CODE.ENTRY_MALFORMED, "registered_by_hash invalid");
  timeOr(p.recorded_at, "recorded_at");
  if (own(p, "key")) validateKey(p.key);
  if (p.op === "REGISTER") {
    const from = timeOr(p.valid_from, "valid_from");
    if (own(p, "valid_until") && p.valid_until !== "") {
      if (!(timeOr(p.valid_until, "valid_until") > from)) fail(DIRECTORY_CODE.ENTRY_MALFORMED, "valid_until must be after valid_from");
    }
    if (!HEX128.test(p.proof_of_possession_hex)) fail(DIRECTORY_CODE.ENTRY_MALFORMED, "proof_of_possession_hex must be 128 lowercase hex digits");
  } else if (p.op === "RETIRE") {
    if (own(p, "valid_until") && p.valid_until !== "") timeOr(p.valid_until, "valid_until");
  } else if (p.op === "REVOKE") {
    timeOr(p.revoked_at, "revoked_at");
    if (!REASON.test(p.revocation_reason)) fail(DIRECTORY_CODE.ENTRY_MALFORMED, "revocation_reason invalid");
  } else if (!validHash(p.approver_set_hash)) {
    fail(DIRECTORY_CODE.ENTRY_MALFORMED, "approver_set_hash invalid");
  }
  return p;
}

export function verifyProofOfPossession(tenantID, key, popHex) {
  const message = Buffer.from(KEY_POP_PREFIX + serialize({ key, tenant_id: tenantID }, PROFILE_INT), "utf8");
  if (!HEX128.test(popHex) || !ed25519Verify(key.public_key_hex, message, popHex)) {
    fail(DIRECTORY_CODE.PROOF_OF_POSSESSION, "proof of possession does not verify under the registered key");
  }
}

const keyRef = (id, version) => `${id}\u0000${version}`;
const sameKey = (a, b) => serialize(a, PROFILE_INT) === serialize(b, PROFILE_INT);

// Snapshot is the directory state at one head.
export class Snapshot {
  constructor(tenantID) {
    this.tenantID = tenantID;
    this.head = "";
    this.seq = 0;
    this.entries = [];
    this.keys = new Map();
    this.approverSetHash = "";
  }

  apply(p, envelopeHash, recordedAt) {
    if (p.op === "REGISTER") {
      const ref = keyRef(p.key.key_id, p.key.key_version);
      if (this.keys.has(ref)) fail(DIRECTORY_CODE.KEY_ALREADY_REGISTERED, `key ${p.key.key_id}/${p.key.key_version} is already registered`);
      for (const other of this.keys.values()) {
        if (other.key.public_key_hex === p.key.public_key_hex) fail(DIRECTORY_CODE.KEY_ALREADY_REGISTERED, "public key is already registered");
      }
      verifyProofOfPossession(p.tenant_id, p.key, p.proof_of_possession_hex);
      const st = { key: p.key, validFrom: parseTime(p.valid_from), entryHash: envelopeHash };
      if (own(p, "valid_until") && p.valid_until !== "") st.validUntil = parseTime(p.valid_until);
      this.keys.set(ref, st);
    } else if (p.op === "RETIRE" || p.op === "REVOKE") {
      const st = this.keys.get(keyRef(p.key.key_id, p.key.key_version));
      if (!st) fail(DIRECTORY_CODE.KEY_NOT_REGISTERED, `${p.op} names unregistered key ${p.key.key_id}/${p.key.key_version}`);
      if (!sameKey(st.key, p.key)) fail(DIRECTORY_CODE.KEY_STATE_INVALID, `${p.op} key object differs from the registered key`);
      if (st.revokedAt !== undefined || (st.revocationReason ?? "") !== "") {
        const escalation = p.op === "REVOKE" && p.revocation_reason === "KEY_COMPROMISE" && st.revocationReason !== "KEY_COMPROMISE";
        if (!escalation) fail(DIRECTORY_CODE.KEY_STATE_INVALID, `key ${p.key.key_id}/${p.key.key_version} is already revoked`);
        st.revocationReason = p.revocation_reason;
        return;
      }
      if (p.op === "RETIRE") {
        if (st.retiredAt !== undefined) fail(DIRECTORY_CODE.KEY_STATE_INVALID, `key ${p.key.key_id}/${p.key.key_version} is already retired`);
        st.retiredAt = own(p, "valid_until") && p.valid_until !== "" ? parseTime(p.valid_until) : recordedAt;
      } else {
        st.revokedAt = parseTime(p.revoked_at);
        st.revocationReason = p.revocation_reason;
      }
    } else if (p.op === "SET_APPROVERS") {
      this.approverSetHash = p.approver_set_hash;
    }
  }

  // at returns the snapshot at an earlier (or the current) head.
  at(head) {
    const i = this.entries.findIndex((e) => e.envelopeHash === head);
    if (i < 0) fail(DIRECTORY_CODE.HEAD_UNKNOWN, `head ${head} is not in the directory`);
    const out = new Snapshot(this.tenantID);
    for (const prior of this.entries.slice(0, i + 1)) {
      out.apply(prior.payload, prior.envelopeHash, prior.recordedAt);
      out.entries.push(prior);
      out.head = prior.envelopeHash;
      out.seq = prior.payload.entry_seq;
    }
    return out;
  }

  keyState(keyID, keyVersion) {
    const st = this.keys.get(keyRef(keyID, keyVersion));
    return st ? { ...st } : undefined;
  }

  // resolveKey makes a snapshot a KeyResolver for verifyEnvelope; a retired
  // key's validity ends at its retirement time.
  resolveKey(keyID, keyVersion) {
    const st = this.keys.get(keyRef(keyID, keyVersion));
    if (!st) return undefined;
    let validUntil = st.validUntil;
    if (st.retiredAt !== undefined && (validUntil === undefined || st.retiredAt < validUntil)) validUntil = st.retiredAt;
    return {
      keyId: st.key.key_id,
      keyVersion: st.key.key_version,
      publicKeyHex: st.key.public_key_hex,
      purpose: st.key.purpose,
      validFrom: st.validFrom,
      validUntil,
      revokedAt: st.revokedAt,
      revocationReason: st.revocationReason ?? "",
    };
  }
}

// verifyChain mirrors tenantkeydir.VerifyChain. entries are bare envelopes
// (raw JSON or in-memory values); directoryKeys is a KeyResolver.
export function verifyChain(tenantID, entries, directoryKeys) {
  const s = new Snapshot(tenantID);
  let lastRecorded = null;
  entries.forEach((entry, i) => {
    const raw = typeof entry === "string" || entry instanceof Uint8Array ? entry : JSON.stringify(entry);
    let res;
    try {
      res = verifyEnvelope(raw, { payloadType: ENTRY_SCHEMA_VERSION, purpose: PURPOSE.TENANT_KEY_DIRECTORY, signingTimeField: "recorded_at" }, directoryKeys);
    } catch (err) {
      fail(DIRECTORY_CODE.ENTRY_MALFORMED, `entry ${i + 1}: ${err.message}`);
    }
    if (!res.integrityOk) fail(DIRECTORY_CODE.ENTRY_SIGNATURE, `entry ${i + 1}: ${res.code}`);
    if (!res.trusted) fail(DIRECTORY_CODE.ENTRY_NOT_TRUSTED, `entry ${i + 1}: ${res.code}`);
    const p = decodeEntryPayload(res.envelope.payload);
    if (p.tenant_id !== tenantID) fail(DIRECTORY_CODE.TENANT_MISMATCH, `entry ${i + 1} names tenant ${JSON.stringify(p.tenant_id)}`);
    if (p.entry_seq !== i + 1) fail(DIRECTORY_CODE.CHAIN_BROKEN, `entry ${i + 1} has entry_seq ${p.entry_seq}`);
    if (i > 0 && p.prev_entry_hash !== s.head) fail(DIRECTORY_CODE.CHAIN_BROKEN, `entry ${i + 1} prev_entry_hash does not match entry ${i}`);
    if (lastRecorded !== null && res.signedAt < lastRecorded) fail(DIRECTORY_CODE.CHAIN_BROKEN, `entry ${i + 1} recorded_at is earlier than entry ${i}`);
    s.apply(p, res.envelope.envelopeHash, res.signedAt);
    lastRecorded = res.signedAt;
    s.entries.push({ envelopeHash: res.envelope.envelopeHash, payload: p, recordedAt: res.signedAt, signature: res.envelope.signature });
    s.head = res.envelope.envelopeHash;
    s.seq = p.entry_seq;
  });
  return s;
}

// parseDirectoryDocument mirrors tenantkeydir.ParseDocument:
// {schema_version, tenant_id, entries: [bare envelopes]}, head computed.
export function parseDirectoryDocument(raw, directoryKeys) {
  let doc;
  try {
    doc = typeof raw === "string" || raw instanceof Uint8Array ? parseJson(raw, PROFILE_ANY) : raw;
  } catch (err) {
    fail(DIRECTORY_CODE.ENTRY_MALFORMED, `directory document: ${err.message}`);
  }
  if (!isObject(doc) || Object.keys(doc).sort().join(",") !== "entries,schema_version,tenant_id" || !Array.isArray(doc.entries)) {
    fail(DIRECTORY_CODE.ENTRY_MALFORMED, "directory document: members must be exactly entries, schema_version, tenant_id");
  }
  if (doc.schema_version !== DIRECTORY_SCHEMA_VERSION) fail(DIRECTORY_CODE.ENTRY_MALFORMED, `directory document schema_version must be ${DIRECTORY_SCHEMA_VERSION}`);
  if (typeof doc.tenant_id !== "string" || !TENANT_ID.test(doc.tenant_id)) fail(DIRECTORY_CODE.ENTRY_MALFORMED, "directory document tenant_id invalid");
  return verifyChain(doc.tenant_id, doc.entries, directoryKeys);
}

// selfAssertedDirectoryKeys trusts each entry's own signing key (for the
// pinned-head mode, where trust comes from the head the chain must reach).
export function selfAssertedDirectoryKeys(doc) {
  const keys = [];
  for (const entry of isObject(doc) && Array.isArray(doc.entries) ? doc.entries : []) {
    const sig = isObject(entry) && Array.isArray(entry.signatures) && isObject(entry.signatures[0]) ? entry.signatures[0] : null;
    if (sig && typeof sig.key_id === "string" && typeof sig.key_version === "string" && typeof sig.public_key_hex === "string") {
      keys.push({ keyId: sig.key_id, keyVersion: sig.key_version, publicKeyHex: sig.public_key_hex, purpose: PURPOSE.TENANT_KEY_DIRECTORY });
    }
  }
  return { resolveKey: (id, version) => keys.find((k) => k.keyId === id && k.keyVersion === version) };
}

// ---------------------------------------------------------------- approver set

const sortedUnique = (list) => list.every((v, i) => i === 0 || list[i - 1] < v);

// decodeApproverSet mirrors tenantkeydir.DecodeApproverSet + Validate:
// exactly the schema members, JCS-INT, and the set rules.
export function decodeApproverSet(raw) {
  let set;
  try {
    set = typeof raw === "string" || raw instanceof Uint8Array ? parseJson(raw, PROFILE_INT) : raw;
    serialize(set, PROFILE_INT);
  } catch (err) {
    fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, err.message);
  }
  const top = ["approvers", "min_approvals", "schema_version", "separation_of_duties", "tenant_id", "version"];
  if (!isObject(set) || Object.keys(set).sort().join(",") !== top.join(",")) fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, "document has members that are not in the schema, or missing members");
  if (!isObject(set.separation_of_duties) || Object.keys(set.separation_of_duties).join(",") !== "approver_must_differ_from_caller") fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, "separation_of_duties members invalid");
  if (set.schema_version !== APPROVER_SET_SCHEMA_VERSION) fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, `schema_version must be ${APPROVER_SET_SCHEMA_VERSION}`);
  if (typeof set.tenant_id !== "string" || !TENANT_ID.test(set.tenant_id)) fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, "tenant_id invalid");
  if (!Number.isSafeInteger(set.version) || set.version < 1) fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, "version must be >= 1");
  if (!Array.isArray(set.approvers) || set.approvers.length === 0 || set.approvers.length > 64) fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, "approvers must hold 1 to 64 entries");
  if (!Number.isSafeInteger(set.min_approvals) || set.min_approvals < 1 || set.min_approvals > set.approvers.length) fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, "min_approvals must be between 1 and the number of approvers");
  if (set.separation_of_duties.approver_must_differ_from_caller !== true) fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, "separation_of_duties.approver_must_differ_from_caller must be true");
  const principals = new Set();
  const keyOwners = new Map();
  set.approvers.forEach((a, i) => {
    if (!isObject(a) || Object.keys(a).sort().join(",") !== "identity_methods,key_ids,may_approve,principal_id") fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, `approvers[${i}] members invalid`);
    if (typeof a.principal_id !== "string" || !PRINCIPAL_ID.test(a.principal_id)) fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, `approvers[${i}].principal_id invalid`);
    if (principals.has(a.principal_id)) fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, `approvers[${i}].principal_id is listed twice`);
    principals.add(a.principal_id);
    for (const list of ["identity_methods", "key_ids", "may_approve"]) if (!Array.isArray(a[list])) fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, `approvers[${i}].${list} must be an array`);
    if (a.identity_methods.length === 0) fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, `approvers[${i}].identity_methods is empty`);
    if (!a.identity_methods.every((m) => typeof m === "string") || !sortedUnique(a.identity_methods)) fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, `approvers[${i}].identity_methods must be sorted and unique`);
    let tenantKey = false;
    for (const m of a.identity_methods) {
      if (m === "TENANT_KEY") tenantKey = true;
      else if (m !== "INTENTRAX_ATTESTED_OIDC") fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, `approvers[${i}].identity_methods: ${JSON.stringify(m)} is not supported`);
    }
    if (tenantKey !== (a.key_ids.length > 0)) fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, `approvers[${i}].key_ids must be non-empty exactly when TENANT_KEY is permitted`);
    if (!a.key_ids.every((k) => typeof k === "string") || !sortedUnique(a.key_ids)) fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, `approvers[${i}].key_ids must be sorted and unique`);
    for (const k of a.key_ids) {
      if (!KEY_ID.test(k)) fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, `approvers[${i}].key_ids: ${JSON.stringify(k)} invalid`);
      if (keyOwners.has(k)) fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, `key_id ${JSON.stringify(k)} is listed twice`);
      keyOwners.set(k, a.principal_id);
    }
    if (a.may_approve.length === 0) fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, `approvers[${i}].may_approve is empty`);
    a.may_approve.forEach((m, j) => {
      if (!isObject(m) || Object.keys(m).sort().join(",") !== "constraint_id,policy_id" || typeof m.constraint_id !== "string" || typeof m.policy_id !== "string"
        || !PRINCIPAL_ID.test(m.constraint_id) || !PRINCIPAL_ID.test(m.policy_id)) {
        fail(DIRECTORY_CODE.APPROVER_SET_MALFORMED, `approvers[${i}].may_approve[${j}] invalid`);
      }
    });
  });
  return set;
}

export const approverSetHash = (set) => digest(DOMAIN_APPROVER_SET, set, PROFILE_INT);
export const findApprover = (set, principalID) => set.approvers.find((a) => a.principal_id === principalID);
export const approverPermits = (a, constraintID, policyID) => a.may_approve.some((m) => m.constraint_id === constraintID && m.policy_id === policyID);

export { ENVELOPE_CODE };
