// `intentrax approve`: sign an intentrax.approval/0.1 envelope with a local
// APPROVER key (identity method TENANT_KEY), after showing the approver the
// exact request. Specs: docs/architecture/specs/02-approval-record.md (approved
// 2026-11-21, amended 2026-11-22: human-only approvers, execute-time re-check)
// and 01-admission-request-v1.1.md §3.2 / §4.1.
//
// Local only: nothing is sent anywhere. The signed approval is written to a
// file; hosted submission comes later.
//
// What the approver approves is pinned by hashes this module recomputes
// itself: admission_request_hash from the request envelope, and
// arguments_hash from the exact arguments. A mismatch with what the pending
// approval request claims is refused before anything is shown or signed.

import { createHash, createPrivateKey, createPublicKey, randomBytes, sign } from "node:crypto";

import {
  CODE,
  PROFILE_ANY,
  PROFILE_INT,
  PURPOSE,
  SIGNING_PREFIX,
  digest,
  parseEnvelope,
  parseJson,
  parseTime,
  pinnedKeys,
  serialize,
  validHash,
  verifyEnvelope,
} from "../envelope/index.mjs";

export const APPROVAL_SCHEMA_VERSION = "intentrax.approval/0.1";
export const APPROVER_KEY_FILE_SCHEMA_VERSION = "intentrax.approver_key/0.1";
export const ENVELOPE_V11_SCHEMA_VERSION = "intentrax.runtime.agent_admission.mcp_tool_call_envelope/1.1";
export const DOMAIN_ARGUMENTS = "INTENTRAX_MCP_TOOL_ARGUMENTS_V0_1";
export const DOMAIN_ADMISSION_REQUEST = "INTENTRAX_ADMISSION_REQUEST_V1_1";
export const DOMAIN_FACT_COMMITMENT = "INTENTRAX_FACT_COMMITMENT_V0_1";
export const DOMAIN_APPROVER_SET = "INTENTRAX_APPROVER_SET_V0_1";
export const KEY_POP_PREFIX = "INTENTRAX_KEY_POP_V0_1\n";
export const DEFAULT_VALIDITY_SECONDS = 900;
export const HARD_CAP_VALIDITY_SECONDS = 86_400;

export class ApproveError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = "ApproveError";
    this.code = code;
  }
}
const refuse = (code, message) => { throw new ApproveError(code, message); };

const sha256Hex = (data) => createHash("sha256").update(data).digest("hex");
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const HEX64 = /^[0-9a-f]{64}$/;

// ---------------------------------------------------------------- hashes

// argumentsHash applies spec 01 §4.1: arguments must be a JSON object; duplicate
// names, lone surrogates, non-finite numbers and integer-valued numbers beyond
// ±(2^53−1) are refused (ARGUMENTS_NOT_CANONICALISABLE). Same rule as the Go
// engine (runtime/preapproval.ArgumentsHash). Returns {jcs, hash, value}.
export function argumentsHash(raw) {
  let value;
  try {
    value = typeof raw === "string" || raw instanceof Uint8Array ? parseJson(raw, PROFILE_ANY) : raw;
    if (!isObject(value)) throw new Error("arguments must be a JSON object");
    checkIntegerRange(value, "$");
    const jcs = serialize(value, PROFILE_ANY);
    return { jcs, hash: sha256Hex(Buffer.from(DOMAIN_ARGUMENTS + jcs, "utf8")), value };
  } catch (err) {
    if (err instanceof ApproveError) throw err;
    refuse("ARGUMENTS_NOT_CANONICALISABLE", err.message);
  }
}

function checkIntegerRange(value, path) {
  if (typeof value === "number") {
    if (Number.isInteger(value) && Math.abs(value) > Number.MAX_SAFE_INTEGER) {
      throw new Error(`integer at ${path} exceeds 2^53-1; send it as a string`);
    }
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => checkIntegerRange(v, `${path}[${i}]`));
  } else if (isObject(value)) {
    for (const [k, v] of Object.entries(value)) checkIntegerRange(v, `${path}.${k}`);
  }
}

// admissionRequestHash applies spec 01 §3.2 to a v1.1 envelope:
// D("INTENTRAX_ADMISSION_REQUEST_V1_1", envelope minus {arguments, caller_attestation, approvals}).
export function admissionRequestHash(envelope) {
  if (!isObject(envelope) || envelope.schema_version !== ENVELOPE_V11_SCHEMA_VERSION) {
    refuse("REQUEST_INVALID", `the request must be a ${ENVELOPE_V11_SCHEMA_VERSION} envelope`);
  }
  const hashed = {};
  for (const [k, v] of Object.entries(envelope)) {
    if (k !== "arguments" && k !== "caller_attestation" && k !== "approvals") hashed[k] = v;
  }
  return digest(DOMAIN_ADMISSION_REQUEST, hashed, PROFILE_ANY);
}

// ---------------------------------------------------------------- keys

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const KEY_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const PRINCIPAL_ID_PATTERN = /^[A-Za-z0-9._:-]{1,200}$/;

function privateKeyFromSeedHex(seedHex) {
  if (!HEX64.test(seedHex)) refuse("KEY_INVALID", "private_seed_hex must be 64 lowercase hex digits");
  return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seedHex, "hex")]), format: "der", type: "pkcs8" });
}
const publicKeyHexOf = (privateKey) => Buffer.from(createPublicKey(privateKey).export({ format: "jwk" }).x, "base64url").toString("hex");

// keyEntry is the `key` object a tenant key directory REGISTER entry carries
// (spec 00 §5). Approvers are human-only in v0.1 (spec 02 §2.1).
function keyEntry(file) {
  return {
    alg: "ED25519",
    key_id: file.key_id,
    key_version: file.key_version,
    principal_id: file.principal_id,
    principal_type: "HUMAN",
    public_key_hex: file.public_key_hex,
    purpose: PURPOSE.APPROVER,
  };
}

// generateApproverKey creates a fresh Ed25519 APPROVER key for a human
// principal. Returns {keyFile, registration}: keyFile holds the private seed
// and must stay with the approver (write it 0600); registration is the public
// request to register the key in the tenant key directory, with its proof of
// possession over UTF-8("INTENTRAX_KEY_POP_V0_1\n") || JCS({key, tenant_id}).
export function generateApproverKey({ tenantId, principalId, keyId, keyVersion = "1", validFrom, validUntil, seedHex } = {}) {
  if (typeof tenantId !== "string" || tenantId === "") refuse("KEY_INVALID", "--tenant-id is required");
  if (typeof principalId !== "string" || !PRINCIPAL_ID_PATTERN.test(principalId)) refuse("KEY_INVALID", "--principal-id must be an opaque id ([A-Za-z0-9._:-], never an email address)");
  if (typeof keyId !== "string" || !KEY_ID_PATTERN.test(keyId)) refuse("KEY_INVALID", "--key-id must match [A-Za-z0-9._:-]{1,128}");
  if (typeof keyVersion !== "string" || !/^[1-9][0-9]{0,8}$/.test(keyVersion)) refuse("KEY_INVALID", "--key-version must be a decimal string (1, 2, …)");
  for (const [name, value] of [["valid_from", validFrom], ["valid_until", validUntil]]) {
    if (value !== undefined) {
      try { parseTime(value); } catch (err) { refuse("KEY_INVALID", `${name}: ${err.message}`); }
    }
  }
  const seed = seedHex ?? randomBytes(32).toString("hex");
  const privateKey = privateKeyFromSeedHex(seed);
  const keyFile = {
    schema_version: APPROVER_KEY_FILE_SCHEMA_VERSION,
    tenant_id: tenantId,
    principal_id: principalId,
    principal_type: "HUMAN",
    purpose: PURPOSE.APPROVER,
    key_id: keyId,
    key_version: keyVersion,
    public_key_hex: publicKeyHexOf(privateKey),
    private_seed_hex: seed,
  };
  const key = keyEntry(keyFile);
  const pop = sign(null, Buffer.from(KEY_POP_PREFIX + serialize({ key, tenant_id: tenantId }, PROFILE_INT), "utf8"), privateKey).toString("hex");
  // Exactly the spec 00 §5 REGISTER subset the console and engine accept
  // (no extra members): {key, tenant_id, proof_of_possession_hex,
  // valid_from?, valid_until?}. Paste it as is.
  const registration = {
    key,
    proof_of_possession_hex: pop,
    tenant_id: tenantId,
    ...(validFrom === undefined ? {} : { valid_from: validFrom }),
    ...(validUntil === undefined ? {} : { valid_until: validUntil }),
  };
  return { keyFile, registration };
}

// loadApproverKey validates an approver key file and returns it with its
// private key object. A key that is not a HUMAN APPROVER key, or whose seed
// does not match public_key_hex, is refused.
export function loadApproverKey(raw) {
  let file;
  try {
    file = parseJson(raw, PROFILE_INT);
  } catch (err) {
    refuse("KEY_INVALID", `approver key file: ${err.message}`);
  }
  const members = ["key_id", "key_version", "principal_id", "principal_type", "private_seed_hex", "public_key_hex", "purpose", "schema_version", "tenant_id"];
  if (!isObject(file) || Object.keys(file).sort().join(",") !== members.join(",")) {
    refuse("KEY_INVALID", `approver key file must have exactly: ${members.join(", ")}`);
  }
  if (file.schema_version !== APPROVER_KEY_FILE_SCHEMA_VERSION) refuse("KEY_INVALID", `schema_version must be ${APPROVER_KEY_FILE_SCHEMA_VERSION}`);
  // Human-only approvers (spec 02 §2.1): only a HUMAN APPROVER key signs.
  if (file.principal_type !== "HUMAN") refuse("APPROVER_NOT_HUMAN", "approver keys belong to HUMAN principals only (spec 02 §2.1)");
  if (file.purpose !== PURPOSE.APPROVER) refuse("KEY_PURPOSE_MISMATCH", `the key's purpose is ${JSON.stringify(file.purpose)}, not APPROVER`);
  const privateKey = privateKeyFromSeedHex(file.private_seed_hex);
  if (publicKeyHexOf(privateKey) !== file.public_key_hex) refuse("KEY_INVALID", "private_seed_hex does not match public_key_hex");
  return { file, privateKey };
}

// ---------------------------------------------------------------- approval request

// The pending approval request the engine returns with PENDING_APPROVAL
// (spec 02 §4 "The approval flow"). Only the members a local approver needs.
export function parseApprovalRequest(raw) {
  let req;
  try {
    req = parseJson(raw, PROFILE_ANY);
  } catch (err) {
    refuse("APPROVAL_REQUEST_INVALID", err.message);
  }
  if (!isObject(req)) refuse("APPROVAL_REQUEST_INVALID", "approval request must be a JSON object");
  for (const k of ["admission_request_hash", "arguments_hash"]) {
    if (!validHash(req[k])) refuse("APPROVAL_REQUEST_INVALID", `${k} must be 64 lowercase hex digits`);
  }
  if (typeof req.constraint_id !== "string" || req.constraint_id === "") refuse("APPROVAL_REQUEST_INVALID", "constraint_id is required");
  const p = req.policy;
  const policyMembers = ["policy_id", "policy_version", "rule_id", "source_policy_hash"];
  if (!isObject(p) || Object.keys(p).sort().join(",") !== policyMembers.join(",") || policyMembers.some((k) => typeof p[k] !== "string" || p[k] === "") || !validHash(p.source_policy_hash)) {
    refuse("APPROVAL_REQUEST_INVALID", "policy must be exactly {policy_id, policy_version, rule_id, source_policy_hash}");
  }
  if (req.expires_at !== undefined) {
    try { parseTime(req.expires_at); } catch (err) { refuse("APPROVAL_REQUEST_INVALID", `expires_at: ${err.message}`); }
  }
  return req;
}

// ---------------------------------------------------------------- context

// directoryContext reads a tenant key directory snapshot
// ({schema_version: intentrax.trust.tenant_key_directory/0.1, tenant_id,
// entries: [bare signed envelopes]}) and returns, for the approver's key, the
// envelope_hash of its REGISTER entry and the approver_set_hash in force at
// the head (newest SET_APPROVERS). The approver uses it to name what they sign
// under; trust in the directory is the relying party's business (verify-proof).
export function directoryContext(raw, keyFile, now = Date.now()) {
  let snapshot;
  try {
    snapshot = parseJson(raw, PROFILE_ANY);
  } catch (err) {
    refuse("DIRECTORY_INVALID", err.message);
  }
  if (!isObject(snapshot) || snapshot.schema_version !== "intentrax.trust.tenant_key_directory/0.1" || !Array.isArray(snapshot.entries) || snapshot.entries.length === 0) {
    refuse("DIRECTORY_INVALID", "expected an intentrax.trust.tenant_key_directory/0.1 snapshot with entries");
  }
  if (snapshot.tenant_id !== keyFile.tenant_id) refuse("DIRECTORY_INVALID", "the directory belongs to another tenant");
  let keyEntryHash = "";
  let approverSetHash = "";
  let previous = "";
  let registered = null;
  const ended = [];
  snapshot.entries.forEach((entry, index) => {
    let parsed;
    try {
      parsed = parseEnvelope(JSON.stringify(entry));
    } catch (err) {
      refuse("DIRECTORY_INVALID", `entry ${index + 1}: ${err.message}`);
    }
    const p = parsed.payload;
    if (parsed.payloadType !== "intentrax.trust.tenant_key_entry/0.1" || p.entry_seq !== index + 1 || p.tenant_id !== keyFile.tenant_id
      || (index === 0 ? Object.hasOwn(p, "prev_entry_hash") : p.prev_entry_hash !== previous)) {
      refuse("DIRECTORY_INVALID", `entry ${index + 1} is out of sequence`);
    }
    previous = parsed.envelopeHash;
    const forThisKey = isObject(p.key) && p.key.key_id === keyFile.key_id && p.key.key_version === keyFile.key_version;
    if (p.op === "REGISTER" && forThisKey) {
      const want = keyEntry(keyFile);
      if (serialize(p.key, PROFILE_INT) !== serialize(want, PROFILE_INT)) {
        refuse("DIRECTORY_INVALID", `the directory registers ${keyFile.key_id}@${keyFile.key_version} with different key material, principal or purpose`);
      }
      keyEntryHash = parsed.envelopeHash;
      registered = p;
    }
    // A retired or revoked key signs nothing (tenant key directory rules:
    // RETIRE ends validity at valid_until, else recorded_at; REVOKE ends it
    // at revoked_at, and KEY_COMPROMISE voids every signature).
    if ((p.op === "RETIRE" || p.op === "REVOKE") && forThisKey) ended.push(p);
    if (p.op === "SET_APPROVERS") approverSetHash = p.approver_set_hash;
  });
  if (keyEntryHash === "") refuse("APPROVER_KEY_NOT_REGISTERED", `${keyFile.key_id}@${keyFile.key_version} has no REGISTER entry in the directory`);
  const nowNs = BigInt(now) * 1_000_000n;
  const timeOf = (value) => {
    try {
      return parseTime(value);
    } catch {
      refuse("DIRECTORY_INVALID", `invalid time ${JSON.stringify(value)} in the directory`);
    }
  };
  for (const e of ended) {
    if (e.op === "REVOKE") {
      if (e.revocation_reason === "KEY_COMPROMISE" || nowNs >= timeOf(e.revoked_at)) {
        refuse("APPROVER_KEY_REVOKED", `${keyFile.key_id}@${keyFile.key_version} is revoked in the tenant key directory (${e.revocation_reason})`);
      }
    } else if (nowNs >= timeOf(e.valid_until ?? e.recorded_at)) {
      refuse("APPROVER_KEY_RETIRED", `${keyFile.key_id}@${keyFile.key_version} is retired in the tenant key directory`);
    }
  }
  if ((registered.valid_from !== undefined && nowNs < timeOf(registered.valid_from)) || (registered.valid_until !== undefined && nowNs >= timeOf(registered.valid_until))) {
    refuse("APPROVER_KEY_NOT_VALID", `${keyFile.key_id}@${keyFile.key_version} is outside its validity window (${registered.valid_from ?? "-"} to ${registered.valid_until ?? "-"})`);
  }
  if (!validHash(approverSetHash)) refuse("APPROVER_SET_NOT_IN_FORCE", "the directory has no SET_APPROVERS entry");
  return { keyEntryHash, approverSetHash, head: previous };
}

// checkApproverSet checks the local approver against the approver set in
// force (spec 02 §2, §4.1 conditions 7 and 8) so that a useless approval is
// refused before signing. Returns the set hash.
export function checkApproverSet(raw, { keyFile, constraintId, policyId, expectedHash }) {
  let set;
  try {
    set = parseJson(raw, PROFILE_INT);
  } catch (err) {
    refuse("APPROVER_SET_INVALID", err.message);
  }
  if (!isObject(set) || set.schema_version !== "intentrax.approver_set/0.1" || !Array.isArray(set.approvers)) refuse("APPROVER_SET_INVALID", "expected an intentrax.approver_set/0.1 document");
  const hash = digest(DOMAIN_APPROVER_SET, set, PROFILE_INT);
  if (expectedHash && hash !== expectedHash) refuse("APPROVER_SET_NOT_IN_FORCE", "the approver set file is not the set in force in the directory");
  if (set.tenant_id !== keyFile.tenant_id) refuse("APPROVER_SET_INVALID", "the approver set belongs to another tenant");
  const member = set.approvers.find((a) => isObject(a) && a.principal_id === keyFile.principal_id);
  if (!member) refuse("APPROVER_NOT_AUTHORISED", `${keyFile.principal_id} is not in the approver set`);
  if (!Array.isArray(member.identity_methods) || !member.identity_methods.includes("TENANT_KEY")) refuse("APPROVER_NOT_AUTHORISED", "the approver set does not allow TENANT_KEY for this principal");
  if (!Array.isArray(member.key_ids) || !member.key_ids.includes(keyFile.key_id)) refuse("APPROVER_NOT_AUTHORISED", `key ${keyFile.key_id} is not listed for this principal`);
  if (!Array.isArray(member.may_approve) || !member.may_approve.some((m) => isObject(m) && m.constraint_id === constraintId && m.policy_id === policyId)) {
    refuse("APPROVER_NOT_AUTHORISED", `may_approve does not cover ${constraintId} on ${policyId}`);
  }
  return hash;
}

// ---------------------------------------------------------------- approval

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
export function newApprovalId(bytes = randomBytes(26)) {
  let out = "apr_";
  for (let i = 0; i < 26; i++) out += CROCKFORD[bytes[i] & 31];
  return out;
}

export function formatTime(ms) {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

const freshSalt = () => randomBytes(32).toString("hex");

function commitment(field, value, saltFor) {
  const opening = { field, salt: saltFor(field), value };
  return { commitment: digest(DOMAIN_FACT_COMMITMENT, opening, PROFILE_INT), opening };
}

// buildApproval prepares the approval: recomputes both hashes, checks them
// against the pending approval request, and returns everything the approver
// must see plus the unsigned payload. Nothing is signed here.
export function buildApproval({ request, argumentsRaw, approvalRequest, key, context, decision = "APPROVE", validForSeconds = DEFAULT_VALIDITY_SECONDS, reason, now = Date.now(), approvalId = newApprovalId(), saltFor = freshSalt }) {
  if (decision !== "APPROVE" && decision !== "REJECT") refuse("DECISION_INVALID", "decision must be APPROVE or REJECT");
  if (!Number.isSafeInteger(validForSeconds) || validForSeconds < 1 || validForSeconds > HARD_CAP_VALIDITY_SECONDS) {
    refuse("VALIDITY_INVALID", `--valid-for must be 1..${HARD_CAP_VALIDITY_SECONDS} seconds (default ${DEFAULT_VALIDITY_SECONDS})`);
  }
  const requestHash = admissionRequestHash(request);
  if (requestHash !== approvalRequest.admission_request_hash) {
    refuse("ADMISSION_REQUEST_HASH_MISMATCH", `the request hashes to ${requestHash}, the approval request names ${approvalRequest.admission_request_hash}`);
  }
  const args = argumentsHash(argumentsRaw);
  if (args.hash !== request.arguments_hash) refuse("ARGUMENTS_HASH_MISMATCH", `the arguments hash to ${args.hash}, the request declares ${request.arguments_hash}`);
  if (args.hash !== approvalRequest.arguments_hash) refuse("ARGUMENTS_HASH_MISMATCH", `the arguments hash to ${args.hash}, the approval request names ${approvalRequest.arguments_hash}`);
  if (request.tenant_id !== key.file.tenant_id) refuse("TENANT_MISMATCH", "the request belongs to another tenant than the approver key");
  if (approvalRequest.expires_at !== undefined && BigInt(now) * 1_000_000n >= parseTime(approvalRequest.expires_at)) {
    refuse("APPROVAL_REQUEST_EXPIRED", `the approval request expired at ${approvalRequest.expires_at}`);
  }
  // Separation of duties (spec 02 §4.1 condition 8).
  const callerPrincipal = callerPrincipalOf(request);
  if (callerPrincipal !== "" && callerPrincipal === key.file.principal_id) {
    refuse("APPROVER_IS_CALLER", "the approver must differ from the caller principal of the request");
  }
  const approvedAt = formatTime(Math.floor(now / 1000) * 1000);
  const notAfter = formatTime(Math.floor(now / 1000) * 1000 + validForSeconds * 1000);
  const subject = commitment("approver_subject", { key_entry_hash: context.keyEntryHash }, saltFor);
  const reasonCommit = typeof reason === "string" && reason !== "" ? commitment("reason", reason, saltFor) : null;
  const payload = {
    schema_version: APPROVAL_SCHEMA_VERSION,
    approval_id: approvalId,
    tenant_id: key.file.tenant_id,
    decision,
    subject: {
      admission_request_hash: requestHash,
      arguments_hash: args.hash,
      constraint_id: approvalRequest.constraint_id,
      policy: {
        policy_id: approvalRequest.policy.policy_id,
        policy_version: approvalRequest.policy.policy_version,
        rule_id: approvalRequest.policy.rule_id,
        source_policy_hash: approvalRequest.policy.source_policy_hash,
      },
    },
    approver: {
      approver_set_hash: context.approverSetHash,
      identity_method: "TENANT_KEY",
      principal_id: key.file.principal_id,
      principal_type: "HUMAN",
      subject_commitment: subject.commitment,
    },
    approved_at: approvedAt,
    not_after: notAfter,
    single_use: true,
    ...(reasonCommit ? { reason_commitment: reasonCommit.commitment } : {}),
  };
  const disclosures = [
    { type: "COMMITMENT_OPENING", commitment: subject.commitment, opening: subject.opening },
    ...(reasonCommit ? [{ type: "COMMITMENT_OPENING", commitment: reasonCommit.commitment, opening: reasonCommit.opening }] : []),
  ];
  return { payload, disclosures, argumentsJcs: args.jcs, argumentsValue: args.value, requestHash };
}

function callerPrincipalOf(request) {
  const env = request.caller_attestation;
  if (!isObject(env) || !isObject(env.payload) || !isObject(env.payload.caller)) return "";
  return typeof env.payload.caller.principal_id === "string" ? env.payload.caller.principal_id : "";
}

// signApproval signs the payload with the approver key and verifies the
// result against that key as a pinned APPROVER key before returning it.
export function signApproval(payload, key) {
  const message = Buffer.from(SIGNING_PREFIX + serialize({ payload, payload_type: APPROVAL_SCHEMA_VERSION }, PROFILE_INT), "utf8");
  const envelope = {
    payload_type: APPROVAL_SCHEMA_VERSION,
    payload,
    signatures: [{
      alg: "ED25519",
      key_id: key.file.key_id,
      key_version: key.file.key_version,
      public_key_hex: key.file.public_key_hex,
      signature_hex: sign(null, message, key.privateKey).toString("hex"),
    }],
  };
  const check = verifyEnvelope(JSON.stringify(envelope), { payloadType: APPROVAL_SCHEMA_VERSION, purpose: PURPOSE.APPROVER, signingTimeField: "approved_at" },
    pinnedKeys([{ keyId: key.file.key_id, keyVersion: key.file.key_version, publicKeyHex: key.file.public_key_hex, purpose: PURPOSE.APPROVER }]));
  if (!check.trusted) refuse(CODE.SIGNATURE_INVALID, "the signed approval did not verify under the approver key");
  return { envelope, envelopeHash: check.envelope.envelopeHash };
}

// ---------------------------------------------------------------- rendering

// displayString renders a JSON value for a terminal: JSON-encoded, with every
// character outside printable ASCII escaped as \uXXXX, so control sequences,
// bidirectional overrides and lookalike characters cannot disguise a value.
export function displayValue(value) {
  return escapeNonPrintable(serialize(value, PROFILE_ANY));
}

// escapeNonPrintable keeps printable ASCII and writes everything else as
// \uXXXX (JCS has already escaped control characters inside strings).
export function escapeNonPrintable(text) {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    out += c >= 0x20 && c <= 0x7e ? text[i] : "\\u" + c.toString(16).padStart(4, "0");
  }
  return out;
}

const escapePointer = (name) => name.replace(/~/g, "~0").replace(/\//g, "~1");

// argumentLines flattens arguments to one "pointer = value" line per leaf
// (RFC 6901 pointers), so nested values cannot hide.
// Every line goes through displayPointer and displayValue, including empty
// containers, so a member name cannot smuggle terminal control sequences.
export function argumentLines(value, pointer = "") {
  if (Array.isArray(value)) {
    if (value.length === 0) return [`${displayPointer(pointer || "/")} = []`];
    return value.flatMap((v, i) => argumentLines(v, `${pointer}/${i}`));
  }
  if (isObject(value)) {
    const names = Object.keys(value).sort();
    if (names.length === 0) return [`${displayPointer(pointer || "/")} = {}`];
    return names.flatMap((n) => argumentLines(value[n], `${pointer}/${escapePointer(n)}`));
  }
  return [`${displayPointer(pointer)} = ${displayValue(value)}`];
}

// displayPointer renders a JSON Pointer unquoted, with quotes, backslashes and
// control characters JSON-escaped and everything outside printable ASCII
// written as \uXXXX.
export function displayPointer(pointer) {
  return escapeNonPrintable(JSON.stringify(pointer).slice(1, -1));
}

function pointerGet(value, pointer) {
  if (pointer === "") return { found: true, value };
  if (!pointer.startsWith("/")) return { found: false };
  let current = value;
  for (const raw of pointer.slice(1).split("/")) {
    const name = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(current) && /^(0|[1-9][0-9]*)$/.test(name) && Number(name) < current.length) current = current[Number(name)];
    else if (isObject(current) && Object.hasOwn(current, name)) current = current[name];
    else return { found: false };
  }
  return { found: true, value: current };
}

// Names commonly used for money and counterparties. Used only to draw the
// approver's eye; they are labelled as detected by name, never as facts.
const AMOUNT_NAMES = new Set(["amount", "amount_minor", "amount_cents", "value", "total", "price", "quantity"]);
const CURRENCY_NAMES = new Set(["currency", "currency_code"]);
const PAYEE_NAMES = new Set(["payee", "recipient", "to", "destination", "account", "beneficiary", "charge", "customer", "iban", "email", "resource"]);

// keyFacts returns the amount, currency and payee/resource to highlight.
// With a fact map entry for this tool (spec 03 §4.2), its pointers are used
// and labelled "fact map"; otherwise top-level members with common names are
// shown and labelled "detected by name".
export function keyFacts(argumentsValue, { factMap, serverId, toolName } = {}) {
  const out = [];
  const entry = factMap && Array.isArray(factMap.tools) ? factMap.tools.find((t) => isObject(t) && t.server_id === serverId && t.tool_name === toolName) : undefined;
  if (entry && isObject(entry.facts)) {
    for (const [fact, spec] of Object.entries(entry.facts)) {
      if (!isObject(spec) || typeof spec.pointer !== "string") continue;
      const got = pointerGet(argumentsValue, spec.pointer);
      out.push({ label: displayPointer(fact), source: `fact map ${displayPointer(spec.pointer)}`, value: got.found ? displayValue(got.value) : "(absent)" });
    }
    return out;
  }
  for (const name of Object.keys(argumentsValue).sort()) {
    const lower = name.toLowerCase();
    const label = AMOUNT_NAMES.has(lower) ? "amount" : CURRENCY_NAMES.has(lower) ? "currency" : PAYEE_NAMES.has(lower) ? "payee/resource" : "";
    if (label) out.push({ label, source: `detected by name ${displayPointer("/" + escapePointer(name))}`, value: displayValue(argumentsValue[name]) });
  }
  return out;
}

// renderRequest is the text shown to the approver before signing.
export function renderRequest({ request, built, approvalRequest, key, decision, factMap }) {
  const lines = [];
  lines.push(`You are about to ${decision} this exact tool call, signed with your key ${key.file.key_id}@${key.file.key_version} (${key.file.principal_id}).`);
  lines.push("");
  lines.push(`  tenant        ${displayValue(request.tenant_id)}`);
  lines.push(`  server        ${displayValue(request.server_id)}${request.server_origin ? ` at ${displayValue(request.server_origin)}` : ""}`);
  lines.push(`  tool          ${displayValue(request.tool_name)}`);
  lines.push(`  policy        ${displayValue(approvalRequest.policy.policy_id)}@${displayValue(approvalRequest.policy.policy_version)}, rule ${displayValue(approvalRequest.policy.rule_id)}`);
  lines.push(`  constraint    ${displayValue(approvalRequest.constraint_id)}`);
  const facts = keyFacts(built.argumentsValue, { factMap, serverId: request.server_id, toolName: request.tool_name });
  for (const f of facts) lines.push(`  ${f.label.padEnd(13)} ${f.value}   (${f.source})`);
  lines.push("");
  lines.push("  arguments, one value per line (strings JSON-escaped; non-ASCII shown as \\uXXXX):");
  for (const l of argumentLines(built.argumentsValue)) lines.push(`    ${l}`);
  lines.push("");
  lines.push("  arguments, canonical bytes (RFC 8785; exactly what arguments_hash covers):");
  lines.push(`    ${escapeNonPrintable(built.argumentsJcs)}`);
  lines.push("");
  lines.push(`  admission_request_hash  ${built.requestHash}   (recomputed from the request)`);
  lines.push(`  arguments_hash          ${built.payload.subject.arguments_hash}   (recomputed from the arguments)`);
  lines.push(`  valid                   ${built.payload.approved_at} until ${built.payload.not_after}, single use`);
  lines.push("");
  lines.push("At execution the gate recomputes arguments_hash over what it sends and refuses any difference (spec 01 §4.3): this approval covers these arguments only.");
  return lines.join("\n");
}
