// Proof export attachments and disclosures (spec 00 §8), and what the
// verifier opens with them. Port of the Go verifier (offlineproof/export.go
// and disclosures.go, PR #569).
//
// The export container is unsigned: it can lower an assessment, never raise
// one. `attachments` are bare signed envelopes; `disclosures` are typed
// objects: ARGUMENTS, COMMITMENT_OPENING, APPROVER_SET, TENANT_KEY_DIRECTORY,
// FACT_MAP, POLICY_DOCUMENT. Unknown or malformed items are ignored and
// reported. result_hash is computed without both members.
//
// Opening is fail-closed: disclosed arguments that do not hash to the sealed
// (or opened) arguments_hash, and an opening that does not reproduce its
// commitment, fail verification.
//
// Parse the export with the strict parser (envelope/jcs.mjs parseJson), not
// JSON.parse: duplicate member names inside disclosed arguments must be
// refused, not silently collapsed.

import { PROFILE_ANY, digest, serialize, verifyCommitment } from "../envelope/index.mjs";
import { REQUEST_FACT_KEYS } from "./policy-binding.mjs";

export const DOMAIN_MCP_TOOL_ARGUMENTS = "INTENTRAX_MCP_TOOL_ARGUMENTS_V0_1";
export const TOOL_COMMITMENT_FIELD = "tool";
export const EVENT_SALT_FIELD = "eeo.commitment_salt";
const DISCLOSURE_MEMBERS = Object.freeze({
  ARGUMENTS: "arguments",
  APPROVER_SET: "approver_set",
  TENANT_KEY_DIRECTORY: "directory",
  FACT_MAP: "fact_map",
  POLICY_DOCUMENT: "policy_document",
});
const HEX64 = /^[0-9a-f]{64}$/;
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// Go's folded member name (encoding/json): ASCII letters upper-cased, and the
// two non-ASCII runes whose fold set holds an ASCII letter (U+017F long s,
// U+212A Kelvin sign) mapped to it. Any other non-ASCII name matches no field.
function goFoldName(name) {
  let out = "";
  for (const ch of name) {
    const c = ch.codePointAt(0);
    if (c < 0x80) out += ch.toUpperCase();
    else if (c === 0x17f) out += "S";
    else if (c === 0x212a) out += "K";
    else return null;
  }
  return out;
}

// goStringFields reads string fields as Go's json.Unmarshal into a struct of
// string fields does: member names match ignoring case (Go's fold), members
// apply in document order so the last match wins, null leaves a field as it
// was, and any other non-string value is a type error. Returns
// {values, typeError}; values holds "" for fields never set.
export function goStringFields(object, fields) {
  const byFold = new Map(fields.map((f) => [goFoldName(f), f]));
  const values = Object.fromEntries(fields.map((f) => [f, ""]));
  let typeError = false;
  for (const [name, value] of Object.entries(object)) {
    const field = byFold.get(goFoldName(name));
    if (field === undefined || value === null) continue;
    if (typeof value !== "string") typeError = true;
    else values[field] = value;
  }
  return { values, typeError };
}

// splitProofExport separates the unsigned extras from the proof lookup
// result. Returns {lookup, extras}; lookup is the export without
// `attachments` and `disclosures`, so result_hash is computed as before.
export function splitProofExport(exportValue) {
  if (!isObject(exportValue)) throw new Error("proof export is not a JSON object");
  const extras = { attachments: [], arguments: [], openings: [], approverSets: [], directories: [], factMaps: [], policyDocuments: [], ignored: [] };
  if (!own(exportValue, "attachments") && !own(exportValue, "disclosures")) return { lookup: exportValue, extras };
  const lookup = {};
  for (const [k, v] of Object.entries(exportValue)) if (k !== "attachments" && k !== "disclosures") lookup[k] = v;
  if (own(exportValue, "attachments")) {
    if (!Array.isArray(exportValue.attachments)) throw new Error("proof export attachments must be an array");
    extras.attachments = [...exportValue.attachments];
  }
  if (own(exportValue, "disclosures")) {
    if (!Array.isArray(exportValue.disclosures)) throw new Error("proof export disclosures must be an array");
    exportValue.disclosures.forEach((item, i) => addDisclosure(extras, i, item));
  }
  return { lookup, extras };
}

function addDisclosure(extras, index, item) {
  if (!isObject(item)) return extras.ignored.push(`${index}:NOT_AN_OBJECT`);
  if (typeof item.type !== "string") return extras.ignored.push(`${index}:TYPE_MISSING`);
  if (item.type === "COMMITMENT_OPENING") {
    if (Object.keys(item).length !== 3 || !own(item, "opening") || typeof item.commitment !== "string") return extras.ignored.push(`${index}:MALFORMED`);
    return extras.openings.push({ commitment: item.commitment, opening: item.opening });
  }
  const member = DISCLOSURE_MEMBERS[item.type];
  if (!own(DISCLOSURE_MEMBERS, item.type)) return extras.ignored.push(`${index}:UNKNOWN_TYPE`);
  if (!own(item, member) || Object.keys(item).length !== 2) return extras.ignored.push(`${index}:MALFORMED`);
  const target = { ARGUMENTS: "arguments", APPROVER_SET: "approverSets", TENANT_KEY_DIRECTORY: "directories", FACT_MAP: "factMaps", POLICY_DOCUMENT: "policyDocuments" }[item.type];
  return extras[target].push(item[member]);
}

// argumentsHash is spec 01 §4.1 over a disclosed arguments object (JCS-ANY;
// integer-valued |x| > 2^53−1, 1e21 included, refused). Same rule as the
// engine and `intentrax approve`.
export function argumentsHash(value) {
  if (!isObject(value)) throw new Error("arguments must be a JSON object");
  rejectUnsafeIntegers(value);
  return digest(DOMAIN_MCP_TOOL_ARGUMENTS, value, PROFILE_ANY);
}

function rejectUnsafeIntegers(v) {
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error(`arguments number ${v} is not finite`);
    if (Number.isInteger(v) && Math.abs(v) > Number.MAX_SAFE_INTEGER) throw new Error(`arguments integer ${v} exceeds 2^53-1`);
  } else if (Array.isArray(v)) {
    v.forEach(rejectUnsafeIntegers);
  } else if (isObject(v)) {
    Object.values(v).forEach(rejectUnsafeIntegers);
  }
}

function openCommitment(item, field) {
  verifyCommitment(item.commitment, item.opening);
  if (!isObject(item.opening) || item.opening.field !== field) {
    throw new Error(`opening field ${JSON.stringify(item.opening?.field)}, sealed field ${JSON.stringify(field)}`);
  }
  return item.opening.value;
}

// The value rules of the request facts (spec 03 §4.1; Go
// PolicyRequestFactsInvalidFields).
function openedFactValue(field, value) {
  const key = REQUEST_FACT_KEYS[field];
  const bad = () => { throw new Error(`opened ${field} out of contract`); };
  switch (key) {
    case "amount_minor":
      if (!Number.isSafeInteger(value)) throw new Error(`opened ${field} is not an integer`);
      return value;
    case "currency":
      if (typeof value !== "string" || !/^[A-Z]{3}$/.test(value)) bad();
      return value;
    case "environment":
      if (!["PROD", "STAGING", "DEV"].includes(value)) bad();
      return value;
    case "resource":
      if (typeof value !== "string" || value === "" || [...value].length > 256) bad();
      return value;
    default:
      if (typeof value !== "string" || !/^[A-Za-z0-9_.-]{1,128}$/.test(value)) bad();
      return value;
  }
}

// openDisclosures mirrors offlineproof.openDisclosures. admission and policy
// are the sealed members (null when absent). Returns {report, argumentsHash,
// facts, salt, arguments, serverId, toolName}; throws (fail closed) on a
// mismatch or a bad opening.
//   report: {arguments_recomputed, tool_commitment_opened, facts_opened?, ignored?}
//   arguments: the JCS-ANY text of disclosed arguments that hash to the
//     sealed arguments_hash, or null. Facts are re-derived from this form, as
//     at admission: a hash-equivalent disclosure (12500.0, 1.25e4) reads as
//     12500 (spec 03 §6.5).
//   serverId, toolName: the tool, sealed in PLAINTEXT or opened from
//     tool_commitment in COMMITTED ("" when unknown).
export function openDisclosures(admission, policy, extras) {
  const report = { arguments_recomputed: false, tool_commitment_opened: false };
  const ignored = [...(extras.ignored ?? [])];
  const factsOpened = [];
  const facts = {};
  let salt = "";
  let argumentsText = null;
  let serverId = "";
  let toolName = "";
  const finish = (sealedArgumentsHash) => ({
    report: { ...report, ...(factsOpened.length ? { facts_opened: [...factsOpened].sort() } : {}), ...(ignored.length ? { ignored } : {}) },
    argumentsHash: sealedArgumentsHash,
    facts,
    salt,
    arguments: argumentsText,
    serverId,
    toolName,
  });
  if (admission === null) return finish("");
  let sealed = admission.arguments_hash ?? "";
  if (isObject(admission.tool)) {
    serverId = admission.tool.server_id ?? "";
    toolName = admission.tool.tool_name ?? "";
  }
  if (admission.disclosure === "COMMITTED") {
    const item = (extras.openings ?? []).find((o) => o.commitment === admission.tool_commitment);
    if (item) {
      let value;
      try {
        value = openCommitment(item, TOOL_COMMITMENT_FIELD);
      } catch (err) {
        throw new Error(`tool_commitment opening invalid: ${err.message}`);
      }
      // Read as the Go verifier's json.Unmarshal into string fields does.
      const tool = isObject(value) ? goStringFields(value, ["arguments_hash", "server_id", "tool_name"]) : null;
      if (tool === null || tool.typeError || !HEX64.test(tool.values.arguments_hash)) {
        throw new Error("tool_commitment opening has no arguments_hash");
      }
      sealed = tool.values.arguments_hash;
      serverId = tool.values.server_id;
      toolName = tool.values.tool_name;
      report.tool_commitment_opened = true;
    }
  }
  for (const args of extras.arguments ?? []) {
    let hash;
    try {
      hash = argumentsHash(args);
    } catch (err) {
      throw new Error(`disclosed arguments: ${err.message}`);
    }
    if (sealed === "") {
      ignored.push("ARGUMENTS:NO_SEALED_HASH_OPENED");
      continue;
    }
    if (hash !== sealed) throw new Error(`disclosed arguments hash ${hash}, the record seals ${sealed}`);
    report.arguments_recomputed = true;
    argumentsText = serialize(args, PROFILE_ANY);
  }
  const evaluated = policy?.evaluated_facts;
  if (!evaluated) return finish(sealed);
  const wanted = new Map((evaluated.withheld ?? []).map((w) => [w.commitment, w.field]));
  if (evaluated.event_salt_commitment) wanted.set(evaluated.event_salt_commitment, EVENT_SALT_FIELD);
  for (const item of extras.openings ?? []) {
    const field = wanted.get(item.commitment);
    if (field === undefined) continue;
    let value;
    try {
      value = openCommitment(item, field);
    } catch (err) {
      throw new Error(`opening of ${field} invalid: ${err.message}`);
    }
    if (field === EVENT_SALT_FIELD) {
      if (typeof value !== "string" || !HEX64.test(value)) throw new Error("event salt opening is not 64 hex digits");
      salt = value;
    } else {
      facts[field] = openedFactValue(field, value);
    }
    factsOpened.push(field);
  }
  return finish(sealed);
}

// Exposed for parity tests: the canonical bytes of disclosed arguments.
export const argumentsJcs = (value) => serialize(value, PROFILE_ANY);
