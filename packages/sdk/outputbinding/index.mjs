// Engine-computed output binding (spec 10,
// docs/architecture/specs/10-engine-computed-output-binding.md): who computed a
// proof's answer hash, answer and quote checks, execute request /1.2, saved
// answers and the chat-answer region.
//
// A sealed aep.output_binding names its source. ENGINE_COMPUTED: Intentrax
// hashed the answer text itself at issuance (execute request /1.2).
// PRODUCER_DECLARED_AT_ISSUANCE: the company declared the hash and Intentrax
// never saw the text (/1.1). The statements are shared byte for byte with the
// Go offline verifier (persistence.OutputBindingStatement) and the verify
// page; a producer-declared binding must never read as computed or checked by
// Intentrax. A text match is a match against the sealed hash, never a verdict
// on whether the answer is correct.
//
// verify-proof wires this in an SDK release (reporting output_binding,
// output_binding_statement, --answer-file and --quote-file); until then it is
// a library with tests. Node built-ins and ../index.js only.
import {
  CANONICAL_OUTPUT_HASH_ALGORITHM,
  CANONICAL_OUTPUT_NORMALIZATION,
  VERIFICATION_OUTPUT_REGION_ATTRIBUTE,
  canonicalJson,
  canonicalOutputHash,
  normalizeCanonicalOutput,
} from "../index.js";

export const OUTPUT_BINDING_SOURCE_ENGINE_COMPUTED = "ENGINE_COMPUTED";
export const OUTPUT_BINDING_SOURCE_PRODUCER_DECLARED = "PRODUCER_DECLARED_AT_ISSUANCE";
export const OUTPUT_BINDING_STATEMENTS = Object.freeze({
  [OUTPUT_BINDING_SOURCE_ENGINE_COMPUTED]: "Intentrax computed this answer hash itself from the text it received at issuance (binding_source ENGINE_COMPUTED). It shows what the company's system sent through Intentrax, not what a screen displayed.",
  [OUTPUT_BINDING_SOURCE_PRODUCER_DECLARED]: "The company computed this answer hash itself; Intentrax sealed it without seeing the text (binding_source PRODUCER_DECLARED_AT_ISSUANCE). Intentrax did not compare it with any text.",
});
export const ANSWER_CHECK_MATCH = "MATCH";
export const ANSWER_CHECK_MISMATCH = "MISMATCH";
export const QUOTE_CHECK_IN_ANSWER = "QUOTE_IN_ANSWER";
export const QUOTE_CHECK_NOT_IN_ANSWER = "QUOTE_NOT_IN_ANSWER";
export const QUOTE_CHECK_NOT_CHECKABLE = "NOT_CHECKABLE";

const SHA256_HEX = /^[a-f0-9]{64}$/;
const OUTPUT_BINDING_MEMBERS = Object.freeze(["binding_source", "content_hash", "hash_algorithm", "normalization"]);

const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const isDegenerate = (hex) => hex.split("").every((char) => char === hex[0]);

// sealedOutputBinding mirrors the Go persistence.OutputBindingFromCanonicalAEP:
// aep.output_binding, when present, is an object of exactly four string
// members with a "sha256:" + 64 lowercase hex content_hash (not one repeated
// digit), SHA-256, intentrax-content/1.0 and a known binding_source.
// Returns { binding, invalid }: binding null and invalid [] when the AEP binds
// no output (or is not a JSON object); a present but out-of-contract binding
// gives invalid field names and must fail verification closed. Only call it
// on canonical AEP bytes whose signatures were verified.
export function sealedOutputBinding(canonicalAEPJSON) {
  let aep;
  try {
    aep = JSON.parse(canonicalAEPJSON);
  } catch {
    return { binding: null, invalid: [] };
  }
  if (!isRecord(aep) || !Object.hasOwn(aep, "output_binding")) return { binding: null, invalid: [] };
  const binding = aep.output_binding;
  if (!isRecord(binding)) return { binding: null, invalid: ["output_binding"] };
  const members = Object.keys(binding).sort();
  if (members.length !== OUTPUT_BINDING_MEMBERS.length || members.some((member, index) => member !== OUTPUT_BINDING_MEMBERS[index] || typeof binding[member] !== "string")) {
    return { binding: null, invalid: ["output_binding.members"] };
  }
  const invalid = [];
  const digest = binding.content_hash.startsWith("sha256:") ? binding.content_hash.slice("sha256:".length) : "";
  if (!SHA256_HEX.test(digest) || isDegenerate(digest)) invalid.push("output_binding.content_hash");
  if (binding.hash_algorithm !== CANONICAL_OUTPUT_HASH_ALGORITHM) invalid.push("output_binding.hash_algorithm");
  if (binding.normalization !== CANONICAL_OUTPUT_NORMALIZATION) invalid.push("output_binding.normalization");
  if (!Object.hasOwn(OUTPUT_BINDING_STATEMENTS, binding.binding_source)) invalid.push("output_binding.binding_source");
  if (invalid.length > 0) return { binding: null, invalid };
  return {
    binding: Object.freeze({
      binding_source: binding.binding_source,
      content_hash: binding.content_hash,
      hash_algorithm: binding.hash_algorithm,
      normalization: binding.normalization,
    }),
    invalid: [],
  };
}

// outputBindingStatement — the binding source in words, or null for a source
// outside the contract (verifiers refuse those).
export function outputBindingStatement(binding) {
  const source = isRecord(binding) ? binding.binding_source : undefined;
  return Object.hasOwn(OUTPUT_BINDING_STATEMENTS, source) ? OUTPUT_BINDING_STATEMENTS[source] : null;
}

function bareContentDigest(value) {
  if (typeof value !== "string") return null;
  const digest = value.trim().replace(/^sha-?256:/i, "").toLowerCase();
  return SHA256_HEX.test(digest) ? digest : null;
}

// checkAnswerAgainstBinding — MATCH when the answer, normalized with
// intentrax-content/1.0, hashes to the binding's content_hash ("sha256:<hex>"
// as sealed, or the bare hex the public verify response relays). Same members
// as the Go offlineproof.AnswerCheck.
export function checkAnswerAgainstBinding(answer, binding) {
  const computed = canonicalOutputHash(typeof answer === "string" ? answer : "");
  const sealed = isRecord(binding) ? binding.content_hash : undefined;
  const sealedDigest = bareContentDigest(sealed);
  return {
    status: sealedDigest !== null && sealedDigest === computed ? ANSWER_CHECK_MATCH : ANSWER_CHECK_MISMATCH,
    computed_content_hash: "sha256:" + computed,
    sealed_content_hash: typeof sealed === "string" ? sealed : "",
    binding_source: isRecord(binding) && typeof binding.binding_source === "string" ? binding.binding_source : "",
  };
}

// checkQuoteInAnswer — whether the quote, normalized, is a non-empty substring
// of the normalized answer. Use it only after an answer MATCH; with no
// matching full answer a quote is NOT_CHECKABLE (a hash of the whole answer
// cannot confirm part of it).
export function checkQuoteInAnswer(answer, quote) {
  const normalizedQuote = normalizeCanonicalOutput(typeof quote === "string" ? quote : "");
  return normalizedQuote !== "" && normalizeCanonicalOutput(typeof answer === "string" ? answer : "").includes(normalizedQuote)
    ? QUOTE_CHECK_IN_ANSWER
    : QUOTE_CHECK_NOT_IN_ANSWER;
}

// checkAnswerAndQuote — both checks, as verify-proof --answer-file /
// --quote-file and the Go verifier report them: quote_check is null without a
// quote, and NOT_CHECKABLE after an answer MISMATCH.
export function checkAnswerAndQuote(binding, answer, quote = null) {
  const answerCheck = checkAnswerAgainstBinding(answer, binding);
  let quoteCheck = null;
  if (quote !== null && quote !== undefined) {
    quoteCheck = answerCheck.status === ANSWER_CHECK_MATCH
      ? { status: checkQuoteInAnswer(answer, quote) }
      : { status: QUOTE_CHECK_NOT_CHECKABLE, reason: "the answer does not match the sealed hash" };
  }
  return { answer_check: answerCheck, quote_check: quoteCheck };
}

// ---------------------------------------------------------------------------
// Execute request /1.2: the engine hashes output_text itself and seals
// ENGINE_COMPUTED. Accepted only while the engine's
// output_binding_engine_computed_enabled flag is on (off by default); see
// engine/internal/runtime/intentexecute/output_binding_v12.go.
// ---------------------------------------------------------------------------

export const INTENT_EXECUTE_REQUEST_SCHEMA_VERSION_V12 = "intentrax.runtime.intent_execute.request/1.2";
// Mirrors intentexecute.MaxRequestBytesV12 and MaxOutputTextBytes.
export const INTENT_EXECUTE_MAX_REQUEST_BYTES_V12 = 40960;
export const INTENT_EXECUTE_MAX_OUTPUT_TEXT_BYTES = 32768;
const INTENT_EXECUTE_V12_FIELDS = Object.freeze([
  "schema_version", "intent_id", "tenant_id", "action", "idempotency_key", "proof_chain_fixture_ref", "output_text",
]);

// engineBindIntentExecuteOutput returns a NEW /1.2 execute request: the
// caller's request with schema_version /1.2 and output_text = the answer
// exactly as the page will show it. Any output_binding on the input is
// dropped (/1.2 refuses one). The input is not mutated.
export function engineBindIntentExecuteOutput(request, outputText) {
  const { output_binding: _declared, ...rest } = isRecord(request) ? request : {};
  return { ...rest, schema_version: INTENT_EXECUTE_REQUEST_SCHEMA_VERSION_V12, output_text: outputText };
}

const isNonEmptyStable = (value) => typeof value === "string" && value.length > 0 && value.trim() === value;

// isEngineHashableOutputText mirrors the engine's decodeOutputText: a
// well-formed string (no lone surrogates) of 1 to 32768 UTF-8 bytes that is
// non-empty after intentrax-content/1.0 normalization.
export function isEngineHashableOutputText(value) {
  if (typeof value !== "string" || value.length === 0) return false;
  if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value)) return false;
  if (Buffer.byteLength(value, "utf8") > INTENT_EXECUTE_MAX_OUTPUT_TEXT_BYTES) return false;
  return normalizeCanonicalOutput(value) !== "";
}

// validateIntentExecuteRequestV12 mirrors the engine's /1.2 decode: exactly
// the seven members, an UPPER_SNAKE action, a hashable output_text and a
// canonical body within 40960 bytes. Returns sorted invalid field names.
export function validateIntentExecuteRequestV12(request) {
  if (!isRecord(request)) return ["intent_execute_request"];
  const invalid = [];
  for (const key of Object.keys(request)) {
    if (!INTENT_EXECUTE_V12_FIELDS.includes(key)) invalid.push("body");
  }
  if (request.schema_version !== INTENT_EXECUTE_REQUEST_SCHEMA_VERSION_V12) invalid.push("schema_version");
  for (const field of ["intent_id", "tenant_id", "idempotency_key", "proof_chain_fixture_ref"]) {
    if (!isNonEmptyStable(request[field])) invalid.push(field);
  }
  if (typeof request.action !== "string" || !/^[A-Z0-9]+(_[A-Z0-9]+)*$/.test(request.action)) invalid.push("action");
  if (!isEngineHashableOutputText(request.output_text)) invalid.push("output_text");
  if (invalid.length === 0 && Buffer.byteLength(canonicalJson(request), "utf8") > INTENT_EXECUTE_MAX_REQUEST_BYTES_V12) invalid.push("body");
  return [...new Set(invalid)].sort();
}

// ---------------------------------------------------------------------------
// Saved answers. The link carries the answer in the URL FRAGMENT, which
// browsers never send to a server:
//   https://verify.intentrax.com/verify/proof/{proof_id}/check#answer=<base64url(UTF-8 answer)>
// The file form is intentrax.saved_answer/0.1 and may embed the signed proof
// export for offline checks.
// ---------------------------------------------------------------------------

export const SAVED_ANSWER_SCHEMA_VERSION = "intentrax.saved_answer/0.1";
export const SAVED_ANSWER_LINK_MAX_BYTES = 16384;
export const SAVED_ANSWER_VERIFY_BASE_URL = "https://verify.intentrax.com";

// The detection convention's proof-id rule (DETECTION-CONVENTION.md §1).
export function isSafeProofId(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 256 && /^[A-Za-z0-9._:-]+$/.test(value);
}

// savedAnswerLink — the stable link for a bound answer, or null when the proof
// id is unsafe or the answer is empty or longer than SAVED_ANSWER_LINK_MAX_BYTES
// (use buildSavedAnswer for those).
export function savedAnswerLink(proofId, answer, base = SAVED_ANSWER_VERIFY_BASE_URL) {
  if (!isSafeProofId(proofId) || typeof answer !== "string" || answer.length === 0) return null;
  const bytes = Buffer.from(answer, "utf8");
  if (bytes.length > SAVED_ANSWER_LINK_MAX_BYTES) return null;
  return `${String(base).replace(/\/+$/, "")}/verify/proof/${proofId}/check#answer=${bytes.toString("base64url")}`;
}

// readSavedAnswerFragment — the answer carried by a saved link's fragment
// ("#answer=..." or "answer=..."), or null when there is none, it is too long,
// or it does not decode to UTF-8 text.
export function readSavedAnswerFragment(fragment) {
  if (typeof fragment !== "string") return null;
  const match = /(?:^#?|&)answer=([A-Za-z0-9_-]+)(?:&|$)/.exec(fragment);
  if (!match || Math.floor(match[1].length * 3 / 4) > SAVED_ANSWER_LINK_MAX_BYTES) return null;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(match[1], "base64url"));
  } catch {
    return null;
  }
}

// buildSavedAnswer — the intentrax.saved_answer/0.1 file. proof_export (the
// signed proof export, intentrax.registry.proof_lookup/1.0) is optional; with
// it the file can be checked with no network.
export function buildSavedAnswer({ proof_id: proofId, answer_text: answerText, proof_export: proofExport } = {}) {
  if (!isSafeProofId(proofId) || typeof answerText !== "string" || answerText.length === 0) return null;
  return {
    schema_version: SAVED_ANSWER_SCHEMA_VERSION,
    proof_id: proofId,
    verify_url: `${SAVED_ANSWER_VERIFY_BASE_URL}/api/public/verify/proof/${proofId}`,
    answer_text: answerText,
    ...(isRecord(proofExport) ? { proof_export: proofExport } : {}),
  };
}

const escapeHTML = (value) => String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

// chatAnswerRegionHTML — one bot answer as a convention v1.1 scoped region:
// <div data-intentrax-output data-intentrax-proof="{proof_id}">{escaped answer}</div>.
// white-space:pre-wrap keeps the answer's line breaks in the region's visible
// text, which the extension hashes. Render the SAME string you bound. Returns
// null for an unsafe proof id.
export function chatAnswerRegionHTML(proofId, answer) {
  if (!isSafeProofId(proofId) || typeof answer !== "string") return null;
  return `<div ${VERIFICATION_OUTPUT_REGION_ATTRIBUTE} data-intentrax-proof="${escapeHTML(proofId)}" style="white-space:pre-wrap">${escapeHTML(answer)}</div>`;
}
