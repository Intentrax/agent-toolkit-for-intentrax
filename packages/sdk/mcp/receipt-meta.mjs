// MCP receipt references (Workstream A). Ported unchanged in behaviour from
// examples/mcp-trust-receipts/src/receipt-meta.mjs. The server side stays
// behind engine work (assessment §5.A, owner item §9.3).
//
// A server that already obtained an Intentrax proof for a tool call can hand
// the client a POINTER to it, in the result's `_meta`, without touching the
// tool's own output:
//
//   result._meta["com.intentrax/receipt"] = {
//     schema, proof_id, verify_url, record_kind, tool_name,
//     arguments_digest, tool_manifest_digest?, limitations[]
//   }
//
// Design rules (see docs/architecture/INTENTRAX_MCP_TRUST_VISIBILITY_ASSESSMENT.md §5.A):
//   - `content` and `structuredContent` are never modified, so structured
//     output stays valid against the tool's outputSchema.
//   - No text footer. Text appended to tool output is model-visible and
//     indistinguishable from prompt injection; it is deliberately not offered.
//   - An optional `resource_link` content block (opt-in) points at the public
//     verify page with neutral, non-imperative wording.
//   - The reference is UNAUTHENTICATED. Anyone can write any `_meta`. It is a
//     claim to check, never evidence: a client must fetch/verify the proof and
//     compare the proof's own fields with the call it actually made.
//   - `record_kind` is fixed to "decision_record": production proofs record an
//     admission/policy decision. They do not attest execution or its effect.
//
// Pure: no I/O, no network, no clock.

import { domainDigest } from "./canonical.mjs";

export const RECEIPT_META_KEY = "com.intentrax/receipt";
export const RECEIPT_REF_SCHEMA = "intentrax.mcp.receipt_ref/0.1";
export const ARGUMENTS_DIGEST_DOMAIN = "INTENTRAX_MCP_TOOL_ARGUMENTS_V0_1";
export const DEFAULT_VERIFY_HOSTS = Object.freeze(["verify.intentrax.com"]);

// Fixed limitation strings. Kept short, factual and non-imperative because a
// host may show `_meta` (or the resource link) to the model.
export const RECEIPT_LIMITATIONS = Object.freeze([
  "Decision record: shows what was submitted for admission and the recorded decision.",
  "Does not show that the tool ran, what it returned, or what changed downstream.",
  "This reference is unauthenticated until the proof is verified against pinned keys.",
]);

const PROOF_ID_RE = /^[A-Za-z0-9_.-]{1,128}$/;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function isSafeProofId(value) {
  return typeof value === "string" && PROOF_ID_RE.test(value) && !value.includes("..");
}

function checkVerifyUrl(value, allowedHosts) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.port !== "") return null;
  if (!allowedHosts.includes(url.hostname)) return null;
  return url.toString();
}

// argumentsDigest — digest of the arguments object the SERVER received. The
// client computes the same value over the arguments it SENT and compares.
// NOTE: this is this prototype's own rule. The engine's
// MCPToolCallEnvelope.arguments_hash has no published rule: it is supplied
// by the caller and only checked to be 64-hex. Binding the two needs the
// engine to publish one rule as a cross-language vector (owner approval item).
export function argumentsDigest(args) {
  if (!isPlainObject(args)) {
    throw new Error("receipt: tool arguments must be an object");
  }
  return domainDigest(ARGUMENTS_DIGEST_DOMAIN, args);
}

export function buildReceiptRef({ proofId, verifyUrl, toolName, args, toolManifestDigest, allowedHosts = DEFAULT_VERIFY_HOSTS } = {}) {
  if (!isSafeProofId(proofId)) throw new Error("receipt: unsafe proof id");
  const url = checkVerifyUrl(verifyUrl, allowedHosts);
  if (url === null) throw new Error("receipt: verify_url must be https on an allowed host");
  if (typeof toolName !== "string" || toolName.length === 0 || toolName.length > 128) {
    throw new Error("receipt: tool name is required");
  }
  const ref = {
    schema: RECEIPT_REF_SCHEMA,
    proof_id: proofId,
    verify_url: url,
    record_kind: "decision_record",
    tool_name: toolName,
    arguments_digest: argumentsDigest(args),
    limitations: [...RECEIPT_LIMITATIONS],
  };
  if (toolManifestDigest !== undefined) {
    if (typeof toolManifestDigest !== "string" || !DIGEST_RE.test(toolManifestDigest)) {
      throw new Error("receipt: tool_manifest_digest must be sha256:<64 hex>");
    }
    ref.tool_manifest_digest = toolManifestDigest;
  }
  return ref;
}

// attachReceiptMeta(result, ref, { resourceLink }) -> a NEW CallToolResult.
// Never mutates `result`; never changes `content` entries, `structuredContent`
// or `isError`; refuses to overwrite an existing receipt key.
export function attachReceiptMeta(result, ref, { resourceLink = false } = {}) {
  if (!isPlainObject(result) || !Array.isArray(result.content)) {
    throw new Error("receipt: result must be a CallToolResult with a content array");
  }
  if (!isPlainObject(ref) || ref.schema !== RECEIPT_REF_SCHEMA) {
    throw new Error("receipt: ref must come from buildReceiptRef");
  }
  const existingMeta = result._meta === undefined ? {} : result._meta;
  if (!isPlainObject(existingMeta)) {
    throw new Error("receipt: existing _meta must be an object");
  }
  if (Object.prototype.hasOwnProperty.call(existingMeta, RECEIPT_META_KEY)) {
    throw new Error("receipt: result already carries " + RECEIPT_META_KEY);
  }
  const content = [...result.content];
  if (resourceLink) {
    content.push({
      type: "resource_link",
      uri: ref.verify_url,
      name: "intentrax-decision-record-" + ref.proof_id,
      title: "Intentrax decision record",
      description: "Signed record of the admission decision for this call. It does not show the call's outcome.",
      mimeType: "text/html",
    });
  }
  return {
    ...result,
    content,
    _meta: { ...existingMeta, [RECEIPT_META_KEY]: structuredClone(ref) },
  };
}

// readReceiptMeta(result, { allowedHosts }) — the CLIENT side. Returns
// { status: "ABSENT" } | { status: "MALFORMED", reasons[] } |
// { status: "UNVERIFIED_REFERENCE", ref }. It never returns anything that
// reads as verified: verification is a separate step against the proof.
export function readReceiptMeta(result, { allowedHosts = DEFAULT_VERIFY_HOSTS } = {}) {
  const meta = isPlainObject(result) ? result._meta : undefined;
  if (!isPlainObject(meta) || !Object.prototype.hasOwnProperty.call(meta, RECEIPT_META_KEY)) {
    return { status: "ABSENT" };
  }
  const ref = meta[RECEIPT_META_KEY];
  const reasons = [];
  if (!isPlainObject(ref)) {
    return { status: "MALFORMED", reasons: ["not_an_object"] };
  }
  if (ref.schema !== RECEIPT_REF_SCHEMA) reasons.push("schema");
  if (!isSafeProofId(ref.proof_id)) reasons.push("proof_id");
  if (typeof ref.verify_url !== "string" || checkVerifyUrl(ref.verify_url, allowedHosts) === null) reasons.push("verify_url");
  if (ref.record_kind !== "decision_record") reasons.push("record_kind");
  if (typeof ref.tool_name !== "string" || ref.tool_name.length === 0) reasons.push("tool_name");
  if (typeof ref.arguments_digest !== "string" || !DIGEST_RE.test(ref.arguments_digest)) reasons.push("arguments_digest");
  if (ref.tool_manifest_digest !== undefined && (typeof ref.tool_manifest_digest !== "string" || !DIGEST_RE.test(ref.tool_manifest_digest))) {
    reasons.push("tool_manifest_digest");
  }
  if (reasons.length > 0) return { status: "MALFORMED", reasons };
  return { status: "UNVERIFIED_REFERENCE", ref: structuredClone(ref) };
}

// matchReceiptToCall — the cheap local check a client can do BEFORE fetching
// the proof: does the reference even claim to be about the call it made?
// A match proves nothing on its own (the server wrote both sides); a mismatch
// is a definite red flag.
export function matchReceiptToCall(ref, { toolName, args }) {
  const mismatches = [];
  if (ref.tool_name !== toolName) mismatches.push("tool_name");
  if (ref.arguments_digest !== argumentsDigest(args)) mismatches.push("arguments_digest");
  return { consistent: mismatches.length === 0, mismatches };
}
