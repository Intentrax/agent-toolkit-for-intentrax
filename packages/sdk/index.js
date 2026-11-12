import { createHash } from "node:crypto";

export const SDK_VERSION = "1.0.0";
export const API_VERSION = "v1";
export const VERIFY_REQUEST_HASH_DOMAIN = "INTENTRAX_PUBLIC_SDK_VERIFY_REQUEST_V1";
export const IDEMPOTENCY_KEY_DOMAIN = "INTENTRAX_PUBLIC_SDK_IDEMPOTENCY_V1";
export const AGENT_GATEWAY_ADMISSION_REQUEST_HASH_DOMAIN = "INTENTRAX_AGENT_GATEWAY_ADMISSION_REQUEST_V1";
export const AGENT_ADMISSION_SCHEMA_VERSION = "intentrax.runtime.agent_admission_request/1.0";
export const AGENT_ADMISSION_ENDPOINT = "/v1/agent/admissions";
// Live intent execution lane. The schema_version below is the exact string the
// engine's intentexecute.DecodeRequest requires; the endpoint is fail-closed
// (HTTP 423 until LiveExecutionEnabled, HTTP 403 until the tenant is
// allowlisted). See engine/internal/runtime/intentexecute/intentexecute.go.
export const INTENT_EXECUTE_REQUEST_SCHEMA_VERSION = "intentrax.runtime.intent_execute.request/1.0";
export const INTENT_EXECUTE_ENDPOINT = "/v1/intents/execute";
// Mirrors intentexecute.MaxRequestBytes: the engine rejects a canonical body
// larger than this with HTTP 400.
export const INTENT_EXECUTE_MAX_REQUEST_BYTES = 4096;
export const RECEIPT_VERIFICATION_REQUEST_SCHEMA_VERSION = "intentrax.runtime.proof_verification.request/1.0";
export const RECEIPT_VERIFICATION_ENDPOINT = "/v1/proofs/verify";
export const RECEIPT_VERIFICATION_REQUEST_HASH_DOMAIN = "INTENTRAX_RECEIPT_VERIFICATION_REQUEST_V1";
export const RECEIPT_VERIFICATION_IDEMPOTENCY_DOMAIN = "INTENTRAX_RECEIPT_VERIFICATION_IDEMPOTENCY_V1";
export const PROOF_EXPORT_ENDPOINT_PREFIX = "/v1/proofs";
export const PROOF_REPLAY_REQUEST_SCHEMA_VERSION = "intentrax.runtime.proof_replay.request/1.0";
export const PROOF_REPLAY_ENDPOINT = "/v1/proofs/replay";
export const VERIFIER_HANDOFF_ENDPOINT_PREFIX = "/v1/evidence/dry-run";
export const SDK_INPUT_ERROR_CODE = "INTX-SDK-INPUT-001";

const REQUIRED_FIELDS = [
  "action",
  "execution_id",
  "intent_id",
  "payload_hash",
  "principal_id",
  "proof_id",
  "request_body_hash",
  "request_method",
  "request_path",
  "required_tier",
  "timestamp",
];

const AGENT_ADMISSION_REQUIRED_FIELDS = [
  "schema_version",
  "tenant_id",
  "surface_id",
  "action",
  "adapter_id",
  "evidence_refs",
  "proof_refs",
  "request_payload_hash",
  "protocol_payload_ref",
  "idempotency_key_hash",
];

// The engine decodes exactly these six fields with DisallowUnknownFields, so
// any extra field is a 400. The order here is the sorted invalid-field order
// the engine's validateRequest emits.
const INTENT_EXECUTE_REQUIRED_FIELDS = [
  "schema_version",
  "intent_id",
  "tenant_id",
  "action",
  "idempotency_key",
  "proof_chain_fixture_ref",
];

const RECEIPT_VERIFICATION_REQUIRED_FIELDS = [
  "schema_version",
  "receipt_id",
  "receipt_hash",
  "evidence_record_hash",
  "handoff_hash",
  "proof_chain_fixture_ref",
  "proof_chain_fixture_hash",
];

const VALID_TIERS = new Set(["TIER_1", "TIER_2", "TIER_3", "TIER_4"]);
const PROOF_EXPORT_FORMATS = new Set(["json", "aep-json", "pdf"]);
const SHA256_RE = /^[a-f0-9]{64}$/;
const SHA256_REF_RE = /^sha256:[a-f0-9]{64}$/;

export function sha256Hex(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function isSha256Hex(value) {
  return typeof value === "string" && SHA256_RE.test(value);
}

export function isSha256Ref(value) {
  return typeof value === "string" && SHA256_REF_RE.test(value);
}

export function canonicalJson(value) {
  if (value === null) {
    return "null";
  }
  if (Array.isArray(value)) {
    return "[" + value.map((item) => canonicalJson(item)).join(",") + "]";
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "number" && Number.isInteger(value) && Number.isFinite(value)) {
    return String(value);
  }
  if (typeof value === "object") {
    return "{" + Object.keys(value).sort().map((key) => {
      const member = value[key];
      if (member === undefined) {
        throw new Error("canonical_json: undefined member " + key);
      }
      return JSON.stringify(key) + ":" + canonicalJson(member);
    }).join(",") + "}";
  }
  throw new Error("canonical_json: unsupported value");
}

export function validateVerificationRequest(request) {
  const invalid = [];
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    return ["verification_request"];
  }
  for (const field of REQUIRED_FIELDS) {
    if (typeof request[field] !== "string" || request[field].length === 0) {
      invalid.push(field);
    }
  }
  if (!isSha256Hex(request.payload_hash)) {
    invalid.push("payload_hash");
  }
  if (!isSha256Hex(request.request_body_hash)) {
    invalid.push("request_body_hash");
  }
  if (!VALID_TIERS.has(request.required_tier)) {
    invalid.push("required_tier");
  }
  return [...new Set(invalid)].sort();
}

export function verificationRequestHash(request) {
  return sha256Hex(VERIFY_REQUEST_HASH_DOMAIN + canonicalJson(request));
}

export function idempotencyInput(request) {
  return {
    payload_hash: request.payload_hash,
    proof_id: request.proof_id,
    request_body_hash: request.request_body_hash,
    request_method: request.request_method,
    request_path: request.request_path,
  };
}

export function createIdempotencyKey(request) {
  return sha256Hex(IDEMPOTENCY_KEY_DOMAIN + canonicalJson(idempotencyInput(request)));
}

// admissionIdempotencyKeyHash derives the agent-admission request's
// idempotency_key_hash from the SAME logical idempotency key the client later
// sends to execute. Set execute Request.idempotency_key = createIdempotencyKey(request)
// (raw) and admission Request.idempotency_key_hash = admissionIdempotencyKeyHash(request)
// (the SHA-256 of that raw key). The two are then provably the same logical key —
// one raw, one hashed — so a durable admission receipt can be correlated against
// the execution that carried the same key.
export function admissionIdempotencyKeyHash(request) {
  return sha256Hex(createIdempotencyKey(request));
}

export function buildVerificationEnvelope(request) {
  const invalidFields = validateVerificationRequest(request);
  if (invalidFields.length > 0) {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "Verification request is missing or malformed.",
        invalid_fields: invalidFields,
        retriable: false,
      },
    };
  }
  return {
    status: "PASS",
    output: {
      schema_version: "intentrax.public_sdk.verify/1.0",
      request_hash: verificationRequestHash(request),
      idempotency_key: createIdempotencyKey(request),
      request,
    },
  };
}

export function validateReceiptVerificationRequest(request) {
  const invalid = [];
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    return ["receipt_verification_request"];
  }
  for (const field of RECEIPT_VERIFICATION_REQUIRED_FIELDS) {
    if (!(field in request)) {
      invalid.push(field);
    }
  }
  if (request.schema_version !== RECEIPT_VERIFICATION_REQUEST_SCHEMA_VERSION) {
    invalid.push("schema_version");
  }
  if (!isSafeReceiptID(request.receipt_id)) {
    invalid.push("receipt_id");
  }
  for (const field of ["receipt_hash", "evidence_record_hash", "handoff_hash", "proof_chain_fixture_hash"]) {
    if (!isSha256Hex(request[field])) {
      invalid.push(field);
    }
  }
  if (typeof request.proof_chain_fixture_ref !== "string" ||
      request.proof_chain_fixture_ref.length === 0 ||
      request.proof_chain_fixture_ref.trim() !== request.proof_chain_fixture_ref ||
      request.proof_chain_fixture_ref.includes("..")) {
    invalid.push("proof_chain_fixture_ref");
  }
  return [...new Set(invalid)].sort();
}

export function receiptVerificationRequestHash(request) {
  return sha256Hex(RECEIPT_VERIFICATION_REQUEST_HASH_DOMAIN + canonicalJson(request));
}

export function receiptVerificationIdempotencyInput(request) {
  return {
    evidence_record_hash: request.evidence_record_hash,
    handoff_hash: request.handoff_hash,
    proof_chain_fixture_hash: request.proof_chain_fixture_hash,
    proof_chain_fixture_ref: request.proof_chain_fixture_ref,
    receipt_hash: request.receipt_hash,
    receipt_id: request.receipt_id,
  };
}

export function createReceiptVerificationIdempotencyKey(request) {
  return sha256Hex(RECEIPT_VERIFICATION_IDEMPOTENCY_DOMAIN + canonicalJson(receiptVerificationIdempotencyInput(request)));
}

export function buildReceiptVerificationEnvelope(request) {
  const invalidFields = validateReceiptVerificationRequest(request);
  if (invalidFields.length > 0) {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "Receipt verification request is missing or malformed.",
        invalid_fields: invalidFields,
        retriable: false,
      },
    };
  }
  return {
    status: "PASS",
    output: {
      schema_version: "intentrax.public_sdk.receipt_verification/1.0",
      endpoint: RECEIPT_VERIFICATION_ENDPOINT,
      request_hash: receiptVerificationRequestHash(request),
      idempotency_key: createReceiptVerificationIdempotencyKey(request),
      request,
    },
  };
}

export function normalizeProofExportFormat(format) {
  if (format === undefined || format === null || format === "") {
    return "json";
  }
  return String(format).toLowerCase();
}

export function validateProofExportRequest(request) {
  const invalid = [];
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    return ["proof_export_request"];
  }
  if (!isSafeProofID(request.proof_id)) {
    invalid.push("proof_id");
  }
  if (!PROOF_EXPORT_FORMATS.has(normalizeProofExportFormat(request.format))) {
    invalid.push("format");
  }
  return [...new Set(invalid)].sort();
}

export function buildProofExportEnvelope(request) {
  const invalidFields = validateProofExportRequest(request);
  if (invalidFields.length > 0) {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "Proof export request is missing or malformed.",
        invalid_fields: invalidFields,
        retriable: false,
      },
    };
  }
  const format = normalizeProofExportFormat(request.format);
  return {
    status: "PASS",
    output: {
      schema_version: "intentrax.public_sdk.proof_export/1.0",
      endpoint: `${PROOF_EXPORT_ENDPOINT_PREFIX}/${request.proof_id}/export`,
      format,
      authoritative_json: format !== "pdf",
      pdf_receipt_non_authoritative: format === "pdf",
      request: {
        proof_id: request.proof_id,
        format,
      },
    },
  };
}

export function validateProofReadRequest(request) {
  const invalid = [];
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    return ["proof_read_request"];
  }
  if (!isSafeProofID(request.proof_id)) {
    invalid.push("proof_id");
  }
  return [...new Set(invalid)].sort();
}

export function buildProofReadEnvelope(request) {
  const invalidFields = validateProofReadRequest(request);
  if (invalidFields.length > 0) {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "Proof read request is missing or malformed.",
        invalid_fields: invalidFields,
        retriable: false,
      },
    };
  }
  return {
    status: "PASS",
    output: {
      schema_version: "intentrax.public_sdk.proof_read/1.0",
      endpoint: `${PROOF_EXPORT_ENDPOINT_PREFIX}/${request.proof_id}`,
      request: {
        proof_id: request.proof_id,
      },
    },
  };
}

export function validateProofReplayRequest(request) {
  const invalid = [];
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    return ["proof_replay_request"];
  }
  if (request.schema_version !== PROOF_REPLAY_REQUEST_SCHEMA_VERSION) {
    invalid.push("schema_version");
  }
  if (!isSafeProofID(request.proof_id)) {
    invalid.push("proof_id");
  }
  return [...new Set(invalid)].sort();
}

export function buildProofReplayEnvelope(request) {
  const invalidFields = validateProofReplayRequest(request);
  if (invalidFields.length > 0) {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "Proof replay request is missing or malformed.",
        invalid_fields: invalidFields,
        retriable: false,
      },
    };
  }
  return {
    status: "PASS",
    output: {
      schema_version: "intentrax.public_sdk.proof_replay/1.0",
      endpoint: PROOF_REPLAY_ENDPOINT,
      request,
    },
  };
}

export function validateProofInclusionRequest(request) {
  const invalid = [];
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    return ["proof_inclusion_request"];
  }
  if (!isSafeProofID(request.proof_id)) {
    invalid.push("proof_id");
  }
  return [...new Set(invalid)].sort();
}

export function buildProofInclusionEnvelope(request) {
  const invalidFields = validateProofInclusionRequest(request);
  if (invalidFields.length > 0) {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "Proof inclusion request is missing or malformed.",
        invalid_fields: invalidFields,
        retriable: false,
      },
    };
  }
  return {
    status: "PASS",
    output: {
      schema_version: "intentrax.public_sdk.proof_inclusion/1.0",
      endpoint: `${PROOF_EXPORT_ENDPOINT_PREFIX}/${request.proof_id}/inclusion`,
      request: {
        proof_id: request.proof_id,
      },
    },
  };
}

export function validateVerifierHandoffRequest(request) {
  const invalid = [];
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    return ["verifier_handoff_request"];
  }
  if (!isSafeReceiptID(request.receipt_id)) {
    invalid.push("receipt_id");
  }
  return [...new Set(invalid)].sort();
}

export function buildVerifierHandoffEnvelope(request) {
  const invalidFields = validateVerifierHandoffRequest(request);
  if (invalidFields.length > 0) {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "Verifier handoff request is missing or malformed.",
        invalid_fields: invalidFields,
        retriable: false,
      },
    };
  }
  return {
    status: "PASS",
    output: {
      schema_version: "intentrax.public_sdk.verifier_handoff/1.0",
      endpoint: `${VERIFIER_HANDOFF_ENDPOINT_PREFIX}/${request.receipt_id}/verifier-handoff`,
      request: {
        receipt_id: request.receipt_id,
      },
    },
  };
}

export function validateAgentGatewayAdmissionRequest(request) {
  const invalid = [];
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    return ["agent_admission_request"];
  }
  for (const field of AGENT_ADMISSION_REQUIRED_FIELDS) {
    if (!(field in request)) {
      invalid.push(field);
    }
  }
  for (const field of ["tenant_id", "surface_id", "action", "adapter_id"]) {
    if (typeof request[field] !== "string" || request[field].length === 0) {
      invalid.push(field);
    }
  }
  if (request.schema_version !== AGENT_ADMISSION_SCHEMA_VERSION) {
    invalid.push("schema_version");
  }
  for (const field of ["evidence_refs", "proof_refs"]) {
    if (!Array.isArray(request[field]) || request[field].length === 0 || request[field].some((value) => !isSha256Ref(value))) {
      invalid.push(field);
    }
  }
  if (!isSha256Hex(request.request_payload_hash)) {
    invalid.push("request_payload_hash");
  }
  if (!isSha256Ref(request.protocol_payload_ref)) {
    invalid.push("protocol_payload_ref");
  }
  if (!isSha256Hex(request.idempotency_key_hash)) {
    invalid.push("idempotency_key_hash");
  }
  return [...new Set(invalid)].sort();
}

function isNonEmptyStable(value) {
  return typeof value === "string" && value.length > 0 && value.trim() === value;
}

// Mirrors engine intentexecute.isUpperSnake: UPPER_SNAKE over [A-Z0-9_] with no
// leading/trailing whitespace and no "__" run.
function isUpperSnakeAction(value) {
  return isNonEmptyStable(value) && /^[A-Z0-9_]+$/.test(value) && !value.includes("__");
}

function isSafeReceiptID(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]+$/.test(value);
}

function isSafeProofID(value) {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= 128 &&
    value.trim() === value &&
    !value.includes("..") &&
    !value.includes("\u0000") &&
    /^[A-Za-z0-9_.-]+$/.test(value);
}

export function agentGatewayAdmissionRequestHash(request) {
  return sha256Hex(AGENT_GATEWAY_ADMISSION_REQUEST_HASH_DOMAIN + canonicalJson(request));
}

export function buildAgentGatewayAdmissionEnvelope(request) {
  const invalidFields = validateAgentGatewayAdmissionRequest(request);
  if (invalidFields.length > 0) {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "Agent Gateway admission request is missing or malformed.",
        invalid_fields: invalidFields,
        retriable: false,
      },
    };
  }
  return {
    status: "PASS",
    output: {
      schema_version: "intentrax.public_sdk.agent_gateway_admission/1.0",
      request_hash: agentGatewayAdmissionRequestHash(request),
      idempotency_key_hash: request.idempotency_key_hash,
      endpoint: AGENT_ADMISSION_ENDPOINT,
      request,
    },
  };
}

// validateIntentExecuteRequest mirrors the engine's intentexecute.validateRequest
// (and its DecodeRequest strictness): exactly the six fields, an UPPER_SNAKE
// action, and a canonical body no larger than the engine's limit. It computes
// NO proof/hash truth — receipt_id, request_hash, registry_proof_id, and
// response_hash are the engine's to produce.
export function validateIntentExecuteRequest(request) {
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    return ["intent_execute_request"];
  }
  const invalid = [];
  // Unknown fields are a 400 at the engine (DisallowUnknownFields); reject them
  // here too so the SDK never emits a body the engine would refuse.
  for (const key of Object.keys(request)) {
    if (!INTENT_EXECUTE_REQUIRED_FIELDS.includes(key)) {
      invalid.push("body");
    }
  }
  if (request.schema_version !== INTENT_EXECUTE_REQUEST_SCHEMA_VERSION) {
    invalid.push("schema_version");
  }
  if (!isNonEmptyStable(request.intent_id)) {
    invalid.push("intent_id");
  }
  if (!isNonEmptyStable(request.tenant_id)) {
    invalid.push("tenant_id");
  }
  if (!isUpperSnakeAction(request.action)) {
    invalid.push("action");
  }
  // idempotency_key is a caller-supplied OPAQUE body field. It is NOT hashed by
  // the SDK; the engine derives RequestHash over the whole canonical body.
  if (!isNonEmptyStable(request.idempotency_key)) {
    invalid.push("idempotency_key");
  }
  if (!isNonEmptyStable(request.proof_chain_fixture_ref)) {
    invalid.push("proof_chain_fixture_ref");
  }
  if (invalid.every((field) => field !== "body")) {
    const canonicalBytes = Buffer.byteLength(canonicalJson(request), "utf8");
    if (canonicalBytes > INTENT_EXECUTE_MAX_REQUEST_BYTES) {
      invalid.push("body");
    }
  }
  return [...new Set(invalid)].sort();
}

// buildIntentExecuteEnvelope is a THIN envelope builder: it validates and
// passes the caller-supplied body through verbatim. It performs no hashing and
// asserts no proof truth.
export function buildIntentExecuteEnvelope(request) {
  const invalidFields = validateIntentExecuteRequest(request);
  if (invalidFields.length > 0) {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "Intent execute request is missing or malformed.",
        invalid_fields: invalidFields,
        retriable: false,
      },
    };
  }
  return {
    status: "PASS",
    output: {
      schema_version: "intentrax.public_sdk.intent_execute/1.0",
      endpoint: INTENT_EXECUTE_ENDPOINT,
      // Passthrough of the caller-supplied body. No client-computed
      // request_hash/receipt_id: those are returned verbatim from the engine.
      request,
    },
  };
}

// ===========================================================================
// Verification Mark response envelope — the SDK/MCP machine substrate.
//
// A backend-produced, PUBLIC-SAFE projection of a proof's verification status:
//   { display_state, proof_id, verify_url, assurance_level, signature }.
// The SDK is a strict READER. It validates the envelope's SHAPE and normalizes
// it into a verdict a consumer can branch on. It NEVER re-derives crypto, never
// recomputes validity, never regenerates a proof: `verified` is EXACTLY the
// backend's display_state === "verified", nothing more. `signature` is a STATUS
// projection (e.g. "pass"/"fail"/"Not Available"), never a raw signature; a
// value that looks like raw signing material is refused so it can never leak.
// ===========================================================================

export const VERIFICATION_MARK_ENVELOPE_KEY = "intentrax_verification";
export const VERIFICATION_MARK_ENVELOPE_SCHEMA_VERSION = "intentrax.public_sdk.verification_mark_envelope/1.0";
export const VERIFICATION_MARK_VERIFIED_STATE = "verified";
export const VERIFICATION_MARK_NOT_AVAILABLE = "Not Available";

// display_state -> severity. Mirrors the backend §2 MARK_STATE_TABLE. Fail
// NEUTRAL, not fail-red: only a concrete failure/revocation is "negative".
export const VERIFICATION_MARK_STATE_SEVERITY = Object.freeze({
  verified: "green",
  proof_available: "neutral",
  checking: "neutral",
  not_found: "neutral",
  unavailable: "neutral",
  share_expired: "neutral",
  failed: "negative",
  revoked: "negative",
});

const VERIFICATION_MARK_DISPLAY_STATES = new Set(Object.keys(VERIFICATION_MARK_STATE_SEVERITY));
const VERIFICATION_MARK_ASSURANCE_LEVELS = new Set([1, 2, 3, 4]);
const VERIFICATION_MARK_SIGNATURE_MAX_LEN = 64;
const VERIFICATION_MARK_PROOF_ID_MAX_LEN = 128;
const VERIFICATION_MARK_URL_MAX_LEN = 2048;
const CONTROL_CHAR_RE = /[\u0000-\u001F\u007F]/;
// A public-safe field must never carry raw signing material or a secret. This
// guards the SDK from ever surfacing a raw signature/key/token even if a
// malformed upstream stuffs one into a nominally public field.
const VERIFICATION_MARK_SECRET_VALUE_RE = /-----BEGIN|BEGIN (?:RSA|EC|DSA|PGP|OPENSSH)|sk-(?:live|test)|bearer\s|private[_ -]?key|signing[_ -]?material|api[_-]?key|access[_-]?token|refresh[_-]?token/i;

function isVerificationMarkRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function isVerificationMarkDisplayState(value) {
  return typeof value === "string" && VERIFICATION_MARK_DISPLAY_STATES.has(value);
}

export function verificationMarkSeverity(displayState) {
  return isVerificationMarkDisplayState(displayState) ? VERIFICATION_MARK_STATE_SEVERITY[displayState] : null;
}

function isPublicSafeString(value) {
  return typeof value === "string" && !CONTROL_CHAR_RE.test(value) && !VERIFICATION_MARK_SECRET_VALUE_RE.test(value);
}

function normalizePlaceholderText(value, maxLen) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed === "" || trimmed === VERIFICATION_MARK_NOT_AVAILABLE) return null;
  if (trimmed.length > maxLen || !isPublicSafeString(trimmed)) return null;
  return trimmed;
}

// normalizeVerificationMarkSignature — the signature STATUS projection. Returns
// the public-safe status token, or null when it is absent, a placeholder, or
// looks like raw signing material (which is never surfaced). It is NEVER
// re-derived or cryptographically verified — shape only.
export function normalizeVerificationMarkSignature(value) {
  return normalizePlaceholderText(value, VERIFICATION_MARK_SIGNATURE_MAX_LEN);
}

function normalizeVerificationMarkAssuranceLevel(value) {
  return typeof value === "number" && VERIFICATION_MARK_ASSURANCE_LEVELS.has(value) ? value : null;
}

function normalizeVerificationMarkVerifyUrl(value) {
  const text = normalizePlaceholderText(value, VERIFICATION_MARK_URL_MAX_LEN);
  if (text === null) return null;
  // Root-relative verifier paths are public-safe as-is.
  if (text.startsWith("/") && !text.startsWith("//")) return text;
  let url;
  try {
    url = new URL(text);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;
  if (url.username !== "" || url.password !== "") return null;
  return url.toString();
}

// validateVerificationMarkEnvelope — SHAPE-ONLY validation of the backend's
// public-safe verification envelope. Returns the sorted list of invalid field
// names ([] when the shape is well-formed). It performs NO crypto: it never
// verifies the signature, recomputes validity, or regenerates a proof.
export function validateVerificationMarkEnvelope(envelope) {
  if (!isVerificationMarkRecord(envelope)) {
    return ["verification_mark_envelope"];
  }
  const invalid = [];
  if (!isVerificationMarkDisplayState(envelope.display_state)) invalid.push("display_state");
  if (typeof envelope.proof_id !== "string") invalid.push("proof_id");
  if (typeof envelope.verify_url !== "string") invalid.push("verify_url");
  if (!(envelope.assurance_level === null || normalizeVerificationMarkAssuranceLevel(envelope.assurance_level) !== null)) {
    invalid.push("assurance_level");
  }
  if (typeof envelope.signature !== "string") invalid.push("signature");
  // A public-safe envelope must never carry raw secret material in any string
  // field — reject the whole envelope if it does rather than pass it through.
  for (const field of ["proof_id", "verify_url", "signature"]) {
    const value = envelope[field];
    if (typeof value === "string" && !isPublicSafeString(value)) {
      invalid.push(field);
    }
  }
  return [...new Set(invalid)].sort();
}

// normalizeVerificationMarkEnvelope — validate + project the envelope into a
// canonical, public-safe verdict. Returns null when the shape is invalid.
// Placeholder ("Not Available") and secret-looking values collapse to null per
// field. `verified` is EXACTLY the backend display_state === "verified" — the
// SDK asserts no independent verdict and recomputes no crypto.
export function normalizeVerificationMarkEnvelope(envelope) {
  if (validateVerificationMarkEnvelope(envelope).length > 0) return null;
  const displayState = envelope.display_state;
  return {
    schema_version: VERIFICATION_MARK_ENVELOPE_SCHEMA_VERSION,
    display_state: displayState,
    severity: VERIFICATION_MARK_STATE_SEVERITY[displayState],
    verified: displayState === VERIFICATION_MARK_VERIFIED_STATE,
    proof_id: normalizePlaceholderText(envelope.proof_id, VERIFICATION_MARK_PROOF_ID_MAX_LEN),
    verify_url: normalizeVerificationMarkVerifyUrl(envelope.verify_url),
    assurance_level: normalizeVerificationMarkAssuranceLevel(envelope.assurance_level),
    signature: normalizeVerificationMarkSignature(envelope.signature),
  };
}

// extractVerificationMarkEnvelope — locate the verification envelope on an
// arbitrary response object. Handles the bare envelope, the `intentrax_verification`
// key at the top level, and the same key nested under an MCP tool result's
// `structuredContent` / a `result` / `output` wrapper. Returns the raw envelope
// candidate (unvalidated) or null.
export function extractVerificationMarkEnvelope(response) {
  if (!isVerificationMarkRecord(response)) return null;
  if (isVerificationMarkDisplayState(response.display_state) && "signature" in response) {
    return response;
  }
  const wrappers = [
    response,
    isVerificationMarkRecord(response.structuredContent) ? response.structuredContent : undefined,
    isVerificationMarkRecord(response.result) ? response.result : undefined,
    isVerificationMarkRecord(response.output) ? response.output : undefined,
  ];
  for (const wrapper of wrappers) {
    if (wrapper && isVerificationMarkRecord(wrapper[VERIFICATION_MARK_ENVELOPE_KEY])) {
      return wrapper[VERIFICATION_MARK_ENVELOPE_KEY];
    }
  }
  // MCP tool results nest the payload under structuredContent; recurse one level
  // so a proof record carried there is still found.
  if (isVerificationMarkRecord(response.structuredContent)) {
    return extractVerificationMarkEnvelope(response.structuredContent);
  }
  return null;
}

function absentVerificationVerdict(present) {
  return {
    present,
    valid: false,
    verified: false,
    display_state: null,
    severity: null,
    proof_id: null,
    verify_url: null,
    assurance_level: null,
    signature: null,
  };
}

// readVerificationVerdict — the consumer entry point. Given any response that
// may carry a verification envelope, returns a normalized verdict:
//   { present, valid, verified, display_state, severity, proof_id, verify_url,
//     assurance_level, signature }.
// `verified` is the backend display_state === "verified" — never a client-side
// crypto decision. An absent or malformed envelope yields a safe, non-verified
// reading rather than throwing.
export function readVerificationVerdict(response) {
  const raw = extractVerificationMarkEnvelope(response);
  if (raw === null) return absentVerificationVerdict(false);
  const normalized = normalizeVerificationMarkEnvelope(raw);
  if (normalized === null) return absentVerificationVerdict(true);
  return {
    present: true,
    valid: true,
    verified: normalized.verified,
    display_state: normalized.display_state,
    severity: normalized.severity,
    proof_id: normalized.proof_id,
    verify_url: normalized.verify_url,
    assurance_level: normalized.assurance_level,
    signature: normalized.signature,
  };
}

// ===========================================================================
// Rendered-output binding — PRODUCER side of `intentrax-content/1.0`.
//
// The browser extension (the chrome-rendered "padlock for AI") only shows green
// when the VISIBLE text of the page's marked output region hashes to the
// output hash the proof is bound to. These helpers let a producer compute that
// hash from the exact text it renders, using the one canonical normalization
// (docs/architecture/verification-mark-spec.md Appendix A). They MUST stay
// byte-identical to browser-extension/src/binding.js `normalizeContent`; the
// shared vectors in contracts/test_vectors/verification_mark/ pin that.
//
// This is hashing of the PRODUCER'S OWN output, not proof truth: it asserts no
// verdict, signs nothing, and never makes a mark green on its own. Green still
// requires the engine-issued proof to carry this hash and the verifier to
// return it (see docs/architecture/verification-mark-enablement-checklist.md).
// ===========================================================================

export const CANONICAL_OUTPUT_NORMALIZATION = "intentrax-content/1.0";
export const CANONICAL_OUTPUT_HASH_ALGORITHM = "SHA-256";
export const VERIFICATION_POINTER_META_NAME = "intentrax-verification";
export const VERIFICATION_OUTPUT_REGION_ATTRIBUTE = "data-intentrax-output";

// normalizeCanonicalOutput — the `intentrax-content/1.0` normalization:
// NFC; CRLF/CR -> LF; collapse runs of space/tab/FF/VT/NBSP to one space;
// strip horizontal whitespace around newlines and collapse blank-line runs to a
// single LF; trim. Accepts one region string, or an array of region strings
// (one per marked region, in document order) which are joined exactly as the
// extension joins them: each region followed by "\n".
export function normalizeCanonicalOutput(content) {
  const raw = Array.isArray(content)
    ? content.map((region) => (typeof region === "string" ? region : "") + "\n").join("")
    : typeof content === "string" ? content : "";
  return raw
    .normalize("NFC")
    .replace(/\r\n?/g, "\n")
    .replace(/[ \t\f\v\u00a0]+/g, " ")
    .replace(/[ \t]*\n[ \t]*/g, "\n")
    .replace(/\n{2,}/g, "\n")
    .trim();
}

// canonicalOutputHash — bare lowercase 64-hex SHA-256 over the UTF-8 bytes of
// the normalized output (the canonical `content_hash` spelling).
export function canonicalOutputHash(content) {
  return sha256Hex(normalizeCanonicalOutput(content));
}

// buildOutputBinding — the `output_binding` block a producer hands to the
// engine at proof generation, and that the verifier returns for the extension.
export function buildOutputBinding(content) {
  return {
    content_hash: canonicalOutputHash(content),
    hash_algorithm: CANONICAL_OUTPUT_HASH_ALGORITHM,
    normalization: CANONICAL_OUTPUT_NORMALIZATION,
  };
}

function escapeVerificationPointerAttribute(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// verificationPointerMetaTag — the page-level POINTER the extension detects:
//   <meta name="intentrax-verification" content="proof_id={id};verify_url={url}">
// It carries only the proof id and an https verify URL — never the proof. The
// producer additionally wraps the rendered output in an element carrying
// `data-intentrax-output`. Returns null for an unsafe proof id or URL.
export function verificationPointerMetaTag({ proof_id: proofId, verify_url: verifyUrl } = {}) {
  if (!isSafeProofID(proofId)) return null;
  let url;
  try {
    url = new URL(verifyUrl);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "") return null;
  const href = url.toString();
  if (href.includes(";")) return null;
  return `<meta name="${VERIFICATION_POINTER_META_NAME}" content="${escapeVerificationPointerAttribute(`proof_id=${proofId};verify_url=${href}`)}">`;
}
