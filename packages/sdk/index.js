import { createHash } from "node:crypto";

export const SDK_VERSION = "1.0.0";
export const API_VERSION = "v1";
export const VERIFY_REQUEST_HASH_DOMAIN = "INTENTRAX_PUBLIC_SDK_VERIFY_REQUEST_V1";
export const IDEMPOTENCY_KEY_DOMAIN = "INTENTRAX_PUBLIC_SDK_IDEMPOTENCY_V1";
export const AGENT_HOOK_IDEMPOTENCY_KEY_DOMAIN = "INTENTRAX_AGENT_HOOK_IDEMPOTENCY_V1";
export const AGENT_GATEWAY_ADMISSION_REQUEST_HASH_DOMAIN = "INTENTRAX_AGENT_GATEWAY_ADMISSION_REQUEST_V1";
export const AGENT_ADMISSION_SCHEMA_VERSION = "intentrax.runtime.agent_admission_request/1.0";
export const AGENT_ADMISSION_ENDPOINT = "/v1/agent/admissions";
// Live intent execution lane. The schema_version below is the exact string the
// engine's intentexecute.DecodeRequest requires; the endpoint is fail-closed
// (HTTP 423 until LiveExecutionEnabled, HTTP 403 until the tenant is
// allowlisted). See engine/internal/runtime/intentexecute/intentexecute.go.
export const INTENT_EXECUTE_REQUEST_SCHEMA_VERSION = "intentrax.runtime.intent_execute.request/1.0";
// /1.1 adds exactly one OPTIONAL field to /1.0: output_binding, the
// producer-declared `intentrax-content/1.0` hash of the rendered output. The
// engine seals it into the signed proof (aep.output_binding,
// binding_source PRODUCER_DECLARED_AT_ISSUANCE); see
// engine/internal/runtime/intentexecute/output_binding.go.
export const INTENT_EXECUTE_REQUEST_SCHEMA_VERSION_V11 = "intentrax.runtime.intent_execute.request/1.1";
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

// The engine decodes a /1.1 output_binding with DisallowUnknownFields into
// exactly these three string fields (intentexecute.OutputBinding).
const INTENT_EXECUTE_OUTPUT_BINDING_FIELDS = ["content_hash", "hash_algorithm", "normalization"];

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
  return executeIdempotencyKeyHash(createIdempotencyKey(request));
}

// executeIdempotencyKeyHash is the ONE idempotency-key rule shared by the
// admission and execute lanes. The engine records SHA-256(raw execute
// idempotency_key), with no domain prefix, as the execution's link key; an
// admission receipt correlates with an execution only when its
// idempotency_key_hash equals that value. So send the raw key K as the execute
// request's idempotency_key and executeIdempotencyKeyHash(K) as the admission
// request's idempotency_key_hash. Any other derivation (for example a
// domain-prefixed hash of a payload hash with no raw key the caller can send to
// execute) can never match, and every such execution reads as unadmitted.
export function executeIdempotencyKeyHash(idempotencyKey) {
  if (!isNonEmptyStable(idempotencyKey)) {
    throw new TypeError("executeIdempotencyKeyHash: idempotencyKey must be a non-empty string without leading or trailing whitespace");
  }
  return sha256Hex(idempotencyKey);
}

// agentHookExecuteIdempotencyKey returns the raw execute idempotency key that
// hooks generated by `intentrax agent init` derive from an admission
// request_payload_hash. The hook's admission idempotency_key_hash is
// executeIdempotencyKeyHash of this key, and the hook result exposes the key as
// execute_idempotency_key, so the execution that follows the admission carries
// the matching key.
export function agentHookExecuteIdempotencyKey(requestPayloadHash) {
  if (!isSha256Hex(requestPayloadHash)) {
    throw new TypeError("agentHookExecuteIdempotencyKey: requestPayloadHash must be 64 lowercase hex");
  }
  return AGENT_HOOK_IDEMPOTENCY_KEY_DOMAIN + requestPayloadHash;
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
// (and its DecodeRequest strictness): exactly the six fields (plus an optional
// output_binding under /1.1 only), an UPPER_SNAKE action, and a canonical body
// no larger than the engine's limit. It computes NO proof/hash truth —
// receipt_id, request_hash, registry_proof_id, and response_hash are the
// engine's to produce.
export function validateIntentExecuteRequest(request) {
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    return ["intent_execute_request"];
  }
  const invalid = [];
  const isV11 = request.schema_version === INTENT_EXECUTE_REQUEST_SCHEMA_VERSION_V11;
  // Unknown fields are a 400 at the engine (DisallowUnknownFields); reject them
  // here too so the SDK never emits a body the engine would refuse. A /1.0 body
  // carrying output_binding is such an unknown field.
  for (const key of Object.keys(request)) {
    if (!INTENT_EXECUTE_REQUIRED_FIELDS.includes(key) && !(isV11 && key === "output_binding")) {
      invalid.push("body");
    }
  }
  if (request.schema_version !== INTENT_EXECUTE_REQUEST_SCHEMA_VERSION && !isV11) {
    invalid.push("schema_version");
  }
  if (isV11 && Object.prototype.hasOwnProperty.call(request, "output_binding")) {
    invalid.push(...validateIntentExecuteOutputBinding(request.output_binding));
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
  // Size-check only an otherwise-valid body: an invalid field (e.g. an explicit
  // `undefined`) may not be canonicalizable, and must surface as a structured
  // FAIL naming that field rather than a canonical_json throw.
  if (invalid.length === 0) {
    const canonicalBytes = Buffer.byteLength(canonicalJson(request), "utf8");
    if (canonicalBytes > INTENT_EXECUTE_MAX_REQUEST_BYTES) {
      invalid.push("body");
    }
  }
  return [...new Set(invalid)].sort();
}

// validateIntentExecuteOutputBinding mirrors the engine's decodeOutputBinding +
// validateOutputBinding: a non-null object of exactly the three string fields
// (anything else is a decode error, reported as "output_binding"), then a
// sealable content_hash, the SHA-256 algorithm and the intentrax-content/1.0
// normalization.
function validateIntentExecuteOutputBinding(binding) {
  if (binding === null || typeof binding !== "object" || Array.isArray(binding)) {
    return ["output_binding"];
  }
  for (const key of Object.keys(binding)) {
    if (!INTENT_EXECUTE_OUTPUT_BINDING_FIELDS.includes(key) || typeof binding[key] !== "string") {
      return ["output_binding"];
    }
  }
  const invalid = [];
  if (!isSealableOutputContentHash(binding.content_hash)) {
    invalid.push("output_binding.content_hash");
  }
  if (binding.hash_algorithm !== CANONICAL_OUTPUT_HASH_ALGORITHM) {
    invalid.push("output_binding.hash_algorithm");
  }
  if (binding.normalization !== CANONICAL_OUTPUT_NORMALIZATION) {
    invalid.push("output_binding.normalization");
  }
  return invalid;
}

// isSealableOutputContentHash mirrors the engine's sealedContentHash: the bare
// 64 lowercase hex the SDK emits, or the same with a "sha256:" prefix. Uppercase,
// other prefixes, other lengths, and a degenerate digest (one repeated digit)
// are refused.
function isSealableOutputContentHash(value) {
  if (typeof value !== "string") return false;
  const digest = value.startsWith("sha256:") ? value.slice("sha256:".length) : value;
  if (!SHA256_RE.test(digest)) return false;
  return digest.split("").some((char) => char !== digest[0]);
}

// bindIntentExecuteOutput returns a NEW /1.1 execute request: the caller's
// request with schema_version /1.1 and output_binding = buildOutputBinding of
// the output the producer is about to render. The input is not mutated. Pass
// the result to buildIntentExecuteEnvelope / executeIntentHttp, which validate
// it. Bind exactly what the page will show inside its data-intentrax-output
// region(s): the browser extension recomputes this hash over that visible text.
export function bindIntentExecuteOutput(request, renderedOutput) {
  return {
    ...request,
    schema_version: INTENT_EXECUTE_REQUEST_SCHEMA_VERSION_V11,
    output_binding: buildOutputBinding(renderedOutput),
  };
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

// Evidence-quality model (INTENTRAX_ASSURANCE_GAP_ANALYSIS.md §5,
// implementation plan P0-6 / P1-D).
//
// A verification result is a set of per-dimension assessments. The overall
// verdict is COMPUTED from them by the fixed rule in deriveAssuranceVerdict();
// no signer asserts it. The rule, dimensions, results, profiles and verdict
// precedence are ported unchanged from examples/effect-assurance-demo
// (src/model.mjs), plus the LEGACY_DECISION_RECORD profile that every proof
// issued today maps to. The Go offline verifier carries the same model
// (engine/internal/verificationinfra/offlineproof/assessment.go); the two must
// stay in step.
export const VERIFICATION_ASSESSMENT_SCHEMA_VERSION = "intentrax.verification.assessment/0.1";

export const ASSURANCE_DIMENSIONS = Object.freeze([
  "RECORD_INTEGRITY",
  "SIGNER_AUTHENTICITY",
  "AUTHORIZATION",
  "EXECUTION_REPORTED",
  "EXECUTION_ATTESTED",
  "EFFECT_OBSERVED",
  "EFFECT_CONFIRMED",
  "CAUSAL_CHAIN",
]);

// §5.2, plus OBSERVED for the EFFECT_OBSERVED dimension.
export const ASSESSMENT_RESULTS = Object.freeze([
  "VERIFIED",
  "REPORTED",
  "ATTESTED",
  "OBSERVED",
  "CONFIRMED",
  "CONTRADICTED",
  "PENDING",
  "INSUFFICIENT_EVIDENCE",
  "NOT_ASSESSED",
  "NOT_APPLICABLE",
  "FAILED",
]);

export const ASSESSMENT_PROVENANCE = Object.freeze({
  SELF_REPORTED: "SELF_REPORTED",
  INTENTRAX_DECISION: "INTENTRAX_DECISION",
  ENFORCEMENT_ATTESTED: "ENFORCEMENT_ATTESTED",
  AUTHORITATIVE_SOURCE: "AUTHORITATIVE_SOURCE",
  THIRD_PARTY_ATTESTED: "THIRD_PARTY_ATTESTED",
  VERIFIER_COMPUTED: "VERIFIER_COMPUTED",
});

// Required dimensions per assurance profile. EXECUTION_REPORTED is
// deliberately never required: a self-report can never satisfy a profile
// (invariant 1).
export const ASSURANCE_PROFILES = Object.freeze({
  LEGACY_DECISION_RECORD: Object.freeze(["RECORD_INTEGRITY"]),
  DECISION_RECORD: Object.freeze(["RECORD_INTEGRITY", "SIGNER_AUTHENTICITY", "AUTHORIZATION"]),
  AUTHORIZED_AND_ATTESTED: Object.freeze(["RECORD_INTEGRITY", "SIGNER_AUTHENTICITY", "AUTHORIZATION", "EXECUTION_ATTESTED"]),
  EFFECT_CONFIRMED: Object.freeze(["RECORD_INTEGRITY", "SIGNER_AUTHENTICITY", "AUTHORIZATION", "EFFECT_OBSERVED", "EFFECT_CONFIRMED"]),
  CAUSAL_CHAIN: Object.freeze([
    "RECORD_INTEGRITY", "SIGNER_AUTHENTICITY", "AUTHORIZATION", "EFFECT_OBSERVED", "EFFECT_CONFIRMED", "CAUSAL_CHAIN",
  ]),
});

export const ASSURANCE_VERDICTS = Object.freeze({
  VERIFICATION_FAILED: "VERIFICATION_FAILED",
  INTEGRITY_ONLY: "INTEGRITY_ONLY",
  CONFLICTING_EVIDENCE: "CONFLICTING_EVIDENCE",
  PENDING_FINALITY: "PENDING_FINALITY",
  INSUFFICIENT_EVIDENCE: "INSUFFICIENT_EVIDENCE",
  VERIFIED_FOR_SCOPE: "VERIFIED_FOR_SCOPE",
});

// Rule precedence, first-matching rule = 0. Weakening any dimension must
// never move the verdict to a later rule.
export const ASSURANCE_VERDICT_PRECEDENCE = Object.freeze({
  VERIFICATION_FAILED: 0,
  INTEGRITY_ONLY: 1,
  CONFLICTING_EVIDENCE: 2,
  PENDING_FINALITY: 3,
  INSUFFICIENT_EVIDENCE: 4,
  VERIFIED_FOR_SCOPE: 5,
});

const WEAK_ASSESSMENT_RESULTS = new Set(["REPORTED", "INSUFFICIENT_EVIDENCE", "NOT_ASSESSED"]);
const SATISFYING_ASSESSMENT_RESULTS = new Set(["VERIFIED", "ATTESTED", "OBSERVED", "CONFIRMED"]);

// §5.4, verbatim order. `assessments` is { [dimension]: result }. A required
// dimension that is missing or NOT_APPLICABLE counts as INSUFFICIENT_EVIDENCE
// (invariant 4: never a bare pass). A CONTRADICTED result in ANY dimension,
// required by the profile or not, yields CONFLICTING_EVIDENCE (finding V-1):
// a sealed NON_COMPLIANT policy decision must never read as VERIFIED_FOR_SCOPE.
export function deriveAssuranceVerdict(assessments, profile) {
  const required = Object.hasOwn(ASSURANCE_PROFILES, profile) ? ASSURANCE_PROFILES[profile] : undefined;
  if (!required) {
    throw new Error("unknown assurance profile " + profile);
  }
  const all = Object.values(assessments);
  const req = required.map((d) => assessments[d] ?? "INSUFFICIENT_EVIDENCE");
  if (all.includes("FAILED")) return ASSURANCE_VERDICTS.VERIFICATION_FAILED;
  if (assessments.SIGNER_AUTHENTICITY !== "VERIFIED") return ASSURANCE_VERDICTS.INTEGRITY_ONLY;
  if (all.includes("CONTRADICTED")) return ASSURANCE_VERDICTS.CONFLICTING_EVIDENCE;
  if (req.includes("PENDING")) return ASSURANCE_VERDICTS.PENDING_FINALITY;
  if (req.some((r) => WEAK_ASSESSMENT_RESULTS.has(r) || !SATISFYING_ASSESSMENT_RESULTS.has(r))) return ASSURANCE_VERDICTS.INSUFFICIENT_EVIDENCE;
  return ASSURANCE_VERDICTS.VERIFIED_FOR_SCOPE;
}

// Published wording of each limitation code; identical to the Go verifier.
export const ASSURANCE_LIMITATION_TEXT = Object.freeze({
  EXECUTION_NOT_ATTESTED: "No trusted in-path enforcement component observed the action. The proof records an Intentrax decision, not an attested execution.",
  EFFECT_NOT_VERIFIED: "No authoritative downstream system was queried. The proof does not show that any external effect happened.",
  POLICY_BINDING_SYNTHETIC: "The policy reference in this proof is a fixed value of the proof pipeline, not a binding to an evaluated customer policy or mandate.",
  COMPLETENESS_NOT_ESTABLISHED: "Nothing proves that every consequential agent action was routed through Intentrax. A proof covers only the action it records.",
  SIGNER_AUTHENTICITY_REQUIRES_PINNED_ANCHORS: "Signatures were checked against public keys carried inside the proof. Who signed is established only when every signing key is pinned to a trust-bearing key in a published Intentrax key set.",
  // Used instead of POLICY_BINDING_SYNTHETIC when the signed AEP seals a
  // policy binding (AEP 1.1 policy-binding profile, RECORD_ONLY).
  POLICY_EVALUATION_NOT_RECHECKABLE: "The proof seals Intentrax's evaluation of a hash-pinned policy, but this verifier did not re-run it: the evaluated event cannot be rebuilt from this proof, or the policy document was not available. The recorded decision is Intentrax's statement, not an independently checked result.",
  POLICY_DECISION_NOT_ENFORCED: "The policy binding is RECORD_ONLY: the evaluation was recorded with the action, and nothing shows the action was gated on its result.",
  POLICY_CONSTRAINT_NOT_EVALUATED: "At least one constraint of the matched policy rule was not checked. This proof binds no evidence that it was met.",
  // Used instead of POLICY_EVALUATION_NOT_RECHECKABLE when the verifier
  // re-ran the sealed evaluation and it matched.
  POLICY_EVENT_SELF_REPORTED: "The verifier re-ran the published policy over the facts sealed in this proof and got the same evaluation: the decision follows from those facts and the published rule. The re-check does not independently witness that the facts (such as mutation_performed) are true; the runtime's signature attests to them.",
});

// Limitations every proof under LEGACY_DECISION_RECORD carries.
export const LEGACY_DECISION_RECORD_LIMITATIONS = Object.freeze([
  "EXECUTION_NOT_ATTESTED",
  "EFFECT_NOT_VERIFIED",
  "POLICY_BINDING_SYNTHETIC",
  "COMPLETENESS_NOT_ESTABLISHED",
]);

// Maps a verifier's signer-trust outcome to the SIGNER_AUTHENTICITY result.
// Only TRUSTED against a supplied key set is VERIFIED. Without any key set the
// dimension is NOT_ASSESSED; a REVOKED signer is FAILED; every other outcome
// is INSUFFICIENT_EVIDENCE. Accepts the CLI's labels (UNPINNED_SIGNER,
// MIXED_TRUST) and the Go verifier's (UNPINNED).
export function signerAuthenticityAssessment(signerTrust, keySetSupplied) {
  if (!keySetSupplied) return { result: "NOT_ASSESSED", reasons: ["NO_TRUSTED_KEY_SET"] };
  switch (signerTrust) {
    case "TRUSTED":
      return { result: "VERIFIED", reasons: [] };
    case "REVOKED_SIGNER":
      return { result: "FAILED", reasons: ["REVOKED_SIGNER"] };
    case "SANDBOX_NON_TRUST_BEARING":
    case "INSUFFICIENT_TRUSTED_SIGNERS":
    case "MIXED_TRUST":
      return { result: "INSUFFICIENT_EVIDENCE", reasons: [signerTrust] };
    default:
      return { result: "INSUFFICIENT_EVIDENCE", reasons: ["UNPINNED_SIGNER"] };
  }
}

// Maps the policy binding sealed in the signed AEP (null when there is none)
// and the outcome of re-running it (null when no re-run was attempted) to the
// AUTHORIZATION result, provenance, reasons and limitations. Same rule as the
// Go verifier. Without a binding nothing is assessed. Only a re-run that
// MATCHed lifts the dimension above REPORTED: a re-checked COMPLIANT decision
// with no unchecked constraint is VERIFIED (VERIFIER_COMPUTED); with an
// unchecked constraint it stays REPORTED. Without a matching re-run COMPLIANT
// is REPORTED (INTENTRAX_DECISION). NON_COMPLIANT is CONTRADICTED and ERROR is
// INSUFFICIENT_EVIDENCE either way.
export function authorizationAssessment(policyBinding, policyReevaluation = null) {
  if (policyBinding === null || policyBinding === undefined) {
    return { result: "NOT_ASSESSED", provenance: "INTENTRAX_DECISION", reasons: ["DECISION_NOT_REEVALUATED_OFFLINE"], limitations: ["POLICY_BINDING_SYNTHETIC"] };
  }
  const rechecked = policyReevaluation !== null && policyReevaluation !== undefined && policyReevaluation.status === "MATCH";
  const unchecked = (Array.isArray(policyBinding.constraints) ? policyBinding.constraints : []).filter((constraint) => constraint.status !== "SATISFIED");
  let result = "INSUFFICIENT_EVIDENCE";
  const reasons = [];
  if (policyBinding.decision === "COMPLIANT") {
    result = rechecked && unchecked.length === 0 ? "VERIFIED" : "REPORTED";
    reasons.push("POLICY_DECISION_COMPLIANT");
  } else if (policyBinding.decision === "NON_COMPLIANT") {
    result = "CONTRADICTED";
    reasons.push("POLICY_DECISION_NON_COMPLIANT");
  } else {
    reasons.push("POLICY_DECISION_ERROR");
  }
  let limitations;
  if (rechecked) {
    reasons.push("POLICY_EVALUATION_RECHECKED");
    limitations = ["POLICY_EVENT_SELF_REPORTED", "POLICY_DECISION_NOT_ENFORCED"];
  } else {
    reasons.push("POLICY_EVALUATION_NOT_RECHECKED_OFFLINE");
    const reason = policyReevaluation === null || policyReevaluation === undefined ? "" : policyReevaluation.reason;
    if (typeof reason === "string" && reason !== "") reasons.push(`POLICY_REEVALUATION_${reason}`);
    limitations = ["POLICY_EVALUATION_NOT_RECHECKABLE", "POLICY_DECISION_NOT_ENFORCED"];
  }
  for (const constraint of unchecked) reasons.push(`POLICY_CONSTRAINT_NOT_EVALUATED:${constraint.constraint_id}`);
  if (unchecked.length > 0) limitations.push("POLICY_CONSTRAINT_NOT_EVALUATED");
  return { result, provenance: rechecked ? "VERIFIER_COMPUTED" : "INTENTRAX_DECISION", reasons, limitations };
}

// Builds the verification_assessment block for a proof whose record
// integrity has been verified, under the LEGACY_DECISION_RECORD profile.
// policyBinding is the binding sealed in the signed AEP, or null;
// policyReevaluation is the outcome of re-running it, or null. Nothing beyond
// the record, its signers and the (re-checked or recorded) policy decision is
// claimed.
export function buildLegacyVerificationAssessment({ signerTrust, keySetSupplied, policyBinding = null, policyReevaluation = null } = {}) {
  const signer = signerAuthenticityAssessment(signerTrust, keySetSupplied === true);
  const authorization = authorizationAssessment(policyBinding, policyReevaluation);
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
  const verdict = deriveAssuranceVerdict(Object.fromEntries(assessments.map((a) => [a.dimension, a.result])), "LEGACY_DECISION_RECORD");
  // The fixed legacy set, with POLICY_BINDING_SYNTHETIC replaced by the
  // AUTHORIZATION limitations when the proof seals a policy binding.
  const codes = [
    ...LEGACY_DECISION_RECORD_LIMITATIONS.flatMap((code) => (code === "POLICY_BINDING_SYNTHETIC" ? authorization.limitations : [code])),
    ...(signerVerified ? [] : ["SIGNER_AUTHENTICITY_REQUIRES_PINNED_ANCHORS"]),
  ];
  return {
    schema_version: VERIFICATION_ASSESSMENT_SCHEMA_VERSION,
    assurance_profile: "LEGACY_DECISION_RECORD",
    required_dimensions: [...ASSURANCE_PROFILES.LEGACY_DECISION_RECORD],
    verdict,
    assessments,
    limitations: codes.map((code) => ({ code, text: ASSURANCE_LIMITATION_TEXT[code] })),
  };
}

// ---------------------------------------------------------------------------
// Policy re-evaluation (AEP 1.1 policy-binding profile, P1-C step 2).
//
// A port of the Go policy engine pipeline (engine/internal/policyengine:
// C2.1 DSL -> C2.2 parser -> C2.3 bytecode compiler -> C2.4 VM) that
// recomputes every value an aep.policy_binding seals: source_policy_hash,
// compiled_policy_hash, execution_event_hash, evaluation_hash, decision,
// rule_id and the matched rule's constraints. A verifier fetches the policy by
// hash (GET /v1/policies/{source_policy_hash}), rebuilds the evaluated event,
// re-runs it here, and requires identical values instead of trusting them.
//
// It must reproduce the Go engine byte for byte: the shared vectors in
// test-fixtures/policy-binding/policy-reevaluation-vectors.json are
// generated by the Go engine and checked by policy-reevaluation.test.mjs. Any
// divergence fails closed (a hash mismatch), never open.
// ---------------------------------------------------------------------------

export const POLICY_HASH_DOMAIN = "INTENTRAX_POLICY_V1";
export const POLICY_BYTECODE_HASH_DOMAIN = "INTENTRAX_BYTECODE_V1";
export const POLICY_VM_TRACE_HASH_DOMAIN = "INTENTRAX_TRACE_V1";
export const POLICY_VM_EVENT_HASH_DOMAIN = "INTENTRAX_POLICY_VM_EVENT_V1";
export const POLICY_VM_EVALUATION_HASH_DOMAIN = "INTENTRAX_POLICY_VM_EVALUATION_V1";

const POLICY_BYTECODE_SCHEMA_VERSION = "1.0";
const POLICY_BYTECODE_VERSION = "1.0";
const POLICY_COMPILER_VERSION = "C2.3-1.0.0";
const POLICY_VM_RUNTIME_VERSION = "PVM-1";
const POLICY_MAX_RULES = 100;
const POLICY_MAX_CONDITIONS_PER_RULE = 20;
const POLICY_MAX_INSTRUCTIONS = 10000;
const POLICY_MAX_CONSTANTS = 1000;
const POLICY_MAX_STACK_DEPTH = 256;
const POLICY_VM_MAX_EXECUTION_COST = 10000;
const POLICY_VM_TASK_IDS = Object.freeze([
  "C2.4-S1-T1", "C2.4-S1-T2", "C2.4-S1-T3",
  "C2.4-S2-T1", "C2.4-S2-T2", "C2.4-S2-T3",
  "C2.4-S3-T1", "C2.4-S3-T2", "C2.4-S3-T3",
]);

const POLICY_IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/;
const POLICY_VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const POLICY_FIELDS = new Set(["policy_id", "policy_version", "rules", "default_effect"]);
const POLICY_RULE_FIELDS = new Set(["rule_id", "effect", "conditions", "constraints", "priority"]);
const POLICY_CONDITION_FIELDS = new Set(["field", "operator", "value"]);
const POLICY_CONSTRAINT_FIELDS = new Set(["constraint_id", "type", "value"]);
const POLICY_EFFECTS = new Set(["ALLOW", "DENY", "CONDITIONAL"]);
const POLICY_CONDITION_OPERATORS = new Set(["EQUALS", "NOT_EQUALS", "IN", "NOT_IN", "EXISTS", "GREATER_THAN", "GREATER_THAN_OR_EQUAL", "LESS_THAN", "LESS_THAN_OR_EQUAL"]);
const POLICY_CONSTRAINT_TYPES = new Set(["MAX_AMOUNT", "MAX_RETRIES", "TIMEOUT_MS", "REQUIRE_APPROVAL", "REQUIRE_GUARDRAIL_PASS", "RESTRICT_TARGET"]);
const POLICY_FORBIDDEN_TOKENS = Object.freeze(["clock", "command", "dynamic", "eval", "external", "function", "http://", "https://", "latest", "now", "random", "script", "webhook"]);
const POLICY_COMPARISON_OPCODES = Object.freeze({
  EQUALS: "CMP_EQ",
  NOT_EQUALS: "CMP_NEQ",
  GREATER_THAN: "CMP_GT",
  GREATER_THAN_OR_EQUAL: "CMP_GTE",
  LESS_THAN: "CMP_LT",
  LESS_THAN_OR_EQUAL: "CMP_LTE",
});
const POLICY_OPCODE_VALUES = Object.freeze({
  LOAD_FIELD: 0x01, LOAD_CONST: 0x02, CMP_EQ: 0x03, CMP_NEQ: 0x04, CMP_GT: 0x05, CMP_GTE: 0x06,
  CMP_LT: 0x07, CMP_LTE: 0x08, AND: 0x09, OR: 0x0a, NOT: 0x0b, JUMP: 0x0c, JUMP_IF_FALSE: 0x0d,
  RULE_ALLOW: 0x0e, RULE_DENY: 0x0f, RULE_END: 0x10,
});

class PolicyReevaluationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PolicyReevaluationError";
    this.code = code;
  }
}

// Members of an ordered object are emitted in declaration order (Go
// canonicaljson.OrderedObject); plain objects are emitted with keys sorted
// bytewise (Go maps).
const ORDERED_MEMBERS = Symbol("intentrax.policy.ordered");

function orderedObject(...members) {
  return { [ORDERED_MEMBERS]: members };
}

function utf8Compare(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

// Go encoding/json string encoding: HTML-safe escapes and U+2028/U+2029.
function goJSONString(value) {
  if (/[\ud800-\udfff]/.test(value.replace(/[\ud800-\udbff][\udc00-\udfff]/g, ""))) {
    throw new PolicyReevaluationError("POLICY_ENCODING_UNSUPPORTED", "lone surrogate in a policy string");
  }
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(new RegExp(String.fromCharCode(0x2028), "g"), "\\u2028")
    .replace(new RegExp(String.fromCharCode(0x2029), "g"), "\\u2029");
}

function policyCanonical(value) {
  if (value === null) return "null";
  if (typeof value === "string") return goJSONString(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new PolicyReevaluationError("POLICY_ENCODING_UNSUPPORTED", "only safe integers are supported");
    return String(value);
  }
  if (Array.isArray(value)) return "[" + value.map(policyCanonical).join(",") + "]";
  if (typeof value === "object") {
    const members = value[ORDERED_MEMBERS];
    if (members !== undefined) {
      return "{" + members.map(([key, member]) => goJSONString(key) + ":" + policyCanonical(member)).join(",") + "}";
    }
    const keys = Object.keys(value).sort(utf8Compare);
    return "{" + keys.map((key) => goJSONString(key) + ":" + policyCanonical(value[key])).join(",") + "}";
  }
  throw new PolicyReevaluationError("POLICY_ENCODING_UNSUPPORTED", "unsupported value");
}

function isPlainPolicyObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function policyNonEmpty(value) {
  return typeof value === "string" && value !== "" && value.trim() === value;
}

function hasForbiddenPolicyToken(value) {
  const lower = value.toLowerCase();
  return POLICY_FORBIDDEN_TOKENS.some((token) => lower.includes(token));
}

function policyLiteral(value) {
  if (typeof value === "string") return policyNonEmpty(value) && !hasForbiddenPolicyToken(value) ? { ok: true, value } : { ok: false };
  if (typeof value === "boolean") return { ok: true, value };
  if (typeof value === "number") return Number.isSafeInteger(value) ? { ok: true, value } : { ok: false };
  if (Array.isArray(value)) {
    if (value.length === 0) return { ok: false };
    const out = [];
    for (const item of value) {
      const literal = policyLiteral(item);
      if (!literal.ok) return { ok: false };
      out.push(literal.value);
    }
    return { ok: true, value: out };
  }
  return { ok: false };
}

function onlyKnownFields(object, allowed) {
  return Object.keys(object).every((key) => allowed.has(key));
}

function invalidPolicy(message) {
  return new PolicyReevaluationError("POLICY_DOCUMENT_INVALID", message);
}

// C2.1: validate the policy document and return the normalized definition.
function validatePolicyDefinition(policy, allowedEventFields) {
  if (!isPlainPolicyObject(policy)) throw invalidPolicy("policy must be a JSON object");
  if (!onlyKnownFields(policy, POLICY_FIELDS)) throw invalidPolicy("policy contains unknown top-level fields");
  if (typeof policy.policy_id !== "string" || !POLICY_IDENTIFIER_RE.test(policy.policy_id)) throw invalidPolicy("policy_id invalid");
  if (typeof policy.policy_version !== "string" || !POLICY_VERSION_RE.test(policy.policy_version)) throw invalidPolicy("policy_version invalid");
  if (policy.default_effect !== "DENY") throw invalidPolicy("default_effect must be DENY");
  const allowedFields = new Set(allowedEventFields);
  if (!Array.isArray(policy.rules) || policy.rules.length === 0) throw invalidPolicy("rules must be a non-empty array");
  const seenRuleIDs = new Set();
  const rules = policy.rules.map((rule, ruleIndex) => {
    if (!isPlainPolicyObject(rule) || !onlyKnownFields(rule, POLICY_RULE_FIELDS)) throw invalidPolicy(`rules[${ruleIndex}] invalid`);
    if (typeof rule.rule_id !== "string" || !POLICY_IDENTIFIER_RE.test(rule.rule_id) || seenRuleIDs.has(rule.rule_id)) throw invalidPolicy(`rules[${ruleIndex}].rule_id invalid`);
    seenRuleIDs.add(rule.rule_id);
    if (!POLICY_EFFECTS.has(rule.effect)) throw invalidPolicy(`rules[${ruleIndex}].effect invalid`);
    if (!Number.isSafeInteger(rule.priority)) throw invalidPolicy(`rules[${ruleIndex}].priority invalid`);
    if (!Array.isArray(rule.conditions)) throw invalidPolicy(`rules[${ruleIndex}].conditions invalid`);
    const conditions = rule.conditions.map((condition, conditionIndex) => {
      const at = `rules[${ruleIndex}].conditions[${conditionIndex}]`;
      if (!isPlainPolicyObject(condition) || !onlyKnownFields(condition, POLICY_CONDITION_FIELDS)) throw invalidPolicy(`${at} invalid`);
      if (!policyNonEmpty(condition.field) || !allowedFields.has(condition.field)) throw invalidPolicy(`${at}.field invalid`);
      if (!POLICY_CONDITION_OPERATORS.has(condition.operator)) throw invalidPolicy(`${at}.operator invalid`);
      const literal = policyLiteral(condition.value);
      if (!literal.ok) throw invalidPolicy(`${at}.value invalid`);
      return { field: condition.field, operator: condition.operator, value: literal.value, sourcePath: `policy.rules[${ruleIndex}].conditions[${conditionIndex}]` };
    });
    if (!Array.isArray(rule.constraints)) throw invalidPolicy(`rules[${ruleIndex}].constraints invalid`);
    const seenConstraintIDs = new Set();
    const constraints = rule.constraints.map((constraint, constraintIndex) => {
      const at = `rules[${ruleIndex}].constraints[${constraintIndex}]`;
      if (!isPlainPolicyObject(constraint) || !onlyKnownFields(constraint, POLICY_CONSTRAINT_FIELDS)) throw invalidPolicy(`${at} invalid`);
      if (typeof constraint.constraint_id !== "string" || !POLICY_IDENTIFIER_RE.test(constraint.constraint_id) || seenConstraintIDs.has(constraint.constraint_id)) throw invalidPolicy(`${at}.constraint_id invalid`);
      seenConstraintIDs.add(constraint.constraint_id);
      if (!POLICY_CONSTRAINT_TYPES.has(constraint.type)) throw invalidPolicy(`${at}.type invalid`);
      const literal = policyLiteral(constraint.value);
      if (!literal.ok) throw invalidPolicy(`${at}.value invalid`);
      return { constraint_id: constraint.constraint_id, type: constraint.type, value: literal.value };
    });
    if (rule.effect === "CONDITIONAL" && constraints.length === 0) throw invalidPolicy(`rules[${ruleIndex}] CONDITIONAL needs a constraint`);
    return { rule_id: rule.rule_id, effect: rule.effect, conditions, constraints, priority: rule.priority };
  });
  const seenPriorities = new Set();
  rules.forEach((rule, index) => {
    if (seenPriorities.has(rule.priority) || (index > 0 && rule.priority > rules[index - 1].priority)) throw invalidPolicy("rule priorities must be unique and descending");
    seenPriorities.add(rule.priority);
  });
  return { policy_id: policy.policy_id, policy_version: policy.policy_version, rules, default_effect: policy.default_effect };
}

function canonicalPolicyDefinition(definition) {
  return policyCanonical(orderedObject(
    ["policy_id", definition.policy_id],
    ["policy_version", definition.policy_version],
    ["rules", definition.rules.map((rule) => orderedObject(
      ["rule_id", rule.rule_id],
      ["effect", rule.effect],
      ["conditions", rule.conditions.map((condition) => orderedObject(["field", condition.field], ["operator", condition.operator], ["value", condition.value]))],
      ["constraints", rule.constraints.map((constraint) => orderedObject(["constraint_id", constraint.constraint_id], ["type", constraint.type], ["value", constraint.value]))],
      ["priority", rule.priority],
    ))],
    ["default_effect", definition.default_effect],
  ));
}

function literalConstantType(value) {
  if (typeof value === "number") return "NUMBER";
  if (typeof value === "boolean") return "BOOLEAN";
  if (typeof value === "string") return "STRING";
  return "STRUCTURED";
}

function constantTypeRank(type) {
  return { FIELD: 1, STRING: 2, NUMBER: 3, BOOLEAN: 4 }[type] ?? 5;
}

function sortedPolicyConditions(conditions) {
  return [...conditions].sort((left, right) =>
    utf8Compare(left.field, right.field)
    || utf8Compare(left.operator, right.operator)
    || utf8Compare(policyCanonical(left.value), policyCanonical(right.value))
    || utf8Compare(left.sourcePath, right.sourcePath));
}

function constraintsPayload(constraints) {
  return constraints
    .map((constraint) => ({ constraint_id: constraint.constraint_id, type: constraint.type, value: constraint.value }))
    .sort((left, right) => utf8Compare(policyCanonical(left), policyCanonical(right)));
}

function estimatePolicyStackDepth(rules) {
  let maxDepth = 0;
  for (const rule of rules) {
    let depth = 0;
    rule.conditions.forEach((_, conditionIndex) => {
      depth += 1;
      maxDepth = Math.max(maxDepth, depth);
      depth += 1;
      maxDepth = Math.max(maxDepth, depth);
      depth -= 1;
      if (conditionIndex > 0) depth -= 1;
    });
  }
  return maxDepth;
}

function compiledPolicyHash(bytecode) {
  const header = bytecode.bytecode_header_domain;
  return sha256Hex(POLICY_BYTECODE_HASH_DOMAIN + policyCanonical(orderedObject(
    ["bytecode_header_domain", orderedObject(
      ["bytecode_schema_version", header.bytecode_schema_version],
      ["bytecode_version", header.bytecode_version],
      ["policy_hash", header.policy_hash],
      ["compiler_version", header.compiler_version],
      ["instruction_count", header.instruction_count],
    )],
    ["constant_pool", bytecode.constant_pool.map((constant) => orderedObject(
      ["index", constant.index], ["constant_type", constant.constant_type], ["value", constant.value], ["value_hash", constant.value_hash],
    ))],
    ["instruction_stream", bytecode.instruction_stream.map((instruction) => orderedObject(
      ["index", instruction.index], ["opcode", instruction.opcode], ["opcode_value", instruction.opcode_value],
      ["operand_a_type", instruction.operand_a_type], ["operand_a", instruction.operand_a],
      ["operand_b_type", instruction.operand_b_type], ["operand_b", instruction.operand_b],
    ))],
  )));
}

// C2.1 -> C2.3: compile a policy document (its JSON text) to bytecode.
export function compilePolicyDocument(policyJSON, allowedEventFields) {
  if (typeof policyJSON !== "string") throw invalidPolicy("policy document must be JSON text");
  if (!Array.isArray(allowedEventFields) || allowedEventFields.length === 0 || !allowedEventFields.every(policyNonEmpty)) {
    throw invalidPolicy("allowed event fields are required");
  }
  let parsed;
  try {
    parsed = JSON.parse(policyJSON);
  } catch {
    throw invalidPolicy("policy document is not JSON");
  }
  const definition = validatePolicyDefinition(parsed, allowedEventFields);
  const sourcePolicyHash = sha256Hex(POLICY_HASH_DOMAIN + canonicalPolicyDefinition(definition));
  // C2.3 supports ALLOW/DENY with comparison operators only.
  for (const rule of definition.rules) {
    if (rule.effect !== "ALLOW" && rule.effect !== "DENY") throw new PolicyReevaluationError("POLICY_COMPILE_FAILED", `rule ${rule.rule_id}: effect not compilable`);
    for (const condition of rule.conditions) {
      if (!(condition.operator in POLICY_COMPARISON_OPCODES)) throw new PolicyReevaluationError("POLICY_COMPILE_FAILED", `rule ${rule.rule_id}: operator not compilable`);
    }
  }
  const entries = new Map();
  const addConstant = (type, value) => {
    const canonical = policyCanonical(value);
    const key = type + "\u0000" + canonical;
    if (!entries.has(key)) entries.set(key, { type, canonical, value, value_hash: sha256Hex(type + "|" + canonical) });
  };
  for (const rule of definition.rules) {
    addConstant("STRING", rule.rule_id);
    addConstant("STRUCTURED", constraintsPayload(rule.constraints));
    for (const condition of sortedPolicyConditions(rule.conditions)) {
      addConstant("FIELD", condition.field);
      addConstant(literalConstantType(condition.value), condition.value);
    }
  }
  addConstant("STRING", "__default__");
  addConstant("STRUCTURED", []);
  if (entries.size > POLICY_MAX_CONSTANTS) throw new PolicyReevaluationError("POLICY_COMPILE_FAILED", "constant pool too large");
  const constants = [...entries.values()]
    .sort((left, right) => (constantTypeRank(left.type) - constantTypeRank(right.type)) || utf8Compare(left.canonical, right.canonical) || utf8Compare(left.type, right.type))
    .map((entry, index) => ({ index, constant_type: entry.type, value: entry.value, value_hash: entry.value_hash, canonical: entry.canonical }));
  const constantIndex = (type, value) => {
    const canonical = policyCanonical(value);
    const found = constants.find((constant) => constant.constant_type === type && constant.canonical === canonical);
    if (found === undefined) throw new PolicyReevaluationError("POLICY_COMPILE_FAILED", "constant missing");
    return found.index;
  };
  const instructions = [];
  const add = (opcode, operandAType, operandA, operandBType, operandB) => {
    instructions.push({ index: instructions.length, opcode, opcode_value: POLICY_OPCODE_VALUES[opcode], operand_a_type: operandAType, operand_a: operandA, operand_b_type: operandBType, operand_b: operandB });
    return instructions.length - 1;
  };
  for (const rule of definition.rules) {
    sortedPolicyConditions(rule.conditions).forEach((condition, conditionIndex) => {
      add("LOAD_FIELD", "FIELD_INDEX", constantIndex("FIELD", condition.field), "NONE", 0);
      add("LOAD_CONST", "CONST_INDEX", constantIndex(literalConstantType(condition.value), condition.value), "NONE", 0);
      add(POLICY_COMPARISON_OPCODES[condition.operator], "NONE", 0, "NONE", 0);
      if (conditionIndex > 0) add("AND", "NONE", 0, "NONE", 0);
    });
    const jumpIndex = rule.conditions.length > 0 ? add("JUMP_IF_FALSE", "JUMP_OFFSET", 0, "NONE", 0) : -1;
    const ruleIDIndex = constantIndex("STRING", rule.rule_id);
    const constraintIndex = constantIndex("STRUCTURED", constraintsPayload(rule.constraints));
    add(rule.effect === "ALLOW" ? "RULE_ALLOW" : "RULE_DENY", "CONST_INDEX", ruleIDIndex, "CONST_INDEX", constraintIndex);
    const ruleEndIndex = add("RULE_END", "NONE", 0, "NONE", 0);
    if (jumpIndex >= 0) instructions[jumpIndex].operand_a = ruleEndIndex - jumpIndex;
  }
  add("RULE_DENY", "CONST_INDEX", constantIndex("STRING", "__default__"), "CONST_INDEX", constantIndex("STRUCTURED", []));
  add("RULE_END", "NONE", 0, "NONE", 0);
  if (definition.rules.length > POLICY_MAX_RULES
    || definition.rules.some((rule) => rule.conditions.length > POLICY_MAX_CONDITIONS_PER_RULE)
    || instructions.length > POLICY_MAX_INSTRUCTIONS
    || estimatePolicyStackDepth(definition.rules) > POLICY_MAX_STACK_DEPTH) {
    throw new PolicyReevaluationError("POLICY_COMPILE_FAILED", "policy exceeds compiler safety limits");
  }
  const bytecode = {
    bytecode_header_domain: {
      bytecode_schema_version: POLICY_BYTECODE_SCHEMA_VERSION,
      bytecode_version: POLICY_BYTECODE_VERSION,
      policy_hash: sourcePolicyHash,
      compiled_policy_hash: "",
      compiler_version: POLICY_COMPILER_VERSION,
      instruction_count: instructions.length,
    },
    constant_pool: constants.map(({ canonical, ...constant }) => constant),
    instruction_stream: instructions,
  };
  bytecode.bytecode_header_domain.compiled_policy_hash = compiledPolicyHash(bytecode);
  return {
    policy_id: definition.policy_id,
    policy_version: definition.policy_version,
    source_policy_hash: sourcePolicyHash,
    compiled_policy_hash: bytecode.bytecode_header_domain.compiled_policy_hash,
    bytecode,
  };
}

function cloneStackValue(value) {
  return { value_type: value.value_type, value: clonePolicyValue(value.value) };
}

function clonePolicyValue(value) {
  if (Array.isArray(value)) return value.map(clonePolicyValue);
  if (isPlainPolicyObject(value)) return Object.fromEntries(Object.entries(value).map(([key, member]) => [key, clonePolicyValue(member)]));
  return value;
}

function stackValueFromEventValue(value) {
  if (typeof value === "string") return { value_type: "string", value };
  if (typeof value === "boolean") return { value_type: "boolean", value };
  if (typeof value === "number" && Number.isSafeInteger(value)) return { value_type: "number", value };
  return { value_type: "unsupported", value: null };
}

function resolveEventField(event, field) {
  let current = event;
  for (const part of field.split(".")) {
    if (!isPlainPolicyObject(current) || !Object.hasOwn(current, part)) return { value_type: "NULL_VALUE", value: null };
    current = current[part];
  }
  if (current === null) return { value_type: "NULL_LITERAL", value: null };
  return stackValueFromEventValue(current);
}

function stackValueFromConstant(constant) {
  switch (constant.constant_type) {
    case "STRING": return typeof constant.value === "string" ? { value_type: "string", value: constant.value } : null;
    case "NUMBER": return Number.isSafeInteger(constant.value) ? { value_type: "number", value: constant.value } : null;
    case "BOOLEAN": return typeof constant.value === "boolean" ? { value_type: "boolean", value: constant.value } : null;
    default: return null;
  }
}

function isNullStackValue(value) {
  return value.value_type === "NULL_VALUE" || value.value_type === "NULL_LITERAL";
}

function compareStackValues(left, right, opcode) {
  if (isNullStackValue(left) || isNullStackValue(right)) {
    if (opcode === "CMP_EQ") return { value: left.value_type === right.value_type };
    if (opcode === "CMP_NEQ") return { value: left.value_type !== right.value_type };
    return { error: "ERR_TYPE_MISMATCH" };
  }
  if (left.value_type !== right.value_type) return { error: "ERR_TYPE_MISMATCH" };
  if (left.value_type === "string" || left.value_type === "boolean") {
    if (opcode === "CMP_EQ") return { value: left.value === right.value };
    if (opcode === "CMP_NEQ") return { value: left.value !== right.value };
    return { error: "ERR_TYPE_MISMATCH" };
  }
  if (left.value_type === "number") {
    switch (opcode) {
      case "CMP_EQ": return { value: left.value === right.value };
      case "CMP_NEQ": return { value: left.value !== right.value };
      case "CMP_GT": return { value: left.value > right.value };
      case "CMP_GTE": return { value: left.value >= right.value };
      case "CMP_LT": return { value: left.value < right.value };
      case "CMP_LTE": return { value: left.value <= right.value };
      default: return { error: "ERR_INVALID_INSTRUCTION" };
    }
  }
  return { error: "ERR_TYPE_MISMATCH" };
}

function policyInstructionCost(opcode) {
  if (opcode === "LOAD_FIELD") return 3;
  if (opcode.startsWith("CMP_")) return 2;
  return 1;
}

function policyRuntimeError(errorCode) {
  return { decision: "ERROR", rule_id: "", constraints: [], error_code: errorCode };
}

// C2.4: run the bytecode over the event; returns the evaluation result and
// the VM trace exactly as the Go VM records them.
function executePolicyBytecode(bytecode, event) {
  const instructions = bytecode.instruction_stream;
  const constants = bytecode.constant_pool;
  const stack = [];
  const trace = [];
  let ip = 0;
  let step = 0;
  let cost = 0;
  const constantAt = (index, type) => {
    const constant = Number.isInteger(index) && index >= 0 && index < constants.length ? constants[index] : undefined;
    if (constant === undefined || (type !== "" && constant.constant_type !== type)) return undefined;
    return constant;
  };
  const push = (value) => {
    if (stack.length + 1 > POLICY_MAX_STACK_DEPTH) return "ERR_STACK_OVERFLOW";
    stack.push(value);
    return "";
  };
  const pop = () => (stack.length === 0 ? { error: "ERR_STACK_UNDERFLOW" } : { value: stack.pop() });
  const popBool = () => {
    const popped = pop();
    if (popped.error) return popped;
    if (popped.value.value_type !== "boolean" || typeof popped.value.value !== "boolean") return { error: "ERR_TYPE_MISMATCH" };
    return { value: popped.value.value };
  };
  const apply = (instruction) => {
    const next = ip + 1;
    switch (instruction.opcode) {
      case "LOAD_FIELD": {
        const constant = constantAt(instruction.operand_a, "FIELD");
        if (constant === undefined || typeof constant.value !== "string" || constant.value === "") return { next, error: "ERR_INVALID_CONSTANT" };
        return { next, error: push(resolveEventField(event, constant.value)) };
      }
      case "LOAD_CONST": {
        const constant = constantAt(instruction.operand_a, "");
        if (constant === undefined || constant.constant_type === "FIELD" || constant.constant_type === "STRUCTURED") return { next, error: "ERR_INVALID_CONSTANT" };
        const value = stackValueFromConstant(constant);
        if (value === null) return { next, error: "ERR_INVALID_CONSTANT" };
        return { next, error: push(value) };
      }
      case "CMP_EQ": case "CMP_NEQ": case "CMP_GT": case "CMP_GTE": case "CMP_LT": case "CMP_LTE": {
        const right = pop();
        if (right.error) return { next, error: right.error };
        const left = pop();
        if (left.error) return { next, error: left.error };
        const compared = compareStackValues(left.value, right.value, instruction.opcode);
        if (compared.error) return { next, error: compared.error };
        return { next, error: push({ value_type: "boolean", value: compared.value }) };
      }
      case "AND": case "OR": {
        const right = popBool();
        if (right.error) return { next, error: right.error };
        const left = popBool();
        if (left.error) return { next, error: left.error };
        const value = instruction.opcode === "AND" ? left.value && right.value : left.value || right.value;
        return { next, error: push({ value_type: "boolean", value }) };
      }
      case "NOT": {
        const value = popBool();
        if (value.error) return { next, error: value.error };
        return { next, error: push({ value_type: "boolean", value: !value.value }) };
      }
      case "JUMP": {
        const target = ip + instruction.operand_a;
        if (target < 0 || target >= instructions.length) return { next, error: "ERR_INVALID_JUMP" };
        return { next: target, error: "" };
      }
      case "JUMP_IF_FALSE": {
        const condition = popBool();
        if (condition.error) return { next, error: condition.error };
        if (condition.value) return { next, error: "" };
        const target = ip + instruction.operand_a;
        if (target < 0 || target >= instructions.length) return { next, error: "ERR_INVALID_JUMP" };
        return { next: target, error: "" };
      }
      case "RULE_ALLOW": case "RULE_DENY": {
        const ruleConstant = constantAt(instruction.operand_a, "STRING");
        if (ruleConstant === undefined || typeof ruleConstant.value !== "string" || ruleConstant.value === "") return { next, error: "ERR_INVALID_CONSTANT" };
        const constraintConstant = constantAt(instruction.operand_b, "STRUCTURED");
        if (constraintConstant === undefined || !Array.isArray(constraintConstant.value)) return { next, error: "ERR_INVALID_CONSTANT" };
        return {
          next,
          error: "",
          result: {
            decision: instruction.opcode === "RULE_DENY" ? "NON_COMPLIANT" : "COMPLIANT",
            rule_id: ruleConstant.value,
            constraints: clonePolicyValue(constraintConstant.value),
            error_code: "",
          },
        };
      }
      case "RULE_END":
        return { next, error: "" };
      default:
        return { next, error: "ERR_INVALID_INSTRUCTION" };
    }
  };
  while (ip >= 0 && ip < instructions.length) {
    const instruction = instructions[ip];
    if (step >= POLICY_MAX_INSTRUCTIONS || cost + policyInstructionCost(instruction.opcode) > POLICY_VM_MAX_EXECUTION_COST) return { result: policyRuntimeError("ERR_RUNTIME_LIMIT_EXCEEDED"), trace };
    if (trace.length + 1 > POLICY_MAX_INSTRUCTIONS) return { result: policyRuntimeError("ERR_RUNTIME_LIMIT_EXCEEDED"), trace };
    const before = stack.map(cloneStackValue);
    const applied = apply(instruction);
    const after = stack.map(cloneStackValue);
    step += 1;
    cost += policyInstructionCost(instruction.opcode);
    trace.push({ step, instruction_index: instruction.index, opcode: instruction.opcode, stack_before: before, stack_after: after });
    if (applied.error) return { result: policyRuntimeError(applied.error), trace };
    if (applied.result) return { result: applied.result, trace };
    ip = applied.next;
  }
  return { result: policyRuntimeError("ERR_NO_TERMINAL_RULE"), trace };
}

function orderedPolicyTrace(trace) {
  const stackOrdered = (stack) => stack.map((value) => orderedObject(["value_type", value.value_type], ["value", value.value]));
  return trace.map((entry) => orderedObject(
    ["step", entry.step],
    ["instruction_index", entry.instruction_index],
    ["opcode", entry.opcode],
    ["stack_before", stackOrdered(entry.stack_before)],
    ["stack_after", stackOrdered(entry.stack_after)],
  ));
}

// The C2.4 execution-event hash of an event object.
export function policyExecutionEventHash(event) {
  return sha256Hex(POLICY_VM_EVENT_HASH_DOMAIN + policyCanonical(event));
}

// C2.4: evaluate a compiled policy over an execution event and return every
// value a policy binding seals.
export function evaluateCompiledPolicy(compiled, event) {
  if (!isPlainPolicyObject(event) || Object.keys(event).length === 0) throw new PolicyReevaluationError("POLICY_EVENT_INVALID", "execution event must be a non-empty object");
  const header = compiled.bytecode.bytecode_header_domain;
  const { result, trace } = executePolicyBytecode(compiled.bytecode, event);
  const vmTrace = orderedPolicyTrace(trace);
  const traceHash = sha256Hex(POLICY_VM_TRACE_HASH_DOMAIN + policyCanonical(vmTrace));
  const executionEventHash = policyExecutionEventHash(event);
  const evaluationHash = sha256Hex(POLICY_VM_EVALUATION_HASH_DOMAIN + policyCanonical(orderedObject(
    ["evaluation_result", orderedObject(["decision", result.decision], ["rule_id", result.rule_id], ["constraints", result.constraints], ["error_code", result.error_code])],
    ["vm_trace", vmTrace],
    ["trace_hash", traceHash],
    ["runtime_fingerprint", orderedObject(["pvm_runtime_version", POLICY_VM_RUNTIME_VERSION], ["compiler_version", header.compiler_version], ["bytecode_version", header.bytecode_version])],
    ["integrity", orderedObject(
      ["source_policy_hash", header.policy_hash],
      ["compiled_policy_hash", header.compiled_policy_hash],
      ["execution_event_hash", executionEventHash],
      ["trace_hash", traceHash],
      ["hash_algorithm", "SHA-256"],
    )],
    ["task_ids", [...POLICY_VM_TASK_IDS]],
    ["valid", true],
  )));
  const constraints = result.constraints.map((constraint) => {
    if (!isPlainPolicyObject(constraint) || !policyNonEmpty(constraint.constraint_id) || !policyNonEmpty(constraint.type)) {
      throw new PolicyReevaluationError("POLICY_EVALUATION_INVALID", "evaluation constraint has no id or type");
    }
    return { constraint_id: constraint.constraint_id, type: constraint.type };
  }).sort((left, right) => utf8Compare(left.constraint_id, right.constraint_id));
  return {
    policy_id: compiled.policy_id,
    policy_version: compiled.policy_version,
    source_policy_hash: header.policy_hash,
    compiled_policy_hash: header.compiled_policy_hash,
    execution_event_hash: executionEventHash,
    evaluation_hash: evaluationHash,
    decision: result.decision,
    rule_id: result.rule_id,
    error_code: result.error_code,
    constraints,
  };
}

// Compiles policyJSON and evaluates event in one step.
export function reevaluatePolicy({ policyJSON, allowedEventFields, event }) {
  return evaluateCompiledPolicy(compilePolicyDocument(policyJSON, allowedEventFields), event);
}

// Lists every sealed policy-binding member the recomputed evaluation
// disagrees with (sorted policy_binding.<member> paths). Constraint statuses
// are not part of the evaluation and are not compared.
export function policyReevaluationMismatches(binding, recomputed) {
  const fields = [];
  for (const member of ["compiled_policy_hash", "decision", "evaluation_hash", "execution_event_hash", "policy_id", "policy_version", "rule_id", "source_policy_hash"]) {
    if (binding[member] !== recomputed[member]) fields.push(`policy_binding.${member}`);
  }
  const sealed = Array.isArray(binding.constraints) ? binding.constraints : [];
  if (sealed.length !== recomputed.constraints.length
    || sealed.some((constraint, index) => constraint.constraint_id !== recomputed.constraints[index].constraint_id || constraint.type !== recomputed.constraints[index].type)) {
    fields.push("policy_binding.constraints");
  }
  return fields.sort();
}
