export declare const SDK_VERSION: "1.0.0";
export declare const API_VERSION: "v1";
export declare const VERIFY_REQUEST_HASH_DOMAIN: "INTENTRAX_PUBLIC_SDK_VERIFY_REQUEST_V1";
export declare const IDEMPOTENCY_KEY_DOMAIN: "INTENTRAX_PUBLIC_SDK_IDEMPOTENCY_V1";
export declare const AGENT_GATEWAY_ADMISSION_REQUEST_HASH_DOMAIN: "INTENTRAX_AGENT_GATEWAY_ADMISSION_REQUEST_V1";
export declare const AGENT_ADMISSION_SCHEMA_VERSION: "intentrax.runtime.agent_admission_request/1.0";
export declare const AGENT_ADMISSION_ENDPOINT: "/v1/agent/admissions";
export declare const INTENT_EXECUTE_REQUEST_SCHEMA_VERSION: "intentrax.runtime.intent_execute.request/1.0";
export declare const INTENT_EXECUTE_REQUEST_SCHEMA_VERSION_V11: "intentrax.runtime.intent_execute.request/1.1";
export declare const INTENT_EXECUTE_ENDPOINT: "/v1/intents/execute";
export declare const INTENT_EXECUTE_MAX_REQUEST_BYTES: 4096;
export declare const RECEIPT_VERIFICATION_REQUEST_SCHEMA_VERSION: "intentrax.runtime.proof_verification.request/1.0";
export declare const RECEIPT_VERIFICATION_ENDPOINT: "/v1/proofs/verify";
export declare const RECEIPT_VERIFICATION_REQUEST_HASH_DOMAIN: "INTENTRAX_RECEIPT_VERIFICATION_REQUEST_V1";
export declare const RECEIPT_VERIFICATION_IDEMPOTENCY_DOMAIN: "INTENTRAX_RECEIPT_VERIFICATION_IDEMPOTENCY_V1";
export declare const PROOF_EXPORT_ENDPOINT_PREFIX: "/v1/proofs";
export declare const PROOF_REPLAY_REQUEST_SCHEMA_VERSION: "intentrax.runtime.proof_replay.request/1.0";
export declare const PROOF_REPLAY_ENDPOINT: "/v1/proofs/replay";
export declare const VERIFIER_HANDOFF_ENDPOINT_PREFIX: "/v1/evidence/dry-run";
export declare const SDK_INPUT_ERROR_CODE: "INTX-SDK-INPUT-001";

export type VerifyProofRequest = {
  action: string;
  execution_id: string;
  intent_id: string;
  payload_hash: string;
  principal_id: string;
  proof_id: string;
  request_body_hash: string;
  request_method: string;
  request_path: string;
  required_tier: "TIER_1" | "TIER_2" | "TIER_3" | "TIER_4";
  timestamp: string;
};

export type AgentGatewayAdmissionRequest = {
  schema_version: "intentrax.runtime.agent_admission_request/1.0";
  tenant_id: string;
  surface_id: string;
  action: string;
  adapter_id: string;
  evidence_refs: string[];
  proof_refs: string[];
  request_payload_hash: string;
  protocol_payload_ref: string;
  idempotency_key_hash: string;
};

type IntentExecuteRequestFields = {
  intent_id: string;
  tenant_id: string;
  action: string;
  idempotency_key: string;
  proof_chain_fixture_ref: string;
};
export type IntentExecuteRequestV10 = IntentExecuteRequestFields & {
  schema_version: "intentrax.runtime.intent_execute.request/1.0";
};
// /1.1: the /1.0 fields plus an optional producer-declared output_binding that
// the engine seals into the signed proof. content_hash may be the bare 64
// lowercase hex buildOutputBinding emits or the same with a "sha256:" prefix.
export type IntentExecuteRequestV11 = IntentExecuteRequestFields & {
  schema_version: "intentrax.runtime.intent_execute.request/1.1";
  output_binding?: {
    content_hash: string;
    hash_algorithm: "SHA-256";
    normalization: "intentrax-content/1.0";
  };
};
export type IntentExecuteRequest = IntentExecuteRequestV10 | IntentExecuteRequestV11;

export type ReceiptVerificationRequest = {
  schema_version: "intentrax.runtime.proof_verification.request/1.0";
  receipt_id: string;
  receipt_hash: string;
  evidence_record_hash: string;
  handoff_hash: string;
  proof_chain_fixture_ref: string;
  proof_chain_fixture_hash: string;
};

export type ProofExportFormat = "json" | "aep-json" | "pdf";

export type ProofExportRequest = {
  proof_id: string;
  format?: ProofExportFormat | "";
};

export type ProofReadRequest = {
  proof_id: string;
};

export type ProofReplayRequest = {
  schema_version: "intentrax.runtime.proof_replay.request/1.0";
  proof_id: string;
};

export type ProofInclusionRequest = {
  proof_id: string;
};

export type VerifierHandoffRequest = {
  receipt_id: string;
};

export type SDKError = {
  error_code: string;
  error_type: "public_sdk_input_error";
  message: string;
  invalid_fields: string[];
  retriable: false;
};

export declare function sha256Hex(value: string): string;
export declare function isSha256Hex(value: unknown): boolean;
export declare function isSha256Ref(value: unknown): boolean;
export declare function canonicalJson(value: unknown): string;
export declare function validateVerificationRequest(request: unknown): string[];
export declare function verificationRequestHash(request: VerifyProofRequest): string;
export declare function idempotencyInput(request: VerifyProofRequest): Record<string, unknown>;
export declare function createIdempotencyKey(request: VerifyProofRequest): string;
export declare function admissionIdempotencyKeyHash(request: VerifyProofRequest): string;
/** SHA-256 hex of a raw execute idempotency key: the admission `idempotency_key_hash` that correlates with that execution. */
export declare function executeIdempotencyKeyHash(idempotencyKey: string): string;
export declare const AGENT_HOOK_IDEMPOTENCY_KEY_DOMAIN: "INTENTRAX_AGENT_HOOK_IDEMPOTENCY_V1";
/** The raw execute idempotency key a generated agent hook derives from its admission `request_payload_hash`. */
export declare function agentHookExecuteIdempotencyKey(requestPayloadHash: string): string;
export declare function buildVerificationEnvelope(request: VerifyProofRequest): {
  status: "PASS";
  output: {
    schema_version: "intentrax.public_sdk.verify/1.0";
    request_hash: string;
    idempotency_key: string;
    request: VerifyProofRequest;
  };
} | {
  status: "FAIL";
  error: SDKError;
};
export declare function validateReceiptVerificationRequest(request: unknown): string[];
export declare function receiptVerificationRequestHash(request: ReceiptVerificationRequest): string;
export declare function receiptVerificationIdempotencyInput(request: ReceiptVerificationRequest): Record<string, unknown>;
export declare function createReceiptVerificationIdempotencyKey(request: ReceiptVerificationRequest): string;
export declare function buildReceiptVerificationEnvelope(request: ReceiptVerificationRequest): {
  status: "PASS";
  output: {
    schema_version: "intentrax.public_sdk.receipt_verification/1.0";
    endpoint: "/v1/proofs/verify";
    request_hash: string;
    idempotency_key: string;
    request: ReceiptVerificationRequest;
  };
} | {
  status: "FAIL";
  error: SDKError;
};
export declare function normalizeProofExportFormat(format?: unknown): ProofExportFormat | string;
export declare function validateProofExportRequest(request: unknown): string[];
export declare function buildProofExportEnvelope(request: ProofExportRequest): {
  status: "PASS";
  output: {
    schema_version: "intentrax.public_sdk.proof_export/1.0";
    endpoint: string;
    format: ProofExportFormat;
    authoritative_json: boolean;
    pdf_receipt_non_authoritative: boolean;
    request: {
      proof_id: string;
      format: ProofExportFormat;
    };
  };
} | {
  status: "FAIL";
  error: SDKError;
};
export declare function validateProofReadRequest(request: unknown): string[];
export declare function buildProofReadEnvelope(request: ProofReadRequest): {
  status: "PASS";
  output: {
    schema_version: "intentrax.public_sdk.proof_read/1.0";
    endpoint: string;
    request: {
      proof_id: string;
    };
  };
} | {
  status: "FAIL";
  error: SDKError;
};
export declare function validateProofReplayRequest(request: unknown): string[];
export declare function buildProofReplayEnvelope(request: ProofReplayRequest): {
  status: "PASS";
  output: {
    schema_version: "intentrax.public_sdk.proof_replay/1.0";
    endpoint: "/v1/proofs/replay";
    request: ProofReplayRequest;
  };
} | {
  status: "FAIL";
  error: SDKError;
};
export declare function validateProofInclusionRequest(request: unknown): string[];
export declare function buildProofInclusionEnvelope(request: ProofInclusionRequest): {
  status: "PASS";
  output: {
    schema_version: "intentrax.public_sdk.proof_inclusion/1.0";
    endpoint: string;
    request: {
      proof_id: string;
    };
  };
} | {
  status: "FAIL";
  error: SDKError;
};
export declare function validateVerifierHandoffRequest(request: unknown): string[];
export declare function buildVerifierHandoffEnvelope(request: VerifierHandoffRequest): {
  status: "PASS";
  output: {
    schema_version: "intentrax.public_sdk.verifier_handoff/1.0";
    endpoint: string;
    request: {
      receipt_id: string;
    };
  };
} | {
  status: "FAIL";
  error: SDKError;
};
export declare function validateIntentExecuteRequest(request: unknown): string[];
export declare function bindIntentExecuteOutput(
  request: IntentExecuteRequestFields & { schema_version?: string },
  renderedOutput: string | readonly string[],
): IntentExecuteRequestV11 & { output_binding: OutputBinding };
export declare function buildIntentExecuteEnvelope(request: IntentExecuteRequest): {
  status: "PASS";
  output: {
    schema_version: "intentrax.public_sdk.intent_execute/1.0";
    endpoint: "/v1/intents/execute";
    request: IntentExecuteRequest;
  };
} | {
  status: "FAIL";
  error: SDKError;
};
export declare function validateAgentGatewayAdmissionRequest(request: unknown): string[];
export declare function agentGatewayAdmissionRequestHash(request: AgentGatewayAdmissionRequest): string;
export declare function buildAgentGatewayAdmissionEnvelope(request: AgentGatewayAdmissionRequest): {
  status: "PASS";
  output: {
    schema_version: "intentrax.public_sdk.agent_gateway_admission/1.0";
    request_hash: string;
    idempotency_key_hash: string;
    endpoint: "/v1/agent/admissions";
    request: AgentGatewayAdmissionRequest;
  };
} | {
  status: "FAIL";
  error: SDKError;
};

// === Verification Mark response envelope (SDK/MCP machine substrate) ===

export type VerificationMarkDisplayState =
  | "verified"
  | "proof_available"
  | "checking"
  | "failed"
  | "revoked"
  | "not_found"
  | "unavailable"
  | "share_expired";

export type VerificationMarkSeverity = "green" | "neutral" | "negative";

export type VerificationMarkAssuranceLevel = 1 | 2 | 3 | 4;

/**
 * The backend-produced, public-safe verification envelope carried on an SDK or
 * MCP tool response. `signature` is a STATUS projection (e.g. "pass"/"fail"/
 * "Not Available"), never a raw signature.
 */
export type VerificationMarkEnvelope = {
  display_state: VerificationMarkDisplayState;
  proof_id: string;
  verify_url: string;
  assurance_level: VerificationMarkAssuranceLevel | null;
  signature: string;
};

/** Normalized, public-safe projection of a verification envelope. */
export type NormalizedVerificationMarkEnvelope = {
  schema_version: "intentrax.public_sdk.verification_mark_envelope/1.0";
  display_state: VerificationMarkDisplayState;
  severity: VerificationMarkSeverity;
  verified: boolean;
  proof_id: string | null;
  verify_url: string | null;
  assurance_level: VerificationMarkAssuranceLevel | null;
  signature: string | null;
};

/** A verdict read off a response — the consumer-facing shape. */
export type VerificationVerdict = {
  present: boolean;
  valid: boolean;
  verified: boolean;
  display_state: VerificationMarkDisplayState | null;
  severity: VerificationMarkSeverity | null;
  proof_id: string | null;
  verify_url: string | null;
  assurance_level: VerificationMarkAssuranceLevel | null;
  signature: string | null;
};

export declare const VERIFICATION_MARK_ENVELOPE_KEY: "intentrax_verification";
export declare const VERIFICATION_MARK_ENVELOPE_SCHEMA_VERSION: "intentrax.public_sdk.verification_mark_envelope/1.0";
export declare const VERIFICATION_MARK_VERIFIED_STATE: "verified";
export declare const VERIFICATION_MARK_NOT_AVAILABLE: "Not Available";
export declare const VERIFICATION_MARK_STATE_SEVERITY: Readonly<Record<VerificationMarkDisplayState, VerificationMarkSeverity>>;

export declare function isVerificationMarkDisplayState(value: unknown): value is VerificationMarkDisplayState;
export declare function verificationMarkSeverity(displayState: unknown): VerificationMarkSeverity | null;
export declare function normalizeVerificationMarkSignature(value: unknown): string | null;
export declare function validateVerificationMarkEnvelope(envelope: unknown): string[];
export declare function normalizeVerificationMarkEnvelope(envelope: unknown): NormalizedVerificationMarkEnvelope | null;
export declare function extractVerificationMarkEnvelope(response: unknown): VerificationMarkEnvelope | null;
export declare function readVerificationVerdict(response: unknown): VerificationVerdict;

// Rendered-output binding — producer side of `intentrax-content/1.0`.
export declare const CANONICAL_OUTPUT_NORMALIZATION: "intentrax-content/1.0";
export declare const CANONICAL_OUTPUT_HASH_ALGORITHM: "SHA-256";
export declare const VERIFICATION_POINTER_META_NAME: "intentrax-verification";
export declare const VERIFICATION_OUTPUT_REGION_ATTRIBUTE: "data-intentrax-output";
export interface OutputBinding {
  readonly content_hash: string;
  readonly hash_algorithm: "SHA-256";
  readonly normalization: "intentrax-content/1.0";
}
export declare function normalizeCanonicalOutput(content: string | readonly string[]): string;
export declare function canonicalOutputHash(content: string | readonly string[]): string;
export declare function buildOutputBinding(content: string | readonly string[]): OutputBinding;
export declare function verificationPointerMetaTag(pointer: { readonly proof_id: string; readonly verify_url: string }): string | null;

// Evidence-quality model: per-dimension assessments, assurance profiles and a
// verdict derived by a fixed rule (same model as the Go offline verifier).
export type AssuranceDimension =
  | "RECORD_INTEGRITY"
  | "SIGNER_AUTHENTICITY"
  | "AUTHORIZATION"
  | "EXECUTION_REPORTED"
  | "EXECUTION_ATTESTED"
  | "EFFECT_OBSERVED"
  | "EFFECT_CONFIRMED"
  | "CAUSAL_CHAIN";
export type AssessmentResult =
  | "VERIFIED"
  | "REPORTED"
  | "ATTESTED"
  | "OBSERVED"
  | "CONFIRMED"
  | "CONTRADICTED"
  | "PENDING"
  | "INSUFFICIENT_EVIDENCE"
  | "NOT_ASSESSED"
  | "NOT_APPLICABLE"
  | "FAILED";
export type AssessmentProvenance =
  | "SELF_REPORTED"
  | "INTENTRAX_DECISION"
  | "ENFORCEMENT_ATTESTED"
  | "AUTHORITATIVE_SOURCE"
  | "THIRD_PARTY_ATTESTED"
  | "VERIFIER_COMPUTED";
export type AssuranceProfile =
  | "LEGACY_DECISION_RECORD"
  | "DECISION_RECORD"
  | "AUTHORIZED_AND_ATTESTED"
  | "EFFECT_CONFIRMED"
  | "CAUSAL_CHAIN";
export type AssuranceVerdict =
  | "VERIFICATION_FAILED"
  | "INTEGRITY_ONLY"
  | "CONFLICTING_EVIDENCE"
  | "PENDING_FINALITY"
  | "INSUFFICIENT_EVIDENCE"
  | "VERIFIED_FOR_SCOPE";
export type AssuranceLimitationCode =
  | "EXECUTION_NOT_ATTESTED"
  | "EFFECT_NOT_VERIFIED"
  | "POLICY_BINDING_SYNTHETIC"
  | "COMPLETENESS_NOT_ESTABLISHED"
  | "SIGNER_AUTHENTICITY_REQUIRES_PINNED_ANCHORS";
export interface DimensionAssessment {
  readonly dimension: AssuranceDimension;
  readonly result: AssessmentResult;
  readonly provenance: AssessmentProvenance | null;
  readonly reasons: readonly string[];
  readonly limitations: readonly AssuranceLimitationCode[];
}
export interface VerificationAssessment {
  readonly schema_version: "intentrax.verification.assessment/0.1";
  readonly assurance_profile: AssuranceProfile;
  readonly required_dimensions: readonly AssuranceDimension[];
  readonly verdict: AssuranceVerdict;
  readonly assessments: readonly DimensionAssessment[];
  readonly limitations: readonly { readonly code: AssuranceLimitationCode; readonly text: string }[];
}
export declare const VERIFICATION_ASSESSMENT_SCHEMA_VERSION: "intentrax.verification.assessment/0.1";
export declare const ASSURANCE_DIMENSIONS: readonly AssuranceDimension[];
export declare const ASSESSMENT_RESULTS: readonly AssessmentResult[];
export declare const ASSESSMENT_PROVENANCE: Readonly<Record<AssessmentProvenance, AssessmentProvenance>>;
export declare const ASSURANCE_PROFILES: Readonly<Record<AssuranceProfile, readonly AssuranceDimension[]>>;
export declare const ASSURANCE_VERDICTS: Readonly<Record<AssuranceVerdict, AssuranceVerdict>>;
export declare const ASSURANCE_VERDICT_PRECEDENCE: Readonly<Record<AssuranceVerdict, number>>;
export declare const ASSURANCE_LIMITATION_TEXT: Readonly<Record<AssuranceLimitationCode, string>>;
export declare const LEGACY_DECISION_RECORD_LIMITATIONS: readonly AssuranceLimitationCode[];
export declare function deriveAssuranceVerdict(assessments: Readonly<Partial<Record<AssuranceDimension, AssessmentResult>>>, profile: AssuranceProfile): AssuranceVerdict;
export declare function signerAuthenticityAssessment(signerTrust: string, keySetSupplied: boolean): { result: AssessmentResult; reasons: string[] };
export declare function buildLegacyVerificationAssessment(input: { readonly signerTrust: string; readonly keySetSupplied: boolean }): VerificationAssessment;
