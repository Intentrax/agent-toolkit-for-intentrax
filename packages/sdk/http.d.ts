import type {
  AgentGatewayAdmissionRequest,
  IntentExecuteRequest,
  ProofExportFormat,
  ProofExportRequest,
  ProofInclusionRequest,
  ProofReadRequest,
  ProofReplayRequest,
  ReceiptVerificationRequest,
  SDKError,
  VerifierHandoffRequest,
  VerifyProofRequest,
} from "./index.js";

export type VerificationHttpRequest = {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
  envelope: {
    schema_version: "intentrax.public_sdk.verify/1.0";
    request_hash: string;
    idempotency_key: string;
    request: VerifyProofRequest;
  };
};

export type AgentGatewayAdmissionHttpRequest = {
  method: "POST";
  url: string;
  headers: Record<string, string>;
  body: string;
  envelope: {
    schema_version: "intentrax.public_sdk.agent_gateway_admission/1.0";
    request_hash: string;
    idempotency_key_hash: string;
    endpoint: "/v1/agent/admissions";
    request: AgentGatewayAdmissionRequest;
  };
};

export type IntentExecuteHttpRequest = {
  method: "POST";
  url: string;
  headers: Record<string, string>;
  body: string;
  envelope: {
    schema_version: "intentrax.public_sdk.intent_execute/1.0";
    endpoint: "/v1/intents/execute";
    request: IntentExecuteRequest;
  };
};

export type ReceiptVerificationHttpRequest = {
  method: "POST";
  url: string;
  headers: Record<string, string>;
  body: string;
  envelope: {
    schema_version: "intentrax.public_sdk.receipt_verification/1.0";
    endpoint: "/v1/proofs/verify";
    request_hash: string;
    idempotency_key: string;
    request: ReceiptVerificationRequest;
  };
};

export type ProofExportHttpRequest = {
  method: "GET";
  url: string;
  headers: Record<string, string>;
  body: "";
  envelope: {
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
};

export type ProofReadHttpRequest = {
  method: "GET";
  url: string;
  headers: Record<string, string>;
  body: "";
  envelope: {
    schema_version: "intentrax.public_sdk.proof_read/1.0";
    endpoint: string;
    request: {
      proof_id: string;
    };
  };
};

export type ProofReplayHttpRequest = {
  method: "POST";
  url: string;
  headers: Record<string, string>;
  body: string;
  envelope: {
    schema_version: "intentrax.public_sdk.proof_replay/1.0";
    endpoint: "/v1/proofs/replay";
    request: ProofReplayRequest;
  };
};

export type ProofInclusionHttpRequest = {
  method: "GET";
  url: string;
  headers: Record<string, string>;
  body: "";
  envelope: {
    schema_version: "intentrax.public_sdk.proof_inclusion/1.0";
    endpoint: string;
    request: {
      proof_id: string;
    };
  };
};

export type VerifierHandoffHttpRequest = {
  method: "GET";
  url: string;
  headers: Record<string, string>;
  body: "";
  envelope: {
    schema_version: "intentrax.public_sdk.verifier_handoff/1.0";
    endpoint: string;
    request: {
      receipt_id: string;
    };
  };
};

export type VerificationHttpResult = {
  status: "PASS";
  output: {
    request: VerificationHttpRequest;
    response: unknown;
  };
} | {
  status: "FAIL";
  error: SDKError;
};

export type AgentGatewayAdmissionHttpResult = {
  status: "PASS";
  output: {
    request: AgentGatewayAdmissionHttpRequest;
    response: unknown;
  };
} | {
  status: "FAIL";
  error: SDKError;
};

export type IntentExecuteHttpResult = {
  status: "PASS";
  output: {
    request: IntentExecuteHttpRequest;
    response: unknown;
  };
} | {
  status: "FAIL";
  error: SDKError;
};

export type ReceiptVerificationHttpResult = {
  status: "PASS";
  output: {
    request: ReceiptVerificationHttpRequest;
    response: unknown;
  };
} | {
  status: "FAIL";
  error: SDKError;
};

export type ProofExportHttpResult = {
  status: "PASS";
  output: {
    request: ProofExportHttpRequest;
    response: unknown;
  };
} | {
  status: "FAIL";
  error: SDKError;
};

export type ProofReadHttpResult = {
  status: "PASS";
  output: {
    request: ProofReadHttpRequest;
    response: unknown;
  };
} | {
  status: "FAIL";
  error: SDKError;
};

export type ProofReplayHttpResult = {
  status: "PASS";
  output: {
    request: ProofReplayHttpRequest;
    response: unknown;
  };
} | {
  status: "FAIL";
  error: SDKError;
};

export type ProofInclusionHttpResult = {
  status: "PASS";
  output: {
    request: ProofInclusionHttpRequest;
    response: unknown;
  };
} | {
  status: "FAIL";
  error: SDKError;
};

export type VerifierHandoffHttpResult = {
  status: "PASS";
  output: {
    request: VerifierHandoffHttpRequest;
    response: unknown;
  };
} | {
  status: "FAIL";
  error: SDKError;
};

export declare function buildVerificationHttpRequest(
  request: VerifyProofRequest,
  options: { base_url: string; api_key: string }
): {
  status: "PASS";
  output: VerificationHttpRequest;
} | {
  status: "FAIL";
  error: SDKError;
};

export declare function verifyProofHttp(
  request: VerifyProofRequest,
  transport: (request: VerificationHttpRequest) => Promise<unknown> | unknown,
  options: { base_url: string; api_key: string }
): Promise<VerificationHttpResult>;

export declare function buildReceiptVerificationHttpRequest(
  request: ReceiptVerificationRequest,
  options: { base_url: string; api_key: string }
): {
  status: "PASS";
  output: ReceiptVerificationHttpRequest;
} | {
  status: "FAIL";
  error: SDKError;
};

export declare function verifyReceiptHttp(
  request: ReceiptVerificationRequest,
  transport: (request: ReceiptVerificationHttpRequest) => Promise<unknown> | unknown,
  options: { base_url: string; api_key: string }
): Promise<ReceiptVerificationHttpResult>;

export declare function buildProofExportHttpRequest(
  request: ProofExportRequest,
  options: { base_url: string; api_key: string }
): {
  status: "PASS";
  output: ProofExportHttpRequest;
} | {
  status: "FAIL";
  error: SDKError;
};

export declare function exportProofHttp(
  request: ProofExportRequest,
  transport: (request: ProofExportHttpRequest) => Promise<unknown> | unknown,
  options: { base_url: string; api_key: string }
): Promise<ProofExportHttpResult>;

export declare function buildProofReadHttpRequest(
  request: ProofReadRequest,
  options: { base_url: string; api_key: string }
): {
  status: "PASS";
  output: ProofReadHttpRequest;
} | {
  status: "FAIL";
  error: SDKError;
};

export declare function readProofHttp(
  request: ProofReadRequest,
  transport: (request: ProofReadHttpRequest) => Promise<unknown> | unknown,
  options: { base_url: string; api_key: string }
): Promise<ProofReadHttpResult>;

export declare function buildProofReplayHttpRequest(
  request: ProofReplayRequest,
  options: { base_url: string; api_key: string }
): {
  status: "PASS";
  output: ProofReplayHttpRequest;
} | {
  status: "FAIL";
  error: SDKError;
};

export declare function replayProofHttp(
  request: ProofReplayRequest,
  transport: (request: ProofReplayHttpRequest) => Promise<unknown> | unknown,
  options: { base_url: string; api_key: string }
): Promise<ProofReplayHttpResult>;

export declare function buildProofInclusionHttpRequest(
  request: ProofInclusionRequest,
  options: { base_url: string; api_key: string }
): {
  status: "PASS";
  output: ProofInclusionHttpRequest;
} | {
  status: "FAIL";
  error: SDKError;
};

export declare function getProofInclusionHttp(
  request: ProofInclusionRequest,
  transport: (request: ProofInclusionHttpRequest) => Promise<unknown> | unknown,
  options: { base_url: string; api_key: string }
): Promise<ProofInclusionHttpResult>;

export declare function buildVerifierHandoffHttpRequest(
  request: VerifierHandoffRequest,
  options: { base_url: string; api_key: string }
): {
  status: "PASS";
  output: VerifierHandoffHttpRequest;
} | {
  status: "FAIL";
  error: SDKError;
};

export declare function getVerifierHandoffHttp(
  request: VerifierHandoffRequest,
  transport: (request: VerifierHandoffHttpRequest) => Promise<unknown> | unknown,
  options: { base_url: string; api_key: string }
): Promise<VerifierHandoffHttpResult>;

export declare function buildAgentGatewayAdmissionHttpRequest(
  request: AgentGatewayAdmissionRequest,
  options: { base_url: string; api_key: string }
): {
  status: "PASS";
  output: AgentGatewayAdmissionHttpRequest;
} | {
  status: "FAIL";
  error: SDKError;
};

export declare function admitAgentGatewayHttp(
  request: AgentGatewayAdmissionRequest,
  transport: (request: AgentGatewayAdmissionHttpRequest) => Promise<unknown> | unknown,
  options: { base_url: string; api_key: string }
): Promise<AgentGatewayAdmissionHttpResult>;

export declare function buildIntentExecuteHttpRequest(
  request: IntentExecuteRequest,
  options: { base_url: string; api_key: string }
): {
  status: "PASS";
  output: IntentExecuteHttpRequest;
} | {
  status: "FAIL";
  error: SDKError;
};

export declare function executeIntentHttp(
  request: IntentExecuteRequest,
  transport: (request: IntentExecuteHttpRequest) => Promise<unknown> | unknown,
  options: { base_url: string; api_key: string }
): Promise<IntentExecuteHttpResult>;

export declare function verifyUrlForProof(base: string, proof_id: string): string;
