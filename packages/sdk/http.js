import {
  AGENT_ADMISSION_ENDPOINT,
  API_VERSION,
  INTENT_EXECUTE_ENDPOINT,
  PROOF_EXPORT_ENDPOINT_PREFIX,
  SDK_INPUT_ERROR_CODE,
  SDK_VERSION,
  buildAgentGatewayAdmissionEnvelope,
  buildIntentExecuteEnvelope,
  buildProofExportEnvelope,
  buildProofInclusionEnvelope,
  buildProofReadEnvelope,
  buildProofReplayEnvelope,
  buildReceiptVerificationEnvelope,
  buildVerifierHandoffEnvelope,
  buildVerificationEnvelope,
  canonicalJson,
} from "./index.js";

export function buildVerificationHttpRequest(request, options) {
  const invalidOptions = [];
  if (!options || typeof options.base_url !== "string" || options.base_url.length === 0) {
    invalidOptions.push("base_url");
  }
  if (!options || typeof options.api_key !== "string" || options.api_key.length === 0) {
    invalidOptions.push("api_key");
  }
  if (invalidOptions.length > 0) {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "Verification HTTP options are missing or malformed.",
        invalid_fields: invalidOptions.sort(),
        retriable: false,
      },
    };
  }
  const envelope = buildVerificationEnvelope(request);
  if (envelope.status !== "PASS") {
    return envelope;
  }
  const baseUrl = options.base_url.replace(/\/+$/, "");
  const path = request.request_path.startsWith("/") ? request.request_path : "/" + request.request_path;
  return {
    status: "PASS",
    output: {
      method: request.request_method,
      url: baseUrl + path,
      headers: {
        "content-type": "application/json",
        "X-Intentrax-Api-Key": options.api_key,
        "X-Intentrax-Idempotency-Key": envelope.output.idempotency_key,
        "intentrax-api-version": API_VERSION,
        "intentrax-request-hash": envelope.output.request_hash,
        "intentrax-sdk-version": SDK_VERSION,
      },
      body: canonicalJson(request),
      envelope: envelope.output,
    },
  };
}

export async function verifyProofHttp(request, transport, options) {
  if (typeof transport !== "function") {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "HTTP transport function is required.",
        invalid_fields: ["transport"],
        retriable: false,
      },
    };
  }
  const httpRequest = buildVerificationHttpRequest(request, options);
  if (httpRequest.status !== "PASS") {
    return httpRequest;
  }
  const response = await transport(httpRequest.output);
  return {
    status: "PASS",
    output: {
      request: httpRequest.output,
      response,
    },
  };
}

export function buildReceiptVerificationHttpRequest(request, options) {
  const invalidOptions = [];
  if (!options || typeof options.base_url !== "string" || options.base_url.length === 0) {
    invalidOptions.push("base_url");
  }
  if (!options || typeof options.api_key !== "string" || options.api_key.length === 0) {
    invalidOptions.push("api_key");
  }
  if (invalidOptions.length > 0) {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "Receipt verification HTTP options are missing or malformed.",
        invalid_fields: invalidOptions.sort(),
        retriable: false,
      },
    };
  }
  const envelope = buildReceiptVerificationEnvelope(request);
  if (envelope.status !== "PASS") {
    return envelope;
  }
  const baseUrl = options.base_url.replace(/\/+$/, "");
  return {
    status: "PASS",
    output: {
      method: "POST",
      url: baseUrl + envelope.output.endpoint,
      headers: {
        "content-type": "application/json",
        "X-Intentrax-Api-Key": options.api_key,
        "X-Intentrax-Idempotency-Key": envelope.output.idempotency_key,
        "intentrax-api-version": API_VERSION,
        "intentrax-request-hash": envelope.output.request_hash,
        "intentrax-sdk-version": SDK_VERSION,
      },
      body: canonicalJson(request),
      envelope: envelope.output,
    },
  };
}

export async function verifyReceiptHttp(request, transport, options) {
  if (typeof transport !== "function") {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "HTTP transport function is required.",
        invalid_fields: ["transport"],
        retriable: false,
      },
    };
  }
  const httpRequest = buildReceiptVerificationHttpRequest(request, options);
  if (httpRequest.status !== "PASS") {
    return httpRequest;
  }
  const response = await transport(httpRequest.output);
  return {
    status: "PASS",
    output: {
      request: httpRequest.output,
      response,
    },
  };
}

export function buildProofExportHttpRequest(request, options) {
  const invalidOptions = [];
  if (!options || typeof options.base_url !== "string" || options.base_url.length === 0) {
    invalidOptions.push("base_url");
  }
  if (!options || typeof options.api_key !== "string" || options.api_key.length === 0) {
    invalidOptions.push("api_key");
  }
  if (invalidOptions.length > 0) {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "Proof export HTTP options are missing or malformed.",
        invalid_fields: invalidOptions.sort(),
        retriable: false,
      },
    };
  }
  const envelope = buildProofExportEnvelope(request);
  if (envelope.status !== "PASS") {
    return envelope;
  }
  const baseUrl = options.base_url.replace(/\/+$/, "");
  const accept = envelope.output.format === "pdf" ? "application/pdf" : "application/json";
  return {
    status: "PASS",
    output: {
      method: "GET",
      url: `${baseUrl}${envelope.output.endpoint}?format=${encodeURIComponent(envelope.output.format)}`,
      headers: {
        accept,
        "X-Intentrax-Api-Key": options.api_key,
        "intentrax-api-version": API_VERSION,
        "intentrax-sdk-version": SDK_VERSION,
      },
      body: "",
      envelope: envelope.output,
    },
  };
}

export async function exportProofHttp(request, transport, options) {
  if (typeof transport !== "function") {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "HTTP transport function is required.",
        invalid_fields: ["transport"],
        retriable: false,
      },
    };
  }
  const httpRequest = buildProofExportHttpRequest(request, options);
  if (httpRequest.status !== "PASS") {
    return httpRequest;
  }
  const response = await transport(httpRequest.output);
  return {
    status: "PASS",
    output: {
      request: httpRequest.output,
      response,
    },
  };
}

export function buildProofReadHttpRequest(request, options) {
  const invalidOptions = [];
  if (!options || typeof options.base_url !== "string" || options.base_url.length === 0) {
    invalidOptions.push("base_url");
  }
  if (!options || typeof options.api_key !== "string" || options.api_key.length === 0) {
    invalidOptions.push("api_key");
  }
  if (invalidOptions.length > 0) {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "Proof read HTTP options are missing or malformed.",
        invalid_fields: invalidOptions.sort(),
        retriable: false,
      },
    };
  }
  const envelope = buildProofReadEnvelope(request);
  if (envelope.status !== "PASS") {
    return envelope;
  }
  const baseUrl = options.base_url.replace(/\/+$/, "");
  return {
    status: "PASS",
    output: {
      method: "GET",
      url: baseUrl + envelope.output.endpoint,
      headers: {
        accept: "application/json",
        "X-Intentrax-Api-Key": options.api_key,
        "intentrax-api-version": API_VERSION,
        "intentrax-sdk-version": SDK_VERSION,
      },
      body: "",
      envelope: envelope.output,
    },
  };
}

export async function readProofHttp(request, transport, options) {
  if (typeof transport !== "function") {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "HTTP transport function is required.",
        invalid_fields: ["transport"],
        retriable: false,
      },
    };
  }
  const httpRequest = buildProofReadHttpRequest(request, options);
  if (httpRequest.status !== "PASS") {
    return httpRequest;
  }
  const response = await transport(httpRequest.output);
  return {
    status: "PASS",
    output: {
      request: httpRequest.output,
      response,
    },
  };
}

export function buildProofReplayHttpRequest(request, options) {
  const invalidOptions = [];
  if (!options || typeof options.base_url !== "string" || options.base_url.length === 0) {
    invalidOptions.push("base_url");
  }
  if (!options || typeof options.api_key !== "string" || options.api_key.length === 0) {
    invalidOptions.push("api_key");
  }
  if (invalidOptions.length > 0) {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "Proof replay HTTP options are missing or malformed.",
        invalid_fields: invalidOptions.sort(),
        retriable: false,
      },
    };
  }
  const envelope = buildProofReplayEnvelope(request);
  if (envelope.status !== "PASS") {
    return envelope;
  }
  const baseUrl = options.base_url.replace(/\/+$/, "");
  return {
    status: "PASS",
    output: {
      method: "POST",
      url: baseUrl + envelope.output.endpoint,
      headers: {
        "content-type": "application/json",
        "X-Intentrax-Api-Key": options.api_key,
        "intentrax-api-version": API_VERSION,
        "intentrax-sdk-version": SDK_VERSION,
      },
      body: canonicalJson(request),
      envelope: envelope.output,
    },
  };
}

export async function replayProofHttp(request, transport, options) {
  if (typeof transport !== "function") {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "HTTP transport function is required.",
        invalid_fields: ["transport"],
        retriable: false,
      },
    };
  }
  const httpRequest = buildProofReplayHttpRequest(request, options);
  if (httpRequest.status !== "PASS") {
    return httpRequest;
  }
  const response = await transport(httpRequest.output);
  return {
    status: "PASS",
    output: {
      request: httpRequest.output,
      response,
    },
  };
}

export function buildProofInclusionHttpRequest(request, options) {
  const invalidOptions = [];
  if (!options || typeof options.base_url !== "string" || options.base_url.length === 0) {
    invalidOptions.push("base_url");
  }
  if (!options || typeof options.api_key !== "string" || options.api_key.length === 0) {
    invalidOptions.push("api_key");
  }
  if (invalidOptions.length > 0) {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "Proof inclusion HTTP options are missing or malformed.",
        invalid_fields: invalidOptions.sort(),
        retriable: false,
      },
    };
  }
  const envelope = buildProofInclusionEnvelope(request);
  if (envelope.status !== "PASS") {
    return envelope;
  }
  const baseUrl = options.base_url.replace(/\/+$/, "");
  return {
    status: "PASS",
    output: {
      method: "GET",
      url: baseUrl + envelope.output.endpoint,
      headers: {
        accept: "application/json",
        "X-Intentrax-Api-Key": options.api_key,
        "intentrax-api-version": API_VERSION,
        "intentrax-sdk-version": SDK_VERSION,
      },
      body: "",
      envelope: envelope.output,
    },
  };
}

export async function getProofInclusionHttp(request, transport, options) {
  if (typeof transport !== "function") {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "HTTP transport function is required.",
        invalid_fields: ["transport"],
        retriable: false,
      },
    };
  }
  const httpRequest = buildProofInclusionHttpRequest(request, options);
  if (httpRequest.status !== "PASS") {
    return httpRequest;
  }
  const response = await transport(httpRequest.output);
  return {
    status: "PASS",
    output: {
      request: httpRequest.output,
      response,
    },
  };
}

export function buildVerifierHandoffHttpRequest(request, options) {
  const invalidOptions = [];
  if (!options || typeof options.base_url !== "string" || options.base_url.length === 0) {
    invalidOptions.push("base_url");
  }
  if (!options || typeof options.api_key !== "string" || options.api_key.length === 0) {
    invalidOptions.push("api_key");
  }
  if (invalidOptions.length > 0) {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "Verifier handoff HTTP options are missing or malformed.",
        invalid_fields: invalidOptions.sort(),
        retriable: false,
      },
    };
  }
  const envelope = buildVerifierHandoffEnvelope(request);
  if (envelope.status !== "PASS") {
    return envelope;
  }
  const baseUrl = options.base_url.replace(/\/+$/, "");
  return {
    status: "PASS",
    output: {
      method: "GET",
      url: baseUrl + envelope.output.endpoint,
      headers: {
        accept: "application/json",
        "X-Intentrax-Api-Key": options.api_key,
        "intentrax-api-version": API_VERSION,
        "intentrax-sdk-version": SDK_VERSION,
      },
      body: "",
      envelope: envelope.output,
    },
  };
}

export async function getVerifierHandoffHttp(request, transport, options) {
  if (typeof transport !== "function") {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "HTTP transport function is required.",
        invalid_fields: ["transport"],
        retriable: false,
      },
    };
  }
  const httpRequest = buildVerifierHandoffHttpRequest(request, options);
  if (httpRequest.status !== "PASS") {
    return httpRequest;
  }
  const response = await transport(httpRequest.output);
  return {
    status: "PASS",
    output: {
      request: httpRequest.output,
      response,
    },
  };
}

export function buildAgentGatewayAdmissionHttpRequest(request, options) {
  const invalidOptions = [];
  if (!options || typeof options.base_url !== "string" || options.base_url.length === 0) {
    invalidOptions.push("base_url");
  }
  if (!options || typeof options.api_key !== "string" || options.api_key.length === 0) {
    invalidOptions.push("api_key");
  }
  if (invalidOptions.length > 0) {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "Agent Gateway HTTP options are missing or malformed.",
        invalid_fields: invalidOptions.sort(),
        retriable: false,
      },
    };
  }
  const envelope = buildAgentGatewayAdmissionEnvelope(request);
  if (envelope.status !== "PASS") {
    return envelope;
  }
  const baseUrl = options.base_url.replace(/\/+$/, "");
  return {
    status: "PASS",
    output: {
      method: "POST",
      url: baseUrl + AGENT_ADMISSION_ENDPOINT,
      headers: {
        "content-type": "application/json",
        "X-Intentrax-Tenant-ID": request.tenant_id,
        "X-Intentrax-Api-Key": options.api_key,
        "X-Intentrax-Idempotency-Key": request.idempotency_key_hash,
        "intentrax-api-version": API_VERSION,
        "intentrax-sdk-version": SDK_VERSION,
      },
      body: canonicalJson(request),
      envelope: envelope.output,
    },
  };
}

export async function admitAgentGatewayHttp(request, transport, options) {
  if (typeof transport !== "function") {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "HTTP transport function is required.",
        invalid_fields: ["transport"],
        retriable: false,
      },
    };
  }
  const httpRequest = buildAgentGatewayAdmissionHttpRequest(request, options);
  if (httpRequest.status !== "PASS") {
    return httpRequest;
  }
  const response = await transport(httpRequest.output);
  return {
    status: "PASS",
    output: {
      request: httpRequest.output,
      response,
    },
  };
}

// buildIntentExecuteHttpRequest builds the POST for the fail-closed live
// execution lane. It is a thin envelope + transport builder: the body is the
// caller-supplied request canonicalized, and there is NO idempotency header
// (the engine derives RequestHash from the body; the caller's idempotency_key
// is an opaque body field). The lane returns HTTP 423 until the engine's
// LiveExecutionEnabled flag is set and HTTP 403 until the tenant is allowlisted;
// this builder does not assert that the lane is live.
export function buildIntentExecuteHttpRequest(request, options) {
  const invalidOptions = [];
  if (!options || typeof options.base_url !== "string" || options.base_url.length === 0) {
    invalidOptions.push("base_url");
  }
  if (!options || typeof options.api_key !== "string" || options.api_key.length === 0) {
    invalidOptions.push("api_key");
  }
  if (invalidOptions.length > 0) {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "Intent execute HTTP options are missing or malformed.",
        invalid_fields: invalidOptions.sort(),
        retriable: false,
      },
    };
  }
  const envelope = buildIntentExecuteEnvelope(request);
  if (envelope.status !== "PASS") {
    return envelope;
  }
  const baseUrl = options.base_url.replace(/\/+$/, "");
  return {
    status: "PASS",
    output: {
      method: "POST",
      url: baseUrl + INTENT_EXECUTE_ENDPOINT,
      headers: {
        "content-type": "application/json",
        "X-Intentrax-Tenant-ID": request.tenant_id,
        "X-Intentrax-Api-Key": options.api_key,
        "intentrax-api-version": API_VERSION,
        "intentrax-sdk-version": SDK_VERSION,
      },
      body: canonicalJson(request),
      envelope: envelope.output,
    },
  };
}

// executeIntentHttp builds the request and awaits the caller-supplied
// transport. The engine response is returned VERBATIM under output.response:
// receipt_id, request_hash, registry_proof_id, response_hash, status, and
// vee_recorded are the engine's to produce and are never synthesized here.
export async function executeIntentHttp(request, transport, options) {
  if (typeof transport !== "function") {
    return {
      status: "FAIL",
      error: {
        error_code: SDK_INPUT_ERROR_CODE,
        error_type: "public_sdk_input_error",
        message: "HTTP transport function is required.",
        invalid_fields: ["transport"],
        retriable: false,
      },
    };
  }
  const httpRequest = buildIntentExecuteHttpRequest(request, options);
  if (httpRequest.status !== "PASS") {
    return httpRequest;
  }
  const response = await transport(httpRequest.output);
  return {
    status: "PASS",
    output: {
      request: httpRequest.output,
      response,
    },
  };
}

// verifyUrlForProof is a pure string concatenation helper: given a base URL and
// a proof_id returned by the engine, it composes the read-only proof read URL.
// It computes no truth and performs no I/O.
export function verifyUrlForProof(base, proof_id) {
  const baseUrl = String(base).replace(/\/+$/, "");
  return `${baseUrl}${PROOF_EXPORT_ENDPOINT_PREFIX}/${proof_id}`;
}
