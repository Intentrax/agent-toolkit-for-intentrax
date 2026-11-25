#!/usr/bin/env node
import { createHash, createPublicKey, verify as verifySignatureBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { buildAgentGatewayAdmissionEnvelope, buildLegacyVerificationAssessment, compilePolicyDocument, deriveAssuranceVerdict, evaluateCompiledPolicy, policyReevaluationMismatches } from "../index.js";

const VERSION = "1.11.0";
const ADMISSION_SCHEMA_VERSION = "intentrax.runtime.agent_admission_request/1.0";
const INIT_SCHEMA_VERSION = "intentrax.onboarding.agent_adapter_init/1.0";
const ACTION_RECEIPT_SCHEMA_VERSION = "intentrax.onboarding.agent_adapter_action_receipt/1.0";
const HOST_WIRING_GUIDE_SCHEMA_VERSION = "intentrax.onboarding.agent_adapter_host_wiring_guide/1.0";
const LOCAL_INIT_CHECK_SCHEMA_VERSION = "intentrax.sdk.agent_adapter_init_offline_check/1.0";
const LOCAL_INIT_CHECK_VERIFIER_VERSION = "intentrax-typescript-cli-init-offline-checker/1.0";
const LOCAL_PROOF_VERIFICATION_SCHEMA_VERSION = "intentrax.sdk.local_proof_verification_report/2.0";
const LOCAL_PROOF_VERIFIER_VERSION = "intentrax-typescript-cli-local-proof-verifier/2.0";
// Signature verification (1.1.0). These mirror the engine exactly:
//   aep_hash     = SHA-256(AEP_HASH_DOMAIN + canonical_aep_json)              (C4.3)
//   payload_hash = SHA-256(SIGNATURE_PAYLOAD_HASH_DOMAIN + canonical_payload_json) (C5.2)
//   each key reference carries an ed25519 signature over canonical_payload_json (C5.4)
const AEP_HASH_DOMAIN = "INTENTRAX_PROOF_CANONICAL_AEP_V1";
const SIGNATURE_PAYLOAD_HASH_DOMAIN = "INTENTRAX_TRUST_SIGNATURE_PAYLOAD_V1";
const SIGNATURE_PAYLOAD_VERSION = "intentrax.trust.signature_payload/1.0";
const SIGNATURE_PAYLOAD_FIELDS = Object.freeze(["payload_version", "canonical_aep_json", "aep_hash"]);
// 1.1 adds a required min_trusted_signers: how many distinct trust-bearing keys
// (by key_id) must have signed a proof for it to PASS. 1.0 is still accepted,
// but only for sets with no trust-bearing keys (sandbox sets).
const PUBLISHED_KEY_SET_SCHEMA_VERSION = "intentrax.trust.published_key_set/1.1";
const PUBLISHED_KEY_SET_SCHEMA_VERSION_V1 = "intentrax.trust.published_key_set/1.0";
const BUILT_IN_KEY_SET_URLS = Object.freeze([
  // Published production signer keys (trust-bearing), exported from the production
  // keyring with engine/cmd/sovereign-public-key-set.
  new URL("../trust/production-key-set.json", import.meta.url),
  // Published sandbox keys (not trust-bearing).
  new URL("../trust/sandbox-key-set.json", import.meta.url),
]);
// The published policy registry bundled with the SDK: byte-identical copies of
// engine/internal/policyengine/published/policies/<source_policy_hash>.json,
// the documents GET /v1/policies/{source_policy_hash} serves. Used to re-run a
// sealed policy evaluation offline.
const BUILT_IN_POLICY_REGISTRY_URL = new URL("../trust/policies/", import.meta.url);
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const SIGNER_TRUST_EXIT_CODE = 3;
// verify-proof --answer-file: the answer is not the answer the proof binds.
const ANSWER_MISMATCH_EXIT_CODE = 1;
const LOCAL_PDF_RECEIPT_VERIFICATION_SCHEMA_VERSION = "intentrax.sdk.local_pdf_receipt_verification_report/1.0";
const LOCAL_PDF_RECEIPT_VERIFIER_VERSION = "intentrax-typescript-cli-local-pdf-receipt-verifier/1.0";
const ENDPOINT = "/v1/agent/admissions";
const DOMAIN = "INTENTRAX_AGENT_ADAPTER_INIT_V1";
const ACTION_RECEIPT_DOMAIN = "INTENTRAX_AGENT_ADAPTER_ACTION_RECEIPT_V1";
const HOST_WIRING_GUIDE_DOMAIN = "INTENTRAX_AGENT_ADAPTER_HOST_WIRING_GUIDE_V1";
const LOCAL_INIT_CHECK_DOMAIN = "INTENTRAX_AGENT_ADAPTER_INIT_OFFLINE_CHECK_V1";
const LOCAL_PROOF_VERIFY_DOMAIN = "INTENTRAX_LOCAL_PROOF_VERIFY_V1";
const LOCAL_PDF_RECEIPT_VERIFY_DOMAIN = "INTENTRAX_LOCAL_PDF_RECEIPT_VERIFY_V1";
const TENANT_HEADER = "X-Intentrax-Tenant-ID";
const API_KEY_HEADER = "X-Intentrax-Api-Key";
const IDEMPOTENCY_HEADER = "X-Intentrax-Idempotency-Key";
const MVP_ADAPTERS = Object.freeze(["claude-code", "cursor", "mcp", "langchain", "langgraph", "vercel-ai-sdk"]);
const ADAPTER_ALIASES = Object.freeze({ "generic-mcp": "mcp" });
const OAP_COMPATIBILITY_BOUNDARY = "EXCLUDED_FROM_MVP";
const OAP_EXCLUSION_MARKERS = Object.freeze(["OAP", "Open Agent Passport", "Open Agent Protocol"]);
const OAP_EXCLUSION_PATTERN = /\bOAP\b|Open Agent Passport|Open Agent Protocol/i;
const INIT_CHECK_REQUIRED_FILES = Object.freeze([
  ".intentrax/agent-adapter.json",
  ".intentrax/sample-admission-request.json",
  ".intentrax/action-receipt.json",
  ".intentrax/submit_sample.curl",
]);
const SECRET_FIXTURE_MARKERS = Object.freeze([
  "intentrax-check-init-secret-token",
  "intentrax-check-init-secret-api-key",
  "intentrax-check-init-secret-password",
  "intentrax-check-init-secret-private-key",
  "intentrax-check-init-secret-cookie",
]);
const REQUIRED_GATEWAY_REFS = [
  "sha256:46f136e995bf1921533652a0721e8ea47816d250aee0da951258bec5645754af",
  "sha256:4c6a9a6ce776170fa968682c51efafdd39301390f94176b2029e22594917ee1f",
  "sha256:8a6d71f9e60ab0ef32de1eb63d049adb3820104c30489a5c42e7acaeeb222ce1",
  "sha256:8c63d17014da7fd015b77c10fb702bcf005f0ed1dee1516991747e230c3dbfc0",
  "sha256:b4c6a6ab375273436e38f7b5fb58b1c270a453297a184c019c4cabab3007e698",
  "sha256:b9d82729f18f8720ee4d8575192966b9aec2320b25a8e79c6e2862c005053787",
];
const SAMPLE_ACTION_BY_SURFACE = {
  A2A_DELEGATION: "HAND_OFF_PROOF",
  DIRECT_TOOL_CALL: "GET_PROOF",
  MCP_TOOL_CALL: "GET_PROOF",
  SDK_AGENT_CALL: "SUBMIT_INTENT",
};

const ADAPTERS = {
  "claude-code": {
    display_name: "Claude Code Agent",
    matrix_adapter_id: "CLAUDE_CODE_AGENT",
    normalized_surface_id: "MCP_TOOL_CALL",
    normalized_adapter_id: "GENERIC_MCP_PROOF_ADAPTER",
    hook_surface: "pre_tool_use",
    hook_file_name: "claude-code-pre-tool-use.mjs",
    hook_entrypoint: "beforeClaudeCodeToolUse",
    hook_label: "Claude Code pre-tool-use hook",
    native_template_id: "claude_code_pre_tool_use_v1",
    native_event_kind: "CLAUDE_CODE_PRE_TOOL_USE",
    native_normalizer: "normalizeClaudeCodePreToolUse",
    quickstart_ref: "examples/adapters/claude-code.md",
  },
  cursor: {
    display_name: "Cursor Agent",
    matrix_adapter_id: "CURSOR_AGENT",
    normalized_surface_id: "MCP_TOOL_CALL",
    normalized_adapter_id: "GENERIC_MCP_PROOF_ADAPTER",
    hook_surface: "before_shell_execution",
    hook_file_name: "cursor-before-shell-execution.mjs",
    hook_entrypoint: "beforeCursorShellExecution",
    hook_label: "Cursor before-shell-execution hook",
    native_template_id: "cursor_before_shell_execution_v1",
    native_event_kind: "CURSOR_BEFORE_SHELL_EXECUTION",
    native_normalizer: "normalizeCursorShellExecution",
    quickstart_ref: "examples/adapters/cursor.md",
  },
  mcp: {
    display_name: "Generic MCP",
    matrix_adapter_id: "GENERIC_MCP",
    normalized_surface_id: "MCP_TOOL_CALL",
    normalized_adapter_id: "GENERIC_MCP_PROOF_ADAPTER",
    hook_surface: "mcp_tool_call",
    hook_file_name: "mcp-tool-call-admission.mjs",
    hook_entrypoint: "beforeMCPToolCall",
    hook_label: "generic MCP tool-call hook",
    native_template_id: "mcp_tool_call_v1",
    native_event_kind: "MCP_TOOL_CALL",
    native_normalizer: "normalizeMCPToolCall",
    quickstart_ref: "examples/adapters/mcp.md",
  },
  langchain: {
    display_name: "LangChain Agent",
    matrix_adapter_id: "LANGCHAIN_AGENT",
    normalized_surface_id: "SDK_AGENT_CALL",
    normalized_adapter_id: "SDK_AGENT_PROOF_ADAPTER",
    hook_surface: "callback_or_tool_wrapper",
    hook_file_name: "langchain-callback-wrapper.mjs",
    hook_entrypoint: "withIntentraxLangChainCallback",
    hook_label: "LangChain callback or tool wrapper",
    native_template_id: "langchain_callback_wrapper_v1",
    native_event_kind: "LANGCHAIN_CALLBACK_OR_TOOL",
    native_normalizer: "normalizeLangChainCallback",
    quickstart_ref: "examples/adapters/langchain.md",
  },
  langgraph: {
    display_name: "LangGraph Agent",
    matrix_adapter_id: "LANGGRAPH_AGENT",
    normalized_surface_id: "SDK_AGENT_CALL",
    normalized_adapter_id: "SDK_AGENT_PROOF_ADAPTER",
    hook_surface: "graph_node_middleware",
    hook_file_name: "langgraph-node-middleware.mjs",
    hook_entrypoint: "withIntentraxLangGraphNode",
    hook_label: "LangGraph node middleware",
    native_template_id: "langgraph_node_middleware_v1",
    native_event_kind: "LANGGRAPH_NODE_MIDDLEWARE",
    native_normalizer: "normalizeLangGraphNode",
    quickstart_ref: "examples/adapters/langgraph.md",
  },
  "vercel-ai-sdk": {
    display_name: "Vercel AI SDK Agent",
    matrix_adapter_id: "VERCEL_AI_SDK_AGENT",
    normalized_surface_id: "SDK_AGENT_CALL",
    normalized_adapter_id: "SDK_AGENT_PROOF_ADAPTER",
    hook_surface: "typescript_route_wrapper",
    hook_file_name: "vercel-ai-sdk-route-wrapper.mjs",
    hook_entrypoint: "withIntentraxVercelAIRoute",
    hook_label: "Vercel AI SDK route wrapper",
    native_template_id: "vercel_ai_sdk_route_wrapper_v1",
    native_event_kind: "VERCEL_AI_SDK_ROUTE_WRAPPER",
    native_normalizer: "normalizeVercelAIRoute",
    quickstart_ref: "examples/adapters/vercel-ai-sdk.md",
  },
  "custom-agent": {
    display_name: "Custom Agent",
    matrix_adapter_id: "CUSTOM_AGENT",
    normalized_surface_id: "DIRECT_TOOL_CALL",
    normalized_adapter_id: "DIRECT_TOOL_PROOF_ADAPTER",
    hook_surface: "direct_http_or_sdk",
    hook_file_name: "custom-agent-admission-hook.mjs",
    hook_entrypoint: "withIntentraxCustomAgentAdmission",
    hook_label: "custom agent admission hook",
    quickstart_ref: "integrations/agent-adapters/custom-agent.md",
  },
  crewai: {
    display_name: "CrewAI Agent",
    matrix_adapter_id: "CREWAI_AGENT",
    normalized_surface_id: "SDK_AGENT_CALL",
    normalized_adapter_id: "SDK_AGENT_PROOF_ADAPTER",
    hook_surface: "crew_step_wrapper",
    hook_file_name: "crewai-step-wrapper.mjs",
    hook_entrypoint: "withIntentraxCrewAIStep",
    hook_label: "CrewAI step wrapper",
    quickstart_ref: "integrations/agent-adapters/crewai-agent.md",
  },
  autogen: {
    display_name: "AutoGen Agent",
    matrix_adapter_id: "AUTOGEN_AGENT",
    normalized_surface_id: "A2A_DELEGATION",
    normalized_adapter_id: "GENERIC_A2A_PROOF_ADAPTER",
    hook_surface: "multi_agent_a2a_wrapper",
    hook_file_name: "autogen-a2a-wrapper.mjs",
    hook_entrypoint: "withIntentraxAutoGenA2AWrapper",
    hook_label: "AutoGen A2A wrapper",
    quickstart_ref: "integrations/agent-adapters/autogen-agent.md",
  },
  openclaw: {
    display_name: "OpenClaw Agent",
    matrix_adapter_id: "OPENCLAW_AGENT",
    normalized_surface_id: "SDK_AGENT_CALL",
    normalized_adapter_id: "SDK_AGENT_PROOF_ADAPTER",
    hook_surface: "generic_agent_wrapper",
    hook_file_name: "openclaw-agent-wrapper.mjs",
    hook_entrypoint: "withIntentraxOpenClawAgent",
    hook_label: "OpenClaw agent wrapper",
    quickstart_ref: "integrations/agent-adapters/openclaw-agent.md",
  },
  n8n: {
    display_name: "n8n",
    matrix_adapter_id: "N8N",
    normalized_surface_id: "DIRECT_TOOL_CALL",
    normalized_adapter_id: "DIRECT_TOOL_PROOF_ADAPTER",
    hook_surface: "http_request_node",
    hook_file_name: "n8n-http-request-node.mjs",
    hook_entrypoint: "withIntentraxN8NRequestNode",
    hook_label: "n8n HTTP request node wrapper",
    quickstart_ref: "integrations/agent-adapters/n8n.md",
  },
  deepflow: {
    display_name: "DeepFlow Agent",
    matrix_adapter_id: "DEEPFLOW_AGENT",
    normalized_surface_id: "SDK_AGENT_CALL",
    normalized_adapter_id: "SDK_AGENT_PROOF_ADAPTER",
    hook_surface: "workflow_step_wrapper",
    hook_file_name: "deepflow-step-wrapper.mjs",
    hook_entrypoint: "withIntentraxDeepFlowStep",
    hook_label: "DeepFlow workflow step wrapper",
    quickstart_ref: "integrations/agent-adapters/deepflow-agent.md",
  },
};

async function main(argv) {
  const [command, subject, ...rest] = argv;
  if (!command || command === "--help" || command === "-h") {
    printHelp();
    return 0;
  }
  if (command === "--version" || command === "-v") {
    console.log(VERSION);
    return 0;
  }
  if (command === "sandbox") {
    // Local assurance sandbox: ephemeral local keys, no network, verdict capped at
    // LOCAL_NON_TRUST_BEARING. Never production assurance. See sandbox/README.md.
    const { sandboxMain } = await import("../sandbox/cli.mjs");
    return sandboxMain([subject, ...rest].filter((value) => value !== undefined));
  }
  if (command === "mcp") {
    // MCP tool pinning: pin a server's tool definitions, check them, or proxy
    // with --on-drift block. Offline; no Intentrax account. See mcp/README.md.
    const { mcpMain } = await import("../mcp/cli.mjs");
    return mcpMain([subject, ...rest].filter((value) => value !== undefined));
  }
  if (command === "readback") {
    // Read the outcome back before reporting success (SELF_REPORTED; not an
    // Intentrax attestation). See readback/README.md.
    const { readbackMain } = await import("../readback/cli.mjs");
    return readbackMain([subject, ...rest].filter((value) => value !== undefined));
  }
  if (command === "scan") {
    // Static, report-only scan for agent actions an agent can reach (exit 0
    // none, 20 findings, 2 error). Nothing is run or sent. See scan/README.md.
    const { scanMain } = await import("../scan/cli.mjs");
    return scanMain([subject, ...rest].filter((value) => value !== undefined));
  }
  if (command === "guard") {
    // Local Claude Code gate: a PreToolUse hook that blocks or asks before
    // risky tool calls, with a local hash-chained record. No account, no
    // network; not trust-bearing. See guard/README.md.
    const { guardMain } = await import("../guard/cli.mjs");
    return guardMain([subject, ...rest].filter((value) => value !== undefined));
  }
  if (command === "policy") {
    // Open policy packs: list, show, hash, validate, init --from-scan, check.
    // Local and static; nothing is run or sent. See policy-packs/README.md.
    const { policyMain } = await import("../policy-packs/cli.mjs");
    return policyMain([subject, ...rest].filter((value) => value !== undefined));
  }
  if (command === "approve") {
    // Sign a pre-approval (intentrax.approval/0.1) with a local, human APPROVER
    // key, or generate one (keygen). Local only: nothing is sent. See approve/README.md.
    const [{ runApprove }, { ApproveError }] = await Promise.all([import("../approve/cli.mjs"), import("../approve/approve.mjs")]);
    try {
      return await runApprove([subject, ...rest].filter((value) => value !== undefined));
    } catch (error) {
      if (!(error instanceof ApproveError)) throw error;
      console.error(`intentrax approve: ${error.message}`);
      return 1;
    }
  }
  if (command === "check-init") {
    const options = parseCheckInitOptions([subject, ...rest].filter((value) => value !== undefined));
    const output = await checkInitCommand(options);
    if (options.json) {
      console.log(JSON.stringify(output, null, 2));
    } else if (output.status === "PASS") {
      console.log(`Intentrax init verification PASS: adapter=${output.adapter_name} hook=${output.hook_starter.file_path} offline=true`);
    } else {
      console.error(`Intentrax init verification FAIL: ${output.errors.map((error) => error.field).join(", ")}`);
    }
    return output.status === "PASS" ? 0 : 2;
  }
  if (command === "verify-proof") {
    const options = parseVerifyProofOptions(rest);
    // The transparency-log module loads only with --tlog-trust, so copies of
    // this CLI without tlog/ (the console's vendored verifier) keep working.
    if (options.tlogTrust !== "") {
      options.tlogModule = await import("../tlog/index.mjs");
    }
    // Signed pre-approval (specs 01–03): the preapproval/ and envelope/
    // modules load only when the proof, a key set or a flag needs them, so
    // copies of this CLI without those directories keep working on every
    // other proof.
    if (needsPreapprovalModules(subject, options)) {
      try {
        options.preapprovalModule = await import("../preapproval/index.mjs");
        options.envelopeModule = await import("../envelope/index.mjs");
      } catch (error) {
        fail(`this copy of the CLI cannot verify signed pre-approval records (preapproval/ or envelope/ is missing): ${stableErrorMessage(error)}`);
      }
    }
    // Rendered-output binding (spec 10): outputbinding/ loads only when the
    // proof seals one or --answer-file is given, for the same reason.
    if (options.answerFile !== "" || proofSealsOutputBinding(subject)) {
      try {
        options.outputBindingModule = await import("../outputbinding/index.mjs");
      } catch (error) {
        fail(`this copy of the CLI cannot check rendered-output bindings (outputbinding/ is missing): ${stableErrorMessage(error)}`);
      }
    }
    const output = verifyProofExportCommand(subject, options);
    const signerOK = output.signer_trust === "TRUSTED" || output.signer_trust === "SANDBOX_NON_TRUST_BEARING";
    const exitCode = output.status === "PASS" || output.status === "SANDBOX_NON_TRUST_BEARING"
      ? 0
      : output.status === "APPROVAL_EVIDENCE_INVALID" ? 2
        : output.status === "ANSWER_MISMATCH" && signerOK ? ANSWER_MISMATCH_EXIT_CODE : SIGNER_TRUST_EXIT_CODE;
    if (options.json) {
      console.log(JSON.stringify(output, null, 2));
    } else if (output.status === "PASS") {
      console.log(`Intentrax proof export verification PASS: proof=${output.registry_entry_id} signer=TRUSTED report=${output.report_path} hash=${output.report_hash}${transparencySuffix(output)}`);
    } else if (output.status === "SANDBOX_NON_TRUST_BEARING") {
      console.log(`Intentrax proof export verification: SANDBOX — not trust-bearing. Integrity and ed25519 signatures check out, and the signers are published sandbox keys. This shows the verification mechanics, not production assurance. proof=${output.registry_entry_id} report=${output.report_path}${transparencySuffix(output)}`);
    }
    if (!options.json) {
      console.log(assessmentTable(output.verification_assessment));
      if (output.output_binding) {
        console.log(`output binding: ${output.output_binding.binding_source} content_hash=${output.output_binding.content_hash}`);
        console.log(`  ${output.output_binding_statement}`);
      }
      if (output.answer_check) console.log(`answer check: ${output.answer_check.status}`);
      if (output.quote_check) console.log(`quote check: ${output.quote_check.status}`);
    }
    if (exitCode !== 0) {
      if (output.status === "ANSWER_MISMATCH") {
        console.error(`intentrax: answer_check=${output.answer_check.status}: the answer text is not the answer this proof binds (a match is a match against the sealed hash, never a verdict on whether the answer is correct).`);
      }
      if (output.status === "APPROVAL_EVIDENCE_INVALID") {
        console.error(`intentrax: the proof binds approval evidence that does not check out (${output.approval_evidence.filter((check) => check.status === "INVALID").map((check) => check.code).join(",")}); the sealed approval or rejection must not be relied on.`);
      }
      if (output.transparency?.status === "FAILED") {
        console.error(transparencyFailureMessage(output));
      }
      if (output.signer_trust !== "TRUSTED" && output.signer_trust !== "SANDBOX_NON_TRUST_BEARING") {
        console.error(signerTrustMessage(output));
      }
    }
    return exitCode;
  }
  if (command === "verify-pdf-receipt") {
    const options = parseVerifyPDFReceiptOptions(rest);
    const output = verifyPDFReceiptCommand(subject, options);
    if (options.json) {
      console.log(JSON.stringify(output, null, 2));
      return 0;
    }
    console.log(`Intentrax PDF receipt verification PASS: pdf=${output.pdf_path} report=${output.report_path} hash=${output.pdf_hash}`);
    return 0;
  }
  if (command !== "init") {
    fail(`unknown command: ${command}`);
  }
  const adapterName = resolveAdapterName(subject || "");
  const adapter = ADAPTERS[adapterName];
  if (!adapter) {
    fail(`unknown adapter: ${subject || "<missing>"}`);
  }
  const options = parseOptions(rest);
  const output = buildInitOutput(adapterName, adapter, options);
  if (options.dryRun || options.json) {
    console.log(JSON.stringify(output, null, 2));
    return 0;
  }
  const targetDir = resolve(options.outputDir || process.cwd(), ".intentrax");
  const writePlan = buildInitWritePlan(output, options);
  assertNoUnsafeInitOverwrite(writePlan, options);
  mkdirSync(targetDir, { recursive: true });
  mkdirSync(join(targetDir, "hooks"), { recursive: true });
  mkdirSync(join(targetDir, "wiring"), { recursive: true });
  for (const file of writePlan) {
    writeFileSync(file.path, file.content, { mode: 0o600 });
  }
  console.log(`Intentrax adapter initialized: ${adapterName}`);
  console.log(`Config: ${join(targetDir, "agent-adapter.json")}`);
  console.log(`Sample admission: ${join(targetDir, "sample-admission-request.json")}`);
  console.log(`Action receipt: ${join(targetDir, "action-receipt.json")}`);
  console.log(`Submit sample: ${join(resolve(options.outputDir || process.cwd()), output.submit_sample.file_path)}`);
  console.log(`Hook starter: ${join(resolve(options.outputDir || process.cwd()), output.hook_starter.file_path)}`);
  console.log(`Host wiring guide: ${join(resolve(options.outputDir || process.cwd()), output.host_wiring_guide.file_path)}`);
  console.log(`Endpoint: ${output.normalized_contract.endpoint}`);
  console.log(`Next: set INTENTRAX_API_KEY, then run from ${output.submit_sample.working_directory}:`);
  console.log(output.submit_sample.curl);
  console.log("Note: the default base URL http://127.0.0.1:8080 targets a locally run Intentrax engine; the hosted engine base URL is https://api.intentrax.com (override with --base-url or INTENTRAX_BASE_URL).");
  console.log("INTENTRAX_API_KEY and your sandbox base URL are issued after an architectural review: https://www.intentrax.com/request-architectural-review");
  console.log("Offline check that works right now with no key: npx @intentrax/sdk check-init");
  console.log("See the whole assurance flow locally, no key or network (not production assurance): npx @intentrax/sdk sandbox");
  return 0;
}

function parseOptions(args) {
  const options = {
    dryRun: false,
    force: false,
    json: false,
    outputDir: "",
    baseUrl: process.env.INTENTRAX_BASE_URL || "http://127.0.0.1:8080",
    tenantId: "tenant-local-dev",
  };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--dry-run") {
      options.dryRun = true;
    } else if (arg === "--force") {
      options.force = true;
    } else if (arg === "--json") {
      options.json = true;
    } else if (arg === "--output-dir") {
      options.outputDir = requireValue(args, ++index, arg);
    } else if (arg === "--base-url") {
      options.baseUrl = requireValue(args, ++index, arg);
    } else if (arg === "--tenant-id") {
      options.tenantId = requireValue(args, ++index, arg);
    } else {
      fail(`unknown option: ${arg}`);
    }
  }
  return options;
}

function resolveAdapterName(adapterName) {
  return ADAPTER_ALIASES[adapterName] || adapterName;
}

function buildInitWritePlan(output, options) {
  const root = resolve(options.outputDir || process.cwd());
  return Object.freeze([
    initFile(root, ".intentrax/agent-adapter.json", JSON.stringify(output.config, null, 2) + "\n"),
    initFile(root, ".intentrax/sample-admission-request.json", JSON.stringify(output.sample_admission_request, null, 2) + "\n"),
    initFile(root, ".intentrax/action-receipt.json", JSON.stringify(output.action_receipt, null, 2) + "\n"),
    initFile(root, output.submit_sample.file_path, output.submit_sample.curl + "\n"),
    initFile(root, output.hook_starter.file_path, output.hook_starter.source + "\n"),
    initFile(root, output.host_wiring_guide.file_path, output.host_wiring_guide.source + "\n"),
  ]);
}

function initFile(root, filePath, content) {
  return Object.freeze({
    file_path: filePath,
    path: join(root, filePath),
    content,
  });
}

function assertNoUnsafeInitOverwrite(writePlan, options) {
  if (options.force) return;
  const conflicts = [];
  for (const file of writePlan) {
    if (!existsSync(file.path)) continue;
    const existing = readFileSync(file.path, "utf8");
    if (existing !== file.content) {
      conflicts.push(file.file_path);
    }
  }
  if (conflicts.length > 0) {
    fail(`refusing to overwrite existing Intentrax init file(s): ${conflicts.join(", ")}. Re-run with --force after reviewing local changes.`);
  }
}

function parseCheckInitOptions(args) {
  const options = {
    json: false,
    outputDir: "",
  };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--json") {
      options.json = true;
    } else if (arg === "--output-dir") {
      options.outputDir = requireValue(args, ++index, arg);
    } else {
      fail(`unknown option: ${arg}`);
    }
  }
  if (!options.outputDir) {
    fail("check-init requires --output-dir");
  }
  return options;
}

async function checkInitCommand(options) {
  const root = resolve(options.outputDir);
  const errors = [];
  const files = {};
  const fileSources = {};

  for (const filePath of INIT_CHECK_REQUIRED_FILES) {
    fileSources[filePath] = readInitCheckFile(root, filePath, files, errors);
  }

  const config = parseInitCheckJSON(fileSources[".intentrax/agent-adapter.json"], ".intentrax/agent-adapter.json", errors);
  const sampleAdmission = parseInitCheckJSON(fileSources[".intentrax/sample-admission-request.json"], ".intentrax/sample-admission-request.json", errors);
  const actionReceipt = parseInitCheckJSON(fileSources[".intentrax/action-receipt.json"], ".intentrax/action-receipt.json", errors);
  const submitSampleSource = fileSources[".intentrax/submit_sample.curl"] ?? "";

  validateInitCheckConfig(config, errors);
  validateInitCheckActionReceipt(actionReceipt, config, errors);
  validateInitCheckAdmission(sampleAdmission, config, actionReceipt, errors);
  validateInitCheckSubmitSample(submitSampleSource, config, actionReceipt, sampleAdmission, errors);
  validateInitCheckOAPBoundary(fileSources, errors);

  const hookBinding = findHookBinding(config, actionReceipt, errors);
  let hookSource = "";
  let hostWiringGuideSourceText = "";
  let hookInvocation = {
    invoked: false,
    entrypoint_found: false,
    submitted: false,
    network_attempted: false,
    secret_leakage_detected: false,
    result_payload_hash: "",
  };
  if (hookBinding.file_path) {
    hookSource = readInitCheckFile(root, hookBinding.file_path, files, errors);
    const hookErrorsBeforeSourceValidation = errors.length;
    validateInitCheckHookSource(hookSource, hookBinding, errors);
    const hookSourceValidationFailed = errors.length > hookErrorsBeforeSourceValidation;
    if (!hookSourceValidationFailed) {
      hookInvocation = await invokeInitCheckHook(root, hookBinding, errors);
    }
  }
  const hostWiringBinding = findHostWiringBinding(config, actionReceipt, hookBinding, errors);
  if (hostWiringBinding.file_path) {
    hostWiringGuideSourceText = readInitCheckFile(root, hostWiringBinding.file_path, files, errors);
    validateInitCheckHostWiringGuideSource(hostWiringGuideSourceText, hostWiringBinding, hookBinding, errors);
  }

  const adapterName = readString(actionReceipt, ["adapter_profile", "adapter_name"]) ||
    readString(config, ["adapter_profile", "adapter_name"]);
  const admissionEnvelope = isRecord(sampleAdmission) ? buildAgentGatewayAdmissionEnvelope(sampleAdmission) : { status: "FAIL" };
  const status = errors.length === 0 ? "PASS" : "FAIL";
  const sortedErrors = errors.map((error) => Object.freeze(error)).sort((a, b) => canonicalJson(a).localeCompare(canonicalJson(b)));
  const boundaries = {
    offline_verifier_used: true,
    runtime_server_not_required: true,
    network_not_required: true,
    intentrax_api_key_not_required: true,
    generated_hook_invoked_no_submit: hookInvocation.invoked && hookInvocation.submitted === false,
    generated_hook_network_not_attempted: hookInvocation.network_attempted === false,
    secret_bearing_fixture_redacted: hookInvocation.secret_leakage_detected === false,
    no_secret_material_written: readBoolean(config, ["boundary_assertions", "no_secret_material_written"]) === true &&
      readBoolean(actionReceipt, ["boundary_assertions", "no_secret_material_written"]) === true,
    aevn_aep_remains_authoritative: readBoolean(config, ["boundary_assertions", "aevn_aep_remains_authoritative"]) === true &&
      readBoolean(actionReceipt, ["boundary_assertions", "canonical_aep_remains_authoritative"]) === true,
    action_receipt_non_authoritative: readBoolean(actionReceipt, ["authoritative"]) === false,
    production_authorization_unchanged: readBoolean(actionReceipt, ["production_authorization_unchanged"]) === true,
    oap_compatibility: OAP_COMPATIBILITY_BOUNDARY,
  };
  const withoutHash = {
    schema_version: LOCAL_INIT_CHECK_SCHEMA_VERSION,
    verifier_version: LOCAL_INIT_CHECK_VERIFIER_VERSION,
    status,
    offline: true,
    output_dir: root,
    adapter_name: adapterName,
    mvp_adapter: MVP_ADAPTERS.includes(adapterName),
    normalized_contract: {
      endpoint: ENDPOINT,
      method: "POST",
      tenant_header: TENANT_HEADER,
      api_key_header: API_KEY_HEADER,
      idempotency_header: IDEMPOTENCY_HEADER,
    },
    files,
    admission_fixture: {
      file_path: ".intentrax/sample-admission-request.json",
      status: admissionEnvelope.status,
      request_hash: admissionEnvelope.output?.request_hash ?? "",
      idempotency_key_hash: isRecord(sampleAdmission) ? sampleAdmission.idempotency_key_hash ?? "" : "",
      request_payload_hash: isRecord(sampleAdmission) ? sampleAdmission.request_payload_hash ?? "" : "",
    },
    action_receipt: {
      file_path: ".intentrax/action-receipt.json",
      receipt_hash: isRecord(actionReceipt) ? actionReceipt.receipt_hash ?? "" : "",
      authoritative: isRecord(actionReceipt) ? actionReceipt.authoritative === true : false,
    },
    hook_starter: {
      file_path: hookBinding.file_path,
      entrypoint: hookBinding.entrypoint,
      source_hash: hookSource ? hashGeneratedHookSource(hookSource) : "",
      expected_source_hash: hookBinding.source_hash,
      invoked: hookInvocation.invoked,
      entrypoint_found: hookInvocation.entrypoint_found,
      submitted: hookInvocation.submitted,
      network_attempted: hookInvocation.network_attempted,
      secret_leakage_detected: hookInvocation.secret_leakage_detected,
      result_payload_hash: hookInvocation.result_payload_hash,
    },
    host_wiring_guide: {
      file_path: hostWiringBinding.file_path,
      host_runtime: hostWiringBinding.host_runtime,
      hook_file_path: hostWiringBinding.hook_file_path,
      hook_entrypoint: hostWiringBinding.hook_entrypoint,
      guide_hash: hostWiringGuideSourceText ? hashGeneratedHostWiringSource(hostWiringGuideSourceText) : "",
      expected_guide_hash: hostWiringBinding.guide_hash,
      present: hostWiringBinding.file_path ? files[hostWiringBinding.file_path]?.present === true : false,
    },
    boundaries,
    errors: sortedErrors,
    report_hash: "",
  };
  return Object.freeze({
    ...withoutHash,
    report_hash: sha256Hex(LOCAL_INIT_CHECK_DOMAIN + canonicalJson(withoutHash)),
  });
}

function readInitCheckFile(root, filePath, files, errors) {
  const resolved = resolveInitCheckPath(root, filePath, errors);
  files[filePath] = {
    present: false,
    sha256: "",
    byte_length: 0,
  };
  if (!resolved) return "";
  if (!existsSync(resolved)) {
    pushCheckError(errors, "missing_file", filePath, "Expected init file is missing.");
    return "";
  }
  const source = readFileSync(resolved, "utf8");
  files[filePath] = {
    present: true,
    sha256: sha256Hex(source),
    byte_length: Buffer.byteLength(source, "utf8"),
  };
  return source;
}

function resolveInitCheckPath(root, filePath, errors) {
  if (!isSafeInitCheckRelativePath(filePath)) {
    pushCheckError(errors, "unsafe_path", filePath, "Configured init file path escapes the output directory.");
    return "";
  }
  const resolved = resolve(root, filePath);
  const rel = relative(root, resolved);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    pushCheckError(errors, "unsafe_path", filePath, "Configured init file path escapes the output directory.");
    return "";
  }
  return resolved;
}

function isSafeInitCheckRelativePath(filePath) {
  return typeof filePath === "string" &&
    filePath.length > 0 &&
    filePath.trim() === filePath &&
    !isAbsolute(filePath) &&
    !/^[A-Za-z]:[\\/]/.test(filePath) &&
    !filePath.includes("\u0000") &&
    !filePath.split(/[\\/]+/).includes("..") &&
    filePath.startsWith(".intentrax/");
}

function parseInitCheckJSON(source, filePath, errors) {
  if (!source) return null;
  try {
    return JSON.parse(source);
  } catch (error) {
    pushCheckError(errors, "invalid_json", filePath, `Invalid JSON: ${stableErrorMessage(error)}`);
    return null;
  }
}

function validateInitCheckConfig(config, errors) {
  if (!isRecord(config)) {
    pushCheckError(errors, "invalid_json_shape", ".intentrax/agent-adapter.json", "Agent adapter config must be a JSON object.");
    return;
  }
  if (config.schema_version !== INIT_SCHEMA_VERSION) {
    pushCheckError(errors, "schema_version", "config.schema_version", "Unexpected agent adapter config schema version.");
  }
  const adapterName = readString(config, ["adapter_profile", "adapter_name"]);
  const adapter = ADAPTERS[adapterName];
  if (!adapter) {
    pushCheckError(errors, "adapter_profile", "config.adapter_profile.adapter_name", "Unknown Intentrax adapter profile.");
  } else {
    assertCheckEqual(errors, config.adapter_profile.display_name, adapter.display_name, "config.adapter_profile.display_name");
    assertCheckEqual(errors, config.adapter_profile.matrix_adapter_id, adapter.matrix_adapter_id, "config.adapter_profile.matrix_adapter_id");
    assertCheckEqual(errors, config.adapter_profile.hook_surface, adapter.hook_surface, "config.adapter_profile.hook_surface");
    assertCheckEqual(errors, config.adapter_profile.native_hook_starter?.file_path, `.intentrax/hooks/${adapter.hook_file_name}`, "config.adapter_profile.native_hook_starter.file_path");
    assertCheckEqual(errors, config.adapter_profile.native_hook_starter?.entrypoint, adapter.hook_entrypoint, "config.adapter_profile.native_hook_starter.entrypoint");
    assertCheckEqual(errors, config.adapter_profile.native_hook_starter?.native_template_id, adapter.native_template_id ?? "generic_admission_hook_v1", "config.adapter_profile.native_hook_starter.native_template_id");
    assertCheckEqual(errors, config.adapter_profile.native_hook_starter?.native_event_kind, adapter.native_event_kind ?? "GENERIC_AGENT_EVENT", "config.adapter_profile.native_hook_starter.native_event_kind");
    assertCheckEqual(errors, config.adapter_profile.host_wiring_guide?.file_path, `.intentrax/wiring/${adapterName}-host-wiring.md`, "config.adapter_profile.host_wiring_guide.file_path");
    assertCheckEqual(errors, config.adapter_profile.host_wiring_guide?.host_runtime, adapter.display_name, "config.adapter_profile.host_wiring_guide.host_runtime");
    assertCheckEqual(errors, config.adapter_profile.host_wiring_guide?.hook_file_path, `.intentrax/hooks/${adapter.hook_file_name}`, "config.adapter_profile.host_wiring_guide.hook_file_path");
    assertCheckEqual(errors, config.adapter_profile.host_wiring_guide?.hook_entrypoint, adapter.hook_entrypoint, "config.adapter_profile.host_wiring_guide.hook_entrypoint");
    assertCheckEqual(errors, config.adapter_profile.host_wiring_guide?.setup_level, "HOST_BINDING_GUIDE", "config.adapter_profile.host_wiring_guide.setup_level");
    assertCheckEqual(errors, config.adapter_profile.host_wiring_guide?.authoritative, false, "config.adapter_profile.host_wiring_guide.authoritative");
    assertCheckEqual(errors, config.adapter_profile.host_wiring_guide?.secret_material_written, false, "config.adapter_profile.host_wiring_guide.secret_material_written");
  }
  assertCheckEqual(errors, config.normalized_contract?.endpoint, ENDPOINT, "config.normalized_contract.endpoint");
  assertCheckEqual(errors, config.normalized_contract?.method, "POST", "config.normalized_contract.method");
  assertCheckEqual(errors, config.normalized_contract?.tenant_header, TENANT_HEADER, "config.normalized_contract.tenant_header");
  assertCheckEqual(errors, config.normalized_contract?.api_key_header, API_KEY_HEADER, "config.normalized_contract.api_key_header");
  assertCheckEqual(errors, config.normalized_contract?.idempotency_header, IDEMPOTENCY_HEADER, "config.normalized_contract.idempotency_header");
  assertCheckEqual(errors, config.boundary_assertions?.no_secret_material_written, true, "config.boundary_assertions.no_secret_material_written");
  assertCheckEqual(errors, config.boundary_assertions?.no_tool_execution_inside_admission, true, "config.boundary_assertions.no_tool_execution_inside_admission");
  assertCheckEqual(errors, config.boundary_assertions?.aevn_aep_remains_authoritative, true, "config.boundary_assertions.aevn_aep_remains_authoritative");
  assertCheckEqual(errors, config.boundary_assertions?.oap_compatibility, OAP_COMPATIBILITY_BOUNDARY, "config.boundary_assertions.oap_compatibility");
  assertCheckEqual(errors, config.sample_submission?.api_key_env, "INTENTRAX_API_KEY", "config.sample_submission.api_key_env");
}

function validateInitCheckActionReceipt(actionReceipt, config, errors) {
  if (!isRecord(actionReceipt)) {
    pushCheckError(errors, "invalid_json_shape", ".intentrax/action-receipt.json", "Action receipt must be a JSON object.");
    return;
  }
  if (actionReceipt.schema_version !== ACTION_RECEIPT_SCHEMA_VERSION) {
    pushCheckError(errors, "schema_version", "action_receipt.schema_version", "Unexpected action receipt schema version.");
  }
  assertCheckEqual(errors, actionReceipt.receipt_type, "AGENT_ADAPTER_INIT_SAMPLE_ACTION_RECEIPT", "action_receipt.receipt_type");
  assertCheckEqual(errors, actionReceipt.file_path, ".intentrax/action-receipt.json", "action_receipt.file_path");
  assertCheckEqual(errors, actionReceipt.authoritative, false, "action_receipt.authoritative");
  assertCheckEqual(errors, actionReceipt.canonical_aep_authoritative, true, "action_receipt.canonical_aep_authoritative");
  assertCheckEqual(errors, actionReceipt.production_authorization_unchanged, true, "action_receipt.production_authorization_unchanged");
  assertCheckEqual(errors, actionReceipt.boundary_assertions?.canonical_aep_remains_authoritative, true, "action_receipt.boundary_assertions.canonical_aep_remains_authoritative");
  assertCheckEqual(errors, actionReceipt.boundary_assertions?.oap_compatibility, OAP_COMPATIBILITY_BOUNDARY, "action_receipt.boundary_assertions.oap_compatibility");
  assertCheckEqual(errors, actionReceipt.boundary_assertions?.action_receipt_does_not_replace_aep, true, "action_receipt.boundary_assertions.action_receipt_does_not_replace_aep");
  assertCheckEqual(errors, actionReceipt.boundary_assertions?.production_authorization_unchanged, true, "action_receipt.boundary_assertions.production_authorization_unchanged");
  assertCheckEqual(errors, actionReceipt.evidence_links?.runtime_admission_endpoint, ENDPOINT, "action_receipt.evidence_links.runtime_admission_endpoint");
  assertCheckEqual(errors, actionReceipt.evidence_links?.proof_verification_endpoint, "/v1/proofs/verify", "action_receipt.evidence_links.proof_verification_endpoint");
  assertCheckEqual(errors, actionReceipt.evidence_links?.proof_export_endpoint_template, "/v1/proofs/{proof_id}/export?format=json|aep-json|pdf", "action_receipt.evidence_links.proof_export_endpoint_template");
  assertCheckEqual(errors, actionReceipt.evidence_links?.verifier_handoff_endpoint_template, "/v1/evidence/dry-run/{receipt_id}/verifier-handoff", "action_receipt.evidence_links.verifier_handoff_endpoint_template");
  assertCheckEqual(errors, actionReceipt.evidence_links?.aevn_authoritative, true, "action_receipt.evidence_links.aevn_authoritative");
  assertCheckEqual(errors, actionReceipt.evidence_links?.aep_authoritative, true, "action_receipt.evidence_links.aep_authoritative");
  if (isRecord(config)) {
    assertCheckEqual(errors, actionReceipt.receipt_hash, config.action_receipt?.receipt_hash, "config.action_receipt.receipt_hash");
    assertCheckEqual(errors, actionReceipt.adapter_profile?.adapter_name, config.adapter_profile?.adapter_name, "action_receipt.adapter_profile.adapter_name");
    assertCheckEqual(errors, actionReceipt.hook_starter_binding?.file_path, config.adapter_profile?.native_hook_starter?.file_path, "action_receipt.hook_starter_binding.file_path");
    assertCheckEqual(errors, actionReceipt.hook_starter_binding?.entrypoint, config.adapter_profile?.native_hook_starter?.entrypoint, "action_receipt.hook_starter_binding.entrypoint");
    assertCheckEqual(errors, actionReceipt.host_wiring_guide_binding?.file_path, config.adapter_profile?.host_wiring_guide?.file_path, "action_receipt.host_wiring_guide_binding.file_path");
    assertCheckEqual(errors, actionReceipt.host_wiring_guide_binding?.guide_hash, config.adapter_profile?.host_wiring_guide?.guide_hash, "action_receipt.host_wiring_guide_binding.guide_hash");
    assertCheckEqual(errors, actionReceipt.host_wiring_guide_binding?.hook_file_path, config.adapter_profile?.native_hook_starter?.file_path, "action_receipt.host_wiring_guide_binding.hook_file_path");
    assertCheckEqual(errors, actionReceipt.host_wiring_guide_binding?.hook_entrypoint, config.adapter_profile?.native_hook_starter?.entrypoint, "action_receipt.host_wiring_guide_binding.hook_entrypoint");
  }
  const receiptHash = actionReceipt.receipt_hash;
  if (!isSHA256(receiptHash)) {
    pushCheckError(errors, "receipt_hash", "action_receipt.receipt_hash", "Action receipt hash must be a SHA-256 hex string.");
  } else {
    const { receipt_hash: _receiptHash, ...withoutHash } = actionReceipt;
    const expectedReceiptHash = sha256Hex(ACTION_RECEIPT_DOMAIN + canonicalJson(withoutHash));
    if (receiptHash !== expectedReceiptHash) {
      pushCheckError(errors, "receipt_hash_mismatch", "action_receipt.receipt_hash", "Action receipt hash does not match the on-disk receipt body.");
    }
  }
}

function validateInitCheckAdmission(sampleAdmission, config, actionReceipt, errors) {
  if (!isRecord(sampleAdmission)) {
    pushCheckError(errors, "invalid_json_shape", ".intentrax/sample-admission-request.json", "Sample admission request must be a JSON object.");
    return;
  }
  const envelope = buildAgentGatewayAdmissionEnvelope(sampleAdmission);
  if (envelope.status !== "PASS") {
    pushCheckError(errors, "agent_gateway_admission_shape", ".intentrax/sample-admission-request.json", `Malformed Agent Gateway admission fixture: ${envelope.error.invalid_fields.join(",")}.`);
  }
  const adapterName = readString(actionReceipt, ["adapter_profile", "adapter_name"]) ||
    readString(config, ["adapter_profile", "adapter_name"]);
  const adapter = ADAPTERS[adapterName];
  if (!adapter) return;
  const expectedAction = SAMPLE_ACTION_BY_SURFACE[adapter.normalized_surface_id];
  assertCheckEqual(errors, sampleAdmission.surface_id, adapter.normalized_surface_id, "sample_admission_request.surface_id");
  assertCheckEqual(errors, sampleAdmission.adapter_id, adapter.normalized_adapter_id, "sample_admission_request.adapter_id");
  assertCheckEqual(errors, sampleAdmission.action, expectedAction, "sample_admission_request.action");
  if (!sameJSON(sampleAdmission.evidence_refs, REQUIRED_GATEWAY_REFS)) {
    pushCheckError(errors, "gateway_refs", "sample_admission_request.evidence_refs", "Sample evidence refs differ from the locked private-alpha Agent Gateway refs.");
  }
  if (!sameJSON(sampleAdmission.proof_refs, REQUIRED_GATEWAY_REFS)) {
    pushCheckError(errors, "gateway_refs", "sample_admission_request.proof_refs", "Sample proof refs differ from the locked private-alpha Agent Gateway refs.");
  }
  const expectedPayload = {
    adapter: adapterName,
    action: expectedAction,
    hook_surface: adapter.hook_surface,
    tenant_id: sampleAdmission.tenant_id,
  };
  const expectedPayloadHash = sha256Hex(canonicalJson(expectedPayload));
  assertCheckEqual(errors, sampleAdmission.request_payload_hash, expectedPayloadHash, "sample_admission_request.request_payload_hash");
  assertCheckEqual(errors, sampleAdmission.protocol_payload_ref, `sha256:${expectedPayloadHash}`, "sample_admission_request.protocol_payload_ref");
  assertCheckEqual(errors, sampleAdmission.idempotency_key_hash, sha256Hex("INTENTRAX_AGENT_INIT_IDEMPOTENCY_V1" + expectedPayloadHash), "sample_admission_request.idempotency_key_hash");
  if (isRecord(actionReceipt)) {
    assertCheckEqual(errors, sampleAdmission.tenant_id, actionReceipt.sample_admission_binding?.tenant_id, "action_receipt.sample_admission_binding.tenant_id");
    assertCheckEqual(errors, sampleAdmission.request_payload_hash, actionReceipt.sample_admission_binding?.request_payload_hash, "action_receipt.sample_admission_binding.request_payload_hash");
    assertCheckEqual(errors, sampleAdmission.protocol_payload_ref, actionReceipt.sample_admission_binding?.protocol_payload_ref, "action_receipt.sample_admission_binding.protocol_payload_ref");
    assertCheckEqual(errors, sampleAdmission.idempotency_key_hash, actionReceipt.sample_admission_binding?.idempotency_key_hash, "action_receipt.sample_admission_binding.idempotency_key_hash");
    assertCheckEqual(errors, sampleAdmission.evidence_refs.length, actionReceipt.sample_admission_binding?.evidence_ref_count, "action_receipt.sample_admission_binding.evidence_ref_count");
    assertCheckEqual(errors, sampleAdmission.proof_refs.length, actionReceipt.sample_admission_binding?.proof_ref_count, "action_receipt.sample_admission_binding.proof_ref_count");
  }
  if (isRecord(config)) {
    assertCheckEqual(errors, sampleAdmission.action, config.runtime_gate_fixture?.sample_action, "config.runtime_gate_fixture.sample_action");
    assertCheckEqual(errors, sampleAdmission.idempotency_key_hash, config.sample_submission?.idempotency_key_hash, "config.sample_submission.idempotency_key_hash");
  }
}

function validateInitCheckSubmitSample(submitSampleSource, config, actionReceipt, sampleAdmission, errors) {
  if (!submitSampleSource) return;
  if (isRecord(config)) {
    assertCheckEqual(errors, submitSampleSource, `${config.sample_submission?.curl ?? ""}\n`, ".intentrax/submit_sample.curl");
    assertCheckEqual(errors, config.sample_submission?.file_path, ".intentrax/submit_sample.curl", "config.sample_submission.file_path");
    assertCheckEqual(errors, config.sample_submission?.body_file, ".intentrax/sample-admission-request.json", "config.sample_submission.body_file");
  }
  if (isRecord(actionReceipt)) {
    assertCheckEqual(errors, actionReceipt.submit_sample_binding?.file_path, ".intentrax/submit_sample.curl", "action_receipt.submit_sample_binding.file_path");
    assertCheckEqual(errors, actionReceipt.submit_sample_binding?.body_file, ".intentrax/sample-admission-request.json", "action_receipt.submit_sample_binding.body_file");
    assertCheckEqual(errors, actionReceipt.submit_sample_binding?.api_key_env, "INTENTRAX_API_KEY", "action_receipt.submit_sample_binding.api_key_env");
  }
  if (isRecord(sampleAdmission)) {
    assertCheckEqual(errors, actionReceipt?.submit_sample_binding?.idempotency_key_hash, sampleAdmission.idempotency_key_hash, "action_receipt.submit_sample_binding.idempotency_key_hash");
    if (!submitSampleSource.includes(`${IDEMPOTENCY_HEADER}: ${sampleAdmission.idempotency_key_hash}`)) {
      pushCheckError(errors, "submit_sample", ".intentrax/submit_sample.curl", "Submit sample does not bind the sample idempotency hash.");
    }
  }
  if (!submitSampleSource.includes("$INTENTRAX_API_KEY")) {
    pushCheckError(errors, "submit_sample", ".intentrax/submit_sample.curl", "Submit sample must reference INTENTRAX_API_KEY rather than writing a secret.");
  }
  if (/fixture-api-key|test-api-key|begin private|seed_hex|current_seed_hex/i.test(submitSampleSource)) {
    pushCheckError(errors, "secret_material", ".intentrax/submit_sample.curl", "Submit sample contains forbidden test or private material markers.");
  }
}

function validateInitCheckOAPBoundary(fileSources, errors) {
  for (const [filePath, source] of Object.entries(fileSources)) {
    if (containsOAPCompatibilityMarkerInArtifact(filePath, source)) {
      pushCheckError(errors, "oap_excluded", filePath, oapExcludedMessage());
    }
  }
}

function findHookBinding(config, actionReceipt, errors) {
  const configHook = readString(config, ["adapter_profile", "native_hook_starter", "file_path"]);
  const receiptHook = readString(actionReceipt, ["hook_starter_binding", "file_path"]);
  const configEntrypoint = readString(config, ["adapter_profile", "native_hook_starter", "entrypoint"]);
  const receiptEntrypoint = readString(actionReceipt, ["hook_starter_binding", "entrypoint"]);
  const sourceHash = readString(actionReceipt, ["hook_starter_binding", "source_hash"]);
  if (!configHook) {
    pushCheckError(errors, "hook_binding", "config.adapter_profile.native_hook_starter.file_path", "Config does not identify a generated hook starter.");
  }
  if (!receiptHook) {
    pushCheckError(errors, "hook_binding", "action_receipt.hook_starter_binding.file_path", "Action receipt does not identify a generated hook starter.");
  }
  if (configHook && receiptHook && configHook !== receiptHook) {
    pushCheckError(errors, "hook_binding", "action_receipt.hook_starter_binding.file_path", "Config and action receipt hook file paths differ.");
  }
  if (configEntrypoint && receiptEntrypoint && configEntrypoint !== receiptEntrypoint) {
    pushCheckError(errors, "hook_binding", "action_receipt.hook_starter_binding.entrypoint", "Config and action receipt hook entrypoints differ.");
  }
  if (sourceHash && !isSHA256(sourceHash)) {
    pushCheckError(errors, "hook_binding", "action_receipt.hook_starter_binding.source_hash", "Hook source hash must be a SHA-256 hex string.");
  }
  return {
    file_path: configHook || receiptHook || "",
    entrypoint: configEntrypoint || receiptEntrypoint || "",
    source_hash: sourceHash || "",
  };
}

function findHostWiringBinding(config, actionReceipt, hookBinding, errors) {
  const configGuide = readString(config, ["adapter_profile", "host_wiring_guide", "file_path"]);
  const receiptGuide = readString(actionReceipt, ["host_wiring_guide_binding", "file_path"]);
  const configHash = readString(config, ["adapter_profile", "host_wiring_guide", "guide_hash"]);
  const receiptHash = readString(actionReceipt, ["host_wiring_guide_binding", "guide_hash"]);
  const configHookPath = readString(config, ["adapter_profile", "host_wiring_guide", "hook_file_path"]);
  const receiptHookPath = readString(actionReceipt, ["host_wiring_guide_binding", "hook_file_path"]);
  const configEntrypoint = readString(config, ["adapter_profile", "host_wiring_guide", "hook_entrypoint"]);
  const receiptEntrypoint = readString(actionReceipt, ["host_wiring_guide_binding", "hook_entrypoint"]);
  if (!configGuide) {
    pushCheckError(errors, "host_wiring_guide_binding", "config.adapter_profile.host_wiring_guide.file_path", "Config does not identify a generated host wiring guide.");
  }
  if (!receiptGuide) {
    pushCheckError(errors, "host_wiring_guide_binding", "action_receipt.host_wiring_guide_binding.file_path", "Action receipt does not identify a generated host wiring guide.");
  }
  if (configGuide && receiptGuide && configGuide !== receiptGuide) {
    pushCheckError(errors, "host_wiring_guide_binding", "action_receipt.host_wiring_guide_binding.file_path", "Config and action receipt host wiring guide paths differ.");
  }
  if (configHash && receiptHash && configHash !== receiptHash) {
    pushCheckError(errors, "host_wiring_guide_binding", "action_receipt.host_wiring_guide_binding.guide_hash", "Config and action receipt host wiring guide hashes differ.");
  }
  if (receiptHash && !isSHA256(receiptHash)) {
    pushCheckError(errors, "host_wiring_guide_binding", "action_receipt.host_wiring_guide_binding.guide_hash", "Host wiring guide hash must be a SHA-256 hex string.");
  }
  if (configHookPath && hookBinding.file_path && configHookPath !== hookBinding.file_path) {
    pushCheckError(errors, "host_wiring_guide_binding", "config.adapter_profile.host_wiring_guide.hook_file_path", "Host wiring guide is not bound to the generated hook starter.");
  }
  if (receiptHookPath && hookBinding.file_path && receiptHookPath !== hookBinding.file_path) {
    pushCheckError(errors, "host_wiring_guide_binding", "action_receipt.host_wiring_guide_binding.hook_file_path", "Action receipt host wiring guide is not bound to the generated hook starter.");
  }
  if (configEntrypoint && hookBinding.entrypoint && configEntrypoint !== hookBinding.entrypoint) {
    pushCheckError(errors, "host_wiring_guide_binding", "config.adapter_profile.host_wiring_guide.hook_entrypoint", "Host wiring guide entrypoint does not match the generated hook starter.");
  }
  if (receiptEntrypoint && hookBinding.entrypoint && receiptEntrypoint !== hookBinding.entrypoint) {
    pushCheckError(errors, "host_wiring_guide_binding", "action_receipt.host_wiring_guide_binding.hook_entrypoint", "Action receipt host wiring guide entrypoint does not match the generated hook starter.");
  }
  return {
    file_path: configGuide || receiptGuide || "",
    host_runtime: readString(config, ["adapter_profile", "host_wiring_guide", "host_runtime"]) ||
      readString(actionReceipt, ["host_wiring_guide_binding", "host_runtime"]),
    hook_file_path: configHookPath || receiptHookPath || "",
    hook_entrypoint: configEntrypoint || receiptEntrypoint || "",
    guide_hash: receiptHash || configHash || "",
  };
}

function validateInitCheckHookSource(hookSource, hookBinding, errors) {
  if (!hookSource) return;
  const actualHash = hashGeneratedHookSource(hookSource);
  if (hookBinding.source_hash && actualHash !== hookBinding.source_hash) {
    pushCheckError(errors, "hook_source_hash_mismatch", "action_receipt.hook_starter_binding.source_hash", "Generated hook source hash does not match the action receipt binding.");
  }
  if (!hookBinding.entrypoint) {
    pushCheckError(errors, "hook_binding", "action_receipt.hook_starter_binding.entrypoint", "Generated hook entrypoint is missing.");
  } else if (!hookSource.includes(`function ${hookBinding.entrypoint}`)) {
    pushCheckError(errors, "hook_entrypoint", hookBinding.file_path, "Generated hook source does not contain the configured entrypoint.");
  }
  if (containsOAPCompatibilityMarker(hookSource)) {
    pushCheckError(errors, "oap_excluded", hookBinding.file_path, oapExcludedMessage());
  }
}

function validateInitCheckHostWiringGuideSource(source, hostWiringBinding, hookBinding, errors) {
  if (!source) return;
  const actualHash = hashGeneratedHostWiringSource(source);
  if (hostWiringBinding.guide_hash && actualHash !== hostWiringBinding.guide_hash) {
    pushCheckError(errors, "host_wiring_guide_hash_mismatch", "action_receipt.host_wiring_guide_binding.guide_hash", "Generated host wiring guide hash does not match the action receipt binding.");
  }
  if (hookBinding.file_path && !source.includes(`\`${hookBinding.file_path}\``)) {
    pushCheckError(errors, "host_wiring_guide_binding", hostWiringBinding.file_path, "Host wiring guide does not reference the generated hook starter path.");
  }
  if (hookBinding.entrypoint && !source.includes(hookBinding.entrypoint)) {
    pushCheckError(errors, "host_wiring_guide_binding", hostWiringBinding.file_path, "Host wiring guide does not reference the generated hook entrypoint.");
  }
  if (!source.includes(ENDPOINT) || !source.includes(TENANT_HEADER) || !source.includes(API_KEY_HEADER) || !source.includes(IDEMPOTENCY_HEADER)) {
    pushCheckError(errors, "host_wiring_guide_binding", hostWiringBinding.file_path, "Host wiring guide does not include the locked runtime admission binding.");
  }
  if (!source.includes("npx @intentrax/sdk check-init --output-dir .")) {
    pushCheckError(errors, "host_wiring_guide_binding", hostWiringBinding.file_path, "Host wiring guide does not include the offline check-init command.");
  }
  if (containsOAPCompatibilityMarker(source)) {
    pushCheckError(errors, "oap_excluded", hostWiringBinding.file_path, oapExcludedMessage());
  }
  if (/fixture-api-key|test-api-key|begin private|seed_hex|current_seed_hex|must-not-appear/i.test(source)) {
    pushCheckError(errors, "secret_material", hostWiringBinding.file_path, "Host wiring guide contains forbidden test or private material markers.");
  }
}

function containsOAPCompatibilityMarker(source) {
  return OAP_EXCLUSION_PATTERN.test(source ?? "");
}

function containsOAPCompatibilityMarkerInArtifact(filePath, source) {
  if (!source) return false;
  if (!filePath.endsWith(".json")) {
    return containsOAPCompatibilityMarker(source);
  }
  try {
    const parsed = JSON.parse(source);
    return containsOAPCompatibilityMarkerInJSONValue(parsed, []);
  } catch {
    return containsOAPCompatibilityMarker(source);
  }
}

function containsOAPCompatibilityMarkerInJSONValue(value, path) {
  if (typeof value === "string") {
    return !isOAPMarkerExemptJSONPath(path) && containsOAPCompatibilityMarker(value);
  }
  if (Array.isArray(value)) {
    return value.some((item, index) => containsOAPCompatibilityMarkerInJSONValue(item, path.concat(String(index))));
  }
  if (isRecord(value)) {
    return Object.entries(value).some(([key, nested]) => containsOAPCompatibilityMarkerInJSONValue(nested, path.concat(key)));
  }
  return false;
}

function isOAPMarkerExemptJSONPath(path) {
  const field = path[path.length - 1] ?? "";
  return field === "working_directory";
}

function oapExcludedMessage() {
  return `OAP compatibility is excluded from this MVP verifier. Excluded markers: ${OAP_EXCLUSION_MARKERS.join(", ")}.`;
}

async function invokeInitCheckHook(root, hookBinding, errors) {
  const result = {
    invoked: false,
    entrypoint_found: false,
    submitted: false,
    network_attempted: false,
    secret_leakage_detected: false,
    result_payload_hash: "",
  };
  const resolvedHookPath = resolveInitCheckPath(root, hookBinding.file_path, errors);
  if (!resolvedHookPath || !existsSync(resolvedHookPath) || !hookBinding.entrypoint) {
    return result;
  }
  const hadAPIKey = Object.prototype.hasOwnProperty.call(process.env, "INTENTRAX_API_KEY");
  const previousAPIKey = process.env.INTENTRAX_API_KEY;
  const previousFetch = globalThis.fetch;
  const networkBlocker = async () => {
    result.network_attempted = true;
    throw new Error("Intentrax check-init blocked network access during offline hook invocation.");
  };
  try {
    delete process.env.INTENTRAX_API_KEY;
    globalThis.fetch = networkBlocker;
    const hookModule = await import(pathToFileURL(resolvedHookPath).href);
    const entrypoint = hookModule[hookBinding.entrypoint];
    result.entrypoint_found = typeof entrypoint === "function";
    if (!result.entrypoint_found) {
      pushCheckError(errors, "hook_entrypoint", hookBinding.entrypoint, "Generated hook module does not export the configured entrypoint.");
      return result;
    }
    const hookResult = await entrypoint(buildSecretBearingHookFixture(), {
      submit: false,
      fetchImpl: networkBlocker,
    });
    result.invoked = true;
    result.submitted = hookResult?.submitted === true;
    result.result_payload_hash = isRecord(hookResult?.admission_request) ? hookResult.admission_request.request_payload_hash ?? "" : "";
    const serialized = JSON.stringify(hookResult);
    result.secret_leakage_detected = SECRET_FIXTURE_MARKERS.some((marker) => serialized.includes(marker));
    if (result.submitted) {
      pushCheckError(errors, "hook_offline_mode", hookBinding.entrypoint, "Generated hook submitted during offline check-init invocation.");
    }
    if (result.network_attempted) {
      pushCheckError(errors, "hook_network", hookBinding.entrypoint, "Generated hook attempted network access during offline check-init invocation.");
    }
    if (result.secret_leakage_detected) {
      pushCheckError(errors, "hook_secret_leakage", hookBinding.entrypoint, "Generated hook result leaked a secret-bearing fixture value.");
    }
    assertCheckEqual(errors, hookResult?.mutation_performed, false, "hook_result.mutation_performed");
    assertCheckEqual(errors, hookResult?.tool_execution_performed, false, "hook_result.tool_execution_performed");
    assertCheckEqual(errors, hookResult?.proof_generation_performed, false, "hook_result.proof_generation_performed");
    assertCheckEqual(errors, hookResult?.policy_re_evaluation_performed, false, "hook_result.policy_re_evaluation_performed");
  } catch (error) {
    pushCheckError(errors, "hook_invocation", hookBinding.entrypoint, `Generated hook failed offline invocation: ${stableErrorMessage(error)}`);
  } finally {
    if (hadAPIKey) {
      process.env.INTENTRAX_API_KEY = previousAPIKey;
    } else {
      delete process.env.INTENTRAX_API_KEY;
    }
    globalThis.fetch = previousFetch;
  }
  return result;
}

function buildSecretBearingHookFixture() {
  const [token, apiKey, password, privateKey, cookie] = SECRET_FIXTURE_MARKERS;
  return Object.freeze({
    tool_name: "intentrax.check_init.fixture",
    toolName: "intentrax.check_init.fixture",
    name: "intentrax.check_init.fixture",
    command: "echo should-not-run",
    input: {
      visible: "ok",
      token,
      api_key: apiKey,
      password,
      nested: {
        private_key: privateKey,
      },
    },
    arguments: {
      visible: "ok",
      authorization: `Bearer ${token}`,
    },
    headers: {
      Authorization: `Bearer ${token}`,
      Cookie: `session=${cookie}`,
    },
    apiKey,
    session: cookie,
    metadata: {
      credential: password,
      trace_id: "check-init-trace",
    },
  });
}

function hashGeneratedHookSource(source) {
  return sha256Hex(source.endsWith("\n") ? source.slice(0, -1) : source);
}

function hashGeneratedHostWiringSource(source) {
  return sha256Hex(HOST_WIRING_GUIDE_DOMAIN + (source.endsWith("\n") ? source.slice(0, -1) : source));
}

function assertCheckEqual(errors, actual, expected, field) {
  if (!sameJSON(actual, expected)) {
    pushCheckError(errors, "binding_mismatch", field, `Expected ${field} to match generated init binding.`);
  }
}

function sameJSON(a, b) {
  if (a === undefined || b === undefined) return a === b;
  return canonicalJson(a) === canonicalJson(b);
}

function readString(value, path) {
  const out = readPath(value, path);
  return typeof out === "string" ? out : "";
}

function readBoolean(value, path) {
  const out = readPath(value, path);
  return typeof out === "boolean" ? out : undefined;
}

function readPath(value, path) {
  let out = value;
  for (const key of path) {
    if (!isRecord(out)) return undefined;
    out = out[key];
  }
  return out;
}

function pushCheckError(errors, code, field, message) {
  errors.push({
    code,
    field,
    message,
  });
}

function stableErrorMessage(error) {
  return error && typeof error.message === "string" ? error.message : String(error);
}

function parseVerifyProofOptions(args) {
  const options = {
    json: false,
    reportOut: ".intentrax/offline-proof-verification.report.json",
    trustedKeys: [],
    policyDocuments: [],
    tlogTrust: "",
    tlogBundle: "",
    tenantKeys: [],
    approverSets: [],
    pinDirectoryHeads: [],
    answerFile: "",
    quoteFile: "",
  };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--json") {
      options.json = true;
    } else if (arg === "--report-out") {
      options.reportOut = requireValue(args, ++index, arg);
    } else if (arg === "--answer-file") {
      options.answerFile = requireValue(args, ++index, arg);
    } else if (arg === "--quote-file") {
      options.quoteFile = requireValue(args, ++index, arg);
    } else if (arg === "--tenant-keys") {
      options.tenantKeys.push(requireValue(args, ++index, arg));
    } else if (arg === "--approver-set") {
      options.approverSets.push(requireValue(args, ++index, arg));
    } else if (arg === "--pin-directory-head") {
      const head = requireValue(args, ++index, arg);
      if (!/^[0-9a-f]{64}$/.test(head)) {
        fail("--pin-directory-head needs a tenant key directory head: 64 lowercase hex digits");
      }
      options.pinDirectoryHeads.push(head);
    } else if (arg === "--trusted-keys") {
      options.trustedKeys.push(requireValue(args, ++index, arg));
    } else if (arg === "--policy-document") {
      options.policyDocuments.push(requireValue(args, ++index, arg));
    } else if (arg === "--tlog-trust") {
      options.tlogTrust = requireValue(args, ++index, arg);
    } else if (arg === "--tlog-bundle") {
      options.tlogBundle = requireValue(args, ++index, arg);
    } else {
      fail(`unknown option: ${arg}`);
    }
  }
  if (options.tlogBundle !== "" && options.tlogTrust === "") {
    fail("--tlog-bundle needs --tlog-trust: a bundle is only checked against a pinned transparency-log trust document");
  }
  if (options.quoteFile !== "" && options.answerFile === "") {
    fail("--quote-file needs --answer-file: a hash of the whole answer cannot confirm part of it");
  }
  return options;
}

function parseVerifyPDFReceiptOptions(args) {
  const options = {
    json: false,
    pdfHash: "",
    reportOut: ".intentrax/pdf-receipt-verification.report.json",
  };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--json") {
      options.json = true;
    } else if (arg === "--pdf-hash") {
      options.pdfHash = requireValue(args, ++index, arg);
    } else if (arg === "--report-out") {
      options.reportOut = requireValue(args, ++index, arg);
    } else {
      fail(`unknown option: ${arg}`);
    }
  }
  return options;
}

// Markers of the signed pre-approval formats (specs 01–03) in a proof export
// or a key set. Any match, or any pre-approval flag, loads the preapproval
// and envelope modules; a false positive only loads them.
const PREAPPROVAL_MARKERS = Object.freeze([
  "admission_binding",
  "intentrax.aep.policy_binding/1.2",
  "\"attachments\"",
  "\"disclosures\"",
  "intentrax.trust.published_key_set/1.2",
]);

// Whether the proof's signed AEP seals aep.output_binding. Decided from the
// parsed export and AEP, so a JSON escape such as "\u006futput_binding" cannot
// hide the binding; the raw-text check is a fallback for an export that does
// not parse here (the command reports it). A missing file is reported by the
// command itself.
function proofSealsOutputBinding(path) {
  if (!path) return false;
  let text;
  try {
    text = readFileSync(resolve(path), "utf8");
  } catch {
    return false;
  }
  try {
    const proofExport = JSON.parse(text);
    const canonical = isRecord(proofExport) && isRecord(proofExport.proof_record) ? proofExport.proof_record.canonical_aep_json : undefined;
    if (typeof canonical === "string") {
      const aep = JSON.parse(canonical);
      if (isRecord(aep) && Object.hasOwn(aep, "output_binding")) return true;
    }
  } catch {
    // not parseable here: fall back to the text
  }
  return text.includes("output_binding");
}

function readUTF8TextFile(path, label) {
  let bytes;
  try {
    bytes = readFileSync(resolve(path));
  } catch (error) {
    fail(`cannot read the ${label} file: ${error.code ?? error.message}`);
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail(`the ${label} file is not valid UTF-8`);
  }
}

function needsPreapprovalModules(proofExportPath, options) {
  if (options.tenantKeys.length > 0 || options.approverSets.length > 0 || options.pinDirectoryHeads.length > 0) return true;
  const paths = [...(proofExportPath ? [proofExportPath] : []), ...options.trustedKeys];
  for (const path of paths) {
    let text;
    try {
      text = readFileSync(resolve(path), "utf8");
    } catch {
      continue; // reported by the command itself
    }
    if (PREAPPROVAL_MARKERS.some((marker) => text.includes(marker))) return true;
  }
  return false;
}

function verifyProofExportCommand(proofExportPath, options) {
  if (!proofExportPath) {
    fail("verify-proof requires a proof export JSON path");
  }
  const resolvedProofExportPath = resolve(proofExportPath);
  const source = readFileSync(resolvedProofExportPath, "utf8");
  if (containsForbiddenPrivateMarker(source)) {
    fail("proof export contains private material marker");
  }
  let proofExport = parseSingleJSON(source, "proof export");
  const pa = options.preapprovalModule ?? null;
  let preapproval = null;
  if (pa !== null) {
    // Strict parse first: duplicate member names (for example inside
    // disclosed arguments) are refused, never collapsed.
    try {
      options.envelopeModule.parseJson(source);
    } catch (error) {
      fail(`proof export is not strict JSON: ${stableErrorMessage(error)}`);
    }
    const exportHadExtras = isRecord(proofExport) && (Object.hasOwn(proofExport, "attachments") || Object.hasOwn(proofExport, "disclosures"));
    let extras;
    try {
      // The unsigned attachments and disclosures come off before the lookup
      // is checked, so result_hash is computed exactly as before.
      ({ lookup: proofExport, extras } = pa.splitProofExport(proofExport));
    } catch (error) {
      fail(`proof export verification failed closed: ${stableErrorMessage(error)}`);
    }
    const readDocument = (path, label) => {
      const text = readFileSync(resolve(path), "utf8");
      if (containsForbiddenPrivateMarker(text)) fail(`${label} contains private material marker`);
      return text;
    };
    preapproval = {
      module: pa,
      envelope: options.envelopeModule,
      extras,
      exportHadExtras,
      tenantKeyDocuments: options.tenantKeys.map((path) => readDocument(path, "tenant key directory")),
      approverSetDocuments: options.approverSets.map((path) => readDocument(path, "approver set")),
      pinnedDirectoryHeads: options.pinDirectoryHeads,
    };
  }
  const keySets = loadPublishedKeySets(options.trustedKeys, pa);
  const policyDocuments = options.policyDocuments.map((path) => readFileSync(resolve(path), "utf8"));
  const transparency = loadTransparencyInputs(options);
  const outputBindingInputs = options.outputBindingModule === undefined
    ? null
    : {
      module: options.outputBindingModule,
      answer: options.answerFile === "" ? null : readUTF8TextFile(options.answerFile, "answer"),
      quote: options.quoteFile === "" ? null : readUTF8TextFile(options.quoteFile, "quote"),
    };
  const report = buildLocalProofVerificationReport(proofExport, resolvedProofExportPath, resolve(options.reportOut), keySets, policyDocuments, transparency, preapproval, outputBindingInputs);
  const reportData = JSON.stringify(report, null, 2) + "\n";
  mkdirSync(dirname(resolve(options.reportOut)), { recursive: true });
  writeFileSync(resolve(options.reportOut), reportData, { mode: 0o600 });
  return report;
}

function verifyPDFReceiptCommand(pdfPath, options) {
  if (!pdfPath) {
    fail("verify-pdf-receipt requires a PDF receipt path");
  }
  if (!options.pdfHash) {
    fail("verify-pdf-receipt requires --pdf-hash");
  }
  const resolvedPDFPath = resolve(pdfPath);
  const resolvedReportPath = resolve(options.reportOut);
  const bytes = readFileSync(resolvedPDFPath);
  const report = buildLocalPDFReceiptVerificationReport(bytes, resolvedPDFPath, resolvedReportPath, options.pdfHash);
  const reportData = JSON.stringify(report, null, 2) + "\n";
  mkdirSync(dirname(resolvedReportPath), { recursive: true });
  writeFileSync(resolvedReportPath, reportData, { mode: 0o600 });
  return report;
}

function buildLocalPDFReceiptVerificationReport(bytes, pdfPath, reportPath, expectedPDFHash) {
  const expectedHash = normalizeSHA256Hex(expectedPDFHash, "pdf_hash");
  const actualHash = sha256HexBytes(bytes);
  const pdfHeaderPresent = bytes.length >= 5 && bytes.subarray(0, 5).toString("ascii") === "%PDF-";
  const invalid = [];
  if (!pdfHeaderPresent) invalid.push("pdf_header");
  if (actualHash !== expectedHash) invalid.push("pdf_hash");
  if (invalid.length > 0) {
    fail(`pdf receipt verification failed closed: ${invalid.join(",")}`);
  }
  const withoutHash = {
    schema_version: LOCAL_PDF_RECEIPT_VERIFICATION_SCHEMA_VERSION,
    verifier_version: LOCAL_PDF_RECEIPT_VERIFIER_VERSION,
    status: "PASS",
    offline: true,
    pdf_path: pdfPath,
    report_path: reportPath,
    pdf_hash: actualHash,
    expected_pdf_hash: expectedHash,
    byte_length: bytes.length,
    hash_algorithm: "SHA-256",
    pdf_header_present: true,
    pdf_receipt_non_authoritative: true,
    canonical_json_authoritative: true,
    production_authorization_unchanged: true,
    boundary_assertions: {
      offline_verifier_used: true,
      runtime_server_not_required: true,
      network_not_required: true,
      private_key_material_absent: true,
      pdf_hash_recomputed: true,
      pdf_hash_matches_response_header: true,
      pdf_receipt_non_authoritative: true,
      canonical_json_authoritative: true,
      production_authorization_unchanged: true,
    },
    report_hash: "",
  };
  return Object.freeze({
    ...withoutHash,
    report_hash: sha256Hex(LOCAL_PDF_RECEIPT_VERIFY_DOMAIN + canonicalJson(withoutHash)),
  });
}

// Transparency-log inclusion (R7, rollout step 2): opt-in with --tlog-trust,
// mirroring the Go offline verifier (offlineproof/transparency.go). Returns
// null when no trust document was given, so the report is unchanged.
function loadTransparencyInputs(options) {
  if (options.tlogTrust === "") {
    return null;
  }
  const trustDocument = readFileSync(resolve(options.tlogTrust), "utf8");
  if (containsForbiddenPrivateMarker(trustDocument)) {
    fail("transparency-log trust document contains private material marker");
  }
  const bundle = options.tlogBundle === "" ? null : readFileSync(resolve(options.tlogBundle), "utf8");
  return { trustDocument, bundle, tlog: options.tlogModule };
}

// The transparency block for the record hash the verifier recomputed. A
// malformed trust document fails closed; a malformed bundle is a FAILED
// result in the report.
function buildTransparencyReport(proofRecordHash, transparency) {
  try {
    return transparency.tlog.transparencyReport({ proofRecordHash, trustDocument: transparency.trustDocument, bundle: transparency.bundle });
  } catch (error) {
    fail(`transparency-log trust document invalid: ${stableErrorMessage(error)}`);
  }
}

// Appends the optional TRANSPARENCY row after the fixed dimensions and
// re-derives the verdict over every row. No profile requires the row, so it
// can lower a verdict (FAILED) but never raise one.
function withTransparencyAssessment(assessment, tr, tlogModule) {
  const row = tlogModule.transparencyAssessment(tr);
  const assessments = [...assessment.assessments, row];
  const results = Object.fromEntries(assessments.map((a) => [a.dimension, a.result]));
  return {
    ...assessment,
    verdict: deriveAssuranceVerdict(results, assessment.assurance_profile),
    assessments,
    limitations: [...assessment.limitations, ...row.limitations.map((code) => ({ code, text: tlogModule.TRANSPARENCY_LIMITATION_TEXT[code] }))],
  };
}

function transparencySuffix(report) {
  return report.transparency ? ` transparency=${report.transparency.status}` : "";
}

function transparencyFailureMessage(report) {
  const codes = report.transparency.reasons.map((reason) => reason.code).join(",");
  return `intentrax: the transparency-log inclusion bundle did not verify against the pinned trust document (${codes}); this proof is NOT shown to be in the log and the bundle must not be relied on.`;
}

function buildLocalProofVerificationReport(proofExport, proofExportPath, reportPath, keySets, policyDocuments = [], transparency = null, preapproval = null, outputBindingInputs = null) {
  const invalid = validateProofLookupExport(proofExport);
  if (invalid.length > 0) {
    fail(`proof export verification failed closed: ${invalid.join(",")}`);
  }
  const record = proofExport.proof_record;
  const bundle = record.verification_bundle;
  const signatures = verifySignedProofRecord(record);
  if (signatures.invalid.length > 0) {
    fail(`proof export verification failed closed: ${signatures.invalid.join(",")}`);
  }
  // A rendered-output binding sealed in the signed AEP (aep.output_binding,
  // spec 10) must be well formed, or verification fails closed; --answer-file
  // checks an answer against it (MATCH is a match against the sealed hash,
  // never a verdict on whether the answer is correct).
  const ob = outputBindingInputs === null ? null : outputBindingInputs.module;
  const outputBinding = ob === null ? { binding: null, invalid: [] } : ob.sealedOutputBinding(record.canonical_aep_json);
  if (outputBinding.invalid.length > 0) {
    fail(`proof export verification failed closed: ${outputBinding.invalid.join(",")}`);
  }
  if (ob !== null && outputBindingInputs.answer !== null && outputBinding.binding === null) {
    fail("proof binds no answer: its signed AEP carries no output_binding to check --answer-file against");
  }
  const answerChecks = ob === null || outputBindingInputs.answer === null
    ? null
    : ob.checkAnswerAndQuote(outputBinding.binding, outputBindingInputs.answer, outputBindingInputs.quote);
  // The signed AEP bytes are verified above; a policy binding sealed in them
  // (aep.policy_binding, AEP 1.1 policy-binding profile) must be well formed
  // and is reported as sealed. Absence is never a failure.
  const pa = preapproval === null ? null : preapproval.module;
  const aepJSON = record.canonical_aep_json;
  // policy_binding/1.2 (spec 03) is parsed by the preapproval module; 1.1 by
  // the parser below, unchanged. Without the module a 1.2 binding fails
  // closed as an unknown profile.
  const policyBinding = pa !== null && sealedPolicyBindingProfile(aepJSON) === pa.POLICY_BINDING_PROFILE_V12
    ? pa.sealedPolicyBindingV12(JSON.parse(aepJSON).policy_binding)
    : sealedPolicyBinding(aepJSON);
  if (policyBinding.invalid.length > 0) {
    fail(`proof export verification failed closed: ${policyBinding.invalid.join(",")}`);
  }
  const v12 = pa !== null && policyBinding.binding !== null && policyBinding.binding.binding_profile === pa.POLICY_BINDING_PROFILE_V12;
  // Signed pre-approval admission records (spec 01 §3.4): a present
  // admission_binding must be well formed and consistent with the execution
  // id and the policy binding, or verification fails closed.
  let admissionBinding = null;
  let opened = null;
  if (pa !== null) {
    const sealed = pa.sealedAdmissionBinding(aepJSON);
    if (sealed.invalid.length > 0) {
      fail(`proof export verification failed closed: ${sealed.invalid.join(",")}`);
    }
    admissionBinding = sealed.binding;
    const inconsistency = pa.checkAdmissionConsistency(aepJSON, admissionBinding, policyBinding.binding);
    if (inconsistency !== "") {
      fail(`proof export verification failed closed: admission record inconsistent: ${inconsistency}`);
    }
    try {
      opened = pa.openDisclosures(admissionBinding, policyBinding.binding, preapproval.extras);
    } catch (error) {
      fail(`proof export verification failed closed: disclosures: ${stableErrorMessage(error)}`);
    }
  }
  const disclosedPolicyDocuments = (preapproval?.extras.policyDocuments ?? []).map((document) => (typeof document === "string" ? document : JSON.stringify(document)));
  const allPolicyDocuments = [...policyDocuments, ...disclosedPolicyDocuments];
  // Re-run the sealed evaluation (P1-C step 2); a disagreement fails closed.
  const policyReevaluation = v12 && policyBinding.binding.evaluated_facts.lane === "ADMISSION"
    ? reevaluateAdmissionPolicyBinding(aepJSON, policyBinding.binding, allPolicyDocuments, pa, opened)
    : reevaluateSealedPolicyBinding(aepJSON, policyBinding.binding, allPolicyDocuments);
  // Approval evidence (spec 02 §5): every 1.2 constraint sealed SATISFIED or
  // REJECTED is re-checked against the attached approvals.
  const approvalEvidence = pa === null ? [] : pa.checkApprovalEvidence(record.tenant_id, admissionBinding, policyBinding.binding, opened.argumentsHash, {
    attachments: preapproval.extras.attachments,
    approverSets: [...preapproval.extras.approverSets, ...preapproval.approverSetDocuments],
    directories: [...preapproval.extras.directories, ...preapproval.tenantKeyDocuments],
    pinnedDirectoryHeads: preapproval.pinnedDirectoryHeads,
    directoryKeys: envelopeKeyResolver(keySets, "TENANT_KEY_DIRECTORY", preapproval.envelope),
    approvalServiceKeys: envelopeKeyResolver(keySets, "APPROVAL_SERVICE", preapproval.envelope),
  });
  // A sealed admission decision carries the record's signing time.
  const signingTime = admissionBinding === null ? null : preapproval.envelope.parseTime(admissionBinding.decided_at);
  const trust = classifySignerTrust(signatures.signers, keySets, signingTime, preapproval === null ? null : preapproval.envelope.parseTime);
  const tlog = transparency === null ? null : buildTransparencyReport(record.record_hash, transparency);
  const assessmentInput = { signerTrust: trust.signer_trust, keySetSupplied: keySets.length > 0, policyBinding: policyBinding.binding, policyReevaluation };
  const legacyAssessment = pa === null
    ? buildLegacyVerificationAssessment(assessmentInput)
    : pa.buildPreapprovalAssessment({ ...assessmentInput, admissionBinding, approvalEvidence });
  // A FAILED transparency check is never hidden: status names it and the
  // exit code is non-zero, whatever the signer outcome. Neither is bad
  // approval evidence bound by the record (spec 02 §5.2).
  const signerStatus = trust.signer_trust === "TRUSTED" ? "PASS" : trust.signer_trust;
  const approvalEvidenceInvalid = approvalEvidence.some((check) => check.status === "INVALID");
  const policyStatement = policyBinding.binding === null
    ? ""
    : v12
      ? [pa.policyBindingV12Statement(policyBinding.binding), ...approvalEvidence.filter((check) => check.status === "VERIFIED").map((check) => check.statement)].join(" ")
      : policyBindingStatement(policyBinding.binding);
  const withoutHash = {
    schema_version: LOCAL_PROOF_VERIFICATION_SCHEMA_VERSION,
    verifier_version: LOCAL_PROOF_VERIFIER_VERSION,
    // PASS only when every signer is a published, trust-bearing key and at least
    // min_trusted_signers distinct trusted keys signed. Valid signatures from
    // keys you have not chosen to trust prove nothing about who signed, so they
    // never yield PASS.
    // An answer that is not the bound answer (--answer-file) is
    // ANSWER_MISMATCH: exit 1, or 3 when the signers are not trusted either.
    status: approvalEvidenceInvalid ? "APPROVAL_EVIDENCE_INVALID"
      : tlog !== null && tlog.status === "FAILED" ? "TRANSPARENCY_FAILED"
        : answerChecks !== null && answerChecks.answer_check.status !== "MATCH" ? "ANSWER_MISMATCH"
          : signerStatus,
    signer_trust: trust.signer_trust,
    trust_bearing: trust.signer_trust === "TRUSTED",
    signature_verification: {
      algorithm: "ED25519",
      signed_bytes: "verification_bundle.payload.canonical_payload_json",
      required_signatures: signatures.required,
      valid_signatures: signatures.signers.length,
      // The published policy from the key sets, not the proof's own quorum: a
      // proof's roster and quorum metadata can be reduced together.
      min_trusted_signers: trust.min_trusted_signers,
      distinct_trusted_signers: trust.distinct_trusted_signers,
      signers: trust.signers,
    },
    key_sets: keySets.map((set) => ({ key_set_id: set.key_set_id, environment: set.environment, source: set.source })),
    offline: true,
    proof_export_path: proofExportPath,
    report_path: reportPath,
    tenant_id: record.tenant_id,
    registry_entry_id: record.registry_entry_id,
    aep_hash: record.aep_hash,
    proof_record_hash: record.record_hash,
    proof_lookup_hash: proofExport.result_hash,
    verification_bundle_hash: bundle.bundle_hash,
    // Present only when the signed AEP seals one: RECORD_ONLY means the
    // policy evaluation was recorded, never that it was enforced.
    // policy_binding_statement says the same in words (shared wording with
    // the Go verifier and the public verify page): every constraint's status
    // is spelled out, so an unchecked approval reads NOT CHECKED.
    ...(policyBinding.binding === null
      ? {}
      : {
        policy_binding: policyBinding.binding,
        policy_binding_statement: policyStatement,
        // MATCH when the sealed evaluation was re-run and came out identical;
        // NOT_RECHECKED (with a reason) when it could not be re-run. Never
        // silently passes: a re-run that disagrees fails verification.
        policy_reevaluation: policyReevaluation,
      }),
    // Signed pre-approval (specs 01–03; same members as the Go verifier),
    // each present only when it applies, so every other report is unchanged.
    ...(admissionBinding === null ? {} : { admission_binding: admissionBinding, admission_binding_statement: pa.admissionBindingStatement(admissionBinding) }),
    ...(approvalEvidence.length === 0 ? {} : { approval_evidence: approvalEvidence }),
    ...(preapproval === null || !preapproval.exportHadExtras ? {} : { disclosures: opened.report }),
    // Rendered-output binding (spec 10; same members as the Go verifier):
    // the binding as sealed and who computed its hash, in words. A
    // PRODUCER_DECLARED_AT_ISSUANCE binding never reads as computed by
    // Intentrax. answer_check / quote_check only with --answer-file /
    // --quote-file.
    ...(outputBinding.binding === null ? {} : { output_binding: outputBinding.binding, output_binding_statement: ob.outputBindingStatement(outputBinding.binding) }),
    ...(answerChecks === null ? {} : { answer_check: answerChecks.answer_check }),
    ...(answerChecks === null || answerChecks.quote_check === null ? {} : { quote_check: answerChecks.quote_check }),
    hash_algorithm: "SHA-256",
    boundary_assertions: {
      offline_verifier_used: true,
      runtime_server_not_required: true,
      network_not_required: true,
      private_key_material_absent: true,
      proof_lookup_hash_recomputed: true,
      proof_record_hash_recomputed: true,
      registry_bundle_hash_recomputed: true,
      aep_hash_recomputed: true,
      ed25519_signatures_verified: true,
      signature_quorum_satisfied: true,
      signed_payload_binds_record_aep: true,
      signers_pinned_to_published_keys: trust.signer_trust === "TRUSTED" || trust.signer_trust === "SANDBOX_NON_TRUST_BEARING" || trust.signer_trust === "INSUFFICIENT_TRUSTED_SIGNERS",
      min_trusted_signers_met: trust.signer_trust === "TRUSTED",
      canonical_json_authoritative: true,
      pdf_receipt_non_authoritative: true,
    },
    // Additive: what this proof establishes and what it does not (assurance
    // profile, per-dimension results, verdict by the fixed rule,
    // machine-readable limitations). status, signer_trust and the exit code
    // are unchanged. Covered by report_hash.
    verification_assessment: tlog === null ? legacyAssessment : withTransparencyAssessment(legacyAssessment, tlog, transparency.tlog),
    // Present only with --tlog-trust: transparency-log inclusion of this
    // record (VERIFIED, VERIFIED_UNWITNESSED, NOT_PRESENT or FAILED).
    ...(tlog === null ? {} : { transparency: tlog }),
    report_hash: "",
  };
  return Object.freeze({
    ...withoutHash,
    report_hash: sha256Hex(LOCAL_PROOF_VERIFY_DOMAIN + canonicalJson(withoutHash)),
  });
}

// Policy re-evaluation (P1-C step 2). Mirrors the Go offline verifier
// (engine/internal/verificationinfra/offlineproof/policy_reevaluation.go):
// rebuild the evaluated event from the signed AEP, resolve the policy document
// by its source policy hash (a --policy-document first, then the bundled
// published registry), re-run it with the TS port of the policy engine and
// require every sealed value to come out identical.
// The runtime lane the signed AEP itself names (execution_id prefix and
// policy.policy_id together), or "" when it names none.
function signedRuntimeLane(canonicalAEPJSON) {
  let aep;
  try {
    aep = JSON.parse(canonicalAEPJSON);
  } catch {
    return "";
  }
  const executionID = isRecord(aep) && typeof aep.execution_id === "string" ? aep.execution_id : "";
  const policyID = isRecord(aep) && isRecord(aep.policy) && typeof aep.policy.policy_id === "string" ? aep.policy.policy_id : "";
  const marker = RUNTIME_LANE_MARKERS.find((entry) => executionID.startsWith(entry.executionIDPrefix) && policyID === entry.policyID);
  return marker === undefined ? "" : marker.lane;
}

// Rebuilds the evaluated event from policy_binding.evaluated_facts, or null
// for a binding sealed before step 2. The sealed lane must be the lane the
// signed AEP itself names; otherwise verification fails closed.
function reconstructPolicyEvent(canonicalAEPJSON, binding) {
  const facts = binding.evaluated_facts;
  if (facts === undefined) return null;
  const lane = signedRuntimeLane(canonicalAEPJSON);
  if (lane !== facts.lane) {
    fail(`proof export verification failed closed: policy re-evaluation: policy_binding.evaluated_facts.lane "${facts.lane}" does not match the signed proof's lane "${lane}"`);
  }
  return {
    event: { eeo: { execution_domain: { lane: facts.lane, mutation_performed: facts.mutation_performed } } },
    allowedEventFields: [...RUNTIME_POLICY_EVENT_FIELDS],
  };
}

function resolvePolicyDocument(sourcePolicyHash, allowedEventFields, policyDocuments) {
  const compile = (document) => {
    try {
      const compiled = compilePolicyDocument(document, allowedEventFields);
      return compiled.source_policy_hash === sourcePolicyHash ? compiled : null;
    } catch {
      return null;
    }
  };
  for (const document of policyDocuments) {
    const compiled = compile(document);
    if (compiled !== null) return { compiled, source: "SUPPLIED_DOCUMENT" };
  }
  if (/^[a-f0-9]{64}$/.test(sourcePolicyHash)) {
    const url = new URL(`${sourcePolicyHash}.json`, BUILT_IN_POLICY_REGISTRY_URL);
    if (existsSync(url)) {
      const compiled = compile(readFileSync(url, "utf8"));
      if (compiled !== null) return { compiled, source: "PUBLISHED_REGISTRY" };
    }
  }
  return null;
}

// The binding_profile of a sealed policy binding, or "" when there is none.
function sealedPolicyBindingProfile(canonicalAEPJSON) {
  try {
    const aep = JSON.parse(canonicalAEPJSON);
    return isRecord(aep) && isRecord(aep.policy_binding) && typeof aep.policy_binding.binding_profile === "string" ? aep.policy_binding.binding_profile : "";
  } catch {
    return "";
  }
}

// Re-runs a policy_binding/1.2 evaluation on the ADMISSION lane (spec 03 §6):
// the event is rebuilt from plaintext facts plus the facts and event salt the
// export's disclosures opened, and re-run with the tenant request profile.
// Withheld facts without openings are NOT_RECHECKED / FACTS_WITHHELD.
function reevaluateAdmissionPolicyBinding(canonicalAEPJSON, binding, policyDocuments, pa, opened) {
  let rebuilt;
  try {
    rebuilt = pa.admissionPolicyEvent(canonicalAEPJSON, binding, opened === null ? { facts: {}, salt: "" } : { facts: opened.facts, salt: opened.salt });
  } catch (error) {
    fail(`proof export verification failed closed: policy re-evaluation: ${stableErrorMessage(error)}`);
  }
  if (rebuilt.notRechecked) return { status: "NOT_RECHECKED", reason: rebuilt.notRechecked };
  const resolved = resolvePolicyDocument(binding.source_policy_hash, rebuilt.allowedEventFields, policyDocuments);
  if (resolved === null) return { status: "NOT_RECHECKED", reason: "POLICY_SOURCE_UNAVAILABLE" };
  let recomputed;
  try {
    recomputed = evaluateCompiledPolicy(resolved.compiled, rebuilt.event);
  } catch (error) {
    fail(`proof export verification failed closed: policy re-evaluation failed: ${error.message}`);
  }
  const mismatches = policyReevaluationMismatches(binding, recomputed);
  if (mismatches.length > 0) {
    fail(`proof export verification failed closed: policy re-evaluation mismatch: ${mismatches.join(",")}`);
  }
  return { status: "MATCH", policy_source: resolved.source };
}

// Envelope signers of one purpose (TENANT_KEY_DIRECTORY, APPROVAL_SERVICE),
// pinned by trust-bearing keys of that purpose in published_key_set/1.2 sets,
// or null when no set pins any. The same key may appear in several sets (the
// bundled ones, --trusted-keys). Every entry for the same key_id + key_version
// in ANY supplied set counts, whatever its purpose, trust_bearing or schema:
// - a different public key or a different purpose resolves to no key;
// - any revocation applies: KEY_COMPROMISE, or a revocation without
//   revoked_at (every 1.0/1.1 one), applies at every signing time, otherwise
//   the earliest revoked_at;
// - the validity window is the intersection of the 1.2 windows.
function envelopeKeyResolver(keySets, purpose, envelope) {
  const isV12 = (set) => set.schema_version === "intentrax.trust.published_key_set/1.2";
  const entryPurpose = (key, set) => (isV12(set) && typeof key.purpose === "string" && key.purpose !== "" ? key.purpose : "AEP_RECORD");
  if (!keySets.some((set) => isV12(set) && set.keys.some((key) => key.trust_bearing === true && entryPurpose(key, set) === purpose))) return null;
  const later = (a, b) => (a === undefined ? b : b === undefined ? a : a > b ? a : b);
  const earlier = (a, b) => (a === undefined ? b : b === undefined ? a : a < b ? a : b);
  const time = (set, value) => (isV12(set) && typeof value === "string" && value !== "" ? envelope.parseTime(value) : undefined);
  return {
    resolveKey(keyId, keyVersion) {
      const entries = [];
      for (const set of keySets) {
        for (const key of set.keys) {
          if (key.key_id === keyId && key.key_version === keyVersion) entries.push({ key, set });
        }
      }
      const trusted = entries.filter(({ key, set }) => isV12(set) && key.trust_bearing === true && entryPurpose(key, set) === purpose);
      if (trusted.length === 0) return undefined;
      const publicKeyHex = trusted[0].key.public_key_material;
      if (entries.some(({ key, set }) => key.public_key_material !== publicKeyHex || entryPurpose(key, set) !== purpose)) return undefined;
      // The least trusting entry decides: any non-trust-bearing listing of the
      // same key, revoked or not, leaves it untrusted (as for AEP signers).
      if (entries.some(({ key }) => key.trust_bearing !== true)) return undefined;
      let validFrom;
      let validUntil;
      let revokedAt;
      let revocationReason = "";
      for (const { key, set } of entries) {
        validFrom = later(validFrom, time(set, key.valid_from));
        validUntil = earlier(validUntil, time(set, key.valid_until));
        if (key.status !== "REVOKED") continue;
        const at = time(set, key.revoked_at);
        if (at === undefined || key.revocation_reason === "KEY_COMPROMISE") {
          revocationReason = "KEY_COMPROMISE";
        } else if (revocationReason !== "KEY_COMPROMISE" && (revokedAt === undefined || at < revokedAt)) {
          revokedAt = at;
          revocationReason = key.revocation_reason;
        }
      }
      return envelope.pinnedKeys([{ keyId, keyVersion, publicKeyHex, purpose, validFrom, validUntil, revokedAt, revocationReason }]).resolveKey(keyId, keyVersion);
    },
  };
}

function reevaluateSealedPolicyBinding(canonicalAEPJSON, binding, policyDocuments) {
  if (binding === null) return null;
  const event = reconstructPolicyEvent(canonicalAEPJSON, binding);
  if (event === null) return { status: "NOT_RECHECKED", reason: "EVENT_NOT_RECONSTRUCTIBLE" };
  const resolved = resolvePolicyDocument(binding.source_policy_hash, event.allowedEventFields, policyDocuments);
  if (resolved === null) return { status: "NOT_RECHECKED", reason: "POLICY_SOURCE_UNAVAILABLE" };
  let recomputed;
  try {
    recomputed = evaluateCompiledPolicy(resolved.compiled, event.event);
  } catch (error) {
    fail(`proof export verification failed closed: policy re-evaluation failed: ${error.message}`);
  }
  const mismatches = policyReevaluationMismatches(binding, recomputed);
  if (mismatches.length > 0) {
    fail(`proof export verification failed closed: policy re-evaluation mismatch: ${mismatches.join(",")}`);
  }
  return { status: "MATCH", policy_source: resolved.source };
}

// AEP 1.1 policy-binding profile (aep.policy_binding): the RECORD_ONLY
// evaluation of a hash-pinned policy, sealed inside the signed AEP. Mirrors
// the Go verifier (engine/internal/registrylayer/persistence/policy_binding.go):
// absent => no binding and no failure; present => exactly these members, all
// strings except constraints (mandate_hash optional), the supported
// profile/algorithm/enforcement, a policy VM decision, 64-hex non-degenerate
// hashes, and a constraints array whose entries carry an explicit status
// (SATISFIED requires evidence_hash, NOT_EVALUATED forbids it, ids unique and
// ascending); anything else fails closed. It never means the decision was
// enforced.
const POLICY_BINDING_PROFILE = "intentrax.aep.policy_binding/1.1";
const POLICY_BINDING_OPTIONAL_MEMBERS = Object.freeze(["evaluated_facts", "mandate_hash"]);
const POLICY_EVALUATED_LANES = new Set(["DRY_RUN", "LIVE_EXECUTE"]);
// The runtime execution-event profile (engine recheck.RuntimeEventFields /
// RuntimeExecutionEvent) and the lane markers the signed AEP itself carries
// (engine proofproduction DryRunLane / LiveExecuteLane).
const RUNTIME_POLICY_EVENT_FIELDS = Object.freeze(["eeo.execution_domain.lane", "eeo.execution_domain.mutation_performed"]);
const RUNTIME_LANE_MARKERS = Object.freeze([
  Object.freeze({ lane: "DRY_RUN", executionIDPrefix: "runtime-dry-run-", policyID: "intentrax.runtime.private_alpha.dry_run" }),
  Object.freeze({ lane: "LIVE_EXECUTE", executionIDPrefix: "runtime-execute-", policyID: "intentrax.runtime.private_alpha.live_execute" }),
]);
const POLICY_BINDING_REQUIRED_MEMBERS = Object.freeze([
  "binding_profile", "compiled_policy_hash", "constraints", "decision", "enforcement", "evaluation_hash",
  "execution_event_hash", "hash_algorithm", "policy_id", "policy_version", "rule_id", "source_policy_hash",
]);
const POLICY_CONSTRAINT_MEMBERS = Object.freeze(["constraint_id", "status", "type"]);
const POLICY_CONSTRAINT_SATISFIED = "SATISFIED";
const POLICY_CONSTRAINT_NOT_EVALUATED = "NOT_EVALUATED";
const POLICY_BINDING_HASH_MEMBERS = Object.freeze(["compiled_policy_hash", "evaluation_hash", "execution_event_hash", "source_policy_hash"]);
const POLICY_BINDING_DECISIONS = new Set(["COMPLIANT", "NON_COMPLIANT", "ERROR"]);

function isPolicyBindingHash(value) {
  return isSHA256(value) && !/^(.)\1{63}$/.test(value);
}

function sealedPolicyBinding(canonicalAEPJSON) {
  let aep;
  try {
    aep = JSON.parse(canonicalAEPJSON);
  } catch {
    return { binding: null, invalid: [] };
  }
  if (!isRecord(aep) || !Object.hasOwn(aep, "policy_binding")) return { binding: null, invalid: [] };
  const binding = aep.policy_binding;
  if (!isRecord(binding)) return { binding: null, invalid: ["policy_binding"] };
  const members = Object.keys(binding).sort();
  const expected = [...POLICY_BINDING_REQUIRED_MEMBERS, ...POLICY_BINDING_OPTIONAL_MEMBERS.filter((member) => Object.hasOwn(binding, member))].sort();
  if (members.length !== expected.length || members.some((member, index) => member !== expected[index])) {
    return { binding: null, invalid: ["policy_binding.members"] };
  }
  const invalid = [];
  for (const member of members) {
    if (member !== "constraints" && member !== "evaluated_facts" && typeof binding[member] !== "string") invalid.push(`policy_binding.${member}`);
  }
  if (invalid.length > 0) return { binding: null, invalid };
  // evaluated_facts (P1-C step 2): exactly a string lane and a boolean
  // mutation_performed. Optional: bindings sealed before step 2 omit it.
  let evaluatedFacts;
  if (Object.hasOwn(binding, "evaluated_facts")) {
    const facts = binding.evaluated_facts;
    const factMembers = isRecord(facts) ? Object.keys(facts).sort() : [];
    if (!isRecord(facts) || factMembers.length !== 2 || factMembers[0] !== "lane" || factMembers[1] !== "mutation_performed"
      || typeof facts.lane !== "string" || typeof facts.mutation_performed !== "boolean") {
      return { binding: null, invalid: ["policy_binding.evaluated_facts"] };
    }
    if (!POLICY_EVALUATED_LANES.has(facts.lane)) invalid.push("policy_binding.evaluated_facts.lane");
    evaluatedFacts = Object.freeze({ lane: facts.lane, mutation_performed: facts.mutation_performed });
  }
  const constraints = sealedPolicyConstraints(binding.constraints);
  if (constraints.malformed.length > 0) return { binding: null, invalid: constraints.malformed };
  invalid.push(...constraints.invalid);
  if (binding.binding_profile !== POLICY_BINDING_PROFILE) invalid.push("policy_binding.binding_profile");
  if (!POLICY_BINDING_DECISIONS.has(binding.decision)) invalid.push("policy_binding.decision");
  if (binding.enforcement !== "RECORD_ONLY") invalid.push("policy_binding.enforcement");
  if (binding.hash_algorithm !== "SHA-256") invalid.push("policy_binding.hash_algorithm");
  const hashMembers = Object.hasOwn(binding, "mandate_hash") ? [...POLICY_BINDING_HASH_MEMBERS, "mandate_hash"] : POLICY_BINDING_HASH_MEMBERS;
  for (const member of hashMembers) {
    if (!isPolicyBindingHash(binding[member])) invalid.push(`policy_binding.${member}`);
  }
  for (const member of ["policy_id", "policy_version", "rule_id"]) {
    if (binding[member] === "") invalid.push(`policy_binding.${member}`);
  }
  if (invalid.length > 0) return { binding: null, invalid: invalid.sort() };
  const normalized = {};
  for (const member of members) normalized[member] = member === "constraints" ? constraints.list : member === "evaluated_facts" ? evaluatedFacts : binding[member];
  return { binding: Object.freeze(normalized), invalid: [] };
}

function sealedPolicyConstraints(value) {
  if (!Array.isArray(value)) return { list: [], malformed: ["policy_binding.constraints"], invalid: [] };
  const list = [];
  const invalid = [];
  for (const [index, constraint] of value.entries()) {
    const at = `policy_binding.constraints[${index}]`;
    if (!isRecord(constraint)) return { list: [], malformed: [at], invalid: [] };
    const members = Object.keys(constraint).sort();
    const expected = Object.hasOwn(constraint, "evidence_hash")
      ? [...POLICY_CONSTRAINT_MEMBERS, "evidence_hash"].sort()
      : [...POLICY_CONSTRAINT_MEMBERS];
    if (members.length !== expected.length || members.some((member, i) => member !== expected[i])) {
      return { list: [], malformed: [`${at}.members`], invalid: [] };
    }
    for (const member of members) {
      if (typeof constraint[member] !== "string") return { list: [], malformed: [`${at}.${member}`], invalid: [] };
    }
    if (constraint.constraint_id === "" || (index > 0 && constraint.constraint_id <= value[index - 1].constraint_id)) {
      invalid.push(`${at}.constraint_id`);
    }
    if (constraint.type === "") invalid.push(`${at}.type`);
    if (constraint.status === POLICY_CONSTRAINT_SATISFIED) {
      if (!isPolicyBindingHash(constraint.evidence_hash)) invalid.push(`${at}.evidence_hash`);
    } else if (constraint.status === POLICY_CONSTRAINT_NOT_EVALUATED) {
      if (Object.hasOwn(constraint, "evidence_hash")) invalid.push(`${at}.evidence_hash`);
    } else {
      invalid.push(`${at}.status`);
    }
    const normalized = {};
    for (const member of members) normalized[member] = constraint[member];
    list.push(Object.freeze(normalized));
  }
  return { list: Object.freeze(list), malformed: [], invalid };
}

// The shared verifier wording for a verified policy binding (identical to
// PolicyBindingStatement in the Go verifier and the public verify facade).
function policyBindingStatement(binding) {
  const head = `Policy ${binding.policy_id}@${binding.policy_version} evaluated ${binding.decision} (rule ${binding.rule_id}); recorded only, never enforced.`;
  if (binding.constraints.length === 0) return `${head} The matched rule has no constraints.`;
  return [head, ...binding.constraints.map(policyConstraintStatement)].join(" ");
}

function policyConstraintStatement(constraint) {
  if (constraint.status === POLICY_CONSTRAINT_SATISFIED) {
    return `Constraint ${constraint.constraint_id} (${constraint.type}): SATISFIED; evidence ${constraint.evidence_hash} is bound by this proof.`;
  }
  return `Constraint ${constraint.constraint_id} (${constraint.type}): NOT CHECKED (NOT_EVALUATED); this proof binds no evidence that it was met.`;
}

// Verifies what the record's integrity hashes cannot: that the signatures are
// genuine ed25519 signatures over the signed payload, that enough of them are
// present, and that the signed payload carries this record's own AEP. Without
// the last check the AEP (and every hash derived from it) could be rewritten
// after signing while the original signatures still verify.
function verifySignedProofRecord(record) {
  const invalid = [];
  const bundle = record.verification_bundle;
  const payload = bundle.payload;
  const signatureBundle = isRecord(bundle.registry_output) ? bundle.registry_output.signature : undefined;
  const quorum = isRecord(bundle.key_binding) && isRecord(bundle.key_binding.quorum) ? bundle.key_binding.quorum : undefined;
  if (!isRecord(payload) || typeof payload.canonical_payload_json !== "string" || !isSHA256(payload.payload_hash)) invalid.push("verification_bundle.payload");
  if (!isRecord(signatureBundle) || !Array.isArray(signatureBundle.signatures)) invalid.push("verification_bundle.registry_output.signature");
  if (!isRecord(quorum) || !Number.isInteger(quorum.required_signatures) || quorum.required_signatures < 1) invalid.push("verification_bundle.key_binding.quorum");
  if (invalid.length > 0) return { invalid, signers: [], required: 0 };

  if (sha256Hex(AEP_HASH_DOMAIN + record.canonical_aep_json) !== record.aep_hash) invalid.push("proof_record.aep_hash");
  if (sha256Hex(SIGNATURE_PAYLOAD_HASH_DOMAIN + payload.canonical_payload_json) !== payload.payload_hash) invalid.push("verification_bundle.payload.payload_hash");
  if (signatureBundle.payload_hash !== payload.payload_hash) invalid.push("verification_bundle.registry_output.signature.payload_hash");
  let signedPayload;
  try {
    signedPayload = JSON.parse(payload.canonical_payload_json);
  } catch {
    signedPayload = undefined;
  }
  const signedFields = isRecord(signedPayload) ? Object.keys(signedPayload) : [];
  const bindsRecord = isRecord(signedPayload)
    && signedFields.length === SIGNATURE_PAYLOAD_FIELDS.length
    && SIGNATURE_PAYLOAD_FIELDS.every((field, index) => signedFields[index] === field)
    && signedPayload.payload_version === SIGNATURE_PAYLOAD_VERSION
    && signedPayload.canonical_aep_json === record.canonical_aep_json
    && signedPayload.aep_hash === record.aep_hash
    && isRecord(payload.payload)
    && payload.payload.canonical_aep_json === signedPayload.canonical_aep_json
    && payload.payload.aep_hash === signedPayload.aep_hash;
  if (!bindsRecord) invalid.push("verification_bundle.payload.canonical_payload_json");

  invalid.push(...validateSignerRoster(bundle, signatureBundle, quorum, payload));

  const signedBytes = Buffer.from(payload.canonical_payload_json, "utf8");
  const keyReferences = Array.isArray(bundle.key_references) ? [...bundle.key_references] : [];
  keyReferences.sort((a, b) => `${a.key_id}\u0000${a.key_version}`.localeCompare(`${b.key_id}\u0000${b.key_version}`));
  const signers = [];
  const seen = new Set();
  for (const key of keyReferences) {
    const keyLabel = `${key.key_id}@${key.key_version}`;
    if (seen.has(keyLabel)) {
      invalid.push("verification_bundle.key_references.duplicate");
      continue;
    }
    seen.add(keyLabel);
    if (key.key_status === "REVOKED") {
      invalid.push("verification_bundle.key_references.key_status");
      continue;
    }
    if (key.algorithm !== "ED25519" || !/^[0-9a-f]{64}$/.test(String(key.public_key_material))) {
      invalid.push("verification_bundle.key_references.public_key_material");
      continue;
    }
    const signature = signatureBundle.signatures.find((candidate) => isRecord(candidate) && candidate.key_id === key.key_id && candidate.key_version === key.key_version);
    if (!signature || !/^[0-9a-f]{128}$/.test(String(signature.signature_hex))) {
      invalid.push("verification_bundle.registry_output.signature.signatures");
      continue;
    }
    if (signature.public_key_hash !== sha256Hex(key.public_key_material)) {
      invalid.push("verification_bundle.registry_output.signature.signatures.public_key_hash");
      continue;
    }
    let valid = false;
    try {
      const publicKey = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(key.public_key_material, "hex")]), format: "der", type: "spki" });
      valid = verifySignatureBytes(null, signedBytes, publicKey, Buffer.from(signature.signature_hex, "hex"));
    } catch {
      valid = false;
    }
    if (!valid) {
      invalid.push("verification_bundle.registry_output.signature.signatures.signature_hex");
      continue;
    }
    signers.push({ key_id: key.key_id, key_version: key.key_version, public_key_material: key.public_key_material, public_key_hash: signature.public_key_hash });
  }
  if (invalid.length === 0 && signers.length < quorum.required_signatures) invalid.push("verification_bundle.key_binding.quorum");
  return { invalid: sortedUnique(invalid), signers, required: quorum.required_signatures };
}

// The signer roster (key_references), the key bindings and the signature bundle
// must describe the same signers one-to-one, and the quorum metadata must agree
// everywhere. Mirrors the engine's validateBindingAndSignatureMetadata. Without
// it, an export could drop a failing signer's key reference and lower the
// quorum, and the remaining valid signature would satisfy it.
function validateSignerRoster(bundle, signatureBundle, quorum, payload) {
  const invalid = [];
  const keyReferences = Array.isArray(bundle.key_references) ? bundle.key_references : [];
  const bindingList = isRecord(bundle.key_binding) && Array.isArray(bundle.key_binding.keys) ? bundle.key_binding.keys : [];
  const signatureList = signatureBundle.signatures;
  const tokenOf = (entry) => (isRecord(entry) ? `${entry.key_id}\u0000${entry.key_version}` : "\u0000invalid");

  if (signatureBundle.required_signatures !== quorum.required_signatures) invalid.push("verification_bundle.registry_output.signature.required_signatures");
  if (!Number.isInteger(quorum.total_signers)
    || quorum.required_signatures > quorum.total_signers
    || signatureBundle.total_signers !== quorum.total_signers
    || quorum.total_signers !== keyReferences.length) {
    invalid.push("verification_bundle.registry_output.signature.total_signers");
  }

  const index = (list, duplicateField) => {
    const map = new Map();
    for (const entry of list) {
      const token = tokenOf(entry);
      if (map.has(token)) invalid.push(duplicateField);
      map.set(token, entry);
    }
    return map;
  };
  const bindings = index(bindingList, "verification_bundle.key_binding.keys.duplicate");
  const signatures = index(signatureList, "verification_bundle.registry_output.signature.signatures.duplicate");
  const references = index(keyReferences, "verification_bundle.key_references.duplicate");

  for (const [token, key] of references) {
    const binding = bindings.get(token);
    if (!binding) {
      invalid.push("verification_bundle.key_binding.keys");
      continue;
    }
    const expectedPublicKeyHash = sha256Hex(String(key.public_key_material));
    if (binding.algorithm !== "ED25519" || key.algorithm !== "ED25519") invalid.push("verification_bundle.key_binding.keys.algorithm");
    if (binding.key_status !== key.key_status) invalid.push("verification_bundle.key_binding.keys.key_status");
    if (binding.principal_id !== key.principal_id) invalid.push("verification_bundle.key_binding.keys.principal_id");
    if (binding.public_key_hash !== expectedPublicKeyHash) invalid.push("verification_bundle.key_binding.keys.public_key_hash");
    if (!isSHA256(binding.key_binding_hash)) invalid.push("verification_bundle.key_binding.keys.key_binding_hash");
    const signature = signatures.get(token);
    if (!signature) {
      invalid.push("verification_bundle.registry_output.signature.signatures");
      continue;
    }
    if (signature.algorithm !== "ED25519") invalid.push("verification_bundle.registry_output.signature.signatures.algorithm");
    if (signature.payload_hash !== payload.payload_hash) invalid.push("verification_bundle.registry_output.signature.signatures.payload_hash");
    if (signature.key_binding_hash !== binding.key_binding_hash) invalid.push("verification_bundle.registry_output.signature.signatures.key_binding_hash");
  }
  // Every binding and every signature must belong to a listed signer: nothing
  // may be dropped from the roster while its signature or binding stays behind.
  for (const token of bindings.keys()) {
    if (!references.has(token)) invalid.push("verification_bundle.key_references");
  }
  for (const token of signatures.keys()) {
    if (!references.has(token)) invalid.push("verification_bundle.key_references");
  }
  return invalid;
}

// A published key set pins who may sign: production keys (trust_bearing) or
// sandbox keys (not trust-bearing). The SDK ships both published sets; extra sets
// (or revocations) can be supplied with --trusted-keys.
// pa is the preapproval module when loaded: it adds published_key_set/1.2
// (spec 00 §5, per-key purpose and validity). Without it a 1.2 set is an
// unknown schema and fails closed, as before.
function loadPublishedKeySets(trustedKeyPaths, pa = null) {
  const sets = [];
  for (const url of BUILT_IN_KEY_SET_URLS) {
    if (existsSync(url)) {
      sets.push(parsePublishedKeySet(readFileSync(url, "utf8"), `built-in:trust/${url.pathname.split("/").pop()}`, pa));
    }
  }
  for (const keySetPath of trustedKeyPaths) {
    sets.push(parsePublishedKeySet(readFileSync(resolve(keySetPath), "utf8"), resolve(keySetPath), pa));
  }
  return sets;
}

function parsePublishedKeySet(source, origin, pa = null) {
  if (containsForbiddenPrivateMarker(source)) {
    fail(`trusted key set contains private material marker: ${origin}`);
  }
  const set = parseSingleJSON(source, "trusted key set");
  const invalid = [];
  const v12 = pa !== null && isRecord(set) && set.schema_version === pa.PUBLISHED_KEY_SET_SCHEMA_VERSION_V12;
  if (!isRecord(set) || !(v12 || [PUBLISHED_KEY_SET_SCHEMA_VERSION, PUBLISHED_KEY_SET_SCHEMA_VERSION_V1].includes(set.schema_version))) invalid.push("schema_version");
  if (isRecord(set) && !stableNonEmpty(set.key_set_id)) invalid.push("key_set_id");
  if (!isRecord(set) || !Array.isArray(set.keys) || set.keys.length === 0) invalid.push("keys");
  if (isRecord(set) && Array.isArray(set.keys)) {
    const keyIds = new Set(set.keys.filter(isRecord).map((key) => key.key_id));
    if (v12) {
      // 1.2: min_trusted_signers counts AEP_RECORD key_ids only (spec 00 §5).
      const aepKeyIds = new Set(set.keys.filter((key) => isRecord(key) && pa.anchorPurpose(key) === "AEP_RECORD").map((key) => key.key_id));
      if (!Number.isInteger(set.min_trusted_signers) || set.min_trusted_signers < 1 || set.min_trusted_signers > aepKeyIds.size) invalid.push("min_trusted_signers");
    } else if (set.schema_version === PUBLISHED_KEY_SET_SCHEMA_VERSION) {
      // The policy must be satisfiable by this set's own keys.
      if (!Number.isInteger(set.min_trusted_signers) || set.min_trusted_signers < 1 || set.min_trusted_signers > keyIds.size) invalid.push("min_trusted_signers");
    } else if (set.schema_version === PUBLISHED_KEY_SET_SCHEMA_VERSION_V1) {
      if (Object.hasOwn(set, "min_trusted_signers")) invalid.push("min_trusted_signers");
      // A 1.0 set cannot state a minimum trusted-signer count, so it may not anchor trust.
      if (set.keys.some((key) => isRecord(key) && key.trust_bearing === true)) invalid.push("schema_version");
    }
  }
  if (isRecord(set) && Array.isArray(set.keys)) {
    const seenIdVersions = new Set();
    for (const [index, key] of set.keys.entries()) {
      // One entry per key_id + key_version: a duplicate would let the first
      // match hide a later revocation or a different public key (the Go
      // verifier refuses it as duplicate_key_id_version).
      if (isRecord(key)) {
        const idVersion = `${key.key_id}\u0000${key.key_version}`;
        if (seenIdVersions.has(idVersion)) invalid.push("duplicate_key_id_version");
        seenIdVersions.add(idVersion);
      }
      if (!isRecord(key)
        || !stableNonEmpty(key.key_id)
        || !stableNonEmpty(key.key_version)
        || key.algorithm !== "ED25519"
        || !/^[0-9a-f]{64}$/.test(String(key.public_key_material))
        || typeof key.trust_bearing !== "boolean"
        || !["ACTIVE", "RETIRED", "REVOKED"].includes(key.status)) {
        invalid.push(`keys.${index}`);
      }
      // environment is production or sandbox, and a sandbox key is never
      // trust-bearing (as in the Go verifier).
      if (isRecord(key) && !["production", "sandbox"].includes(key.environment)) invalid.push(`keys.${index}.environment`);
      if (isRecord(key) && key.environment === "sandbox" && key.trust_bearing === true) invalid.push(`keys.${index}.trust_bearing`);
      // 1.2 members (purpose, windows, revocation metadata) are valid only in a
      // 1.2 set; a 1.0/1.1 set carrying them is invalid (as in the Go
      // verifier). Checked whether or not the preapproval module is loaded.
      if (isRecord(key) && !v12 && PUBLISHED_KEY_SET_V12_MEMBERS.some((name) => Object.hasOwn(key, name) && key[name] !== "")) invalid.push(`keys.${index}.purpose`);
      if (v12 && isRecord(key)) invalid.push(...pa.keySetV12KeyInvalidFields(key, true, `keys.${index}.`));
    }
  }
  if (invalid.length > 0) {
    const hint = invalid.includes("schema_version") || invalid.includes("min_trusted_signers")
      ? ` (trust-bearing keys need ${PUBLISHED_KEY_SET_SCHEMA_VERSION} with an integer min_trusted_signers between 1 and the number of distinct key_ids)`
      : "";
    fail(`trusted key set is invalid (${origin}): ${sortedUnique(invalid).join(",")}${hint}`);
  }
  const environments = [...new Set(set.keys.map((key) => key.environment).filter(stableNonEmpty))];
  return {
    key_set_id: set.key_set_id,
    environment: environments.length === 1 ? environments[0] : "mixed",
    source: origin,
    min_trusted_signers: set.schema_version === PUBLISHED_KEY_SET_SCHEMA_VERSION || v12 ? set.min_trusted_signers : 1,
    schema_version: set.schema_version,
    keys: set.keys,
  };
}

const PUBLISHED_KEY_SET_V12_MEMBERS = Object.freeze(["purpose", "valid_from", "valid_until", "revoked_at", "revocation_reason"]);

// The purpose a published key anchors: a 1.2 key's own; a 1.0/1.1 key is
// always AEP_RECORD, whatever members it carries.
function aepAnchorPurpose(key, set) {
  if (set.schema_version !== "intentrax.trust.published_key_set/1.2") return "AEP_RECORD";
  return typeof key.purpose === "string" && key.purpose !== "" ? key.purpose : "AEP_RECORD";
}

// signingTime (bigint nanoseconds, or null) is the record's sealed signing
// time: admission_binding.decided_at (spec 01 §3.4). With it, a 1.2
// AEP_RECORD anchor's valid_from/valid_until window applies (spec 00 §5):
// any matching entry whose window excludes it makes the signer not valid,
// whatever other sets say (the strictest entry wins). Records without a
// sealed signing time cannot be placed in a window, so windows do not apply
// to them (as in the Go verifier).
function classifySignerTrust(signers, keySets, signingTime = null, parseTime = null) {
  // Validity windows and revocation timing are published_key_set/1.2 members:
  // a 1.0/1.1 entry has no window and its REVOKED applies unconditionally,
  // whatever fields it carries (the parser also refuses them there).
  const isV12 = (set) => set.schema_version === "intentrax.trust.published_key_set/1.2";
  const outsideWindow = (key, set) => {
    if (!isV12(set) || signingTime === null || parseTime === null) return false;
    if (typeof key.valid_from === "string" && key.valid_from !== "" && signingTime < parseTime(key.valid_from)) return true;
    return typeof key.valid_until === "string" && key.valid_until !== "" && signingTime >= parseTime(key.valid_until);
  };
  // Whether a REVOKED entry applies to this record (spec 00 §5): KEY_COMPROMISE
  // applies at every signing time, and so does a revocation without revoked_at
  // (a 1.0/1.1 key) or a record without a sealed signing time. Any other reason
  // (SUPERSEDED, CEASED) applies only to records signed at or after revoked_at,
  // so routine key rotation does not invalidate earlier proofs.
  const revokedForRecord = (key, set) => {
    if (key.status !== "REVOKED") return false;
    if (!isV12(set) || signingTime === null || parseTime === null) return true;
    if (key.revocation_reason === "KEY_COMPROMISE") return true;
    if (typeof key.revoked_at !== "string" || key.revoked_at === "") return true;
    return signingTime >= parseTime(key.revoked_at);
  };
  const resolved = signers.map((signer) => {
    // Collect every matching anchor across all key sets: a revocation in ANY
    // trusted set must win over an ACTIVE entry in another.
    const matches = [];
    const otherPurposeMatches = [];
    let purposeMismatch = false;
    let notValidAtSigningTime = false;
    let publicKeyMismatch = false;
    for (const set of keySets) {
      for (const key of set.keys) {
        if (key.key_id !== signer.key_id || key.key_version !== signer.key_version) continue;
        // Another public key under the same key_id + key_version is a conflict:
        // the signer is not pinned (as the Go verifier's PUBLIC_KEY_MISMATCH).
        if (key.public_key_material !== signer.public_key_material) {
          publicKeyMismatch = true;
          continue;
        }
        // Only AEP_RECORD anchors pin AEP signers (published_key_set/1.2,
        // spec 00 §5); a 1.1 or 1.0 key is AEP_RECORD.
        // An entry of another purpose for the same key is a conflict, and its
        // revocation still applies (a compromised key is compromised for
        // every purpose).
        const entry = { key_set_id: set.key_set_id, environment: key.environment ?? set.environment, trust_bearing: key.trust_bearing, status: key.status, revoked: revokedForRecord(key, set) };
        if (aepAnchorPurpose(key, set) !== "AEP_RECORD") {
          purposeMismatch = true;
          otherPurposeMatches.push(entry);
          continue;
        }
        if (outsideWindow(key, set)) notValidAtSigningTime = true;
        matches.push(entry);
      }
    }
    const revokedAnchor = [...matches, ...otherPurposeMatches].find((match) => match.revoked);
    // The least trusting entry decides: one entry that is not trust-bearing
    // (a sandbox listing, say) outweighs a trust-bearing one elsewhere.
    const anchor = revokedAnchor
      ?? (notValidAtSigningTime || purposeMismatch || publicKeyMismatch ? null : matches.find((match) => match.trust_bearing !== true) ?? matches[0])
      ?? null;
    return {
      key_id: signer.key_id, key_version: signer.key_version, public_key_hash: signer.public_key_hash, anchor,
      // Present only when the signer has no usable AEP_RECORD anchor: an
      // anchor whose 1.2 validity window excludes the record's signing time,
      // or the same key also pinned for another purpose (alone or next to an
      // AEP_RECORD entry).
      ...(anchor === null && notValidAtSigningTime ? { anchor_match: "NOT_VALID_AT_SIGNING_TIME" } : {}),
      ...(anchor === null && !notValidAtSigningTime && purposeMismatch ? { anchor_match: "PURPOSE_MISMATCH" } : {}),
      ...(anchor === null && !notValidAtSigningTime && !purposeMismatch && publicKeyMismatch ? { anchor_match: "PUBLIC_KEY_MISMATCH" } : {}),
    };
  });
  // The strictest policy wins: every key set that vouches for any signer as
  // trust-bearing contributes its min_trusted_signers, and the maximum applies.
  // Supplying an extra, laxer set cannot lower the bundled production policy.
  let minTrustedSigners = 1;
  for (const set of keySets) {
    const vouches = set.keys.some((key) => key.trust_bearing === true && !revokedForRecord(key, set) && aepAnchorPurpose(key, set) === "AEP_RECORD" && !outsideWindow(key, set)
      && signers.some((signer) => key.key_id === signer.key_id && key.key_version === signer.key_version && key.public_key_material === signer.public_key_material));
    if (vouches) minTrustedSigners = Math.max(minTrustedSigners, set.min_trusted_signers);
  }
  // Versions of one key are one signer.
  const distinctTrustedSigners = new Set(resolved.filter((signer) => signer.anchor?.trust_bearing === true && !signer.anchor.revoked).map((signer) => signer.key_id)).size;
  let signerTrust;
  if (resolved.some((signer) => signer.anchor?.revoked === true)) signerTrust = "REVOKED_SIGNER";
  else if (resolved.some((signer) => signer.anchor_match === "NOT_VALID_AT_SIGNING_TIME")) signerTrust = "SIGNER_KEY_NOT_VALID_AT_SIGNING_TIME";
  else if (resolved.some((signer) => signer.anchor_match === "PURPOSE_MISMATCH")) signerTrust = "SIGNER_PURPOSE_MISMATCH";
  else if (resolved.length === 0 || resolved.some((signer) => signer.anchor === null)) signerTrust = "UNPINNED_SIGNER";
  else if (resolved.every((signer) => signer.anchor.trust_bearing === true)) {
    signerTrust = distinctTrustedSigners >= minTrustedSigners ? "TRUSTED" : "INSUFFICIENT_TRUSTED_SIGNERS";
  }
  else if (resolved.every((signer) => signer.anchor.trust_bearing === false)) signerTrust = "SANDBOX_NON_TRUST_BEARING";
  else signerTrust = "MIXED_TRUST";
  return { signer_trust: signerTrust, signers: resolved, min_trusted_signers: minTrustedSigners, distinct_trusted_signers: distinctTrustedSigners };
}

// Short human table of the verification_assessment block: dimension, result,
// provenance, limitations.
function assessmentTable(assessment) {
  const rows = [["DIMENSION", "RESULT", "PROVENANCE", "LIMITATIONS"]];
  for (const row of assessment.assessments) {
    rows.push([row.dimension, row.result, row.provenance ?? "-", row.limitations.length > 0 ? row.limitations.join(",") : "-"]);
  }
  const widths = rows[0].map((_, column) => Math.max(...rows.map((row) => row[column].length)));
  const lines = [`assurance: profile=${assessment.assurance_profile} verdict=${assessment.verdict} required=${assessment.required_dimensions.join(",")}`];
  for (const row of rows) {
    lines.push(("  " + row.map((cell, column) => (column === row.length - 1 ? cell : cell.padEnd(widths[column] + 2))).join("")).trimEnd());
  }
  lines.push(`limitations: ${assessment.limitations.map((limitation) => limitation.code).join(", ")}`);
  return lines.join("\n");
}

function signerTrustMessage(report) {
  if (report.signer_trust === "UNPINNED_SIGNER") {
    return "intentrax: signatures are mathematically valid, but at least one signing key is not in any trusted key set, so this proof does NOT establish who signed it. Pass the key set Intentrax publishes with --trusted-keys <file>.";
  }
  if (report.signer_trust === "SIGNER_KEY_NOT_VALID_AT_SIGNING_TIME") {
    return "intentrax: a signing key of this proof is pinned, but its validity window (published_key_set/1.2) does not cover the record's sealed signing time (decided_at); this proof must not be relied on.";
  }
  if (report.signer_trust === "SIGNER_PURPOSE_MISMATCH") {
    return "intentrax: a signing key of this proof is pinned only for another purpose (published_key_set/1.2); AEP records are trusted only under AEP_RECORD keys, so this proof must not be relied on.";
  }
  if (report.signer_trust === "REVOKED_SIGNER") {
    return "intentrax: a signing key is REVOKED in the trusted key set; this proof must not be relied on.";
  }
  if (report.signer_trust === "INSUFFICIENT_TRUSTED_SIGNERS") {
    const verification = report.signature_verification;
    return `intentrax: every signer is a published trust-bearing key, but only ${verification.distinct_trusted_signers} distinct key(s) signed and the published key set requires ${verification.min_trusted_signers}. Signatures may have been stripped from this proof; it must not be relied on.`;
  }
  if (report.signer_trust === "MIXED_TRUST") {
    return "intentrax: the proof mixes trust-bearing and sandbox signers; it is not a production-trusted proof.";
  }
  return `intentrax: proof verification did not reach a trusted result (${report.signer_trust}).`;
}

function validateProofLookupExport(lookup) {
  const invalid = [];
  if (!isRecord(lookup)) return ["proof_export"];
  const query = lookup.query;
  const record = lookup.proof_record;
  const bundle = isRecord(record) ? record.verification_bundle : undefined;
  if (lookup.schema_version !== "intentrax.registry.proof_lookup/1.0") invalid.push("schema_version");
  if (lookup.store_mode !== "POSTGRESQL_APPEND_ONLY") invalid.push("store_mode");
  if (lookup.hash_algorithm !== "SHA-256") invalid.push("hash_algorithm");
  if (!isRecord(query)) invalid.push("query");
  if (!isRecord(record)) invalid.push("proof_record");
  if (!isRecord(bundle)) invalid.push("verification_bundle");
  if (invalid.length > 0) return sortedUnique(invalid);

  if (!stableNonEmpty(query.tenant_id) || query.tenant_id !== record.tenant_id) invalid.push("query.tenant_id");
  if (!stableNonEmpty(query.registry_entry_id) && !isSHA256(query.aep_hash)) invalid.push("query");
  if (stableNonEmpty(query.registry_entry_id) && query.registry_entry_id !== record.registry_entry_id) invalid.push("query.registry_entry_id");
  if (stableNonEmpty(query.aep_hash) && query.aep_hash !== record.aep_hash) invalid.push("query.aep_hash");
  if (record.schema_version !== "intentrax.registry.persistence_foundation/1.0") invalid.push("proof_record.schema_version");
  if (record.record_type !== "REGISTRY_BACKED_PROOF") invalid.push("proof_record.record_type");
  if (record.store_mode !== "POSTGRESQL_APPEND_ONLY") invalid.push("proof_record.store_mode");
  if (record.hash_algorithm !== "SHA-256") invalid.push("proof_record.hash_algorithm");
  if (record.append_only !== true) invalid.push("proof_record.append_only");
  if (record.trust_status !== "VALID") invalid.push("proof_record.trust_status");
  for (const field of ["tenant_id", "registry_entry_id", "execution_id", "canonical_aep_json", "lookup_ref"]) {
    if (!stableNonEmpty(record[field])) invalid.push(`proof_record.${field}`);
  }
  for (const field of ["aep_hash", "admission_hash", "registry_entry_hash", "registry_output_hash", "signature_hash", "verification_hash", "replay_hash", "audit_hash", "record_hash"]) {
    if (!isSHA256(record[field])) invalid.push(`proof_record.${field}`);
  }
  if (!isRecord(record.registry_entry)) invalid.push("proof_record.registry_entry");
  if (isRecord(record.registry_entry)) {
    if (record.registry_entry.registry_entry_id !== record.registry_entry_id) invalid.push("registry_entry.registry_entry_id");
    if (record.registry_entry.execution_id !== record.execution_id) invalid.push("registry_entry.execution_id");
    if (record.registry_entry.tenant_id !== record.tenant_id) invalid.push("registry_entry.tenant_id");
    if (record.registry_entry.aep_hash !== record.aep_hash) invalid.push("registry_entry.aep_hash");
    if (record.registry_entry.canonical_aep_json !== record.canonical_aep_json) invalid.push("registry_entry.canonical_aep_json");
    if (record.registry_entry.trust_status !== record.trust_status) invalid.push("registry_entry.trust_status");
  }
  if (record.lookup_ref !== `intentrax://registry/proofs/${record.tenant_id}/${record.aep_hash}`) invalid.push("proof_record.lookup_ref");

  if (bundle.schema_version !== "intentrax.registry.proof_verification_bundle/1.0") invalid.push("verification_bundle.schema_version");
  if (bundle.hash_algorithm !== "SHA-256") invalid.push("verification_bundle.hash_algorithm");
  if (!isSHA256(bundle.bundle_hash)) invalid.push("verification_bundle.bundle_hash");
  if (!isRecord(bundle.registry_output)) invalid.push("verification_bundle.registry_output");
  if (isRecord(bundle.registry_output)) {
    if (bundle.registry_output.registry_entry_id !== record.registry_entry_id) invalid.push("verification_bundle.registry_output.registry_entry_id");
    if (bundle.registry_output.execution_id !== record.execution_id) invalid.push("verification_bundle.registry_output.execution_id");
    if (bundle.registry_output.aep_hash !== record.aep_hash) invalid.push("verification_bundle.registry_output.aep_hash");
    if (bundle.registry_output.canonical_aep_json !== record.canonical_aep_json) invalid.push("verification_bundle.registry_output.canonical_aep_json");
    if (bundle.registry_output.trust_status !== record.trust_status) invalid.push("verification_bundle.registry_output.trust_status");
  }
  if (!Array.isArray(bundle.key_references) || bundle.key_references.length === 0) invalid.push("verification_bundle.key_references");
  if (Array.isArray(bundle.key_references)) {
    for (const [index, key] of bundle.key_references.entries()) {
      if (!isRecord(key) || !stableNonEmpty(key.public_key_material) || stableNonEmpty(key.key_material)) {
        invalid.push(`verification_bundle.key_references.${index}`);
      }
      if (isRecord(key) && String(key.public_key_material || "").toLowerCase().includes("private")) {
        invalid.push(`verification_bundle.key_references.${index}.public_key_material`);
      }
    }
  }
  if (isSHA256(bundle.bundle_hash) && bundle.bundle_hash !== hashWithBlankField(bundle, "bundle_hash")) invalid.push("verification_bundle.bundle_hash");
  if (isSHA256(record.record_hash) && record.record_hash !== hashWithBlankField(record, "record_hash")) invalid.push("proof_record.record_hash");
  if (isSHA256(lookup.result_hash) && lookup.result_hash !== hashWithBlankField(lookup, "result_hash")) invalid.push("result_hash");
  if (!isSHA256(lookup.result_hash)) invalid.push("result_hash");
  return sortedUnique(invalid);
}

function hashWithBlankField(value, field) {
  return sha256Hex(JSON.stringify(goPersistenceOrder({ ...value, [field]: "" })));
}

function goPersistenceOrder(value) {
  if (!isRecord(value)) {
    if (Array.isArray(value)) return value.map(goPersistenceOrder);
    return value;
  }
  if (value.schema_version === "intentrax.registry.proof_lookup/1.0") {
    return ordered(value, ["schema_version", "store_mode", "query", "proof_record", "result_hash", "hash_algorithm"]);
  }
  if (stableNonEmpty(value.tenant_id) && (stableNonEmpty(value.registry_entry_id) || stableNonEmpty(value.aep_hash)) && Object.keys(value).every((key) => ["tenant_id", "registry_entry_id", "aep_hash"].includes(key))) {
    return ordered(value, ["tenant_id", "registry_entry_id", "aep_hash"]);
  }
  if (value.schema_version === "intentrax.registry.persistence_foundation/1.0") {
    return ordered(value, [
      "schema_version",
      "record_type",
      "store_mode",
      "migration_id",
      "tenant_id",
      "registry_entry_id",
      "execution_id",
      "aep_hash",
      "canonical_aep_json",
      "admission_hash",
      "registry_entry_hash",
      "registry_output_hash",
      "signature_hash",
      "verification_hash",
      "replay_hash",
      "audit_hash",
      "trust_status",
      "lookup_ref",
      "append_only",
      "registry_entry",
      "verification_bundle",
      "record_hash",
      "hash_algorithm",
    ]);
  }
  if (value.schema_version === "intentrax.registry.proof_verification_bundle/1.0") {
    return ordered(value, ["schema_version", "registry_output", "payload", "key_binding", "key_references", "bundle_hash", "hash_algorithm"]);
  }
  if (value.schema_version === "intentrax.registry.entry/1.0") {
    return ordered(value, [
      "schema_version",
      "registry_entry_id",
      "execution_id",
      "tenant_id",
      "aep_hash",
      "canonical_aep_json",
      "policy_id",
      "signer_id",
      "signature_hash",
      "verification_hash",
      "trust_trace_hash",
      "trust_integrity_lock",
      "trust_status",
      "record_version",
      "index_keys",
      "integrity",
    ]);
  }
  if (value.schema_version === "intentrax.trust.key_binding_set/1.0" || (isRecord(value.signer_identity) && isRecord(value.quorum) && Array.isArray(value.keys))) {
    return ordered(value, ["schema_version", "signer_identity", "quorum", "keys", "integrity"]);
  }
  if (value.schema_version === "intentrax.trust.signature_payload_result/1.0" || (isRecord(value.payload) && stableNonEmpty(value.canonical_payload_json))) {
    return ordered(value, ["schema_version", "payload", "canonical_payload_json", "payload_hash", "payload_byte_length", "integrity"]);
  }
  if (value.schema_version === "intentrax.trust.signature_bundle/1.0" || (Array.isArray(value.signatures) && stableNonEmpty(value.payload_hash))) {
    return ordered(value, ["schema_version", "signatures", "payload_hash", "required_signatures", "total_signers", "integrity"]);
  }
  if (stableNonEmpty(value.payload_version) && stableNonEmpty(value.canonical_aep_json) && stableNonEmpty(value.aep_hash)) {
    return ordered(value, ["payload_version", "canonical_aep_json", "aep_hash"]);
  }
  if (stableNonEmpty(value.principal_id) && stableNonEmpty(value.principal_type) && stableNonEmpty(value.identity_binding_ref)) {
    return ordered(value, ["principal_id", "principal_type", "identity_binding_ref"]);
  }
  if (Number.isInteger(value.required_signatures) && Number.isInteger(value.total_signers) && Object.keys(value).every((key) => ["required_signatures", "total_signers"].includes(key))) {
    return ordered(value, ["required_signatures", "total_signers"]);
  }
  if (stableNonEmpty(value.key_id) && stableNonEmpty(value.signature_hex)) {
    return ordered(value, ["key_id", "key_version", "algorithm", "signature_hex", "payload_hash", "public_key_hash", "key_binding_hash"]);
  }
  if (stableNonEmpty(value.key_id) && stableNonEmpty(value.key_version) && stableNonEmpty(value.key_binding_hash)) {
    return ordered(value, ["key_id", "key_version", "key_status", "algorithm", "principal_id", "public_key_hash", "key_material_hash", "key_binding_hash"]);
  }
  if (stableNonEmpty(value.key_id) && stableNonEmpty(value.key_version) && stableNonEmpty(value.public_key_material)) {
    return ordered(value, ["key_id", "key_version", "key_material", "public_key_material", "deterministic_key_handle", "key_status", "algorithm", "principal_id"]);
  }
  if (stableNonEmpty(value.execution_id) && stableNonEmpty(value.aep_hash) && stableNonEmpty(value.canonical_aep_json) && isRecord(value.signature) && isRecord(value.verification_result)) {
    return ordered(value, [
      "execution_id",
      "aep_hash",
      "canonical_aep_json",
      "signature",
      "trust_status",
      "registry_entry_id",
      "index_keys",
      "verification_result",
      "replay_result",
      "projection_views",
      "audit_result",
      "registry_trace",
      "integrity_lock",
    ]);
  }
  if (value.schema_version === "intentrax.registry.stored_verification/1.0" || stableNonEmpty(value.verification_status)) {
    return ordered(value, [
      "schema_version",
      "verification_status",
      "aep_integrity_valid",
      "signature_verification_valid",
      "trust_status_reconfirmed",
      "recomputed_aep_hash",
      "verification_hash",
      "integrity",
    ]);
  }
  if (value.schema_version === "intentrax.registry.replay/1.0" || stableNonEmpty(value.replay_status)) {
    return ordered(value, ["schema_version", "replay_status", "original_aep_hash", "replay_aep_hash", "output_match", "replay_consistent", "replay_result_hash", "integrity"]);
  }
  if (value.schema_version === "intentrax.registry.projection/1.0" || Array.isArray(value.rows)) {
    return ordered(value, ["schema_version", "status", "rows", "result_count", "projection_hash", "integrity"]);
  }
  if (value.schema_version === "intentrax.registry.observability/1.0" || Array.isArray(value.trace_refs)) {
    return ordered(value, ["schema_version", "status", "trace_refs", "report_hash", "integrity"]);
  }
  if (value.schema_version === "intentrax.registry.audit/1.0" || stableNonEmpty(value.audit_status)) {
    return ordered(value, ["schema_version", "audit_status", "checked_artifacts", "anomalies", "registry_output_ready", "audit_hash", "integrity"]);
  }
  if (stableNonEmpty(value.registry_entry_id) && stableNonEmpty(value.policy_id) && stableNonEmpty(value.signer_id) && stableNonEmpty(value.trust_status)) {
    return ordered(value, ["registry_entry_id", "execution_id", "aep_hash", "policy_id", "signer_id", "trust_status", "tenant_id"]);
  }
  if (stableNonEmpty(value.execution_id) && stableNonEmpty(value.policy_id) && stableNonEmpty(value.signer_id) && stableNonEmpty(value.trust_status)) {
    return ordered(value, ["execution_id", "aep_hash", "policy_id", "signer_id", "trust_status", "tenant_id"]);
  }
  if (stableNonEmpty(value.component) && stableNonEmpty(value.artifact_hash)) {
    return ordered(value, ["component", "artifact_hash"]);
  }
  if (stableNonEmpty(value.hash_algorithm) && Object.keys(value).some((key) => ["input_hash", "output_hash", "trace_hash"].includes(key))) {
    return ordered(value, ["input_hash", "output_hash", "trace_hash", "hash_algorithm"]);
  }
  return ordered(value, Object.keys(value).sort());
}

function ordered(value, fieldOrder) {
  const out = {};
  const seen = new Set();
  for (const field of fieldOrder) {
    if (Object.prototype.hasOwnProperty.call(value, field)) {
      out[field] = goPersistenceOrder(value[field]);
      seen.add(field);
    }
  }
  for (const field of Object.keys(value).filter((key) => !seen.has(key)).sort()) {
    out[field] = goPersistenceOrder(value[field]);
  }
  return out;
}

function parseSingleJSON(source, label) {
  try {
    return JSON.parse(source);
  } catch (error) {
    fail(`${label} is not valid JSON: ${error.message}`);
  }
}

function containsForbiddenPrivateMarker(value) {
  return /seed_hex|current_seed_hex|private[_ -]?key|privatekey|private_material|begin private/i.test(value);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function stableNonEmpty(value) {
  return typeof value === "string" && value.length > 0 && value.trim() === value;
}

function isSHA256(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function sortedUnique(values) {
  return [...new Set(values.filter(Boolean))].sort();
}

function buildInitOutput(adapterName, adapter, options) {
  const sampleAction = SAMPLE_ACTION_BY_SURFACE[adapter.normalized_surface_id];
  const payload = {
    adapter: adapterName,
    action: sampleAction,
    hook_surface: adapter.hook_surface,
    tenant_id: options.tenantId,
  };
  const payloadHash = sha256Hex(canonicalJson(payload));
  const idempotencyKeyHash = sha256Hex("INTENTRAX_AGENT_INIT_IDEMPOTENCY_V1" + payloadHash);
  const sampleAdmissionRequest = {
    schema_version: ADMISSION_SCHEMA_VERSION,
    tenant_id: options.tenantId,
    surface_id: adapter.normalized_surface_id,
    action: payload.action,
    adapter_id: adapter.normalized_adapter_id,
    evidence_refs: REQUIRED_GATEWAY_REFS,
    proof_refs: REQUIRED_GATEWAY_REFS,
    request_payload_hash: payloadHash,
    protocol_payload_ref: `sha256:${payloadHash}`,
    idempotency_key_hash: idempotencyKeyHash,
  };
  const submitSample = buildSubmitSample(sampleAdmissionRequest, options);
  const hookStarter = buildHookStarter(adapterName, adapter, sampleAdmissionRequest);
  const hostWiringGuide = buildHostWiringGuide(adapterName, adapter, hookStarter, submitSample);
  const actionReceipt = buildActionReceipt(adapterName, adapter, sampleAdmissionRequest, hookStarter, hostWiringGuide, submitSample);
  const config = {
    schema_version: INIT_SCHEMA_VERSION,
    cli_version: VERSION,
    adapter_profile: {
      adapter_name: adapterName,
      display_name: adapter.display_name,
      matrix_adapter_id: adapter.matrix_adapter_id,
      hook_surface: adapter.hook_surface,
      hook_label: adapter.hook_label,
      quickstart_ref: adapter.quickstart_ref,
      native_hook_starter: {
        file_path: hookStarter.file_path,
        module_format: "ESM",
        entrypoint: hookStarter.entrypoint,
        native_template_id: hookStarter.native_template_id,
        native_event_kind: hookStarter.native_event_kind,
        adapter_surface: adapter.normalized_surface_id,
        adapter_id: adapter.normalized_adapter_id,
        runtime_submission_required: true,
        secret_material_written: false,
      },
      host_wiring_guide: {
        file_path: hostWiringGuide.file_path,
        guide_hash: hostWiringGuide.guide_hash,
        host_runtime: hostWiringGuide.host_runtime,
        hook_file_path: hookStarter.file_path,
        hook_entrypoint: hookStarter.entrypoint,
        adapter_surface: adapter.normalized_surface_id,
        adapter_id: adapter.normalized_adapter_id,
        setup_level: "HOST_BINDING_GUIDE",
        authoritative: false,
        secret_material_written: false,
      },
    },
    normalized_contract: {
      base_url: options.baseUrl,
      endpoint: ENDPOINT,
      method: "POST",
      tenant_header: TENANT_HEADER,
      api_key_header: API_KEY_HEADER,
      idempotency_header: IDEMPOTENCY_HEADER,
      content_type: "application/json",
    },
    runtime_gate_fixture: {
      sample_action: sampleAction,
      required_gateway_ref_count: REQUIRED_GATEWAY_REFS.length,
      sample_is_contract_admissible: true,
      proof_generation_owner: "intentrax_runtime",
    },
    action_receipt: {
      file_path: actionReceipt.file_path,
      receipt_id: actionReceipt.receipt_id,
      receipt_hash: actionReceipt.receipt_hash,
      authoritative: false,
      canonical_aep_authoritative: true,
      production_authorization_unchanged: true,
    },
    boundary_assertions: {
      no_secret_material_written: true,
      no_tool_execution_inside_admission: true,
      no_payload_mutation: true,
      no_policy_re_evaluation: true,
      no_private_key_material_required: true,
      intentrax_owns_proof_generation: true,
      aevn_aep_remains_authoritative: true,
      oap_compatibility: OAP_COMPATIBILITY_BOUNDARY,
    },
    sample_submission: {
      method: submitSample.method,
      url: submitSample.url,
      file_path: submitSample.file_path,
      body_file: submitSample.body_file,
      working_directory: submitSample.working_directory,
      curl: submitSample.curl,
      required_headers: [
        "content-type",
        TENANT_HEADER,
        API_KEY_HEADER,
        IDEMPOTENCY_HEADER,
      ],
      api_key_env: "INTENTRAX_API_KEY",
      idempotency_key_hash: sampleAdmissionRequest.idempotency_key_hash,
    },
    next_steps: [
      "Review .intentrax/sample-admission-request.json.",
      "Review .intentrax/action-receipt.json as a developer summary only.",
      `Wire ${hookStarter.file_path} into your ${adapter.hook_label}.`,
      `Open ${hostWiringGuide.file_path} for the host wiring steps and local check command.`,
      "Set X-Intentrax-Api-Key from your secret manager at runtime.",
      "Run .intentrax/submit_sample.curl after confirming the target runtime uses the locked private-alpha Agent Gateway bundle.",
    ],
  };
  return {
    schema_version: "intentrax.onboarding.agent_adapter_init_result/1.0",
    status: "READY",
    config,
    normalized_contract: config.normalized_contract,
    sample_admission_request: sampleAdmissionRequest,
    action_receipt: actionReceipt,
    hook_starter: hookStarter,
    host_wiring_guide: hostWiringGuide,
    submit_sample: submitSample,
    init_hash: sha256Hex(DOMAIN + canonicalJson({ action_receipt: actionReceipt, config, hook_starter: hookStarter, host_wiring_guide: hostWiringGuide, sample_admission_request: sampleAdmissionRequest })),
  };
}

function buildActionReceipt(adapterName, adapter, sampleAdmissionRequest, hookStarter, hostWiringGuide, submitSample) {
  const withoutHash = {
    schema_version: ACTION_RECEIPT_SCHEMA_VERSION,
    receipt_id: `intentrax-init-${adapterName}-${sampleAdmissionRequest.request_payload_hash.slice(0, 12)}`,
    receipt_type: "AGENT_ADAPTER_INIT_SAMPLE_ACTION_RECEIPT",
    file_path: ".intentrax/action-receipt.json",
    authoritative: false,
    canonical_aep_authoritative: true,
    production_authorization_unchanged: true,
    adapter_profile: {
      adapter_name: adapterName,
      display_name: adapter.display_name,
      matrix_adapter_id: adapter.matrix_adapter_id,
      hook_surface: adapter.hook_surface,
      native_template_id: hookStarter.native_template_id,
      native_event_kind: hookStarter.native_event_kind,
      normalized_surface_id: sampleAdmissionRequest.surface_id,
      normalized_adapter_id: sampleAdmissionRequest.adapter_id,
      action: sampleAdmissionRequest.action,
    },
    sample_admission_binding: {
      file_path: ".intentrax/sample-admission-request.json",
      tenant_id: sampleAdmissionRequest.tenant_id,
      request_payload_hash: sampleAdmissionRequest.request_payload_hash,
      protocol_payload_ref: sampleAdmissionRequest.protocol_payload_ref,
      idempotency_key_hash: sampleAdmissionRequest.idempotency_key_hash,
      evidence_ref_count: sampleAdmissionRequest.evidence_refs.length,
      proof_ref_count: sampleAdmissionRequest.proof_refs.length,
    },
    hook_starter_binding: {
      file_path: hookStarter.file_path,
      entrypoint: hookStarter.entrypoint,
      source_hash: hookStarter.source_hash,
    },
    host_wiring_guide_binding: {
      file_path: hostWiringGuide.file_path,
      host_runtime: hostWiringGuide.host_runtime,
      hook_file_path: hookStarter.file_path,
      hook_entrypoint: hookStarter.entrypoint,
      guide_hash: hostWiringGuide.guide_hash,
      authoritative: false,
    },
    submit_sample_binding: {
      file_path: submitSample.file_path,
      method: submitSample.method,
      url: submitSample.url,
      body_file: submitSample.body_file,
      idempotency_key_hash: sampleAdmissionRequest.idempotency_key_hash,
      api_key_env: "INTENTRAX_API_KEY",
    },
    evidence_links: {
      runtime_admission_endpoint: ENDPOINT,
      proof_verification_endpoint: "/v1/proofs/verify",
      proof_export_endpoint_template: "/v1/proofs/{proof_id}/export?format=json|aep-json|pdf",
      verifier_handoff_endpoint_template: "/v1/evidence/dry-run/{receipt_id}/verifier-handoff",
      aevn_authoritative: true,
      aep_authoritative: true,
      aep_export_link_state: "AVAILABLE_AFTER_RUNTIME_ADMISSION",
      registry_reference_link_state: "AVAILABLE_AFTER_RUNTIME_ADMISSION",
    },
    boundary_assertions: {
      developer_summary_only: true,
      non_authoritative_developer_summary: true,
      canonical_aep_remains_authoritative: true,
      action_receipt_does_not_replace_aep: true,
      no_secret_material_written: true,
      no_tool_execution_inside_admission: true,
      no_payload_mutation: true,
      no_policy_re_evaluation: true,
      no_proof_generation_inside_adapter: true,
      no_registry_write_performed: true,
      production_authorization_unchanged: true,
      oap_compatibility: OAP_COMPATIBILITY_BOUNDARY,
    },
    hash_algorithm: "SHA-256",
  };
  return Object.freeze({
    ...withoutHash,
    receipt_hash: sha256Hex(ACTION_RECEIPT_DOMAIN + canonicalJson(withoutHash)),
  });
}

function buildHostWiringGuide(adapterName, adapter, hookStarter, submitSample) {
  const filePath = `.intentrax/wiring/${adapterName}-host-wiring.md`;
  const source = hostWiringGuideSource(adapterName, adapter, hookStarter, submitSample);
  return Object.freeze({
    schema_version: HOST_WIRING_GUIDE_SCHEMA_VERSION,
    file_path: filePath,
    adapter_name: adapterName,
    host_runtime: adapter.display_name,
    hook_surface: adapter.hook_surface,
    hook_label: adapter.hook_label,
    hook_file_path: hookStarter.file_path,
    hook_entrypoint: hookStarter.entrypoint,
    endpoint: ENDPOINT,
    tenant_header: TENANT_HEADER,
    api_key_header: API_KEY_HEADER,
    idempotency_header: IDEMPOTENCY_HEADER,
    submit_sample_file_path: submitSample.file_path,
    guide_hash: hashGeneratedHostWiringSource(source),
    source,
    boundary_assertions: {
      authoritative: false,
      no_secret_material_written: true,
      no_tool_execution_inside_admission: true,
      no_payload_mutation: true,
      no_policy_re_evaluation: true,
      no_proof_generation_inside_adapter: true,
      no_registry_write_performed: true,
      intentrax_runtime_remains_proof_owner: true,
      aevn_aep_remains_authoritative: true,
    },
  });
}

function hostWiringGuideSource(adapterName, adapter, hookStarter, submitSample) {
  const hostSnippet = hostWiringSnippet(adapterName, adapter, hookStarter);
  return [
    `# Intentrax ${adapter.display_name} Host Wiring`,
    "",
    `Generated by \`intentrax init ${adapterName}\`. This guide is a local developer wiring aid and is not canonical evidence.`,
    "",
    "## Generated Files",
    "",
    `- Hook starter: \`${hookStarter.file_path}\``,
    `- Hook entrypoint: \`${hookStarter.entrypoint}\``,
    "- Sample admission request: `.intentrax/sample-admission-request.json`",
    "- Action receipt: `.intentrax/action-receipt.json`",
    `- Submit sample: \`${submitSample.file_path}\``,
    "",
    "## Runtime Values",
    "",
    `- Endpoint: \`${ENDPOINT}\``,
    `- Tenant header: \`${TENANT_HEADER}\``,
    `- API key header: \`${API_KEY_HEADER}\` from \`INTENTRAX_API_KEY\``,
    `- Idempotency header: \`${IDEMPOTENCY_HEADER}\` from the generated admission request`,
    "",
    "Set runtime values outside the repo, for example:",
    "",
    "```bash",
    "export INTENTRAX_BASE_URL=\"http://127.0.0.1:8080\"",
    "export INTENTRAX_API_KEY=\"...\"",
    "```",
    "",
    "`http://127.0.0.1:8080` targets a locally run Intentrax engine; the hosted engine base URL is `https://api.intentrax.com`. `INTENTRAX_API_KEY` and your sandbox base URL are issued after an architectural review at <https://www.intentrax.com/request-architectural-review>. Before you have a key, `npx @intentrax/sdk check-init` verifies this setup offline and works right now with no key.",
    "",
    "## Host Binding",
    "",
    hostSnippet,
    "",
    "## Local Verification",
    "",
    "Run the offline verifier after wiring the host entrypoint:",
    "",
    "```bash",
    "npx @intentrax/sdk check-init --output-dir .",
    "```",
    "",
    "The verifier reads the generated files, imports the hook starter without submitting to the network, checks the hook and wiring hashes, and confirms no tenant credential is required.",
    "",
    "## Boundaries",
    "",
    "- The adapter submits an admission request only when the host invokes the hook with `submit: true`.",
    "- Intentrax admission does not execute the tool.",
    "- The adapter does not mutate prompts, tool arguments, policy results, proof payloads, or registry entries.",
    "- The adapter does not generate AEP truth or access signing material.",
    "- The generated Action Receipt is a developer summary only; runtime AEVN/AEP evidence and verifier output remain authoritative.",
  ].join("\n");
}

function hostWiringSnippet(adapterName, adapter, hookStarter) {
  const importName = hookStarter.entrypoint;
  const importPath = `./${hookStarter.file_path}`;
  const handlerName = hostWiringHandlerName(adapterName);
  const eventLabel = hostWiringEventLabel(adapterName, adapter);
  return [
    `Import the generated module from your ${adapter.hook_label} and call it before the host allows the native action to continue:`,
    "",
    "```js",
    `import { ${importName} } from "${importPath}";`,
    "",
    `export async function ${handlerName}(${eventLabel}) {`,
    `  const result = await ${importName}(${eventLabel}, { submit: true });`,
    "  if (result.admission_response?.admission_allowed === false) {",
    "    throw new Error(\"Intentrax admission denied before host execution.\");",
    "  }",
    "  return result;",
    "}",
    "```",
    "",
    hostWiringAdapterNote(adapterName, adapter),
  ].join("\n");
}

function hostWiringHandlerName(adapterName) {
  switch (adapterName) {
    case "claude-code":
      return "intentraxClaudeCodePreToolUse";
    case "cursor":
      return "intentraxCursorBeforeShellExecution";
    case "mcp":
      return "intentraxMCPBeforeToolCall";
    case "langchain":
      return "intentraxLangChainToolStart";
    case "langgraph":
      return "intentraxLangGraphNodeTransition";
    case "vercel-ai-sdk":
      return "intentraxVercelAIRouteAdmission";
    default:
      return `intentrax${toPascalCase(adapterName)}Admission`;
  }
}

function hostWiringEventLabel(adapterName, adapter) {
  switch (adapterName) {
    case "claude-code":
      return "preToolUseEvent";
    case "cursor":
      return "shellExecutionEvent";
    case "mcp":
      return "toolCallEvent";
    case "langchain":
      return "toolStartEvent";
    case "langgraph":
      return "nodeTransitionEvent";
    case "vercel-ai-sdk":
      return "routeEvent";
    default:
      return `${adapter.hook_surface.replace(/[^A-Za-z0-9]+/g, "_").replace(/^_+|_+$/g, "") || "adapter"}Event`;
  }
}

function hostWiringAdapterNote(adapterName, adapter) {
  switch (adapterName) {
    case "claude-code":
      return "Use the wrapper from the host's pre-tool-use hook path so the admission decision is evaluated before any tool call proceeds.";
    case "cursor":
      return "Use the wrapper from the IDE or shell-execution hook path before command execution or tool invocation continues.";
    case "mcp":
      return "Use the wrapper around the MCP `tools/call` boundary before forwarding the call to the upstream tool handler.";
    case "langchain":
      return "Use the wrapper from a callback or tool wrapper before the LangChain tool body runs, then attach the returned admission metadata to the run context.";
    case "langgraph":
      return "Use the wrapper from node middleware before the node transition commits, then attach the returned admission metadata to checkpoint state.";
    case "vercel-ai-sdk":
      return "Use the wrapper inside the route handler before model or tool-side effects proceed, then attach the returned admission metadata to route-scoped evidence.";
    default:
      return `Use the wrapper at the ${adapter.hook_label} boundary before native side effects proceed.`;
  }
}

function toPascalCase(value) {
  return String(value)
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((part) => part.slice(0, 1).toUpperCase() + part.slice(1))
    .join("");
}

function buildHookStarter(adapterName, adapter, sampleAdmissionRequest) {
  const filePath = `.intentrax/hooks/${adapter.hook_file_name}`;
  const source = hookSource(adapterName, adapter);
  return {
    schema_version: "intentrax.onboarding.agent_adapter_native_hook_starter/1.0",
    file_path: filePath,
    adapter_name: adapterName,
    hook_surface: adapter.hook_surface,
    hook_label: adapter.hook_label,
    entrypoint: adapter.hook_entrypoint,
    native_template_id: adapter.native_template_id ?? "generic_admission_hook_v1",
    native_event_kind: adapter.native_event_kind ?? "GENERIC_AGENT_EVENT",
    endpoint: ENDPOINT,
    tenant_id: sampleAdmissionRequest.tenant_id,
    surface_id: sampleAdmissionRequest.surface_id,
    adapter_id: sampleAdmissionRequest.adapter_id,
    action: sampleAdmissionRequest.action,
    source_hash: sha256Hex(source),
    source,
    boundary_assertions: {
      no_secret_material_written: true,
      no_tool_execution_inside_admission: true,
      no_payload_mutation: true,
      no_policy_re_evaluation: true,
      no_proof_generation_inside_adapter: true,
      no_private_key_material_required: true,
      intentrax_runtime_remains_proof_owner: true,
      aevn_aep_remains_authoritative: true,
    },
  };
}

function hookSource(adapterName, adapter) {
  const contract = nativeExportContract(adapter);
  const metadataExport = contract?.metadata_export ?? "intentraxHookMetadata";
  return `import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

const SAMPLE_ADMISSION_REQUEST_URL = new URL("../sample-admission-request.json", import.meta.url);
const ENDPOINT = "${ENDPOINT}";
const TENANT_HEADER = "${TENANT_HEADER}";
const API_KEY_HEADER = "${API_KEY_HEADER}";
const IDEMPOTENCY_HEADER = "${IDEMPOTENCY_HEADER}";

const hookMetadata = Object.freeze({
  schema_version: "intentrax.onboarding.agent_adapter_native_hook_starter/1.0",
  adapter_name: "${adapterName}",
  display_name: "${adapter.display_name}",
  hook_surface: "${adapter.hook_surface}",
  native_template_id: "${adapter.native_template_id ?? "generic_admission_hook_v1"}",
  native_event_kind: "${adapter.native_event_kind ?? "GENERIC_AGENT_EVENT"}",
  surface_id: "${adapter.normalized_surface_id}",
  adapter_id: "${adapter.normalized_adapter_id}",
  action: "${SAMPLE_ACTION_BY_SURFACE[adapter.normalized_surface_id]}",
  endpoint: ENDPOINT,
  boundary_assertions: Object.freeze({
    no_secret_material_written: true,
    no_tool_execution_inside_admission: true,
    no_payload_mutation: true,
    no_policy_re_evaluation: true,
    no_proof_generation_inside_adapter: true,
    intentrax_runtime_remains_proof_owner: true,
    aevn_aep_remains_authoritative: true,
  }),
});

export const ${metadataExport} = hookMetadata;

${adapter.native_normalizer ? nativeAdapterExportsSource(adapter, contract) : genericAdapterExportsSource(adapter)}

async function buildNativeHookResult(event = {}, options = {}) {
  const admission_request = await buildNativeAdmissionForHook(event);
  const submit = options.submit === true;
  const admission_response = submit ? await submitNativeAdmission(admission_request, options) : null;
  return Object.freeze({
    schema_version: "intentrax.onboarding.agent_adapter_native_hook_result/1.0",
    adapter_name: hookMetadata.adapter_name,
    hook_surface: hookMetadata.hook_surface,
    admission_request,
    admission_response,
    original_event_ref: stableNativeHookEventRef(event),
    // Send this exact value as idempotency_key on /v1/intents/execute. The
    // engine links the execution under SHA-256(idempotency_key), which equals
    // admission_request.idempotency_key_hash, so the execution correlates with
    // this admission instead of reading as unadmitted.
    execute_idempotency_key: hookExecuteIdempotencyKey(admission_request.request_payload_hash),
    submitted: submit,
    mutation_performed: false,
    tool_execution_performed: false,
    proof_generation_performed: false,
    policy_re_evaluation_performed: false,
  });
}

// The raw execute idempotency key for an admission (same rule as the SDK's
// agentHookExecuteIdempotencyKey). The admission carries only its SHA-256.
function hookExecuteIdempotencyKey(requestPayloadHash) {
  return "INTENTRAX_AGENT_HOOK_IDEMPOTENCY_V1" + requestPayloadHash;
}

async function buildNativeAdmissionForHook(event = {}) {
  const sample = JSON.parse(await readFile(SAMPLE_ADMISSION_REQUEST_URL, "utf8"));
  const requestPayloadHash = sha256Hex(canonicalJson({
    adapter_name: hookMetadata.adapter_name,
    hook_surface: hookMetadata.hook_surface,
    original_event_ref: stableNativeHookEventRef(event),
  }));
  return Object.freeze({
    ...sample,
    request_payload_hash: requestPayloadHash,
    protocol_payload_ref: \`sha256:\${requestPayloadHash}\`,
    idempotency_key_hash: sha256Hex(hookExecuteIdempotencyKey(requestPayloadHash)),
  });
}

async function submitNativeAdmission(request, options = {}) {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new Error("Intentrax hook submission requires fetch or options.fetchImpl.");
  }
  const env = runtimeEnv();
  const apiKey = requiredRuntimeValue(options.apiKey ?? env.INTENTRAX_API_KEY, "INTENTRAX_API_KEY");
  const baseUrl = String(options.baseUrl ?? env.INTENTRAX_BASE_URL ?? "http://127.0.0.1:8080").replace(/\\/+$/, "");
  const response = await fetchImpl(baseUrl + ENDPOINT, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      [TENANT_HEADER]: request.tenant_id,
      [API_KEY_HEADER]: apiKey,
      [IDEMPOTENCY_HEADER]: request.idempotency_key_hash,
    },
    body: canonicalJson(request),
  });
  const text = await response.text();
  const body = text ? JSON.parse(text) : {};
  const admissionAllowed = response.ok && body.admission_status === "ADMITTED";
  const result = Object.freeze({
    status_code: response.status,
    ok: response.ok,
    admission_allowed: admissionAllowed,
    fail_closed: !admissionAllowed,
    response_hash: sha256Hex(text),
    body,
  });
  if (!admissionAllowed) {
    const status = body.admission_status ?? "UNKNOWN";
    throw new Error(\`Intentrax admission failed closed: http_status=\${response.status} admission_status=\${status}\`);
  }
  return result;
}

function stableNativeHookEventRef(event) {
  return "sha256:" + sha256Hex(canonicalJson({
    event_type: typeof event,
    event: sanitizeEvent(event),
  }));
}

function hashedHookPart(value) {
  return "sha256:" + sha256Hex(canonicalJson(sanitizeEvent(value ?? {})));
}

function stableText(value, fallback = "") {
  return typeof value === "string" && value.trim() === value && value.length > 0 ? value : fallback;
}

function firstStableText(values, fallback) {
  for (const value of values) {
    const out = stableText(value);
    if (out) return out;
  }
  return fallback;
}

function sanitizedKeys(value) {
  const sanitized = sanitizeEvent(value);
  return sanitized !== null && typeof sanitized === "object" && !Array.isArray(sanitized) ? Object.keys(sanitized).sort() : [];
}

function sanitizeEvent(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value) && Number.isInteger(value)) return value;
  if (typeof value === "number") return String(value);
  if (Array.isArray(value)) return value.map(sanitizeEvent);
  if (typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      if (isSensitiveKey(key)) continue;
      out[key] = sanitizeEvent(value[key]);
    }
    return out;
  }
  return String(value);
}

function isSensitiveKey(key) {
  return /secret|token|api[_-]?key|password|private[_-]?key|authorization|cookie|credential|session|bearer|client[_-]?key/i.test(key);
}

function canonicalJson(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return \`[\${value.map(canonicalJson).join(",")}]\`;
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number" && Number.isInteger(value) && Number.isFinite(value)) return String(value);
  if (typeof value === "object") {
    return \`{\${Object.keys(value).sort().map((key) => \`\${JSON.stringify(key)}:\${canonicalJson(value[key])}\`).join(",")}}\`;
  }
  throw new Error("canonical_json: unsupported value");
}

function sha256Hex(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function requiredRuntimeValue(value, name) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(\`\${name} must be provided at runtime and is never written by intentrax init.\`);
  }
  return value;
}

function runtimeEnv() {
  if (typeof process !== "object" || process === null || typeof process.env !== "object" || process.env === null) {
    return {};
  }
  return process.env;
}
`;
}

function genericAdapterExportsSource(adapter) {
  return `export async function ${adapter.hook_entrypoint}(event = {}, options = {}) {
  return buildIntentraxHookResult(event, options);
}

export async function buildIntentraxHookResult(event = {}, options = {}) {
  return buildNativeHookResult(event, options);
}

export async function buildIntentraxAdmissionForHook(event = {}) {
  return buildNativeAdmissionForHook(event);
}

export async function submitIntentraxAdmission(request, options = {}) {
  return submitNativeAdmission(request, options);
}`;
}

function nativeExportContract(adapter) {
  switch (adapter.native_normalizer) {
    case "normalizeClaudeCodePreToolUse":
      return {
        metadata_export: "intentraxClaudeCodeHookMetadata",
        result_export: "buildClaudeCodePreToolUseResult",
        admission_export: "buildClaudeCodePreToolUseAdmission",
        extract_export: "extractClaudeCodePreToolUseIntent",
        stable_ref_export: "stableClaudeCodePreToolUseEventRef",
        submit_export: "submitClaudeCodeAdmission",
      };
    case "normalizeCursorShellExecution":
      return {
        metadata_export: "intentraxCursorHookMetadata",
        result_export: "buildCursorShellExecutionResult",
        admission_export: "buildCursorShellExecutionAdmission",
        extract_export: "extractCursorShellExecutionIntent",
        stable_ref_export: "stableCursorShellExecutionEventRef",
        submit_export: "submitCursorAdmission",
      };
    case "normalizeMCPToolCall":
      return {
        metadata_export: "intentraxMCPHookMetadata",
        result_export: "buildMCPToolCallResult",
        admission_export: "buildMCPToolCallAdmission",
        extract_export: "extractMCPToolCallIntent",
        stable_ref_export: "stableMCPToolCallEventRef",
        submit_export: "submitMCPAdmission",
      };
    case "normalizeLangChainCallback":
      return {
        metadata_export: "intentraxLangChainHookMetadata",
        result_export: "buildLangChainToolStartResult",
        admission_export: "buildLangChainToolStartAdmission",
        extract_export: "extractLangChainToolStartIntent",
        stable_ref_export: "stableLangChainRunRef",
        submit_export: "submitLangChainAdmission",
        evidence_export: "buildLangChainIntentraxRunMetadata",
        evidence_kind: "LANGCHAIN_INTENTRAX_RUN_METADATA",
      };
    case "normalizeLangGraphNode":
      return {
        metadata_export: "intentraxLangGraphHookMetadata",
        result_export: "buildLangGraphNodeTransitionResult",
        admission_export: "buildLangGraphNodeTransitionAdmission",
        extract_export: "extractLangGraphNodeTransitionIntent",
        stable_ref_export: "stableLangGraphCheckpointRef",
        submit_export: "submitLangGraphAdmission",
        evidence_export: "buildLangGraphIntentraxStateEvidence",
        evidence_kind: "LANGGRAPH_INTENTRAX_STATE_EVIDENCE",
      };
    case "normalizeVercelAIRoute":
      return {
        metadata_export: "intentraxVercelAISDKHookMetadata",
        result_export: "buildVercelAIRouteResult",
        admission_export: "buildVercelAIRouteAdmission",
        extract_export: "extractVercelAIToolCallIntent",
        stable_ref_export: "stableVercelAIRouteRef",
        submit_export: "submitVercelAIAdmission",
        evidence_export: "buildVercelAIIntentraxResponseMetadata",
        evidence_kind: "VERCEL_AI_INTENTRAX_RESPONSE_METADATA",
      };
    default:
      return null;
  }
}

function nativeAdapterExportsSource(adapter, contract) {
  return `export async function ${adapter.hook_entrypoint}(event = {}, options = {}) {
  return ${contract.result_export}(event, options);
}

export async function ${contract.result_export}(event = {}, options = {}) {
  return buildNativeHookResult(${contract.extract_export}(event), options);
}

export async function ${contract.admission_export}(event = {}) {
  return buildNativeAdmissionForHook(${contract.extract_export}(event));
}

${nativeNormalizerSource(adapter.native_normalizer, contract.extract_export)}

export function ${contract.stable_ref_export}(event = {}) {
  return stableNativeHookEventRef(${contract.extract_export}(event));
}

export async function ${contract.submit_export}(request, options = {}) {
  return submitNativeAdmission(request, options);
}

${contract.evidence_export ? nativeEvidenceSource(contract) : ""}`;
}

function nativeEvidenceSource(contract) {
  return `export function ${contract.evidence_export}(event = {}) {
  const intent = ${contract.extract_export}(event);
  return Object.freeze({
    schema_version: "intentrax.onboarding.agent_adapter_native_evidence/1.0",
    evidence_kind: "${contract.evidence_kind}",
    adapter_name: hookMetadata.adapter_name,
    hook_surface: hookMetadata.hook_surface,
    event_ref: ${contract.stable_ref_export}(event),
    intent,
  });
}`;
}

function nativeNormalizerSource(normalizer, exportName) {
  switch (normalizer) {
    case "normalizeClaudeCodePreToolUse":
      return `export function ${exportName}(event = {}) {
  return Object.freeze({
    adapter_event_kind: hookMetadata.native_event_kind,
    adapter_name: hookMetadata.adapter_name,
    hook_surface: hookMetadata.hook_surface,
    admission_timing: "BEFORE_CLAUDE_CODE_TOOL_USE",
    tool_name: firstStableText([event.tool_name, event.toolName, event.name], "unknown_claude_code_tool"),
    tool_input_keys: sanitizedKeys(event.tool_input ?? event.input ?? event.arguments ?? {}),
    tool_input_ref: hashedHookPart(event.tool_input ?? event.input ?? event.arguments ?? {}),
    permission_prompt_ref: hashedHookPart(event.permission_prompt ?? event.prompt ?? {}),
    raw_event_ref: stableNativeHookEventRef(event),
  });
}`;
    case "normalizeCursorShellExecution":
      return `export function ${exportName}(event = {}) {
  return Object.freeze({
    adapter_event_kind: hookMetadata.native_event_kind,
    adapter_name: hookMetadata.adapter_name,
    hook_surface: hookMetadata.hook_surface,
    admission_timing: "BEFORE_CURSOR_SHELL_EXECUTION",
    shell: firstStableText([event.shell, event.shell_name, event.terminal], "cursor_shell"),
    command_ref: hashedHookPart(event.command ?? event.shell_command ?? event.args ?? {}),
    workspace_ref: hashedHookPart({ cwd: event.cwd, workspace: event.workspace, workspace_id: event.workspace_id }),
    raw_event_ref: stableNativeHookEventRef(event),
  });
}`;
    case "normalizeMCPToolCall":
      return `export function ${exportName}(event = {}) {
  return Object.freeze({
    adapter_event_kind: hookMetadata.native_event_kind,
    adapter_name: hookMetadata.adapter_name,
    hook_surface: hookMetadata.hook_surface,
    admission_timing: "BEFORE_MCP_TOOL_CALL",
    server_name: firstStableText([event.server_name, event.serverName, event.server?.name], "unknown_mcp_server"),
    tool_name: firstStableText([event.tool_name, event.toolName, event.name], "unknown_mcp_tool"),
    argument_keys: sanitizedKeys(event.arguments ?? event.args ?? event.input ?? {}),
    argument_ref: hashedHookPart(event.arguments ?? event.args ?? event.input ?? {}),
    raw_event_ref: stableNativeHookEventRef(event),
  });
}`;
    case "normalizeLangChainCallback":
      return `export function ${exportName}(event = {}) {
  return Object.freeze({
    adapter_event_kind: hookMetadata.native_event_kind,
    adapter_name: hookMetadata.adapter_name,
    hook_surface: hookMetadata.hook_surface,
    admission_timing: "BEFORE_LANGCHAIN_TOOL_OR_CHAIN",
    run_type: firstStableText([event.run_type, event.type, event.serialized?.name], "langchain_callback"),
    tool_name: firstStableText([event.tool_name, event.name, event.serialized?.id], "unknown_langchain_tool"),
    input_ref: hashedHookPart(event.input ?? event.inputs ?? event.arguments ?? {}),
    metadata_ref: hashedHookPart(event.metadata ?? event.tags ?? {}),
    raw_event_ref: stableNativeHookEventRef(event),
  });
}`;
    case "normalizeLangGraphNode":
      return `export function ${exportName}(event = {}) {
  return Object.freeze({
    adapter_event_kind: hookMetadata.native_event_kind,
    adapter_name: hookMetadata.adapter_name,
    hook_surface: hookMetadata.hook_surface,
    admission_timing: "BEFORE_LANGGRAPH_NODE",
    graph_name: firstStableText([event.graph_name, event.graphName, event.graph?.name], "langgraph_graph"),
    node_name: firstStableText([event.node_name, event.nodeName, event.name], "unknown_langgraph_node"),
    state_ref: hashedHookPart(event.state ?? event.input ?? event.messages ?? {}),
    config_ref: hashedHookPart(event.config ?? event.runtime ?? {}),
    raw_event_ref: stableNativeHookEventRef(event),
  });
}`;
    case "normalizeVercelAIRoute":
      return `export function ${exportName}(event = {}) {
  return Object.freeze({
    adapter_event_kind: hookMetadata.native_event_kind,
    adapter_name: hookMetadata.adapter_name,
    hook_surface: hookMetadata.hook_surface,
    admission_timing: "BEFORE_VERCEL_AI_SDK_GENERATION",
    route_ref: hashedHookPart({ method: event.method, path: event.path, url: event.url }),
    model_ref: hashedHookPart(event.model ?? event.provider ?? {}),
    prompt_ref: hashedHookPart(event.prompt ?? event.messages ?? event.body ?? {}),
    raw_event_ref: stableNativeHookEventRef(event),
  });
}`;
    default:
      throw new Error(`unknown native normalizer: ${normalizer}`);
  }
}

function buildSubmitSample(sampleAdmissionRequest, options) {
  const baseUrl = options.baseUrl.replace(/\/+$/, "");
  const url = baseUrl + ENDPOINT;
  const workingDirectory = options.outputDir ? resolve(options.outputDir) : ".";
  const bodyFile = ".intentrax/sample-admission-request.json";
  const filePath = ".intentrax/submit_sample.curl";
  const headers = {
    "content-type": "application/json",
    [TENANT_HEADER]: sampleAdmissionRequest.tenant_id,
    [API_KEY_HEADER]: "$INTENTRAX_API_KEY",
    [IDEMPOTENCY_HEADER]: sampleAdmissionRequest.idempotency_key_hash,
  };
  return {
    schema_version: "intentrax.onboarding.agent_adapter_submit_sample/1.0",
    method: "POST",
    url,
    headers,
    file_path: filePath,
    body_file: bodyFile,
    working_directory: workingDirectory,
    curl: buildCurl(url, headers, bodyFile),
  };
}

function buildCurl(url, headers, bodyFile) {
  return [
    "curl -sS",
    quote(url),
    "-H",
    quote(`content-type: ${headers["content-type"]}`),
    "-H",
    quote(`${TENANT_HEADER}: ${headers[TENANT_HEADER]}`),
    "-H",
    quote(`${API_KEY_HEADER}: ${headers[API_KEY_HEADER]}`),
    "-H",
    quote(`${IDEMPOTENCY_HEADER}: ${headers[IDEMPOTENCY_HEADER]}`),
    "--data-binary",
    quote(`@${bodyFile}`),
  ].join(" ");
}

function quote(value) {
  return JSON.stringify(value);
}

function canonicalJson(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number" && Number.isInteger(value) && Number.isFinite(value)) return String(value);
  if (typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  throw new Error("canonical_json: unsupported value");
}

function sha256Hex(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function sha256HexBytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function normalizeSHA256Hex(value, field) {
  const normalized = String(value || "").trim().toLowerCase().replace(/^sha256:/, "");
  if (!/^[a-f0-9]{64}$/.test(normalized)) {
    fail(`${field}: malformed SHA-256 hex`);
  }
  return normalized;
}

function requireValue(args, index, option) {
  const value = args[index];
  if (!value) {
    fail(`${option} requires a value`);
  }
  return value;
}

function fail(message) {
  console.error(`intentrax: ${message}`);
  printHelp();
  process.exit(2);
}

function printHelp() {
  console.log(`Intentrax CLI ${VERSION}

Usage:
  intentrax init <adapter> [--dry-run] [--force] [--json] [--output-dir <dir>] [--base-url <url>] [--tenant-id <tenant>]
  intentrax check-init --output-dir <dir> [--json]
  intentrax verify-proof <proof-export.json> [--answer-file <answer.txt> [--quote-file <quote.txt>]] [--trusted-keys <key-set.json>] [--policy-document <policy.json>] [--tlog-trust <transparency-log.json> [--tlog-bundle <proof.tlog.json>]] [--tenant-keys <directory.json>] [--approver-set <approver-set.json>] [--pin-directory-head <hex>] [--json] [--report-out <file>]
  intentrax verify-pdf-receipt <receipt.pdf> --pdf-hash <X-Intentrax-PDF-Hash> [--json] [--report-out <file>]
  intentrax sandbox [--scenario confirmed|contradicted] [--check <read-only-check.mjs>] [--dir <dir>] [--json]
  intentrax sandbox verify <bundle.json> [--keys <local-key-set.json>] [--issuer-keys <pinned-external-issuers.json>] [--require-external-issuer <issuer>]... [--json]
  intentrax readback --check <read-only-check.mjs> --expected <json> [--claimed <json>] [--retries N] [--json]
  intentrax scan [dir] [--json] [--include-tests] [--max-files N]
  intentrax mcp pin --server <cmd|url> [--name <name>] [--accept <tool,...> | --replace] [--json]
  intentrax mcp check [--pins <file>] [--name <name>] [--json]
  intentrax mcp proxy [--pins <file>] [--name <name>] [--on-drift block|warn]
  intentrax guard claude-code [--dir <dir>] [--local] [--mcp] [--dry-run] [--json]
  intentrax guard status|verify [--dir <dir>] [--json]
  intentrax guard explain --command '<shell command>' | --tool <name> [--input <json>]
  intentrax guard uninstall [--dir <dir>] [--local] [--purge] [--dry-run]
  intentrax policy list|show <pack>|hash <pack>|validate [file]|check --tool <name> [--input <json>] [--json]
  intentrax policy init --from-scan [dir] [--out <file>] [--environment PROD|STAGING|DEV] [--force]
  intentrax approve keygen --tenant-id <id> --principal-id <id> --key-id <id> --out <key.json> --registration-out <reg.json>
  intentrax approve [<admission_request_hash>] --request <envelope.json> --approval-request <pending.json> --key <key.json> --directory <dir.json> --out <approval.json> [--reject] [--json]

Adapters:
  ${Object.keys(ADAPTERS).join(", ")}

Aliases:
  generic-mcp -> mcp

Init verification:
  check-init verifies an initialized .intentrax adapter directory offline,
  recomputes hook and action receipt bindings, validates the generated Agent
  Gateway admission fixture, and invokes the generated hook without
  INTENTRAX_API_KEY or network submission.

Proof export verification:
  verify-proof reads an exported registry-backed proof lookup JSON package and,
  offline: recomputes its proof lookup, proof record, verification bundle, and
  AEP hashes; verifies every ed25519 signature over the signed payload and the
  signature quorum; checks that the signed payload carries the record's own
  AEP; and checks each signer against published key sets. It writes a
  deterministic report. Runtime access, network access, and private keys are
  not required. The JSON export is authoritative; PDF receipts are companions.

  Result (status / exit code):
    PASS                       0  every signer is a published, trust-bearing key,
                                  and at least the key set's min_trusted_signers
                                  distinct keys signed
    SANDBOX_NON_TRUST_BEARING  0  every signer is a published sandbox key: the
                                  mechanics check out, but it is not production
                                  assurance
    UNPINNED_SIGNER            3  signatures are valid but a signer is not in
                                  any trusted key set (who signed is unproven)
    INSUFFICIENT_TRUSTED_SIGNERS 3  every signer is trusted, but fewer distinct
                                  keys signed than the published key set
                                  requires (signatures may have been stripped)
    REVOKED_SIGNER / MIXED_TRUST 3
    SIGNER_PURPOSE_MISMATCH    3  a signer is pinned only for another purpose
                                  (published_key_set/1.2)
    SIGNER_KEY_NOT_VALID_AT_SIGNING_TIME 3  a signer's 1.2 validity window does
                                  not cover the record's decided_at
    APPROVAL_EVIDENCE_INVALID  2  the proof binds approval evidence that does
                                  not check out
    any integrity or signature failure exits 2 (failed closed)

  A proof that seals a policy binding (AEP 1.1) also gets policy_reevaluation:
  verify-proof rebuilds the evaluated event from the signed proof, resolves the
  policy by its source_policy_hash (--policy-document, as served by
  GET /v1/policies/{source_policy_hash}, or the published registry bundled in
  trust/policies), re-runs the policy engine and requires every sealed value
  to come out identical. MATCH or NOT_RECHECKED (with a reason); a re-run that
  disagrees fails closed (exit 2).

  The report also carries verification_assessment, printed as a table: the
  assurance profile (every proof issued today is LEGACY_DECISION_RECORD,
  which requires only RECORD_INTEGRITY), a result per dimension, a verdict
  derived by a fixed rule, and machine-readable limitations. Verdicts:
    VERIFIED_FOR_SCOPE   record intact and signed by published trusted keys;
                         the scope is the profile's required dimensions only
    INTEGRITY_ONLY       record intact, signer not established
    VERIFICATION_FAILED  a dimension failed (for example a REVOKED signer)
  A legacy proof never claims execution, effect or policy evaluation:
  EXECUTION_NOT_ATTESTED, EFFECT_NOT_VERIFIED, POLICY_BINDING_SYNTHETIC and
  COMPLETENESS_NOT_ESTABLISHED are always listed. The exit code does not
  depend on the assessment.

  Transparency-log inclusion is opt-in: --tlog-trust pins a transparency-log
  trust document (intentrax.trust.transparency_log/0: log key, witness keys,
  quorum; none is bundled while no log is published) and --tlog-bundle gives
  this proof's inclusion bundle (intentrax.tlog.inclusion-bundle/v0). The
  report then carries a transparency block and a TRANSPARENCY row: VERIFIED,
  VERIFIED_UNWITNESSED, NOT_PRESENT (no bundle: the record is not shown to be
  logged; nothing else changes) or FAILED (status TRANSPARENCY_FAILED,
  non-zero exit). Without --tlog-trust the report is exactly as before.

  Signed pre-approval records (specs 01–03): a proof that seals
  admission_binding (an admission decision) or policy_binding/1.2 (ENFORCED,
  the ADMISSION lane, approvals) is checked for consistency and fails closed
  otherwise. The report adds admission_binding and its statement. A sealed
  approval or rejection is re-checked against the export's attachments: the
  approval envelopes, the approver set in force and the tenant key directory.
  The directory is trusted only through a head you pin
  (--pin-directory-head) or a TENANT_KEY_DIRECTORY key of a
  published_key_set/1.2 given with --trusted-keys. Supply directories and
  approver sets the export does not carry with --tenant-keys and
  --approver-set. approval_evidence says VERIFIED, NOT_SUPPLIED or
  NOT_RECHECKED; an approval that was not verified never upgrades
  AUTHORIZATION. Evidence that does not check out gives status
  APPROVAL_EVIDENCE_INVALID (exit 2). The export's disclosures (arguments,
  commitment openings, policy documents) are re-hashed; a mismatch fails
  closed, and opened facts let the ADMISSION-lane evaluation be re-run.

  The SDK ships the production key set (trust/production-key-set.json,
  min_trusted_signers 2) and the sandbox key set (trust/sandbox-key-set.json).
  Add more sets, for example revocations, with --trusted-keys <file>
  (repeatable).

  Rendered-output binding: when the signed AEP seals an output_binding, the
  report shows it and says who computed the answer hash
  (output_binding_statement: ENGINE_COMPUTED or PRODUCER_DECLARED_AT_ISSUANCE).
  --answer-file checks an answer text against it (answer_check MATCH or
  MISMATCH; a mismatch is status ANSWER_MISMATCH, exit 1, or 3 when the
  signers are not trusted either) and --quote-file whether a quote is part of
  that answer. A match is a match against the sealed hash, never a verdict on
  whether the answer is correct. A proof with no binding refuses --answer-file.

Read-back (intentrax readback --help):
  Reads the system of record with your read-only check before anyone reports
  success. 0 CONFIRMED, 12 CONTRADICTED (CAUGHT), 10 PENDING, 11 UNKNOWN,
  64 usage. SELF_REPORTED: not an Intentrax attestation.

Scan (intentrax scan --help):
  Lists the destructive or consequential actions an AI agent can reach in a
  project and flags broad credentials (EXPOSED), missing gates (UNGATED) and
  success reported without a read-back (SELF-REPORTED). Heuristic and static:
  nothing is run or sent. 0 no findings, 20 findings, 2 error.

MCP tool pinning (intentrax mcp --help):
  pin records a server's tool definitions in .intentrax/mcp-pins.json; check
  compares them (0 MATCH, 10 CHANGED, 2 UNCHECKED, 1 usage); proxy blocks
  changed and new tools in a stdio proxy. Covers tool definitions only. It
  does not show that the server's code or behaviour is unchanged.

Guard (intentrax guard --help):
  claude-code installs a Claude Code PreToolUse hook that blocks (force push,
  rm -rf of a root or home, DROP/TRUNCATE, terraform destroy...) or asks
  (pushes, deploys, recursive deletes, SQL writes, consequential MCP tools)
  before a tool call; allow means no objection, and Claude Code's own
  permission rules still apply. It also applies the policy packs in
  .intentrax/policy.jsonc. Every decision goes into a local hash-chained
  record that verify checks offline. No account, no network; the record is
  local, not trust-bearing. 0 ok, 2 broken chain or failed install, 1 usage.

Policy packs (intentrax policy --help):
  Open policy packs, one per scan category, each a C2 policy that decides
  allow, ask or block for an agent's tool call. init --from-scan writes a draft
  .intentrax/policy.jsonc that selects the packs the scan matched; each pack is
  pinned by its pack_hash. Facts are read from the tool input on this machine
  (self-reported); the decision can be re-checked from the policy hash.
  0 ok, 1 invalid, 2 usage or I/O error.

Approve (intentrax approve --help):
  Signs an intentrax.approval/0.1 approval or rejection with a local, human
  APPROVER key after recomputing the request hashes and showing the request.
  Local only: nothing is sent. keygen makes the key and its registration
  request. 0 ok, 1 error.

PDF receipt verification:
  verify-pdf-receipt reads downloaded PDF receipt bytes, checks the PDF header,
  recomputes SHA-256, and compares it with the X-Intentrax-PDF-Hash response
  header. This validates the companion PDF bytes only; the canonical JSON proof
  export and AEP evidence remain authoritative.

Examples:
  intentrax init claude-code --dry-run
  intentrax init cursor --output-dir .
  intentrax init cursor --output-dir . --force
  intentrax init mcp --json
  intentrax init generic-mcp --dry-run
  intentrax init langchain
  intentrax init langgraph
  intentrax init vercel-ai-sdk
  intentrax check-init --output-dir . --json
  intentrax verify-proof node_modules/@intentrax/sdk/examples/sandbox/sandbox-proof-export.json
  intentrax verify-proof node_modules/@intentrax/sdk/examples/sandbox/tampered-aep-swap.json
  intentrax verify-proof proof-export.json --trusted-keys intentrax-production-keys.json
  intentrax verify-pdf-receipt .intentrax/proof-001-aep-receipt.pdf --pdf-hash <X-Intentrax-PDF-Hash>
  intentrax sandbox
  intentrax sandbox --scenario contradicted
  intentrax sandbox --check ./my-check.mjs
  intentrax readback --check ./read-refund.mjs --expected '{"status":"succeeded"}' --claimed '{"status":"processed"}'
  intentrax scan .
  intentrax mcp pin --name github --server https://api.example.com/mcp --header 'Authorization: Bearer \${GITHUB_TOKEN}'
  intentrax mcp check
  intentrax guard claude-code
  intentrax guard explain --command 'git push --force origin main'
  intentrax policy init --from-scan .
  intentrax policy check --tool Bash --input '{"command":"git push --force origin main"}'
`);
}

process.exitCode = await main(process.argv.slice(2));
