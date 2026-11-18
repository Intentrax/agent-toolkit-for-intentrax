// Local assurance sandbox: one consequential action, end to end, in-process.
//
//   local principal ──signs──▶ mandate (agent may SetState on one resource)
//   local decision service ──signs──▶ ALLOW/DENY, made BEFORE execution
//   executor shim ──signs──▶ execution report (SELF_REPORTED)
//   local effect verifier ──own key, read-only──▶ reads the outcome
//        └─ signs intentrax.effect_evidence/0.1 (CONFIRMED / CONTRADICTED / ...)
//   local decision service ──seals──▶ intentrax.local_assurance_bundle/0.1
//   offline verifier (local key set, no network, no clock)
//        └─ 8 dimensions → §5.4 verdict → capped at LOCAL_NON_TRUST_BEARING
//
// Flow ported from examples/effect-assurance-demo (decision-service.mjs,
// executor.mjs, world.mjs, scenarios.mjs; PRs #449, #477), reduced to one
// root mandate, one action and one read.
//
// Hard boundaries (each enforced by a test in ./test):
//   - keys are generated fresh per run; nothing here reads, derives or
//     requests a production or published sandbox key;
//   - no network: no module here imports a network API; the only code that
//     could touch a network is a developer's own --check module;
//   - the sandbox never calls a developer's write path. With --check it only
//     records the claim that the developer's action ran, then calls the
//     developer's read-only check.

import { randomBytes } from "node:crypto";
import { digest } from "./canonical.mjs";
import { signEnvelope, verifyEnvelope, envelopeDigest, PAYLOAD_TYPES } from "./envelope.mjs";
import { evaluate, actionDigest } from "./authority.mjs";
import { OPERATION, claimedOutcome } from "./effects.mjs";
import { LocalEffectVerifier, READ_KINDS } from "./effect-verifier.mjs";
import { assembleBundle } from "./bundle.mjs";
import { generateLocalSigners, localKeySetDocument, localSigningKeysDocument, loadLocalKeySet, LOCAL_PRINCIPALS, ROLES } from "./keys.mjs";
import { verifyLocalBundle } from "./verifier.mjs";

export const SCENARIOS = Object.freeze({
  confirmed: "The executor applies the authorised change; the independent read confirms it.",
  contradicted:
    "Scenario B: the decision is ALLOW and the executor reports SUCCEEDED, but it never wrote; the independent read contradicts it.",
});

export const SAMPLE_ACTION = Object.freeze({
  description: "Approve a 42.00 refund on order SBX-1042 (synthetic, in-memory)",
  resource: "order:SBX-1042",
  initial_state: Object.freeze({ refund_status: "REQUESTED", refund_amount_cents: 0 }),
  authorised_state: Object.freeze({ refund_status: "APPROVED", refund_amount_cents: 4200 }),
});

const AGENT = "agent:local-sandbox-agent";
const DECISION_TTL_SECONDS = 300;
const MANDATE_TTL_SECONDS = 3600;

function iso(ms) {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function addSeconds(isoString, seconds) {
  return iso(Date.parse(isoString) + seconds * 1000);
}

// Logical clock: starts at the real time of the run (whole seconds) and
// advances one step per event, so the record order is unambiguous.
class LogicalClock {
  #ms;

  constructor(start) {
    this.#ms = Math.floor(start.getTime() / 1000) * 1000;
    if (!Number.isFinite(this.#ms)) throw new Error("sandbox clock: bad start time");
  }

  now() {
    return iso(this.#ms);
  }

  advance(seconds = 1) {
    this.#ms += seconds * 1000;
    return this.now();
  }
}

// In-memory stand-in for the system the sample action changes.
class SyntheticStore {
  #state = new Map();
  writeCalls = 0;

  seed(resource, state) {
    this.#state.set(resource, structuredClone(state));
  }

  write(resource, state) {
    this.writeCalls += 1;
    this.#state.set(resource, { ...(this.#state.get(resource) ?? {}), ...structuredClone(state) });
  }

  read(resource) {
    return structuredClone(this.#state.get(resource) ?? null);
  }
}

export class ExecutorRefusal extends Error {
  constructor(code) {
    super("executor refused: " + code);
    this.code = code;
  }
}

class LocalDecisionService {
  #clock;
  #signer;
  #policy;
  #mandateEnv;

  constructor({ clock, signer, policy, mandateEnv }) {
    this.#clock = clock;
    this.#signer = signer;
    this.#policy = policy;
    this.#mandateEnv = mandateEnv;
  }

  decide(request) {
    const now = this.#clock.now();
    const result = evaluate({
      request,
      mandate: this.#mandateEnv.payload,
      policy: this.#policy,
      policyDigest: digest(this.#policy),
      at: now,
    });
    return signEnvelope(PAYLOAD_TYPES.DECISION, {
      schema_version: PAYLOAD_TYPES.DECISION,
      decision_id: "dec-" + digest(request).slice(7, 23),
      request,
      request_digest: digest(request),
      action_digest: actionDigest(request),
      outcome: result.outcome,
      reasons: result.reasons,
      decided_at: now,
      execute_before: result.outcome === "ALLOW" ? addSeconds(now, DECISION_TTL_SECONDS) : null,
      mandate_id: request.mandate_id,
      mandate_chain_digests: [envelopeDigest(this.#mandateEnv)],
      policy_id: this.#policy.policy_id,
      policy_version: this.#policy.version,
      policy_digest: digest(this.#policy),
      required_assurance_profile: result.required_assurance_profile,
    }, this.#signer);
  }
}

// Executor shim. Modes:
//   "apply"                      writes the authorised state to the synthetic store
//   "drop-write-report-success"  never writes, reports SUCCEEDED (scenario B)
//   "record-external-claim"      the developer's action ran outside the sandbox;
//                                this report records that claim (no call made)
class LocalExecutor {
  #clock;
  #signer;
  #pinned;
  #store;
  #used = new Set();

  constructor({ clock, signer, pinned, store, mode }) {
    this.#clock = clock;
    this.#signer = signer;
    this.#pinned = pinned;
    this.#store = store;
    this.mode = mode;
    this.principal = signer.principal;
  }

  execute(decisionEnv) {
    const v = verifyEnvelope(decisionEnv, { pinned: this.#pinned });
    if (decisionEnv?.payload_type !== PAYLOAD_TYPES.DECISION || v.integrity !== "VERIFIED" || v.authenticity !== "VERIFIED") {
      throw new ExecutorRefusal("DECISION_NOT_AUTHENTIC");
    }
    const d = decisionEnv.payload;
    if (d.outcome !== "ALLOW") throw new ExecutorRefusal("DECISION_DENIED");
    if (Date.parse(this.#clock.now()) >= Date.parse(d.execute_before)) throw new ExecutorRefusal("DECISION_EXPIRED");
    if (this.#used.has(d.decision_id)) throw new ExecutorRefusal("DECISION_REPLAYED");
    this.#used.add(d.decision_id);

    const startedAt = this.#clock.now();
    let downstream;
    if (this.mode === "apply") {
      this.#store.write(d.request.resource, d.request.params.state);
      downstream = { system: "sandbox-synthetic-store", call: "write", note: null };
    } else if (this.mode === "drop-write-report-success") {
      downstream = { system: "sandbox-synthetic-store", call: "write", note: null };
    } else if (this.mode === "record-external-claim") {
      downstream = {
        system: "developer-system",
        call: null,
        note: "The action ran outside the sandbox. This report records the claim that it succeeded; the sandbox made no call.",
      };
    } else {
      throw new Error("unknown executor mode " + this.mode);
    }
    this.#clock.advance();
    return signEnvelope(PAYLOAD_TYPES.EXECUTION_REPORT, {
      schema_version: PAYLOAD_TYPES.EXECUTION_REPORT,
      report_id: "rpt-" + d.decision_id.slice(4) + "-1",
      sequence: 1,
      decision_id: d.decision_id,
      decision_digest: envelopeDigest(decisionEnv),
      action_digest: d.action_digest,
      executor_principal: this.principal,
      started_at: startedAt,
      reported_at: this.#clock.now(),
      status: "SUCCEEDED",
      claimed_outcome: claimedOutcome("SUCCEEDED"),
      downstream,
    }, this.#signer);
  }
}

// userCheck: null for the built-in sample, or
//   { read: async (probe) => observedState, expected: {...}, resource: string,
//     checkModule: { file_name, sha256 }, timeoutMs }
export async function runSandbox({ scenario = "confirmed", userCheck = null, now = new Date() } = {}) {
  if (userCheck && scenario !== "confirmed") {
    throw new Error("--scenario applies to the built-in sample only; it cannot be combined with --check");
  }
  if (!Object.prototype.hasOwnProperty.call(SCENARIOS, scenario)) {
    throw new Error("unknown scenario " + scenario + " (expected: " + Object.keys(SCENARIOS).join(", ") + ")");
  }
  const clock = new LogicalClock(now);
  const runId = randomBytes(8).toString("hex");
  const startedAt = clock.now();
  const signers = generateLocalSigners({ now: startedAt });
  const keySet = localKeySetDocument(signers);
  const pinned = loadLocalKeySet(keySet);

  const resource = userCheck ? userCheck.resource : SAMPLE_ACTION.resource;
  const state = userCheck ? userCheck.expected : { ...SAMPLE_ACTION.authorised_state };
  const policy = {
    schema_version: "intentrax.policy/0.1",
    policy_id: "local-sandbox-policy",
    version: 1,
    default: "DENY",
    rules: [{ operation: OPERATION, required_profile: "EFFECT_CONFIRMED" }],
  };
  const mandateEnv = signEnvelope(PAYLOAD_TYPES.MANDATE, {
    schema_version: PAYLOAD_TYPES.MANDATE,
    mandate_id: "mnd-local-" + runId,
    issuer: LOCAL_PRINCIPALS.PRINCIPAL,
    subject: AGENT,
    parent_mandate_id: null,
    policy_digest: digest(policy),
    scope: { operations: [OPERATION], resources: [resource] },
    not_before: startedAt,
    expires_at: addSeconds(startedAt, MANDATE_TTL_SECONDS),
    issued_at: startedAt,
    purpose: userCheck ? "Local sandbox: check the outcome of the developer's own action" : "Local sandbox sample action",
  }, signers[ROLES.PRINCIPAL]);

  const store = new SyntheticStore();
  if (!userCheck) store.seed(SAMPLE_ACTION.resource, SAMPLE_ACTION.initial_state);

  clock.advance();
  const request = {
    request_id: "req-local-" + runId,
    agent: AGENT,
    mandate_id: mandateEnv.payload.mandate_id,
    operation: OPERATION,
    resource,
    params: { state },
    requested_at: clock.now(),
  };
  const decisionService = new LocalDecisionService({ clock, signer: signers[ROLES.DECISION_SERVICE], policy, mandateEnv });
  const decisionEnv = decisionService.decide(request);

  clock.advance();
  const executor = new LocalExecutor({
    clock,
    signer: signers[ROLES.EXECUTOR],
    pinned,
    store,
    mode: userCheck ? "record-external-claim" : scenario === "contradicted" ? "drop-write-report-success" : "apply",
  });
  const reportEnv = executor.execute(decisionEnv);

  clock.advance();
  const effectVerifier = new LocalEffectVerifier({ clock, signer: signers[ROLES.EFFECT_VERIFIER] });
  const reader = userCheck
    ? { kind: READ_KINDS.USER_SUPPLIED_CHECK, read: userCheck.read, checkModule: userCheck.checkModule, timeoutMs: userCheck.timeoutMs }
    : { kind: READ_KINDS.SANDBOX_SYNTHETIC_STORE, read: (probe) => store.read(probe.resource), checkModule: null };
  const { evidence, observation } = await effectVerifier.observe({ decisionEnv, reportEnv, reader });

  clock.advance();
  const bundle = assembleBundle({
    bundleId: "bnd-local-" + runId,
    policy,
    mandates: [mandateEnv],
    decision: decisionEnv,
    executionReports: [reportEnv],
    effectEvidence: [evidence],
    sourceObservations: [observation],
    sealSigner: signers[ROLES.DECISION_SERVICE],
    sealedAt: clock.now(),
  });

  // Verify from the serialised bytes, exactly as a third party would.
  const report = verifyLocalBundle(JSON.parse(JSON.stringify(bundle)), { pinned: loadLocalKeySet(JSON.parse(JSON.stringify(keySet))) });

  return {
    run_id: runId,
    scenario: userCheck ? "user-check" : scenario,
    action: userCheck
      ? { description: "Your action (performed outside the sandbox)", resource, authorised_state: state }
      : { description: SAMPLE_ACTION.description, resource, authorised_state: state },
    facts: {
      decision_outcome: decisionEnv.payload.outcome,
      executor_report_status: reportEnv.payload.status,
      synthetic_store_writes: userCheck ? null : store.writeCalls,
      observed_state: observation.body ? observation.body.state : null,
      read_status: observation.status,
      read_error: observation.error,
      read_kind: observation.read_kind,
    },
    keys: Object.fromEntries(Object.entries(signers).map(([role, s]) => [role, s.key_id])),
    bundle,
    keySet,
    signingKeys: localSigningKeysDocument(signers, startedAt),
    report,
  };
}
