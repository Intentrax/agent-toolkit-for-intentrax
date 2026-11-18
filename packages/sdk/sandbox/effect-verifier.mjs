// Local effect verifier: the sandbox's independent, read-only outcome check.
//
// Adapted from examples/effect-assurance-demo/src/effect-verifier.mjs (PRs
// #449, #477). As in the demo, the check reads the system with its OWN key and
// principal (never the executor's), compares the observed state with the
// state the signed decision authorised, and signs an
// `intentrax.effect_evidence/0.1` object. `assessEffect` is a pure function
// shared with the offline verifier, which recomputes every conclusion from the
// bundled observation and refuses evidence whose signed fields disagree.
//
// What differs from the demo, and is labelled in every bundle:
//   - There is no source-signed receipt or authenticated channel. The read is
//     either the sandbox's synthetic store (source_authentication
//     LOCAL_EFFECT_VERIFIER_READ, provenance THIRD_PARTY_ATTESTED: attested by
//     the local effect-verifier key, distinct from the executor key) or a
//     check module the developer wrote (USER_SUPPLIED_CHECK, provenance
//     SELF_REPORTED: the party whose action is checked also wrote the check).
//     Neither is an Intentrax-pulled authoritative read.
//   - The sandbox never calls a developer's write path. A user check is
//     read-only by contract only; the sandbox cannot enforce that.

import { digest, canonicalJson, isCanonicalizable } from "./canonical.mjs";
import { signEnvelope, envelopeDigest, PAYLOAD_TYPES } from "./envelope.mjs";
import { effectFor, claimedOutcome, expectedStateDigest, OUTCOMES } from "./effects.mjs";
import { isoMs } from "./time.mjs";

export const RETRIEVAL_METHOD = "LOCAL_SANDBOX_PULL";

export const READ_KINDS = Object.freeze({
  SANDBOX_SYNTHETIC_STORE: "SANDBOX_SYNTHETIC_STORE",
  USER_SUPPLIED_CHECK: "USER_SUPPLIED_CHECK",
});

const SOURCE_AUTHENTICATION = Object.freeze({
  SANDBOX_SYNTHETIC_STORE: "LOCAL_EFFECT_VERIFIER_READ",
  USER_SUPPLIED_CHECK: "USER_SUPPLIED_CHECK",
});

const READ_LIMITATIONS = Object.freeze({
  SANDBOX_SYNTHETIC_STORE: ["SOURCE_RESPONSE_NOT_THIRD_PARTY_SIGNED", "SYNTHETIC_SOURCE"],
  USER_SUPPLIED_CHECK: ["USER_SUPPLIED_CHECK_NOT_INDEPENDENT", "USER_CHECK_READ_ONLY_BY_CONTRACT_ONLY"],
});

export function sourceAuthenticationFor(readKind) {
  return Object.prototype.hasOwnProperty.call(SOURCE_AUTHENTICATION, readKind) ? SOURCE_AUTHENTICATION[readKind] : "NONE";
}


export function assessEffect({
  request,
  report,
  retrievalMethod,
  retrievalPrincipal,
  expectedRetrievalPrincipal = null,
  observation,
  observedAt,
}) {
  const eff = effectFor(request.operation);
  const outcome = claimedOutcome(report.status);
  const reasons = [];
  const limitations = [];
  let expected = null;
  try {
    expected = outcome && outcome !== OUTCOMES.PENDING ? expectedStateDigest(request, outcome) : null;
  } catch {
    expected = null;
  }
  const out = {
    claimed_outcome: outcome,
    expected_state_digest: expected,
    observed_state_digest: null,
    evidence_digest: null,
    source_authentication: "NONE",
    finality: "UNKNOWN",
    max_age_seconds: eff.max_age_seconds,
  };

  if (retrievalMethod !== RETRIEVAL_METHOD) reasons.push("READ_NOT_PERFORMED_BY_SANDBOX_EFFECT_VERIFIER");
  if (retrievalPrincipal === report.executor_principal) reasons.push("RETRIEVAL_NOT_INDEPENDENT_OF_EXECUTOR");
  if (expectedRetrievalPrincipal !== null && retrievalPrincipal !== expectedRetrievalPrincipal) {
    reasons.push("RETRIEVAL_PRINCIPAL_IS_NOT_THE_EFFECT_VERIFIER");
  }

  if (!observation) {
    reasons.push("OBSERVATION_MISSING");
  } else {
    out.evidence_digest = isCanonicalizable(observation.body) ? digest(observation.body) : null;
    if (canonicalJson(observation.request) !== canonicalJson(eff.probe(request))) {
      reasons.push("PROBE_DOES_NOT_TARGET_CLAIMED_EFFECT");
    }
    out.source_authentication = sourceAuthenticationFor(observation.read_kind);
    if (out.source_authentication === "NONE") reasons.push("READ_KIND_UNKNOWN");
    else limitations.push(...READ_LIMITATIONS[observation.read_kind]);
    if (observation.status !== "OK") reasons.push("SOURCE_READ_FAILED:" + observation.status);
    const bound = observation.status === "OK" && eff.bound(request, observation.body);
    if (observation.status === "OK" && !bound) reasons.push("OBSERVATION_NOT_BOUND_TO_DECISION");
    if (bound) {
      const problems = eff.observationProblems(request, observation.body);
      if (problems.length) {
        reasons.push(...problems);
      } else {
        out.observed_state_digest = digest(eff.observed(request, observation.body));
        out.finality = eff.finality(observation.body);
      }
    }
  }

  // Strict timestamps (explicit offset; #491 parity): a timezone-less or
  // unparseable time fails closed.
  const reportedMs = isoMs(report.reported_at);
  const observedMs = isoMs(observedAt);
  const age = reportedMs === null || observedMs === null ? null : (observedMs - reportedMs) / 1000;
  if (age === null) reasons.push("OBSERVATION_TIME_INVALID");
  else if (age < 0) reasons.push("OBSERVATION_PREDATES_EXECUTION_REPORT");
  else if (age > eff.max_age_seconds) reasons.push("OBSERVATION_STALE");

  out.observed_result = reasons.length ? "INSUFFICIENT_EVIDENCE" : "OBSERVED";
  if (reasons.length) {
    out.result = "INSUFFICIENT_EVIDENCE";
  } else if (outcome === null) {
    reasons.push("REPORT_STATUS_UNRECOGNISED");
    out.result = "INSUFFICIENT_EVIDENCE";
  } else if (outcome === OUTCOMES.PENDING || out.finality !== "FINAL") {
    out.result = "PENDING";
  } else if (expected === null) {
    reasons.push("EXPECTATION_NOT_DERIVABLE_FROM_DECISION");
    out.result = "INSUFFICIENT_EVIDENCE";
  } else {
    out.result = expected === out.observed_state_digest ? "CONFIRMED" : "CONTRADICTED";
  }
  if (out.result === "CONTRADICTED") reasons.push("OBSERVED_STATE_DIFFERS_FROM_AUTHORISED_EFFECT");
  if (out.result === "PENDING") reasons.push(outcome === OUTCOMES.PENDING ? "EXECUTION_NOT_FINAL" : "SOURCE_STATE_NOT_FINAL");
  if (out.result === "CONFIRMED") limitations.push("EFFECT_NOT_ATTRIBUTED_TO_THIS_EXECUTION");
  out.reasons = reasons;
  out.limitations = limitations;
  return out;
}

// Run a read with a timeout. Never throws: failures become an observation
// status, so a broken check yields INSUFFICIENT_EVIDENCE, not CONFIRMED.
// On timeout the read's AbortSignal fires; a user check (run in a worker
// thread, see check-runner.mjs) is then terminated, so its outstanding
// sockets or timers cannot keep the CLI alive.
async function performRead(read, probe, timeoutMs) {
  const controller = new AbortController();
  let timer;
  try {
    const value = await Promise.race([
      // A copy, so a check that mutates its argument cannot alter the recorded probe.
      Promise.resolve().then(() => read(structuredClone(probe), { signal: controller.signal })),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          const timeout = Object.assign(new Error("timeout"), { sandboxTimeout: true });
          controller.abort(timeout);
          reject(timeout);
        }, timeoutMs);
      }),
    ]);
    if (!isCanonicalizable(value)) {
      return { status: "CHECK_RESULT_NOT_CANONICAL_JSON", state: null, error: "result must be plain JSON data with integer numbers" };
    }
    return { status: "OK", state: value, error: null };
  } catch (err) {
    if (err && err.sandboxTimeout) return { status: "CHECK_TIMED_OUT", state: null, error: "no result within " + timeoutMs + " ms" };
    return { status: "CHECK_THREW", state: null, error: String(err && err.message ? err.message : err).slice(0, 200) };
  } finally {
    clearTimeout(timer);
  }
}

export class LocalEffectVerifier {
  #clock;
  #signer;
  #seq = 0;

  constructor({ clock, signer }) {
    this.#clock = clock;
    this.#signer = signer;
    this.principal = signer.principal;
  }

  // reader: { kind: READ_KINDS.*, read: async (probe) => observedState,
  //           checkModule: { file_name, sha256 } | null, timeoutMs }
  async observe({ decisionEnv, reportEnv, reader }) {
    const d = decisionEnv.payload;
    const r = reportEnv.payload;
    const req = d.request;
    const eff = effectFor(req.operation);
    this.#seq += 1;
    const probe = eff.probe(req);
    const result = await performRead(reader.read, probe, reader.timeoutMs ?? 30000);
    const observedAt = this.#clock.now();
    const observation = {
      observation_id: "obs-" + d.decision_id.slice(4) + "-" + this.#seq,
      read_kind: reader.kind,
      retrieved_by: this.principal,
      check_module: reader.checkModule ?? null,
      request: probe,
      status: result.status,
      error: result.error,
      body: result.status === "OK" ? { resource: req.resource, state: result.state } : null,
    };
    const a = assessEffect({
      request: req,
      report: r,
      retrievalMethod: RETRIEVAL_METHOD,
      retrievalPrincipal: this.principal,
      observation,
      observedAt,
    });
    const payload = {
      schema_version: PAYLOAD_TYPES.EFFECT_EVIDENCE,
      evidence_id: "evd-" + d.decision_id.slice(4) + "-" + this.#seq,
      decision_id: d.decision_id,
      decision_digest: envelopeDigest(decisionEnv),
      execution_report_digest: envelopeDigest(reportEnv),
      claimed_effect: { operation: req.operation, resource: req.resource, outcome: a.claimed_outcome },
      retrieval_method: RETRIEVAL_METHOD,
      retrieval_principal_ref: this.principal,
      read_kind: reader.kind,
      observed_at: observedAt,
      attested_at: this.#clock.now(),
      resource_id: req.resource,
      expected_state_digest: a.expected_state_digest,
      observed_state_digest: a.observed_state_digest,
      result: a.result,
      reasons: a.reasons,
      evidence_digest: a.evidence_digest,
      observation_id: observation.observation_id,
      observation_digest: digest(observation),
      source_authentication: a.source_authentication,
      freshness: {
        max_age_seconds: a.max_age_seconds,
        finality: a.finality,
        consistency_model: eff.consistency_model,
      },
      coverage_boundary: eff.coverage_boundary,
      limitations: a.limitations,
    };
    return { evidence: signEnvelope(PAYLOAD_TYPES.EFFECT_EVIDENCE, payload, this.#signer), observation, assessment: a };
  }
}
