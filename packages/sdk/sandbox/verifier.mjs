// Offline verifier for local assurance bundles.
//
// Ported from examples/effect-assurance-demo/src/verifier.mjs (PRs #449,
// #477), trimmed to the single-mandate, no-budget bundles the sandbox makes.
// Inputs: a bundle and, normally, the run's LOCAL key set. No network, no
// clock: every check is relative to timestamps inside the signed records.
//
// Output: the same eight per-dimension assessments and the same §5.4 verdict
// rule as the demo, then the sandbox ceiling: the reported `verdict` is the
// weaker of the derived verdict and LOCAL_NON_TRUST_BEARING. The ceiling is
// unconditional. It does not depend on which key set is pinned, because the
// only key sets this verifier accepts are local, non-trust-bearing ones.
//
// Optional (B3, ported from the demo, PR #481): a bundle may carry third-party
// signed authorization decisions (`external_decisions`). They are assessed
// against a separately pinned issuer key set as the optional dimension
// EXTERNAL_AUTHORIZATION, which appears only when the bundle carries them or
// the relying party names an issuer. They never change AUTHORIZATION and never
// lift the ceiling.

import { digest, canonicalJson } from "./canonical.mjs";
import { verifyEnvelope, envelopeDigest, PAYLOAD_TYPES } from "./envelope.mjs";
import { evaluate, actionDigest } from "./authority.mjs";
import { assessEffect } from "./effect-verifier.mjs";
import { effectFor } from "./effects.mjs";
import { BUNDLE_SCHEMA, BUNDLE_FIELDS, OPTIONAL_BUNDLE_FIELDS, sealComponents } from "./bundle.mjs";
import { LOCAL_ENVIRONMENT, ROLES } from "./keys.mjs";
import { isoMs } from "./time.mjs";
import {
  DIMENSIONS, OPTIONAL_DIMENSIONS, PROFILES, PROVENANCE, GLOBAL_LIMITATIONS, LOCAL_VERDICT_CEILING, applyLocalCeiling,
  deriveVerdict, strongerProfile,
} from "./model.mjs";
import { assessExternalAuthorization, wrapperIntegrityReasons, EXTERNAL_LIMITATION_TEXT } from "./external-decision.mjs";

export const REPORT_SCHEMA = "intentrax.local.sandbox_verification_report/0.1";

const LIMITATION_TEXT = {
  SOURCE_RESPONSE_NOT_THIRD_PARTY_SIGNED:
    "The read was not signed by the system that was read. It is attested by the sandbox's local effect-verifier " +
    "key (distinct from the executor key), not re-verifiable from the source itself.",
  SYNTHETIC_SOURCE: "The system read is the sandbox's in-memory synthetic store, not a real system.",
  USER_SUPPLIED_CHECK_NOT_INDEPENDENT:
    "The read-only check was supplied by the developer whose action is being checked. It is not an " +
    "Intentrax-pulled authoritative read, and it is only as independent and correct as that code.",
  USER_CHECK_READ_ONLY_BY_CONTRACT_ONLY:
    "The check is read-only by contract. The sandbox cannot enforce that the check has no side effects.",
  EFFECT_NOT_ATTRIBUTED_TO_THIS_EXECUTION:
    "State matches, but nothing links it to this execution; it may pre-date the action.",
  AGENT_IDENTITY_NOT_AUTHENTICATED: "The agent's identity is a string in the sandbox.",
  POLICY_EVALUATOR_SHARED_WITH_ISSUER:
    "The verifier re-runs the same evaluator as the local decision service; a shared bug would affect both.",
  SELF_REPORTED_NOT_INDEPENDENT:
    "Execution reports come from the executor; a valid signature shows who said it, not that it is true.",
  COVERAGE_PARTIAL: "Only the declared coverage boundary of the resource was observed.",
  ...EXTERNAL_LIMITATION_TEXT,
};

function limitation(code) {
  return { code, text: LIMITATION_TEXT[code] ?? code };
}

function assessment(dimension, result, extra = {}) {
  return {
    dimension,
    result,
    provenance: extra.provenance ?? null,
    coverage: extra.coverage ?? null,
    freshness: extra.freshness ?? null,
    evidence_digests: extra.evidence_digests ?? [],
    reasons: extra.reasons ?? [],
    limitations: (extra.limitations ?? []).map(limitation),
    detail: extra.detail ?? null,
  };
}

function same(a, b) {
  try {
    return canonicalJson(a) === canonicalJson(b);
  } catch {
    return false;
  }
}

function isObj(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

// Options:
//   pinned                        Map from loadLocalKeySet(), or null
//   issuerKeys                    relying party's pinned EXTERNAL issuer key set
//                                 (external-decision.mjs loadPinnedIssuerKeySet),
//                                 or null: external decisions are then NOT_ASSESSED
//   externalAuthorizationIssuers  issuers the relying party's assurance profile
//                                 names: makes EXTERNAL_AUTHORIZATION required and
//                                 only those issuers' decisions satisfy it
export function verifyLocalBundle(bundle, { pinned = null, issuerKeys = null, externalAuthorizationIssuers = [] } = {}) {
  if (!Array.isArray(externalAuthorizationIssuers) || !externalAuthorizationIssuers.every((x) => typeof x === "string" && x)) {
    throw new TypeError("externalAuthorizationIssuers must be an array of non-empty strings");
  }
  const opts = { externalAuthorizationIssuers };
  const A = {};
  const set = (a) => {
    A[a.dimension] = a;
  };
  const integrityReasons = [];

  // ---- 0. structure -------------------------------------------------------
  const hasExternal = isObj(bundle) && Object.prototype.hasOwnProperty.call(bundle, "external_decisions");
  const structOk = isObj(bundle)
    && same(Object.keys(bundle).sort(), hasExternal ? [...BUNDLE_FIELDS, ...OPTIONAL_BUNDLE_FIELDS].sort() : BUNDLE_FIELDS)
    && (!hasExternal || Array.isArray(bundle.external_decisions))
    && bundle.schema_version === BUNDLE_SCHEMA
    && typeof bundle.bundle_id === "string"
    && Object.prototype.hasOwnProperty.call(PROFILES, bundle.assurance_profile)
    && isObj(bundle.policy)
    && ["mandates", "execution_reports", "effect_evidence", "source_observations"].every((k) => Array.isArray(bundle[k]))
    && bundle.mandates.length === 1
    && isObj(bundle.decision) && isObj(bundle.seal)
    && bundle.source_observations.every(isObj);
  if (!structOk) {
    return finish(bundle, null, {
      RECORD_INTEGRITY: assessment("RECORD_INTEGRITY", "FAILED", { reasons: ["BUNDLE_MALFORMED_OR_NOT_A_LOCAL_SANDBOX_BUNDLE"] }),
    }, pinned, opts);
  }
  if (bundle.environment !== LOCAL_ENVIRONMENT || bundle.trust_bearing !== false) {
    integrityReasons.push("BUNDLE_NOT_LABELLED_LOCAL_NON_TRUST_BEARING");
  }

  // ---- 1. signatures, roles, key validity ---------------------------------
  const slots = [
    ["mandates[0]", bundle.mandates[0], PAYLOAD_TYPES.MANDATE],
    ["decision", bundle.decision, PAYLOAD_TYPES.DECISION],
    ...bundle.execution_reports.map((e, i) => ["execution_reports[" + i + "]", e, PAYLOAD_TYPES.EXECUTION_REPORT]),
    ...bundle.effect_evidence.map((e, i) => ["effect_evidence[" + i + "]", e, PAYLOAD_TYPES.EFFECT_EVIDENCE]),
    ["seal", bundle.seal, PAYLOAD_TYPES.BUNDLE_SEAL],
  ];
  const authReasons = [];
  const authResults = [];
  const signers = new Map();
  for (const [where, env, type] of slots) {
    if (!isObj(env) || env.payload_type !== type) {
      integrityReasons.push("PAYLOAD_TYPE_SLOT_MISMATCH:" + where);
      authResults.push("FAILED");
      continue;
    }
    const v = verifyEnvelope(env, { pinned });
    if (v.integrity !== "VERIFIED") integrityReasons.push(v.reasons.join("|") + ":" + where);
    authResults.push(v.authenticity);
    if (v.authenticity !== "VERIFIED") {
      authReasons.push(...v.reasons.map((r) => r + ":" + where + (v.key_id ? "(" + v.key_id + ")" : "")));
      continue;
    }
    signers.set(env, v.signer);
    const p = env.payload ?? {};
    const named = type === PAYLOAD_TYPES.MANDATE ? p.issuer
      : type === PAYLOAD_TYPES.EXECUTION_REPORT ? p.executor_principal
        : type === PAYLOAD_TYPES.EFFECT_EVIDENCE ? p.retrieval_principal_ref
          : v.signer.principal;
    if (named !== v.signer.principal) {
      authResults[authResults.length - 1] = "FAILED";
      authReasons.push("SIGNER_PRINCIPAL_MISMATCH:" + where);
    }
  }
  const authResult = authResults.includes("FAILED") ? "FAILED"
    : authResults.includes("INSUFFICIENT_EVIDENCE") ? "INSUFFICIENT_EVIDENCE"
      : authResults.includes("NOT_ASSESSED") ? "NOT_ASSESSED"
        : "VERIFIED";
  set(assessment("SIGNER_AUTHENTICITY", authResult, {
    provenance: PROVENANCE.VERIFIER_COMPUTED,
    reasons: [...new Set(authReasons)],
    limitations: [],
    detail: {
      trust_anchors: pinned ? "LOCAL_KEY_SET (environment local, trust_bearing false)" : "NONE (integrity against self-asserted keys only)",
      trust_bearing: false,
    },
  }));

  // ---- 2. seal ------------------------------------------------------------
  const seal = isObj(bundle.seal.payload) ? bundle.seal.payload : {};
  try {
    if (seal.bundle_id !== bundle.bundle_id) integrityReasons.push("SEAL_BUNDLE_ID_MISMATCH");
    if (seal.bundle_schema_version !== bundle.schema_version) integrityReasons.push("SEAL_SCHEMA_MISMATCH");
    if (seal.assurance_profile !== bundle.assurance_profile) integrityReasons.push("SEAL_PROFILE_MISMATCH");
    if (seal.environment !== LOCAL_ENVIRONMENT || seal.trust_bearing !== false
      || seal.environment !== bundle.environment || seal.trust_bearing !== bundle.trust_bearing) {
      integrityReasons.push("SEAL_ENVIRONMENT_MISMATCH");
    }
    const comps = sealComponents(bundle);
    // The component SET must match too: stripping an optional component (e.g.
    // external_decisions) must not silently drop it from the check.
    if (!same(Object.keys(comps).sort(), Object.keys(isObj(seal.components) ? seal.components : {}).sort())) {
      integrityReasons.push("SEAL_COMPONENT_SET_MISMATCH");
    }
    for (const k of Object.keys(comps)) {
      if (!same(comps[k], seal.components?.[k])) integrityReasons.push("SEAL_COMPONENT_MISMATCH:" + k);
    }
  } catch {
    integrityReasons.push("SEAL_UNCOMPUTABLE");
  }

  // ---- 3. cross-component bindings ----------------------------------------
  const d = isObj(bundle.decision.payload) ? bundle.decision.payload : {};
  const reports = bundle.execution_reports.map((e) => (isObj(e?.payload) ? e.payload : {}));
  const evidence = bundle.effect_evidence.map((e) => (isObj(e?.payload) ? e.payload : {}));
  try {
    const decisionDigest = envelopeDigest(bundle.decision);
    if (d.policy_digest !== digest(bundle.policy)) integrityReasons.push("DECISION_POLICY_BINDING_MISMATCH");
    if (!same(d.mandate_chain_digests, bundle.mandates.map(envelopeDigest))) {
      integrityReasons.push("DECISION_MANDATE_BINDING_MISMATCH");
    }
    if (d.request_digest !== digest(d.request) || d.action_digest !== actionDigest(d.request)) {
      integrityReasons.push("DECISION_REQUEST_BINDING_MISMATCH");
    }
    const reportDigests = bundle.execution_reports.map(envelopeDigest);
    reports.forEach((r, i) => {
      if (r.decision_id !== d.decision_id || r.decision_digest !== decisionDigest || r.action_digest !== d.action_digest) {
        integrityReasons.push("REPORT_DECISION_BINDING_MISMATCH:" + i);
      }
      if (r.sequence !== i + 1) integrityReasons.push("REPORT_SEQUENCE_GAP:" + i);
    });
    const obsDigests = bundle.source_observations.map((o) => digest(o));
    evidence.forEach((ev, i) => {
      if (ev.decision_id !== d.decision_id || ev.decision_digest !== decisionDigest) {
        integrityReasons.push("EVIDENCE_DECISION_BINDING_MISMATCH:" + i);
      }
      if (!reportDigests.includes(ev.execution_report_digest)) integrityReasons.push("EVIDENCE_REPORT_BINDING_MISMATCH:" + i);
      if (!obsDigests.includes(ev.observation_digest)) integrityReasons.push("EVIDENCE_OBSERVATION_BINDING_MISMATCH:" + i);
    });
    if (hasExternal) {
      bundle.external_decisions.forEach((x, i) => integrityReasons.push(...wrapperIntegrityReasons(x, d, i)));
    }
  } catch {
    integrityReasons.push("BINDINGS_UNCOMPUTABLE");
  }

  set(assessment("RECORD_INTEGRITY", integrityReasons.length ? "FAILED" : "VERIFIED", {
    provenance: PROVENANCE.VERIFIER_COMPUTED,
    coverage: { scope: "COMPLETE", coverage_boundary: "Every component listed in the bundle seal." },
    evidence_digests: [envelopeDigestSafe(bundle.seal)],
    reasons: [...new Set(integrityReasons)],
  }));

  if (integrityReasons.length) {
    return finish(bundle, d, A, pinned, opts);
  }

  const denied = d.outcome === "DENY";
  const guard = (dimension, fn) => {
    try {
      set(fn());
    } catch (err) {
      set(assessment(dimension, "FAILED", { reasons: ["VERIFIER_EXCEPTION:" + err.message] }));
    }
  };

  // ---- 4. AUTHORIZATION: re-evaluate, don't trust -------------------------
  guard("AUTHORIZATION", () => {
    const reasons = [];
    const re = evaluate({
      request: d.request,
      mandate: bundle.mandates[0].payload,
      policy: bundle.policy,
      policyDigest: digest(bundle.policy),
      at: d.decided_at,
    });
    for (const k of ["outcome", "reasons", "required_assurance_profile"]) {
      if (!same(re[k], d[k])) reasons.push("DECISION_NOT_REPRODUCIBLE:" + k);
    }
    if (denied && (reports.length || evidence.length)) reasons.push("EXECUTED_DESPITE_DENIAL");
    if (!denied && reports.length) {
      // Strict timestamps (explicit offset; #491 parity); any unparseable one is outside.
      const started = isoMs(reports[0].started_at);
      const decidedAt = isoMs(d.decided_at);
      const executeBefore = isoMs(d.execute_before);
      if (started === null || decidedAt === null || executeBefore === null
        || !(started >= decidedAt && started < executeBefore)) {
        reasons.push("EXECUTION_OUTSIDE_DECISION_WINDOW");
      }
    }
    return assessment("AUTHORIZATION", reasons.length ? "CONTRADICTED" : "VERIFIED", {
      provenance: PROVENANCE.INTENTRAX_DECISION,
      reasons,
      evidence_digests: [envelopeDigest(bundle.decision), digest(bundle.policy)],
      limitations: ["AGENT_IDENTITY_NOT_AUTHENTICATED", "POLICY_EVALUATOR_SHARED_WITH_ISSUER"],
      detail: {
        outcome: d.outcome,
        decision_reasons: d.reasons,
        decided_at: d.decided_at,
        mandate_id: d.mandate_id,
        policy: d.policy_id + "@" + d.policy_version,
        signed_by: "local decision-service key (not trust-bearing)",
      },
    });
  });

  // ---- 5. EXECUTION_REPORTED / EXECUTION_ATTESTED -------------------------
  const latestReportIdx = reports.length - 1;
  const latestReport = reports[latestReportIdx] ?? null;
  guard("EXECUTION_REPORTED", () => {
    if (!latestReport) {
      return assessment("EXECUTION_REPORTED", denied ? "NOT_APPLICABLE" : "INSUFFICIENT_EVIDENCE", {
        reasons: denied ? ["DENIED_BEFORE_EXECUTION"] : ["NO_EXECUTION_REPORT"],
      });
    }
    return assessment("EXECUTION_REPORTED", "REPORTED", {
      provenance: PROVENANCE.SELF_REPORTED,
      evidence_digests: bundle.execution_reports.map(envelopeDigest),
      limitations: ["SELF_REPORTED_NOT_INDEPENDENT"],
      detail: { status: latestReport.status, sequence: latestReport.sequence, downstream: latestReport.downstream },
    });
  });
  set(assessment("EXECUTION_ATTESTED", denied ? "NOT_APPLICABLE" : "NOT_ASSESSED", {
    reasons: denied ? [] : ["NO_IN_PATH_ENFORCEMENT_COMPONENT"],
  }));

  // ---- 6. EFFECT_OBSERVED / EFFECT_CONFIRMED: recompute -------------------
  guard("EFFECT_OBSERVED", () => {
    if (denied) {
      set(assessment("EFFECT_CONFIRMED", "NOT_APPLICABLE", { reasons: ["DENIED_BEFORE_EXECUTION"] }));
      return assessment("EFFECT_OBSERVED", "NOT_APPLICABLE", { reasons: ["DENIED_BEFORE_EXECUTION"] });
    }
    const latestDigest = latestReport ? envelopeDigest(bundle.execution_reports[latestReportIdx]) : null;
    const candidates = bundle.effect_evidence
      .map((env, i) => ({ env, ev: evidence[i] }))
      .filter(({ ev }) => ev.execution_report_digest === latestDigest)
      // Latest attestation wins; an unparseable attested_at sorts first, so it
      // can never be picked over a well-formed one.
      .map((c) => ({ ...c, at: isoMs(c.ev.attested_at) ?? -Infinity }))
      .sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0));
    if (!candidates.length) {
      const reasons = [latestReport ? "NO_EFFECT_EVIDENCE_FOR_LATEST_REPORT" : "NO_EXECUTION_REPORT"];
      set(assessment("EFFECT_CONFIRMED", "INSUFFICIENT_EVIDENCE", { reasons }));
      return assessment("EFFECT_OBSERVED", "INSUFFICIENT_EVIDENCE", { reasons });
    }
    if (!pinned || A.SIGNER_AUTHENTICITY.result !== "VERIFIED") {
      const reasons = [pinned ? "SIGNERS_NOT_AUTHENTICATED" : "NO_LOCAL_KEY_SET"];
      set(assessment("EFFECT_CONFIRMED", "NOT_ASSESSED", { reasons }));
      return assessment("EFFECT_OBSERVED", "NOT_ASSESSED", { reasons });
    }
    // Recompute EVERY evidence object bound to the latest report: a later read
    // must not silently override an earlier one that disagrees.
    const eff = effectFor(d.request.operation);
    const recheck = ({ env, ev }) => {
      const observation = bundle.source_observations.find((o) => digest(o) === ev.observation_digest) ?? null;
      const evSigner = signers.get(env);
      const re = assessEffect({
        request: d.request,
        report: latestReport,
        retrievalMethod: ev.retrieval_method,
        retrievalPrincipal: ev.retrieval_principal_ref,
        expectedRetrievalPrincipal: evSigner && evSigner.role === ROLES.EFFECT_VERIFIER ? evSigner.principal : "(unknown)",
        observation,
        observedAt: ev.observed_at,
      });
      const mismatches = [];
      const cmp = (name, signed, recomputed) => {
        if (!same(signed, recomputed)) mismatches.push(name);
      };
      cmp("result", ev.result, re.result);
      cmp("reasons", ev.reasons, re.reasons);
      cmp("limitations", ev.limitations, re.limitations);
      cmp("claimed_effect", ev.claimed_effect, { operation: d.request.operation, resource: d.request.resource, outcome: re.claimed_outcome });
      cmp("expected_state_digest", ev.expected_state_digest, re.expected_state_digest);
      cmp("observed_state_digest", ev.observed_state_digest, re.observed_state_digest);
      cmp("evidence_digest", ev.evidence_digest, re.evidence_digest);
      cmp("source_authentication", ev.source_authentication, re.source_authentication);
      cmp("read_kind", ev.read_kind, observation ? observation.read_kind : null);
      cmp("freshness", [ev.freshness?.finality, ev.freshness?.max_age_seconds], [re.finality, re.max_age_seconds]);
      cmp("target", ev.resource_id, d.request.resource);
      cmp("coverage_boundary", ev.coverage_boundary, eff.coverage_boundary);
      return { ev, re, observation, mismatches };
    };
    const checked = candidates.map(recheck);
    const broken = checked.find((c) => c.mismatches.length);
    const { ev, re, observation } = checked[checked.length - 1];
    const mismatches = broken ? broken.mismatches.map((m) => m + "@" + broken.ev.evidence_id) : [];
    const finals = checked.filter((c) => c.re.result === "CONFIRMED" || c.re.result === "CONTRADICTED");
    const conflict = new Set(finals.map((c) => c.re.result)).size > 1;

    const provenance = re.source_authentication === "LOCAL_EFFECT_VERIFIER_READ" ? PROVENANCE.THIRD_PARTY_ATTESTED
      : PROVENANCE.SELF_REPORTED;
    const common = {
      provenance,
      coverage: { scope: "PARTIAL", coverage_boundary: ev.coverage_boundary },
      freshness: { observed_at: ev.observed_at, max_age_seconds: re.max_age_seconds, finality: re.finality },
      evidence_digests: [re.evidence_digest, re.expected_state_digest, re.observed_state_digest].filter(Boolean),
    };
    if (mismatches.length) {
      const reasons = mismatches.map((m) => "SIGNED_EVIDENCE_DISAGREES_WITH_RECOMPUTATION:" + m);
      set(assessment("EFFECT_CONFIRMED", "FAILED", { ...common, reasons }));
      return assessment("EFFECT_OBSERVED", "FAILED", { ...common, reasons });
    }
    const lims = ["COVERAGE_PARTIAL", ...re.limitations];
    set(assessment("EFFECT_CONFIRMED", conflict ? "CONTRADICTED" : re.result, {
      ...common,
      provenance: PROVENANCE.VERIFIER_COMPUTED,
      reasons: conflict ? ["CONFLICTING_OBSERVATIONS", ...re.reasons] : re.reasons,
      limitations: lims,
      detail: {
        claimed_outcome: re.claimed_outcome,
        compared: "expected_state_digest (from the signed decision) vs observed_state_digest (from the read)",
        read_provenance: provenance,
        observations: checked.map((c) => ({ evidence_id: c.ev.evidence_id, observed_at: c.ev.observed_at, result: c.re.result })),
      },
    }));
    return assessment("EFFECT_OBSERVED", re.observed_result, {
      ...common,
      reasons: re.reasons,
      limitations: lims,
      detail: {
        retrieval_method: ev.retrieval_method,
        retrieval_principal_ref: ev.retrieval_principal_ref,
        read_kind: observation ? observation.read_kind : null,
        source_authentication: re.source_authentication,
        check_module: observation ? observation.check_module : null,
      },
    });
  });

  // ---- 7. CAUSAL_CHAIN ----------------------------------------------------
  set(assessment("CAUSAL_CHAIN", "NOT_APPLICABLE", { reasons: ["SINGLE_MANDATE_NO_BUDGET"] }));

  // ---- 8. EXTERNAL_AUTHORIZATION (optional; B3) ---------------------------
  // Evidence, never trust: verified only against the relying party's pinned
  // issuer keys, and it never alters AUTHORIZATION above.
  if (hasExternal || externalAuthorizationIssuers.length) {
    guard("EXTERNAL_AUTHORIZATION", () => {
      const body = assessExternalAuthorization({
        wrappers: hasExternal ? bundle.external_decisions : [],
        d,
        reports,
        effectConfirmed: A.EFFECT_CONFIRMED?.result ?? null,
        issuerKeys,
        authorizationIssuers: externalAuthorizationIssuers,
      });
      return assessment("EXTERNAL_AUTHORIZATION", body.result, body);
    });
  }

  return finish(bundle, d, A, pinned, opts);
}

function envelopeDigestSafe(env) {
  try {
    return envelopeDigest(env);
  } catch {
    return null;
  }
}

function finish(bundle, d, A, pinned, opts = {}) {
  const externalIssuers = opts.externalAuthorizationIssuers ?? [];
  const external = externalIssuers.length > 0
    || (isObj(bundle) && Object.prototype.hasOwnProperty.call(bundle, "external_decisions"));
  // Optional dimensions appear only when relevant, so ordinary reports keep
  // exactly the eight core dimensions.
  const dims = [...DIMENSIONS, ...OPTIONAL_DIMENSIONS.filter((x) => x === "EXTERNAL_AUTHORIZATION" && external)];
  for (const dim of dims) {
    if (!A[dim]) A[dim] = assessment(dim, "NOT_ASSESSED", { reasons: ["NOT_REACHED"] });
  }
  const declared = isObj(bundle) && Object.prototype.hasOwnProperty.call(PROFILES, bundle.assurance_profile)
    ? bundle.assurance_profile
    : "DECISION_RECORD";
  const required = d && Object.prototype.hasOwnProperty.call(PROFILES, d.required_assurance_profile)
    ? d.required_assurance_profile
    : declared;
  const profile = strongerProfile(declared, required);
  const extraRequired = externalIssuers.length ? ["EXTERNAL_AUTHORIZATION"] : [];
  const results = Object.fromEntries(dims.map((k) => [k, A[k].result]));
  const uncapped = deriveVerdict(results, profile, { extraRequired });
  const verdict = applyLocalCeiling(uncapped);
  const effectOutcome = A.EFFECT_CONFIRMED.result === "CONFIRMED" ? A.EFFECT_CONFIRMED.detail?.claimed_outcome ?? null : null;
  const decisionOutcome = d && typeof d.outcome === "string" ? d.outcome : null;
  const summaryParts = [verdict + "(" + profile + ")"];
  if (decisionOutcome) summaryParts.push("decision " + decisionOutcome + (d.reasons?.length ? " [" + d.reasons.join(",") + "]" : ""));
  summaryParts.push("EFFECT_CONFIRMED " + A.EFFECT_CONFIRMED.result);
  if (external) {
    const outcomes = (A.EXTERNAL_AUTHORIZATION.detail?.decisions ?? [])
      .filter((x) => x.signature === "VALID_PINNED_KEY" && x.outcome).map((x) => x.outcome + " by " + x.issuer);
    summaryParts.push("external " + A.EXTERNAL_AUTHORIZATION.result + (outcomes.length ? " [" + outcomes.join(",") + "]" : ""));
  }
  const lims = new Map();
  for (const l of GLOBAL_LIMITATIONS) lims.set(l.code, l);
  for (const dim of dims) for (const l of A[dim].limitations) lims.set(l.code, l);
  return {
    schema_version: REPORT_SCHEMA,
    bundle_id: isObj(bundle) ? bundle.bundle_id ?? null : null,
    environment: LOCAL_ENVIRONMENT,
    trust_bearing: false,
    production_assurance: false,
    trust_anchors: pinned ? "LOCAL_KEY_SET" : "NONE",
    assurance_profile: profile,
    required_dimensions: [...new Set([...PROFILES[profile], ...extraRequired])],
    verdict,
    verdict_ceiling: LOCAL_VERDICT_CEILING,
    uncapped_verdict: uncapped,
    decision_outcome: decisionOutcome,
    effect_outcome: effectOutcome,
    summary: summaryParts.join(" · "),
    assessments: dims.map((k) => A[k]),
    limitations: [...lims.values()],
  };
}
