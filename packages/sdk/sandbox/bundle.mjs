// Local assurance bundle (`intentrax.local_assurance_bundle/0.1`).
//
// Adapted from examples/effect-assurance-demo/src/bundle.mjs (PRs #449,
// #477). Every component is signed by the party that produced it and
// cross-bound by digests; the local decision-service seal lists the digest of
// every component. The sandbox adds two sealed top-level labels,
// `environment: "local"` and `trust_bearing: false`, so a local bundle cannot
// be relabelled without breaking the seal. There is no budget ledger.

import { digest } from "./canonical.mjs";
import { signEnvelope, envelopeDigest, PAYLOAD_TYPES } from "./envelope.mjs";
import { LOCAL_ENVIRONMENT } from "./keys.mjs";

export const BUNDLE_SCHEMA = "intentrax.local_assurance_bundle/0.1";

export const BUNDLE_FIELDS = Object.freeze([
  "assurance_profile",
  "bundle_id",
  "decision",
  "effect_evidence",
  "environment",
  "execution_reports",
  "mandates",
  "policy",
  "schema_version",
  "seal",
  "source_observations",
  "trust_bearing",
]);

// Optional field (B3, ported from the demo, PR #481): third-party signed
// authorization decisions, wrapped as `intentrax.external_decision_evidence/0.1`.
// The sandbox never adds it to the bundles it makes, so their seal components
// (and bytes) are unchanged; `sandbox verify` assesses it when present.
export const OPTIONAL_BUNDLE_FIELDS = Object.freeze(["external_decisions"]);

export function sealComponents(bundle) {
  const comps = {
    policy: digest(bundle.policy),
    mandates: bundle.mandates.map(envelopeDigest),
    decision: envelopeDigest(bundle.decision),
    execution_reports: bundle.execution_reports.map(envelopeDigest),
    effect_evidence: bundle.effect_evidence.map(envelopeDigest),
    source_observations: bundle.source_observations.map((o) => digest(o)),
  };
  if (Object.prototype.hasOwnProperty.call(bundle, "external_decisions")) {
    comps.external_decisions = bundle.external_decisions.map((x) => digest(x));
  }
  return comps;
}

export function assembleBundle({
  bundleId,
  policy,
  mandates,
  decision,
  executionReports = [],
  effectEvidence = [],
  sourceObservations = [],
  sealSigner,
  sealedAt,
}) {
  const bundle = {
    schema_version: BUNDLE_SCHEMA,
    bundle_id: bundleId,
    environment: LOCAL_ENVIRONMENT,
    trust_bearing: false,
    assurance_profile: decision.payload.required_assurance_profile,
    policy,
    mandates,
    decision,
    execution_reports: executionReports,
    effect_evidence: effectEvidence,
    source_observations: sourceObservations,
  };
  return resealBundle(bundle, { sealSigner, sealedAt });
}

// (Re)compute and sign the seal over the bundle as it stands.
export function resealBundle(bundle, { sealSigner, sealedAt }) {
  const { seal: _old, ...rest } = bundle;
  const seal = signEnvelope(PAYLOAD_TYPES.BUNDLE_SEAL, {
    schema_version: PAYLOAD_TYPES.BUNDLE_SEAL,
    bundle_id: rest.bundle_id,
    bundle_schema_version: rest.schema_version,
    environment: rest.environment,
    trust_bearing: rest.trust_bearing,
    assurance_profile: rest.assurance_profile,
    sealed_at: sealedAt,
    components: sealComponents(rest),
  }, sealSigner);
  return { ...rest, seal };
}
