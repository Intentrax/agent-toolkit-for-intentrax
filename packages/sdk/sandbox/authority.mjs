// Mandate + policy evaluation for the local assurance sandbox.
//
// Trimmed port of examples/effect-assurance-demo/src/authority.mjs (PRs #449,
// #477). The sandbox issues one root mandate per run, with no delegation and
// no budget, so the delegation-subset and budget-ledger logic is not carried
// over. The evaluator is shared by the local decision service (to decide) and
// the offline verifier (to re-evaluate); sharing it is a stated limitation.
//
// Shapes:
//   mandate payload (intentrax.mandate/0.1)
//     { schema_version, mandate_id, issuer, subject, parent_mandate_id: null,
//       policy_digest, scope: { operations[], resources[] }, not_before,
//       expires_at, issued_at, purpose }
//   policy (intentrax.policy/0.1)
//     { schema_version, policy_id, version, default: "DENY", rules: [{ operation, required_profile }] }

import { digest } from "./canonical.mjs";
import { isoMs } from "./time.mjs";

export function resourceMatches(pattern, resource) {
  if (pattern.endsWith("*")) return resource.startsWith(pattern.slice(0, -1));
  return pattern === resource;
}

// Evaluate `request` against one root `mandate` at time `at`.
export function evaluate({ request, mandate, policy, policyDigest, at }) {
  const reasons = [];
  const add = (r) => {
    if (!reasons.includes(r)) reasons.push(r);
  };
  if (!mandate) {
    return { outcome: "DENY", reasons: ["NO_MANDATE"], required_assurance_profile: "DECISION_RECORD" };
  }
  if (mandate.parent_mandate_id !== null) add("CHAIN_ROOT_HAS_PARENT");
  if (mandate.policy_digest !== policyDigest) add("MANDATE_POLICY_MISMATCH");
  // Strict timestamps (explicit offset; #491 parity). An unparseable decision
  // time or mandate bound fails closed instead of comparing false (NaN).
  const atMs = isoMs(at);
  if (atMs === null) add("DECISION_TIME_INVALID");
  const notBefore = isoMs(mandate.not_before);
  const expiresAt = isoMs(mandate.expires_at);
  if (notBefore === null || expiresAt === null) {
    add("MANDATE_TIME_INVALID");
  } else if (atMs !== null) {
    if (atMs < notBefore) add("MANDATE_NOT_YET_VALID");
    if (atMs >= expiresAt) add("MANDATE_EXPIRED");
  }
  if (request.mandate_id !== mandate.mandate_id) add("REQUEST_MANDATE_MISMATCH");
  if (request.agent !== mandate.subject) add("AGENT_NOT_MANDATE_SUBJECT");
  if (!mandate.scope.operations.includes(request.operation)) add("MANDATE_OPERATION_NOT_PERMITTED");
  if (!mandate.scope.resources.some((p) => resourceMatches(p, request.resource))) add("MANDATE_RESOURCE_NOT_PERMITTED");

  const rule = policy.rules.find((r) => r.operation === request.operation);
  if (!rule) add("POLICY_NO_MATCHING_RULE");

  const outcome = reasons.length ? "DENY" : "ALLOW";
  return {
    outcome,
    reasons,
    required_assurance_profile: outcome === "ALLOW" ? rule.required_profile : "DECISION_RECORD",
  };
}

export function actionDigest(request) {
  return digest({ operation: request.operation, resource: request.resource, params: request.params });
}
