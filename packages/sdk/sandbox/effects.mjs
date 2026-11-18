// Effect definition for the local assurance sandbox.
//
// Adapted from examples/effect-assurance-demo/src/effects.mjs (PRs #449,
// #477). The demo defines three synthetic cloud operations; the sandbox has
// one generic operation, `SetState`: "make these fields of this resource have
// these values". It covers both the built-in sample action and a developer's
// own action checked with `--check`.
//
// The EXPECTED state is derived only from the signed decision (the fields and
// values that were authorised), never from anything the executor reports. The
// OBSERVED state is extracted from the read, limited to the authorised fields
// (the coverage boundary).

import { digest } from "./canonical.mjs";

export const OPERATION = "SetState";

export const OUTCOMES = Object.freeze({ APPLIED: "APPLIED", NOT_APPLIED: "NOT_APPLIED", PENDING: "PENDING" });

// Execution-report status -> the outcome it claims.
export function claimedOutcome(reportStatus) {
  switch (reportStatus) {
    case "SUCCEEDED":
      return OUTCOMES.APPLIED;
    case "ACCEPTED":
      return OUTCOMES.PENDING;
    case "FAILED":
      return OUTCOMES.NOT_APPLIED;
    default:
      return null;
  }
}

function pick(obj, keys) {
  const out = {};
  const src = obj !== null && typeof obj === "object" && !Array.isArray(obj) ? obj : {};
  for (const k of keys.slice().sort()) {
    out[k] = Object.prototype.hasOwnProperty.call(src, k) ? src[k] : null;
  }
  return out;
}

export const SET_STATE = Object.freeze({
  operation: OPERATION,
  max_age_seconds: 300,
  consistency_model: "read treated as final; eventual consistency is not modelled in the sandbox",
  coverage_boundary: "Only the fields named in the authorised state of one resource; nothing else about the resource was read.",
  probe: (request) => ({ resource: request.resource, fields: Object.keys(request.params.state).sort() }),
  // The read must be about this decision's resource.
  bound: (request, body) => body !== null && typeof body === "object" && body.resource === request.resource,
  expected(request, outcome) {
    if (outcome !== OUTCOMES.APPLIED) return null; // NOT_APPLIED is not checkable without a pre-state
    return { resource: request.resource, state: pick(request.params.state, Object.keys(request.params.state)) };
  },
  // A read only counts if it is an object that carries EVERY authorised field.
  // A missing field must not be read as null: otherwise `{}` (or a string)
  // would "confirm" an authorised `{ deleted_at: null }`.
  observationProblems(request, body) {
    const s = body.state;
    if (s === null || typeof s !== "object" || Array.isArray(s)) return ["OBSERVED_STATE_NOT_AN_OBJECT"];
    const missing = Object.keys(request.params.state)
      .filter((k) => !Object.prototype.hasOwnProperty.call(s, k))
      .sort();
    return missing.length ? ["OBSERVED_FIELDS_MISSING:" + missing.join(",")] : [];
  },
  observed(request, body) {
    return { resource: body.resource, state: pick(body.state, Object.keys(request.params.state)) };
  },
  finality: () => "FINAL",
});

export function effectFor(operation) {
  if (operation !== OPERATION) throw new Error("no effect definition for " + operation);
  return SET_STATE;
}

export function expectedStateDigest(request, outcome) {
  const e = effectFor(request.operation).expected(request, outcome);
  return e === null ? null : digest(e);
}
