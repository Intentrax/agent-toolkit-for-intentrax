// toSandboxCheck: turn a read-back check (a recipe or your own function)
// into the module shape `intentrax sandbox --check` loads.
//
//   // my-refund-check.mjs
//   import { toSandboxCheck, stripeRefund } from "<sdk>/readback/index.mjs";
//   const m = toSandboxCheck(
//     stripeRefund({ apiKey: process.env.STRIPE_REFUNDS_READ_KEY, refundId: process.env.REFUND_ID }),
//     { status: "succeeded" },
//   );
//   export const expected = m.expected;
//   export const resource = m.resource;
//   export default m.check;
//
//   $ intentrax sandbox --check ./my-refund-check.mjs
//
// The sandbox then runs the check in its worker, compares the read with
// `expected`, and on a contradiction exits 12 (CONFLICTING_EVIDENCE) and
// writes a LOCAL bundle. That bundle is NON-TRUST-BEARING: it is signed with
// ephemeral keys generated on your machine, the read is SELF_REPORTED (you
// wrote or configured the check), and no production verifier accepts it.
//
// The wrapped check returns only the fields named in `expected` (fields the
// read lacks are left out, never null), so the bundle — which stores the raw
// read — holds no more of the provider's response than the comparison needs.

import { isCanonicalizable } from "../sandbox/canonical.mjs";

export const SANDBOX_BRIDGE_LABEL =
  "LOCAL, NON-TRUST-BEARING: a sandbox bundle from this check is signed with ephemeral local keys and its read is " +
  "SELF_REPORTED (you configured the check). It is not an Intentrax attestation and no production verifier accepts it.";

/**
 * @param {Function} recipeCheck   a read-back recipe check, or any async read-only function
 * @param {object} expected        { field: value } the action should have produced (JSON, integers only)
 * @param {{ resource?: string }} [opts]
 * @returns {{ expected: object, resource: string, check: Function, label: string, trust_bearing: false, provenance: "SELF_REPORTED" }}
 */
export function toSandboxCheck(recipeCheck, expected, opts = {}) {
  if (typeof recipeCheck !== "function") throw new TypeError("recipeCheck must be a function");
  if (expected === null || typeof expected !== "object" || Array.isArray(expected) || Object.keys(expected).length === 0
    || !isCanonicalizable(expected)) {
    throw new TypeError("expected must be a non-empty plain object of JSON values (integers only), as sandbox --check requires");
  }
  const resource = opts.resource !== undefined ? opts.resource : typeof recipeCheck.resource === "string" ? recipeCheck.resource : "readback";
  if (typeof resource !== "string" || resource.length === 0 || resource.length > 200 || resource.endsWith("*")) {
    throw new TypeError("resource must be a non-empty string (max 200 chars, no trailing *)");
  }
  const fields = Object.keys(expected);
  const frozenExpected = JSON.parse(JSON.stringify(expected));

  async function check(probe) {
    const observed = await recipeCheck({ ...(probe && typeof probe === "object" ? probe : {}) });
    // Not an object: hand it through, so the sandbox reports it as unusable
    // (INSUFFICIENT_EVIDENCE) instead of this bridge inventing fields.
    if (observed === null || typeof observed !== "object" || Array.isArray(observed)) return observed;
    const out = {};
    for (const f of fields) {
      if (Object.prototype.hasOwnProperty.call(observed, f) && observed[f] !== undefined) out[f] = observed[f];
    }
    return out;
  }

  return Object.freeze({
    expected: frozenExpected,
    resource,
    check,
    label: SANDBOX_BRIDGE_LABEL,
    trust_bearing: false,
    provenance: "SELF_REPORTED",
  });
}
