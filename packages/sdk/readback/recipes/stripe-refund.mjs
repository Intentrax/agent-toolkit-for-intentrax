// Read-back recipe: Stripe refund status by id.
//
// Minimum scope: a Stripe RESTRICTED key (rk_live_… / rk_test_…) with
// "Refunds: Read" and nothing else. A full secret key (sk_live_…) can move
// money, so it is refused unless the caller passes `allowFullSecretKey: true`;
// sk_test_ keys are accepted for local testing.
//
//   const check = stripeRefund({ apiKey: process.env.STRIPE_REFUNDS_READ_KEY, refundId: "re_123" });
//   // or, with a client you already have (only `refunds.retrieve` is called):
//   const check = stripeRefund({ stripe, refundId: "re_123" });
//
// Reads GET https://api.stripe.com/v1/refunds/{id} and returns the fields
// Stripe returned among: id, status, amount, currency, failure_reason.
// Stripe documents refund `status` as one of pending, requires_action,
// succeeded, failed, canceled; `pending` and `requires_action` are not final,
// so they are this recipe's default PENDING values.

import { checkNotFoundAs, defineRecipe, getJson, pick, requireString, resolveFetch } from "./_shared.mjs";

export const STRIPE_REFUND_FIELDS = Object.freeze(["id", "status", "amount", "currency", "failure_reason"]);
export const STRIPE_REFUND_PENDING = Object.freeze({ status: Object.freeze(["pending", "requires_action"]) });

const ID = /^[A-Za-z0-9_]+$/;

/**
 * @param {object} opts
 * @param {string} opts.refundId
 * @param {string} [opts.apiKey]        restricted key with Refunds: Read
 * @param {object} [opts.stripe]        a Stripe client (only refunds.retrieve is used)
 * @param {boolean} [opts.allowFullSecretKey]  accept an sk_live_ key (not recommended)
 * @param {string} [opts.apiBase]       default https://api.stripe.com
 * @param {object} [opts.notFoundAs]    observation to return on HTTP 404
 * @param {Function} [opts.fetch]
 */
export function stripeRefund(opts = {}) {
  const { refundId, apiKey, stripe, allowFullSecretKey = false, apiBase = "https://api.stripe.com", notFoundAs, fetch: fetchImpl } = opts;
  requireString("refundId", refundId, { pattern: ID, max: 255 });
  if ((apiKey === undefined) === (stripe === undefined)) throw new TypeError("pass exactly one of apiKey or stripe");
  checkNotFoundAs(notFoundAs);
  if (apiKey !== undefined) {
    requireString("apiKey", apiKey, { max: 1000 });
    if (/^sk_live_/.test(apiKey) && !allowFullSecretKey) {
      throw new TypeError("refusing a full secret key (sk_live_); use a restricted key (rk_live_) with only Refunds: Read, or pass allowFullSecretKey: true");
    }
  } else if (!stripe || !stripe.refunds || typeof stripe.refunds.retrieve !== "function") {
    throw new TypeError("stripe client must expose refunds.retrieve");
  }

  let read;
  if (stripe) {
    read = async () => pick(await stripe.refunds.retrieve(refundId), STRIPE_REFUND_FIELDS);
  } else {
    const f = resolveFetch(fetchImpl);
    const url = String(apiBase).replace(/\/+$/, "") + "/v1/refunds/" + encodeURIComponent(refundId);
    const headers = { accept: "application/json", authorization: "Bearer " + apiKey };
    read = async ({ signal }) => {
      const { notFound, body } = await getJson({ fetchImpl: f, url, headers, signal, source: "Stripe", allowNotFound: notFoundAs !== undefined });
      if (notFound) return structuredClone(notFoundAs);
      return pick(body, STRIPE_REFUND_FIELDS);
    };
  }

  return defineRecipe({
    href: import.meta.url,
    exportName: "stripeRefund",
    options: opts,
    secrets: apiKey ? [apiKey] : [],
    resource: "refund " + refundId,
    source: "Stripe",
    pending: STRIPE_REFUND_PENDING,
    read,
  });
}
