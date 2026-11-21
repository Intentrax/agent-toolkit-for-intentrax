// Read-back recipe: email delivery status by provider message id.
//
// A generic provider-status adapter with two built-in adapters. Field names
// below were checked against the providers' public API reference pages on
// 2026-11-19:
//
// Postmark — "Outbound message details"
//   https://postmarkapp.com/developer/api/messages-api
//   GET https://api.postmarkapp.com/messages/outbound/{messageid}/details
//   headers: Accept: application/json, X-Postmark-Server-Token: <server token>
//   response: MessageID, Status ("Sent" | "Processed" | "Queued"),
//             MessageEvents[] with Type in Delivered | Bounced | Transient |
//             Opened | LinkClicked | SubscriptionChanged.
//   Scope: Postmark has no read-only server token. The endpoint needs a
//   Server API token, which can also SEND mail. This recipe only issues GET,
//   but keep that token away from the agent whose claims you are checking.
//
// SendGrid (Twilio) — Email Activity "Filter messages by message ID"
//   https://www.twilio.com/docs/sendgrid/api-reference/email-activity/filter-messages-by-message-id
//   GET https://api.sendgrid.com/v3/messages/{msg_id}
//   headers: Authorization: Bearer <api key>
//   response: msg_id, to_email, status ("processed" | "delivered" |
//             "not_delivered"), events[] with event_name in bounced | opened |
//             clicked | processed | dropped | delivered | deferred | ...
//   Scope: a restricted API key with Email Activity access only. The Email
//   Activity API needs the paid "additional email activity history" add-on,
//   and generates no data for regional (EU) subusers.
//   ASSUMPTION: SendGrid's getting-started guide also mentions a "processing"
//   status value that the response schema does not list; this adapter treats
//   any value other than delivered / not_delivered as in flight only if it is
//   "processed" or "processing", and leaves `delivery` out otherwise.
//
// Normalized observation (only fields that could be derived are present):
//   { message_id, provider_status, delivery }
//   delivery: "delivered" | "bounced" | "not_delivered" | "in_flight"
// `in_flight` is this recipe's default PENDING value. When delivery cannot be
// derived, `delivery` is left out, so confirmThenReport says UNKNOWN rather
// than guessing.
//
// Multi-recipient Postmark messages: any Bounced event makes the message
// "bounced" (a partial failure is not a delivery); "delivered" needs at least
// one Delivered event and no Bounced event.

import { defineRecipe, getJson, requireString, resolveFetch } from "./_shared.mjs";

export const EMAIL_DELIVERY_PENDING = Object.freeze({ delivery: Object.freeze(["in_flight"]) });

const MESSAGE_ID = /^[A-Za-z0-9._<>@+=-]+$/;

function postmarkNormalize(body) {
  const out = {};
  if (!body || typeof body !== "object") return out;
  if (typeof body.MessageID === "string") out.message_id = body.MessageID;
  if (typeof body.Status === "string") out.provider_status = body.Status;
  const types = Array.isArray(body.MessageEvents) ? body.MessageEvents.map((e) => e && e.Type) : [];
  if (types.includes("Bounced")) out.delivery = "bounced";
  else if (types.includes("Delivered")) out.delivery = "delivered";
  else if (["Queued", "Processed", "Sent"].includes(body.Status)) out.delivery = "in_flight";
  return out;
}

function sendgridNormalize(body) {
  const out = {};
  if (!body || typeof body !== "object") return out;
  if (typeof body.msg_id === "string") out.message_id = body.msg_id;
  if (typeof body.status === "string") out.provider_status = body.status;
  const names = Array.isArray(body.events) ? body.events.map((e) => e && e.event_name) : [];
  if (body.status === "delivered") out.delivery = "delivered";
  else if (body.status === "not_delivered") out.delivery = names.includes("bounced") ? "bounced" : "not_delivered";
  else if (body.status === "processed" || body.status === "processing") out.delivery = "in_flight";
  return out;
}

export const EMAIL_ADAPTERS = Object.freeze({
  postmark: Object.freeze({
    source: "Postmark",
    apiBase: "https://api.postmarkapp.com",
    path: (id) => "/messages/outbound/" + encodeURIComponent(id) + "/details",
    headers: (token) => ({ accept: "application/json", "x-postmark-server-token": token }),
    normalize: postmarkNormalize,
  }),
  sendgrid: Object.freeze({
    source: "SendGrid",
    apiBase: "https://api.sendgrid.com",
    path: (id) => "/v3/messages/" + encodeURIComponent(id),
    headers: (token) => ({ accept: "application/json", authorization: "Bearer " + token }),
    normalize: sendgridNormalize,
  }),
});

/**
 * @param {object} opts
 * @param {"postmark"|"sendgrid"} [opts.provider]  built-in adapter name
 * @param {object} [opts.adapter]   custom adapter: { source, apiBase, path(id), headers(token), normalize(json) }
 * @param {string} opts.token       provider credential (see scopes above)
 * @param {string} opts.messageId   provider message id
 * @param {string} [opts.apiBase]   override the adapter's base URL
 * @param {Function} [opts.fetch]
 */
export function emailDelivery(opts = {}) {
  const { provider, adapter: custom, token, messageId, apiBase, fetch: fetchImpl } = opts;
  if ((provider === undefined) === (custom === undefined)) throw new TypeError("pass exactly one of provider or adapter");
  let adapter;
  if (provider !== undefined) {
    if (!Object.prototype.hasOwnProperty.call(EMAIL_ADAPTERS, provider)) {
      throw new TypeError("provider must be one of: " + Object.keys(EMAIL_ADAPTERS).join(", "));
    }
    adapter = EMAIL_ADAPTERS[provider];
  } else {
    adapter = custom;
    for (const k of ["path", "headers", "normalize"]) {
      if (!adapter || typeof adapter[k] !== "function") throw new TypeError("adapter." + k + " must be a function");
    }
    requireString("adapter.source", adapter.source);
    requireString("adapter.apiBase", adapter.apiBase);
  }
  requireString("token", token, { max: 10000 });
  requireString("messageId", messageId, { pattern: MESSAGE_ID, max: 500 });
  const f = resolveFetch(fetchImpl);
  const url = String(apiBase || adapter.apiBase).replace(/\/+$/, "") + adapter.path(messageId);
  const headers = adapter.headers(token);

  return defineRecipe({
    href: import.meta.url,
    exportName: "emailDelivery",
    options: opts,
    secrets: [token],
    resource: "email " + messageId,
    source: adapter.source,
    pending: EMAIL_DELIVERY_PENDING,
    read: async ({ signal }) => {
      const { body } = await getJson({ fetchImpl: f, url, headers, signal, source: adapter.source });
      return adapter.normalize(body);
    },
  });
}
