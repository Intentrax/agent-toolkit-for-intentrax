// Read-back (R1a): confirm an agent's claimed outcome against the system of
// record before reporting success. Local, no account, no network except the
// read you configure. See README.md.

export { confirmThenReport, STATUS, CATCH_WORDS, PROVENANCE, PROVENANCE_NOTE, sameValue } from "./confirm.mjs";
export { toSandboxCheck, SANDBOX_BRIDGE_LABEL } from "./bridge.mjs";
export { redact, REDACTED } from "./redact.mjs";
export { httpJson, selectPath } from "./recipes/http-json.mjs";
export { stripeRefund, STRIPE_REFUND_FIELDS, STRIPE_REFUND_PENDING } from "./recipes/stripe-refund.mjs";
export { emailDelivery, EMAIL_ADAPTERS, EMAIL_DELIVERY_PENDING } from "./recipes/email-delivery.mjs";
export { githubIssue } from "./recipes/github-issue.mjs";
export { sqlRow, assertReadOnlySql } from "./recipes/sql-row.mjs";
