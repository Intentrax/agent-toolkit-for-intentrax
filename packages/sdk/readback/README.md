# Read-back: confirm, then report (preview)

> **Self-reported, not an attestation.** Every result here comes from a check
> that *you* configured, run on *your* machine, with *your* credential. It is
> labelled `SELF_REPORTED`, carries `trust_bearing: false`, and is not an
> Intentrax attestation. It catches mistakes in your own pipeline. It does not
> prove anything to a third party.

The most common agent failure is not a wrong decision. It is a false report
of success: the agent says "refund processed", "email sent" or "issue closed",
and it did not happen. Read-back catches that before the success message goes
anywhere. It reads the system of record with a read-only check, compares the
fields that matter, and leads with the catch:

```text
CAUGHT refund rf_2291: agent reported "processed", provider shows "failed"
```

It runs locally, needs no Intentrax account, and makes no network call except
the read you configure.

## Usage

```js
import { confirmThenReport, stripeRefund } from "@intentrax/sdk/readback"; // @intentrax/sdk 1.8.0 and later

const result = await confirmThenReport({
  claimed: { status: agentResult.status },   // what the agent says happened
  expected: { status: "succeeded" },         // what the system must show
  check: stripeRefund({ apiKey: process.env.STRIPE_REFUNDS_READ_KEY, refundId: "re_123" }),
  retries: 3,          // extra reads while the state is not final (default 2)
  intervalMs: 2000,    // wait between reads (default 1000)
  timeoutMs: 10000,    // limit per read (default 10000)
});

console.log(result.firstLine);
if (result.status !== "CONFIRMED") {
  // Do NOT tell the user it worked. Escalate, retry the action, or say so.
}
```

`confirmThenReport` returns `{ status, firstLine, detail }`:

| `status` | Meaning | `firstLine` begins |
| --- | --- | --- |
| `CONFIRMED` | The read matches every expected field. | `CONFIRMED` |
| `CONTRADICTED` | The read shows a different, final value. | `CAUGHT` |
| `PENDING` | Still in a not-final state (for example `pending`) after all retries. | `PENDING` |
| `UNKNOWN` | The check threw, timed out, returned a non-object, or a field is missing. | `UNKNOWN` |

Only `CONFIRMED` is ever worded as success. The other lines end with
"not confirmed" or are a `CAUGHT` line.

**`expected`** takes one of two forms:

- an **array of field names**, such as `["status", "amount"]`. Each named
  field must equal the agent's `claimed` value. Use this form when the agent
  and the system use the same vocabulary.
- an **object of required values**, such as `{ status: "succeeded" }`. Use
  this form when the vocabularies differ. Here the agent says "processed" and
  Stripe says "succeeded". `claimed` is optional and only appears in the
  message.

**Missing is not null.** A field that the read did not return makes the
result `UNKNOWN`. It is never treated as `null`. A `null` that the system did
return is a value and is compared like any other value. This is the same rule
as `intentrax sandbox --check`. No type coercion is applied: `500` does not
equal `"500"`.

**Eventual consistency.** `pending` maps each field to the values that mean
"not final yet", for example `{ status: ["pending", "requires_action"] }`.
While the read shows one of those values, read-back reads again, up to
`retries` more times. It ends with `PENDING` if the value never settles.
Recipes supply sensible defaults. By default a final mismatch is reported at
once. Pass `retryOnMismatch: true` to re-read a mismatch as well, for systems
that lag without an explicit pending state.

**`detail`** holds:

- `provenance: "SELF_REPORTED"`, `trust_bearing: false` and a `note`;
- the `resource` and `source` labels;
- the `isolation` used;
- for each compared field: `expected`, `claimed` and `observed` (or
  `observed_missing`), plus `matches`;
- every attempt, with its outcome, elapsed time and reason.

Fields that were not compared are not copied into `detail`.

Other options:

- `resource` and `source` label the message, for example `"refund re_123"`
  and `"Stripe"`. Recipes set both.
- `actor` names who made the claim (default `"agent"`).
- `secrets` lists extra strings to redact.
- `isolation` sets where the check runs (see below).

Caller mistakes throw a `TypeError` before any read. Examples are an empty
`expected` or a field missing from `claimed`.

### Isolation

The approach is the same as the sandbox's `--check`. A check runs in a worker
thread. That worker is terminated when the check answers or when `timeoutMs`
passes, so a hung socket or timer cannot keep your process alive.

| Check | Where it runs |
| --- | --- |
| A recipe built from plain data (credential string, ids, base URL) | worker thread, automatically |
| `{ module: "./my-check.mjs", probe?: {...} }` | worker thread, using the sandbox's own runner. The module's default export is called with the probe (default `{ resource, fields }`) |
| Any other function (a closure over your client, a recipe given `fetch` / `stripe` / `octokit` / `query`) | **in-process**, bounded by the same timeout and given an `AbortSignal` |

A function cannot be moved to another thread, so the last row cannot be
isolated. `detail.isolation` says which mode was used. If you pass
`isolation: "worker"`, a check that cannot move to a worker throws instead
of silently running in-process.

### Credentials

- Use the narrowest read-only credential you can. Each recipe below lists
  the minimum scope it needs.
- Keep that credential away from the agent whose claims you are checking. A
  check the agent can edit is not a check.
- Recipes never log. Their error messages are built from status codes,
  never from headers.
- Every string in `firstLine` and `detail` is redacted twice:
  - first, every exact secret the recipe declared or you passed in `secrets`
    is removed;
  - then common credential shapes are removed: `Bearer …`, `sk_`/`rk_` keys,
    `ghp_`/`github_pat_` tokens, `SG.` keys, URL userinfo, and `token=`-style
    query parameters.
- URLs in messages show the origin and path only.

## Recipes

Each recipe is a factory. It takes a read-only credential, or a client you
already built, and returns a `check`. Recipes **never write**:

- HTTP recipes send `GET` with no body and refuse redirects, so a credential
  is never replayed to another URL.
- Client recipes call only one read method.

A field the system did not return is left out of the result, never set to
`null`.

### `httpJson`: any JSON GET endpoint

**Minimum scope:** whatever read-only credential the API offers for that
resource, or none for a public endpoint.

```js
const check = httpJson({
  url: "https://api.example.com/v1/tickets/T-1",
  token: process.env.TICKETS_READ_TOKEN,                 // Authorization: Bearer …
  select: { status: "data.status", owner: "data.assignee.login" },  // dot paths; a[0].b works
  notFoundAs: { exists: false },                         // optional: what a 404 means
});
await confirmThenReport({ claimed: { status: "closed" }, expected: ["status"], check });
```

### `stripeRefund`: refund status by id

**Minimum scope:** a restricted key (`rk_…`) with **Refunds: Read** only.

A full `sk_live_` key can move money, so the recipe refuses one unless you
pass `allowFullSecretKey: true`.

```js
const check = stripeRefund({ apiKey: process.env.STRIPE_REFUNDS_READ_KEY, refundId: "re_123" });
// or with your client (only stripe.refunds.retrieve is called):
const check = stripeRefund({ stripe, refundId: "re_123" });
await confirmThenReport({ claimed: { status: "processed" }, expected: { status: "succeeded" }, check });
// -> CAUGHT refund re_123: agent reported "processed", Stripe shows "failed"
```

- **Reads:** `GET /v1/refunds/{id}`.
- **Returns:** `id`, `status`, `amount`, `currency` and `failure_reason`.
- **Default pending values:** `status` ∈ {`pending`, `requires_action`}.
  Stripe's final refund statuses are `succeeded`, `failed` and `canceled`.

### `emailDelivery`: provider message status (Postmark, SendGrid, or your own adapter)

The recipe normalizes each provider's answer to
`{ message_id, provider_status, delivery }`. `delivery` is one of
`delivered`, `bounced`, `not_delivered` or `in_flight`. `in_flight` is the
default pending value. If the delivery state cannot be derived, `delivery` is
left out, and the result is `UNKNOWN`.

```js
const check = emailDelivery({ provider: "postmark", token: process.env.POSTMARK_SERVER_TOKEN, messageId });
const check = emailDelivery({ provider: "sendgrid", token: process.env.SENDGRID_ACTIVITY_KEY, messageId });
await confirmThenReport({ claimed: { delivery: "delivered" }, expected: ["delivery"], check, retries: 5, intervalMs: 5000 });
```

The field names were checked against the providers' public API reference
pages on 2026-11-19.

**Postmark** ([Messages API, "Outbound message details"](https://postmarkapp.com/developer/api/messages-api)):

- **Endpoint:** `GET /messages/outbound/{messageid}/details`, with the
  headers `Accept: application/json` and `X-Postmark-Server-Token`.
- **`Status`:** one of `Sent`, `Processed` or `Queued`.
- **`MessageEvents[].Type`:** one of `Delivered`, `Bounced`, `Transient`,
  `Opened`, `LinkClicked` or `SubscriptionChanged`.
- **Mapping to `delivery`:**
  - any `Bounced` event gives `bounced`, so a partial failure on a
    multi-recipient message is not a delivery;
  - otherwise a `Delivered` event gives `delivered`;
  - otherwise the message is `in_flight`.
- **Minimum scope: there is no read-only Postmark server token.** This
  endpoint requires a Server API token, and that token can also send mail.
  The recipe only reads, but keep that token out of the agent's reach.

**SendGrid** ([Email Activity, "Filter messages by message ID"](https://www.twilio.com/docs/sendgrid/api-reference/email-activity/filter-messages-by-message-id)):

- **Endpoint:** `GET /v3/messages/{msg_id}`, with the header
  `Authorization: Bearer`.
- **`status`:** one of `processed`, `delivered` or `not_delivered`.
- **`events[].event_name`:** includes `bounced`, `dropped`, `deferred` and
  `delivered`.
- **Mapping to `delivery`:**
  - `not_delivered` with a `bounced` event gives `bounced`;
  - `processed` gives `in_flight`.
- **Minimum scope:** a restricted API key with **Email Activity** access only.
  The docs do not name a scope string, so the recipe does not assert one.
- The API needs SendGrid's paid "additional email activity history" add-on.
- It returns no data for regional (EU) subusers.
- **Assumption:** SendGrid's getting-started guide also mentions a
  `processing` status that the response schema does not list. The recipe
  treats `processing` like `processed`.

**Your own provider:** pass
`adapter: { source, apiBase, path(id), headers(token), normalize(json) }`.

### `githubIssue`: issue or pull request state

**Minimum scope:** a fine-grained token limited to the one repository:

- **Issues: Read-only** for `kind: "issue"`;
- **Pull requests: Read-only** for `kind: "pull"`.

GitHub adds **Metadata: Read-only** itself. Public repositories need no token.

```js
const check = githubIssue({ owner: "acme", repo: "app", number: 42, token: process.env.GH_ISSUES_READ });
await confirmThenReport({ claimed: { state: "closed" }, expected: ["state"], check });

const pr = githubIssue({ owner: "acme", repo: "app", number: 7, kind: "pull", octokit });  // only rest.pulls.get
await confirmThenReport({ expected: { merged: true }, check: pr });
// -> CAUGHT pull request acme/app#7: expected true, GitHub shows false
```

- `kind: "issue"` returns `{ number, state, state_reason, is_pull_request }`.
- `kind: "pull"` returns `{ number, state, merged, draft }`.

### `sqlRow`: one database row through your query function

**Minimum scope:** a database role with `SELECT` on the tables the query
reads and nothing else. Use a read replica if you can, and set
`default_transaction_read_only = on` for that role.

```js
const check = sqlRow({
  query: (sql, params) => readonlyPool.query(sql, params),   // returns rows[] or { rows }
  sql: "SELECT status, amount_cents FROM refunds WHERE id = $1",
  params: ["rf_2291"],
  resource: "refund rf_2291",
});
await confirmThenReport({ claimed: { status: "refunded" }, expected: ["status"], check });
```

The query must match exactly one row.

- **No row** gives `UNKNOWN`, unless you pass `notFoundAs`.
- **More than one row** is always `UNKNOWN`.

The SQL is checked lexically before it runs. It must be a single `SELECT` or
`WITH … SELECT` statement, with no `INSERT`/`UPDATE`/`DELETE`/`MERGE`,
`SELECT … INTO`, row locks or `nextval`. This check catches mistakes. **It is
not a security boundary.** The read-only role is what actually stops the
check from writing.

## Bridge to `intentrax sandbox --check`

`toSandboxCheck(check, expected)` wraps a recipe, or any read-only function,
in the module shape that the sandbox's `--check` loads:

```js
// refund-check.mjs
import { toSandboxCheck, stripeRefund } from "@intentrax/sdk/readback";
const m = toSandboxCheck(
  stripeRefund({ apiKey: process.env.STRIPE_REFUNDS_READ_KEY, refundId: process.env.REFUND_ID }),
  { status: "succeeded" },
);
export const expected = m.expected;
export const resource = m.resource;
export default m.check;
```

```bash
intentrax sandbox --check ./refund-check.mjs   # exit 12 CONFLICTING_EVIDENCE on a contradiction
```

On a contradiction, the sandbox exits 12 and also writes a **local,
non-trust-bearing bundle**:

- it is signed with ephemeral keys generated on your machine;
- its read is `SELF_REPORTED`;
- no production verifier, hosted verify or Verification Mark accepts it.

The wrapped check passes only the fields named in `expected`. The bundle
stores the raw read, so it holds no more of the provider's response than the
comparison needs. The bridge's `label` field says the same thing in one
sentence.

## Honest limits

- **You wrote the check.** Read-back shows that your configured read
  disagrees with the agent's report. It cannot show that the read itself is
  right, complete or unaltered. That is why it is `SELF_REPORTED` and not an
  attestation.
- **A wrong check gives a wrong answer.** A check can point at the wrong
  account or use a stale replica. It can also compare a field that does not
  mean what you think it means. Coverage is only the fields you named.
- **Read-only is a convention, enforced as far as a library can enforce it.**
  The recipes only issue reads. Your own function or `query` can do anything,
  and an in-process check cannot be sandboxed. Least-privilege credentials
  are the real control.
- **Point-in-time.** `CONFIRMED` means the state matched when it was read. It
  does not mean the state will stay that way.
- **Provider semantics vary.** "Delivered" means the receiving server
  accepted the mail, not that a person read it. A Stripe refund can still
  fail after it shows `succeeded`.

## Status

Preview, shipped in `@intentrax/sdk` 1.8.0 as the `@intentrax/sdk/readback`
subpath export (not re-exported from the package root) and as a CLI command:

```bash
npx @intentrax/sdk readback --check ./read-refund.mjs   --expected '{"status":"succeeded"}' --claimed '{"status":"processed"}'
```

The `--check` module's default export runs in a worker thread with
`{ resource, fields }` and returns the object it read. Exit codes, aligned with
the sandbox: `0` CONFIRMED, `12` CONTRADICTED (the line starts with `CAUGHT`),
`10` PENDING, `11` UNKNOWN, `64` usage. `--json` prints the full result.
`npx @intentrax/sdk readback --help` lists every option. To run the tests from
a checkout:

```bash
node --test "sdk/typescript/readback/test/*.test.mjs"
```
