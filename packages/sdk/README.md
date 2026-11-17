# TypeScript / Node.js SDK

## Install

```bash
npm install @intentrax/sdk
```

The package is public on npm (Apache-2.0). Everything below that says
"offline" or "local" runs today with no API key: `init --dry-run`,
`check-init`, `verify-proof` (sandbox sample proofs, including tampered ones,
are bundled at `examples/sandbox/`), and `verify-pdf-receipt`. Live execution
keys and your sandbox base URL are issued after an architectural review at
<https://www.intentrax.com/request-architectural-review>.

First-wave SDK lane for AI apps, MCP clients, SaaS products, browser-adjacent
tooling, and Node.js service integrations.

This package must consume shared Intentrax specs and conformance vectors from
`../shared-specs` and `../conformance`. It must not redefine EEO, AEP,
canonical serialization, proof verification, policy decisions, or tier
enforcement.

Public surfaces:
- `@intentrax/sdk` for deterministic canonicalization and verification envelopes
- `@intentrax/sdk/http` for explicit HTTP API-wrapper execution
- `intentrax init <adapter>` for local developer adapter onboarding
- `intentrax check-init --output-dir <dir>` for offline adapter init verification
- `intentrax verify-proof <proof-export.json>` for offline proof verification:
  integrity hashes, ed25519 signatures and quorum, the signed-payload binding,
  and signer pinning against published key sets
- `intentrax verify-pdf-receipt <receipt.pdf>` for local downloaded PDF receipt
  byte/hash verification

The published package exports Node-runnable `.js` modules with `.d.ts` type
declarations and is gated on Node 20 and Node 24.

One-command adapter onboarding:

```bash
npx @intentrax/sdk init claude-code --dry-run
npx @intentrax/sdk init cursor
npx @intentrax/sdk init mcp
npx @intentrax/sdk init langchain
npx @intentrax/sdk init langgraph
npx @intentrax/sdk init vercel-ai-sdk
npx @intentrax/sdk init cursor --force
npx @intentrax/sdk check-init --output-dir .
```

The MVP-native adapter set is Claude Code, Cursor, MCP, LangChain, LangGraph,
and Vercel AI SDK. The same command also exposes expanded scaffold aliases for
Custom Agent, CrewAI, AutoGen, OpenClaw, n8n, and DeepFlow so teams can try the
admission-only path without changing AEVN/AEP authority or treating those
aliases as MVP-native hooks.

The init command creates `.intentrax/agent-adapter.json`,
`.intentrax/sample-admission-request.json`, `.intentrax/action-receipt.json`,
`.intentrax/submit_sample.curl`, and
`.intentrax/hooks/<adapter-native-hook>.mjs`, plus
`.intentrax/wiring/<adapter-host-wiring>.md`, when not run with `--dry-run`. It
does not store API keys, signing keys, or tenant secrets. The sample admission
request uses the locked private-alpha Agent Gateway refs and an allowed
contract-only action for the selected adapter surface.

The command is safe to rerun when generated files are unchanged. If an existing
`.intentrax` file has local edits, `intentrax init` fails closed before writing
anything; pass `--force` only after reviewing the local changes you intend to
replace.

The generated hook starter builds a fresh admission request for the local
adapter event, drops auth-like fields before hashing, and fails closed when a
submitted admission is denied or unavailable. It still does not execute tools,
mutate payloads, re-run policy, or generate proofs inside the adapter.

The generated host wiring guide shows where to import the hook starter in the
selected host surface and is hash-bound into both `.intentrax/agent-adapter.json`
and `.intentrax/action-receipt.json`. It is developer setup guidance only, not
canonical evidence or production authorization.

After writing files, the CLI prints a no-secret `curl` command that submits the
sample with `X-Intentrax-Tenant-ID`, `X-Intentrax-Api-Key`, and
`X-Intentrax-Idempotency-Key`. Set `INTENTRAX_API_KEY` from your secret manager
before running it.

`.intentrax/action-receipt.json` is a hash-bound developer summary for the
generated sample. It links the adapter profile, admission envelope, hook
starter, host wiring guide, submit command, and future AEVN/AEP proof export or
registry reference path. It is not canonical proof and does not authorize
production traffic.

Offline init verification:

```bash
npx @intentrax/sdk check-init --output-dir . --json
```

`check-init` verifies the initialized `.intentrax` directory without
`INTENTRAX_API_KEY`, runtime access, or network submission. It checks the
expected files, validates the Agent Gateway sample fixture through the SDK
admission semantics, recomputes the action receipt, generated hook source, and
host wiring guide hash bindings, and imports the generated hook in no-submit
mode with a
secret-bearing fixture to confirm the starter does not leak secrets or require
network access. Human output is a concise pass/fail line; `--json` emits the
deterministic status, boundary assertions, file hashes, and errors.

Expanded scaffold aliases:

```bash
npx @intentrax/sdk init custom-agent
npx @intentrax/sdk init crewai
npx @intentrax/sdk init autogen
npx @intentrax/sdk init openclaw
npx @intentrax/sdk init n8n
npx @intentrax/sdk init deepflow
```

Local proof export verification:

Sandbox sample proofs ship with the package in `examples/sandbox/` (see its
README): a valid sandbox proof plus tampered and unpinned variants. They are
produced by the engine's own proof pipeline under published sandbox keys, so
these commands work immediately after `npm install @intentrax/sdk`, with no key,
no network, and no runtime:

```bash
npx @intentrax/sdk verify-proof node_modules/@intentrax/sdk/examples/sandbox/sandbox-proof-export.json
npx @intentrax/sdk verify-proof node_modules/@intentrax/sdk/examples/sandbox/tampered-aep-swap.json
```

To verify your own artifact, point the command at any proof lookup JSON export
downloaded from your tenant's `/v1/proofs/{proof_id}/export?format=json`. The
production key set is bundled, so you don't need any flags. Pass extra key sets
(for example, ones that revoke a key) with `--trusted-keys <file>`.

`verify-proof` reads a registry-backed proof lookup JSON export and, offline:

1. recomputes the proof lookup, proof record, verification bundle, and AEP hashes;
2. verifies every ed25519 signature over the signed payload
   (`canonical_payload_json`) and the signature quorum;
3. checks that the signed payload carries the record's own AEP, so the AEP cannot
   be rewritten after signing even if every outer hash is recomputed;
4. checks each signer against published key sets: the bundled production set
   (`trust/production-key-set.json`, trust-bearing), the bundled sandbox set
   (`trust/sandbox-key-set.json`, not trust-bearing), and any `--trusted-keys` files.
   A revocation in any loaded set wins;
5. checks that at least the key set's `min_trusted_signers` distinct trusted keys
   signed. The production set requires 2. A proof's own quorum isn't enough,
   because a signature can be stripped along with the quorum and roster entries
   that describe it. When several sets vouch for the signers, the strictest
   minimum applies.

| Status | Exit | Meaning |
|---|---|---|
| `PASS` | 0 | Every signer is a published, trust-bearing key, and enough distinct keys signed |
| `SANDBOX_NON_TRUST_BEARING` | 0 | Every signer is a published sandbox key: the mechanics check out, but this is not production assurance |
| `UNPINNED_SIGNER` | 3 | Signatures are valid, but a signer is not in any trusted key set, so who signed is unproven |
| `INSUFFICIENT_TRUSTED_SIGNERS` | 3 | Every signer is trusted, but fewer distinct keys signed than the key set requires (signatures may have been stripped) |
| `REVOKED_SIGNER`, `MIXED_TRUST` | 3 | Not a trusted result |
| (none) | 2 | An integrity, signature, or binding check failed (failed closed) |

Policy binding (SDK 1.5.0). A proof issued under the AEP 1.1 policy-binding
profile carries `policy_binding` inside its signed AEP. The binding names the
hash-pinned policy the engine evaluated (`source_policy_hash`,
`compiled_policy_hash`), the evaluation (`evaluation_hash`,
`execution_event_hash`, `decision`, `rule_id`) and, when one exists, a
`mandate_hash`. It also lists every constraint of the matched rule with an
explicit `status`: `NOT_EVALUATED` (not checked, no evidence) or `SATISFIED`
(with the `evidence_hash` of a real approval artifact). Today every constraint
is `NOT_EVALUATED`. `verify-proof` copies the binding into the report as
`policy_binding`, and states it in words as `policy_binding_statement`. For
example, an execute proof reads "evaluated COMPLIANT … Constraint
constraint.operator-review (REQUIRE_APPROVAL): NOT CHECKED (NOT_EVALUATED)",
meaning allowed, approval not checked. Proofs without a binding verify exactly
as before, and their report has neither key. A binding fails closed (exit 2),
even when its signatures are genuine, if it is malformed, claims anything other
than `enforcement: "RECORD_ONLY"`, has `SATISFIED` without evidence or
`NOT_EVALUATED` with evidence, or has an unknown constraint status.
`RECORD_ONLY` means the decision was recorded when the proof was issued. It
does not mean the decision was enforced.

Re-checking the decision (SDK 1.6.0). A binding also seals the facts the policy evaluated
(`evaluated_facts`: `lane` and `mutation_performed`). `verify-proof` re-derives
the decision instead of trusting it:

1. It rebuilds the evaluated event from those facts, and requires the lane to
   match the one the signed proof itself names.
2. It resolves the policy by its `source_policy_hash`: first a
   `--policy-document <file>` (as served by
   `GET https://api.intentrax.com/v1/policies/{source_policy_hash}`), then the
   published registry bundled in `trust/policies/`.
3. It re-runs the policy engine. The SDK carries a full port of it
   (`reevaluatePolicy`, `compilePolicyDocument`, `evaluateCompiledPolicy`),
   checked against vectors generated by the Go engine.

The report carries `policy_reevaluation`: `MATCH` (with `policy_source`) or
`NOT_RECHECKED` (with a `reason`). A re-run that does not reproduce every
sealed value fails closed (exit 2), even under genuine signatures. A `MATCH`
proves the decision follows from the sealed facts and the published rule. It
does not independently witness that the facts are true; the runtime's
signature attests to them.

A passing verification shows the record is unaltered since signing, genuinely
signed, and bound to its own AEP. It does not show that the described action was
carried out or had its intended effect. The verifier also rejects private key
material markers. It does not require the runtime server, network access, or
private keys.

Since 1.4.0 the report also carries `verification_assessment`, printed as a
table. It states what the proof establishes and what it does not:

- `assurance_profile`: every proof issued today is `LEGACY_DECISION_RECORD`,
  which requires only `RECORD_INTEGRITY`.
- `assessments[]`: one row per dimension (`RECORD_INTEGRITY`,
  `SIGNER_AUTHENTICITY`, `AUTHORIZATION`, `EXECUTION_REPORTED`,
  `EXECUTION_ATTESTED`, `EFFECT_OBSERVED`, `EFFECT_CONFIRMED`, `CAUSAL_CHAIN`)
  with `result`, `provenance`, `reasons` and `limitations`. `SIGNER_AUTHENTICITY`
  is `VERIFIED` only when the status is `PASS`; every dimension after it is
  `NOT_ASSESSED` for a legacy proof.
- `verdict`: derived from the rows by a fixed rule, never asserted by a signer.
  `VERIFIED_FOR_SCOPE` (record intact, trusted signers; the scope is the
  required dimensions only), `INTEGRITY_ONLY` (signer not established) or
  `VERIFICATION_FAILED` (for example a revoked signer).
- `limitations[]`: machine-readable codes with text. A legacy proof always lists
  `EXECUTION_NOT_ATTESTED`, `EFFECT_NOT_VERIFIED`, `POLICY_BINDING_SYNTHETIC` and
  `COMPLETENESS_NOT_ESTABLISHED`, plus `SIGNER_AUTHENTICITY_REQUIRES_PINNED_ANCHORS`
  when the signer is not established.
- When the proof seals an AEP 1.1 `policy_binding` (RECORD_ONLY), only a
  re-evaluation `MATCH` can lift `AUTHORIZATION` above `REPORTED`.
  - A re-checked `COMPLIANT` decision whose matched rule has no unchecked
    constraint is `VERIFIED` (provenance `VERIFIER_COMPUTED`), with
    `POLICY_EVENT_SELF_REPORTED` and `POLICY_DECISION_NOT_ENFORCED`.
  - With a `NOT_EVALUATED` constraint it stays `REPORTED`.
  - When the decision was not re-checked, `COMPLIANT` is `REPORTED`
    (provenance `INTENTRAX_DECISION`), with `POLICY_EVALUATION_NOT_RECHECKABLE`.
  - `NON_COMPLIANT` is `CONTRADICTED` and `ERROR` is `INSUFFICIENT_EVIDENCE`
    either way.
  - `POLICY_CONSTRAINT_NOT_EVALUATED` is added when a constraint was not
    checked. The verdict does not change.

The block is additive: `status`, `signer_trust` and the exit code are unchanged.
The model is exported (`deriveAssuranceVerdict`, `buildLegacyVerificationAssessment`,
`ASSURANCE_PROFILES`, ...) and matches the Go offline verifier's
`verification_assessment`.

The JSON proof export remains authoritative. Downloaded PDF receipts are
human-readable companions and should be checked against their exported hash
metadata, not treated as replacement proof material.

Local PDF receipt verification:

```bash
npx @intentrax/sdk verify-pdf-receipt \
  .intentrax/proof-001-aep-receipt.pdf \
  --pdf-hash "$X_INTENTRAX_PDF_HASH" \
  --report-out .intentrax/pdf-receipt-verification.report.json
```

`verify-pdf-receipt` reads downloaded PDF bytes, checks the `%PDF-` header,
recomputes SHA-256, and compares it with the runtime `X-Intentrax-PDF-Hash`
header. It validates only the human-readable PDF companion. The canonical JSON
proof export and AEP evidence remain the source of truth.

Programmatic receipt and export helpers:

```js
import {
  buildProofExportHttpRequest,
  buildReceiptVerificationHttpRequest,
} from "@intentrax/sdk/http";
```

`buildReceiptVerificationHttpRequest` builds the runtime/OpenAPI receipt
verification request for `POST /v1/proofs/verify`. `buildProofExportHttpRequest`
builds `GET /v1/proofs/{proof_id}/export?format=json|aep-json|pdf`; JSON and
AEP JSON are authoritative proof exports, while PDF is a deterministic
human-readable receipt.

Reading a Verification Mark verdict off a response:

```js
import { readVerificationVerdict } from "@intentrax/sdk";

// `response` can be a bare verification envelope, any object carrying an
// `intentrax_verification` envelope, or an MCP tool result whose
// `structuredContent` carries one.
const verdict = readVerificationVerdict(response);
if (verdict.verified) {
  // verdict.display_state === "verified", verdict.severity === "green"
  console.log(verdict.proof_id, verdict.verify_url, verdict.assurance_level);
}
```

The `intentrax_verification` envelope is a backend-produced, public-safe
projection — `{ display_state, proof_id, verify_url, assurance_level,
signature }`. The SDK is a strict READER: `readVerificationVerdict`,
`normalizeVerificationMarkEnvelope`, and `validateVerificationMarkEnvelope`
validate the envelope's SHAPE only. They never re-derive crypto, recompute
validity, or regenerate a proof — `verified` is exactly the backend's
`display_state === "verified"`. `signature` is a STATUS projection (e.g.
`"pass"`), never a raw signature; a value that looks like raw signing material
is refused so it can never leak. An absent or malformed envelope yields a safe,
non-verified reading rather than throwing.

Binding the rendered output to a proof (execute request `/1.1`):

```js
import { bindIntentExecuteOutput, verificationPointerMetaTag } from "@intentrax/sdk";
import { executeIntentHttp } from "@intentrax/sdk/http";

// Bind exactly the text the page will show inside its data-intentrax-output
// region(s). The request becomes schema /1.1 with an output_binding block.
const request = bindIntentExecuteOutput({
  intent_id: "intent-refund-8812",
  tenant_id: process.env.INTENTRAX_TENANT_ID,
  action: "APPROVE_REFUND",
  idempotency_key: "refund-8812-v1",
  proof_chain_fixture_ref: "intent-execute",
  schema_version: "intentrax.runtime.intent_execute.request/1.0",
}, renderedOutput);

const result = await executeIntentHttp(request, transport, {
  base_url: process.env.INTENTRAX_BASE_URL,
  api_key: process.env.INTENTRAX_API_KEY,
});
```

The engine seals the binding inside the signed proof (`aep.output_binding`,
`binding_source: PRODUCER_DECLARED_AT_ISSUANCE`), and the public verifier
relays it only from that signed proof. The browser extension recomputes the
`intentrax-content/1.0` hash over the page's visible marked output and shows the
green Verification Mark only when the proof is valid and the hashes match. A
copy of the proof id on different content stays neutral.

`validateIntentExecuteRequest` mirrors the engine: `output_binding` is accepted
only under `/1.1` (a `/1.0` body carrying it is refused as `body`), is decoded
strictly (exactly `content_hash`, `hash_algorithm`, `normalization`), and its
`content_hash` must be 64 lowercase hex, optionally `sha256:`-prefixed. `/1.0`
requests are unchanged. The execute lane is fail-closed per tenant (HTTP 423
until live execution is enabled, HTTP 403 until the tenant is allowlisted).

Correlating an admission with the execution that follows it:

```js
import { executeIdempotencyKeyHash } from "@intentrax/sdk";

// One raw key K per logical action. Execute sends K itself; the admission
// sends only its SHA-256 (no domain prefix). The engine links the execution
// under SHA-256(K), so the two correlate.
const key = "refund-8812-v1";
const admission = { /* ...agent admission fields... */ idempotency_key_hash: executeIdempotencyKeyHash(key) };
const execute = { /* ...execute fields... */ idempotency_key: key };
```

Hooks generated by `intentrax agent init` admit under
`executeIdempotencyKeyHash(agentHookExecuteIdempotencyKey(request_payload_hash))`
and return that raw key as `execute_idempotency_key` in the hook result: send it
unchanged as the execute `idempotency_key`. The engine also uses these links for
durable idempotency: once a key has executed one request, a different request
under the same key is refused with HTTP 409, even after a runtime restart.
