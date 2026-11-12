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
downloaded from your tenant's `/v1/proofs/{proof_id}/export?format=json`, and
pass the production key set Intentrax publishes with `--trusted-keys <file>`.

`verify-proof` reads a registry-backed proof lookup JSON export and, offline:

1. recomputes the proof lookup, proof record, verification bundle, and AEP hashes;
2. verifies every ed25519 signature over the signed payload
   (`canonical_payload_json`) and the signature quorum;
3. checks that the signed payload carries the record's own AEP, so the AEP cannot
   be rewritten after signing even if every outer hash is recomputed;
4. checks each signer against published key sets: the bundled sandbox set
   (`trust/sandbox-key-set.json`, not trust-bearing) and any `--trusted-keys` files.

| Status | Exit | Meaning |
|---|---|---|
| `PASS` | 0 | Every signer is a published, trust-bearing key |
| `SANDBOX_NON_TRUST_BEARING` | 0 | Every signer is a published sandbox key: the mechanics check out, but this is not production assurance |
| `UNPINNED_SIGNER` | 3 | Signatures are valid, but a signer is not in any trusted key set, so who signed is unproven |
| `REVOKED_SIGNER`, `MIXED_TRUST` | 3 | Not a trusted result |
| (none) | 2 | An integrity, signature, or binding check failed (failed closed) |

A passing verification shows the record is unaltered since signing, genuinely
signed, and bound to its own AEP. It does not show that the described action was
carried out or had its intended effect. The verifier also rejects private key
material markers. It does not require the runtime server, network access, or
private keys.
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
