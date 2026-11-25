# Spec 00 primitives (`sdk/typescript/envelope`)

The building blocks of signed pre-approval, from
`docs/architecture/specs/00-common-conventions.md` (approved 2026-11-21):

- **RFC 8785 JCS** (`jcs.mjs`) with the two profiles: `JCS-ANY` (third-party
  JSON such as MCP tool arguments) and `JCS-INT` (everything Intentrax or a
  tenant signs: safe integers only, ASCII member names).
- **`D(domain, value)`** = SHA-256(UTF-8(domain) || JCS(value)) (`digest`).
- **`intentrax.signed_envelope/1.0`** parse and verify (`parseEnvelope`,
  `verifyEnvelope`), with pinned key purpose, validity window and revocation.
- **Strict timestamps** (`parseTime`): RFC 3339 with an explicit offset,
  compared as instants (nanoseconds, as a bigint).
- **Commitments** (`verifyCommitment`): `{field, salt, value}` openings.

It is a port of the Go packages `engine/internal/determinism/jcs` and
`engine/internal/verificationinfra/signedenvelope`, with the same codes and the
same hardening:

- the signed message is always rebuilt from `payload_type` and `payload`;
- signer trust comes only from a pinned key, never from `public_key_hex`;
- member names are matched exactly; duplicate and unknown members are
  rejected; a UTF-8 byte-order mark is stripped;
- offsets outside 00:00–23:59 and out-of-range dates fail closed;
- a member named `__proto__` is an ordinary member (objects have no
  prototype), never prototype pollution.

Only `node:crypto` is used (Ed25519, SHA-256). No dependencies. The module
verifies; it holds no keys and signs nothing.

## Status

Exported as `@intentrax/sdk/envelope` and packed since `@intentrax/sdk` 1.10.0.
Its tests run in the SDK conformance lane (`conformance.test.mjs` module
suites). `verify-proof` uses it for signed pre-approval records (specs
01–03, `preapproval/`).

## Tests

```
node --test envelope/test/jcs.test.mjs envelope/test/envelope.test.mjs
```

They replay spec vector 00, every case of the Go tests, and
`test/fixtures/jcs-go-corpus.json`: 56 inputs (valid, invalid and edge cases)
canonicalised by the Go package under both profiles. The TS port must give the
same bytes or reject the same inputs. The corpus was produced by a throwaway
Go test that is not committed; regenerate it the same way if the Go package
changes.
