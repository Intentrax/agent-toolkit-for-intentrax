# Intentrax local assurance sandbox (preview)

> **Not production assurance.** Everything here is signed with ephemeral keys
> generated on your machine (`environment: "local"`, `trust_bearing: false`).
> A local bundle can never verify as a production proof: the production
> `verify-proof`, the Go offline verifier, hosted verify and the Verification
> Mark do not accept it.

The sandbox runs one consequential action through the whole Intentrax
assurance flow, in-process, with no account, no API key and no network:

1. a **signed decision** (ALLOW/DENY), made before execution;
2. an **executor report** (a self-report: "I did it");
3. an **independent read-only check** of the outcome, signed by a different
   key from the executor's;
4. a **sealed bundle** binding all of it by digests;
5. **offline verification**: eight per-dimension assessments and the §5.4
   verdict rule, capped at `LOCAL_NON_TRUST_BEARING`.

The point it demonstrates is the one a decision record alone cannot show: an
action can be authorised and reported as successful, yet not have happened.

Not to be confused with the **published sandbox** (`trust/sandbox-key-set.json`,
the sample proofs in `examples/sandbox/`, and the `SANDBOX_NON_TRUST_BEARING`
status of `verify-proof`). Those are production-format AEPs signed by
Intentrax-published, non-trust-bearing keys. The local sandbox never uses
those keys; it generates its own on your machine.

Design: `docs/architecture/INTENTRAX_APORT_COMPETITIVE_ASSESSMENT.md` §4.3 and
`docs/architecture/INTENTRAX_WAY_FORWARD_ADOPTION_AND_ASSURANCE.md` (P0 items
A1 and B1). The verifier semantics are ported from
`examples/effect-assurance-demo` (PRs #449, #477); see "Relationship to the
demo" below.

## Run it

The sandbox is a subcommand of the SDK CLI (`@intentrax/sdk` 1.7.0 and later):

```bash
npx @intentrax/sdk sandbox                          # sample action, outcome confirmed
npx @intentrax/sdk sandbox --scenario contradicted  # ALLOW + "SUCCEEDED" + read says otherwise
npx @intentrax/sdk sandbox --check ./my-check.mjs   # check the outcome of YOUR action
npx @intentrax/sdk sandbox verify <bundle.json> --keys <local-key-set.json>
```

The packaged example check is at
`node_modules/@intentrax/sdk/sandbox/examples/read-only-check.example.mjs`. From
a checkout of this repository, `node sdk/typescript/sandbox/cli.mjs` runs the
same CLI.

Add `--json` for machine-readable output, and `--dir <project>` to write
somewhere other than the current directory.

| Command | Verdict | Exit |
| --- | --- | --- |
| `sandbox` | `LOCAL_NON_TRUST_BEARING` (uncapped: `VERIFIED_FOR_SCOPE`), `EFFECT_CONFIRMED = CONFIRMED` | 0 |
| `sandbox --scenario contradicted` | `CONFLICTING_EVIDENCE`, `EFFECT_CONFIRMED = CONTRADICTED` | 12 |
| `sandbox --check` (read matches `expected`) | `LOCAL_NON_TRUST_BEARING`, `EFFECT_CONFIRMED = CONFIRMED` | 0 |
| `sandbox --check` (read differs) | `CONFLICTING_EVIDENCE` | 12 |
| `sandbox --check` (check throws, times out, returns non-JSON) | `INSUFFICIENT_EVIDENCE` | 11 |
| `sandbox verify` without `--keys` | `INTEGRITY_ONLY` | 13 |

Exit codes: `0` LOCAL_NON_TRUST_BEARING · `10` PENDING_FINALITY · `11`
INSUFFICIENT_EVIDENCE · `12` CONFLICTING_EVIDENCE · `13` INTEGRITY_ONLY · `14`
VERIFICATION_FAILED · `64` usage. `VERIFIED_FOR_SCOPE` is never returned.

## Check the outcome of your own action (`--check`)

Write a small module that **reads** the state your agent's action should have
produced. Run your action first, then the sandbox:

```js
// my-check.mjs
export const resource = "ticket:1234";                    // optional label
export const expected = { status: "closed" };             // required: what the action should have set
export default async function check({ resource, fields }) {
  const ticket = await myReadOnlyClient.getTicket(1234);  // a READ, never a write
  return { status: ticket.status };
}
```

The sandbox authorises `SetState ticket:1234 -> {"status":"closed"}`, records
that your action reports success, calls `check()` once with its own local
effect-verifier key, compares only the fields named in `expected`, and shows
`EFFECT_CONFIRMED` = `CONFIRMED` or `CONTRADICTED`.

- The read must be an object containing **every** field named in `expected`.
  A missing field is not treated as `null`, so `{}` can never confirm
  `expected = { deleted_at: null }`. A missing field, or a read that is not an
  object, gives `INSUFFICIENT_EVIDENCE`.
- Your module is loaded and called only inside a worker thread, never on the
  sandbox's own thread. The worker is terminated once it answers, or when
  `--check-timeout-ms` (default 30000) runs out. So a check that hangs or
  leaves sockets or timers open still ends with exit 11
  (`INSUFFICIENT_EVIDENCE`, `CHECK_TIMED_OUT`). Return plain data only: the
  result crosses the thread boundary by structured clone. A full example is in
[`examples/read-only-check.example.mjs`](examples/read-only-check.example.mjs).

How the read is labelled, honestly:

| Read | `source_authentication` | Provenance | Why |
| --- | --- | --- | --- |
| Built-in sample (synthetic store) | `LOCAL_EFFECT_VERIFIER_READ` | `THIRD_PARTY_ATTESTED` | Read and signed by the local effect-verifier key, distinct from the executor key. Still a local key. |
| Your `--check` module | `USER_SUPPLIED_CHECK` | `SELF_REPORTED` | You wrote both the action and the check. It is not an Intentrax-pulled authoritative read. |

The bundle records the check module's file name and SHA-256, not its path.

## What gets written

Everything goes under `<project>/.intentrax/local/`, which contains its own
`.gitignore` (`*`), so nothing is committed by accident:

```
.intentrax/local/
  .gitignore                      # "*"
  sandbox-signing-keys.json       # this run's ephemeral PRIVATE keys (mode 0600); regenerated every run
  runs/<bundle_id>/
    bundle.json                   # intentrax.local_assurance_bundle/0.1
    local-key-set.json            # the run's PUBLIC keys, to re-verify the bundle
    verification-report.json      # the eight assessments and the verdict
```

## External authorization decisions (`verify --issuer-keys`)

A bundle may also carry another system's signed authorization decision. The
sandbox treats it as **evidence, never trust**. This is the verifier side of
B3 (`docs/architecture/INTENTRAX_EXTERNAL_DECISION_EVIDENCE.md`), ported from
the demo (PR #481). The sandbox never issues, fetches or adds external
decisions itself. `sandbox verify` assesses them when a bundle carries them:

```bash
node sdk/typescript/sandbox/cli.mjs verify bundle.json --keys local-key-set.json \
  --issuer-keys pinned-external-issuers.json [--require-external-issuer <issuer>]...
```

- Each decision sits in an optional, sealed `external_decisions` array of
  `intentrax.external_decision_evidence/0.1` wrappers. The wrappers keep the
  issuer's original bytes verbatim. Bundles the sandbox makes never have this
  field, so their bytes and seals are unchanged.
- Signatures are checked **only** against the issuer key set you pin
  (`intentrax.local.sandbox_pinned_external_issuers/0.1`; same shape as the
  demo's file). Nothing is fetched: no JWKS, no revocation list, no network.
  The loader fails closed on an unknown schema or profile, a non-Ed25519 or
  malformed key, a duplicate issuer or kid, or a missing, malformed or
  inverted `valid_from`/`valid_until`/`revoked_at`.
- The result is an extra dimension, `EXTERNAL_AUTHORIZATION`, with provenance
  `THIRD_PARTY_ATTESTED`. It appears only when the bundle carries external
  decisions or you name an issuer, so ordinary reports keep eight
  dimensions. It never changes `AUTHORIZATION`.
- Binding: the decision must name the same tool, target and parameters
  digest, be issued before the action, and still be in force when it runs.
  Otherwise the result is `UNBOUND_EXTERNAL_DECISION:*` or
  `EXTERNAL_DECISION_EXPIRED` (`INSUFFICIENT_EVIDENCE`).
- Conflict: an external DENY against a local ALLOW is `CONTRADICTED`, so the
  verdict is `CONFLICTING_EVIDENCE` (exit 12), required or not.
- Non-required by default: a missing or unverifiable external decision does
  not change the verdict. `--require-external-issuer` makes the dimension
  required, and only that issuer's decision satisfies it.
- **The ceiling still applies.** A genuinely signed, bound and required
  external ALLOW still gives `LOCAL_NON_TRUST_BEARING`, never
  `VERIFIED_FOR_SCOPE`.
- Format profile `intentrax.ext_profile.ed25519_jcs_oap_shaped/0.1`: an
  Ed25519-over-JCS decision shaped like an OAP decision, plus an
  `action_binding` extension. Interoperability with real APort/OAP decisions
  is **UNVERIFIED** (never tested against a genuine signed APort decision),
  and no APort compatibility is claimed.
- Documented limit: someone holding the local decision-service key can strip
  `external_decisions` and reseal. Completeness is not established, and the
  verifier cannot know about evidence it was never shown.

## Invariants (each is a test in `test/invariants.test.mjs`)

1. Fresh Ed25519 keys per run, under `.intentrax/local/`, each labelled
   `environment: "local"`, `trust_bearing: false`. The key-set loader refuses
   anything else, including the production and published sandbox key sets.
2. The sandbox never reads, derives or requests a production or published
   sandbox key, and makes no network call. Checked three ways: a static scan
   of the runtime modules' imports, a run with file-read and network spies,
   and a run under the Node permission model with no read access to `trust/`.
   The only code that could touch a network is your own `--check` module.
3. The verdict is capped at `LOCAL_NON_TRUST_BEARING`, also when you pin the
   run's key set, and also if a key map claiming `trust_bearing: true` is
   forced past the loader. The cap removes the positive claim only; a
   contradiction, missing evidence or a failed check is reported as is.
4. `trust/production-key-set.json` (and `trust/sandbox-key-set.json`) are
   hash-pinned and unchanged.
5. `intentrax verify-proof` with the built-in production key set rejects a
   local bundle (fails closed), and rejects a local key set passed as
   `--trusted-keys`.
6. Human and JSON output carry the "not production assurance" banner.

## Limitations (read before showing this to anyone)

1. **Not trust-bearing.** Anyone can generate local keys and sign whatever
   they like. A local bundle shows the verification mechanics and the shape
   of the evidence, not that anything is true.
2. **Preview format.** The bundle is the effect-assurance preview format
   (`intentrax.effect_evidence/0.1` inside
   `intentrax.local_assurance_bundle/0.1`), not the production AEP export.
   Format parity with production is not claimed.
3. **Your check is yours.** A `--check` read is `SELF_REPORTED`: it is only as
   independent and correct as the code you wrote, and it is read-only by
   contract only. The sandbox cannot stop a check from writing.
4. **The sandbox does not run your action.** With `--check`, the executor
   report records the claim that your action ran; the sandbox makes no call
   to your system other than your check function.
5. **No attribution.** A confirmed state may pre-date the action; nothing
   links it to this execution (`EFFECT_NOT_ATTRIBUTED_TO_THIS_EXECUTION`).
6. **Reads are treated as final.** Eventual consistency and asynchronous
   operations are not modelled; the demo's PENDING/FINAL handling is not
   exercised here.
7. **Partial coverage.** Only the fields named in `expected` are compared.
8. **One mandate, no delegation, no budget, no revocation registry.** The
   demo's delegation, aggregate-budget and revocation scenarios are not part
   of the sandbox.
9. **Execution is not attested** (`EXECUTION_ATTESTED = NOT_ASSESSED`), and
   completeness is not established: nothing proves every action went through
   Intentrax.
10. **Times are self-asserted** by local signers, on a logical clock that
    starts at the real time of the run.
    The verifier accepts only RFC 3339 times with an explicit offset (`Z` or
    `±hh:mm`): a timezone-less or unparseable time fails closed, so a result
    never depends on the verifying machine's timezone.
11. **Shared evaluator.** The verifier re-runs the same mandate/policy
    evaluator as the local decision service.
12. **The bundle holds the raw read.** That makes offline recomputation
    possible. Do not point a check at data you would not keep in a local
    file.

## Relationship to the demo

Ported (not imported) from `examples/effect-assurance-demo`, PRs #449 and
#477: `canonical.mjs` (unchanged), `model.mjs` (unchanged rule plus the local
ceiling), `envelope.mjs` (sandbox signing domain, no revocation),
`verifier.mjs` (single mandate, no budget), `effect-verifier.mjs` (local
reads instead of source receipts), `bundle.mjs` (sealed
`environment`/`trust_bearing` labels), and the decision service and executor
flow (`run.mjs`). Each file names its source. Scenario B of the demo is
`--scenario contradicted` here.

From PR #481 (B3), the verifier side only: `external-decision.mjs` (no
issuing, no ingestion), the optional `EXTERNAL_AUTHORIZATION` dimension,
`deriveVerdict(..., { extraRequired })`, the optional sealed
`external_decisions` component, and the `SEAL_COMPONENT_SET_MISMATCH` check.
Scenario J of the demo is `test/external-decision.test.mjs` here (rows J1 to
J9, with the local ceiling applied). The test-only issuer is in
`test-fixtures/external-issuer.mjs`.

## Release status

Shipped in `@intentrax/sdk` 1.7.0: `cli/intentrax.mjs` dispatches `sandbox`
to `sandbox/cli.mjs`, and the package `files` include `sandbox/*.mjs`,
`sandbox/examples` and this README (not the tests or fixtures). The npm
release goes through staged trusted publishing; the owner approves it with
`npm stage approve`.
