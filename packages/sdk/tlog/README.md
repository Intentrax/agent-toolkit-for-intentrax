# Transparency-log inclusion (`@intentrax/sdk/tlog`)

Offline checks that an Intentrax proof record is in a transparency log. They cover:

- **The checkpoint.** It is signed by the pinned log key and cosigned by enough pinned witnesses.
- **The inclusion proof.** It ties the record to the checkpoint.

This module is a port of the Go package `engine/internal/transparencylog`. It uses only `node:crypto`. It reads no network, clock or environment.

> **Status:** rollout step 2 ("verifiers learn the format").
>
> - **No log is published yet.** No transparency-log trust document is bundled. You pass one in yourself.
> - **Claim 6 is not made.** Intentrax does not say proofs are logged until witnessed checkpoints are published.
>
> See `docs/architecture/INTENTRAX_TRANSPARENCY_LOG_DESIGN.md` in the Intentrax repository.

## Formats

- **Inclusion bundle** (`intentrax.tlog.inclusion-bundle/v0`). The unsigned sidecar that travels next to a proof export. It has these fields:
  - `record_hash`
  - `leaf_index`
  - `tree_size`
  - `inclusion_path` (base64 hashes)
  - `checkpoint` (the signed, cosigned C2SP note, verbatim)
- **Trust document** (`intentrax.trust.transparency_log/0`). What you pin. It has these fields:
  - `origin`
  - `log_key` (C2SP vkey, Ed25519)
  - `witnesses[]` (C2SP vkeys, cosignature/v1)
  - `witness_quorum`
  - `max_integration_delay_seconds`

  A quorum of `0` means an unwitnessed log, and results are then `VERIFIED_UNWITNESSED`.

Both are parsed strictly:

- every field is required;
- keys must match exactly, case included;
- duplicate or unknown keys are rejected;
- trailing data is rejected.

## Use

```js
import { parseInclusionBundle, parseTrustDocument, verifyBundleOffline } from "@intentrax/sdk/tlog";

const doc = parseTrustDocument(trustDocumentJson);
const bundle = parseInclusionBundle(bundleJson);
// recordHash: the proof_record_hash YOU recomputed from the signed record,
// never the bundle's own record_hash.
const result = verifyBundleOffline(recordHash, bundle, doc);
// result.status: VERIFIED | VERIFIED_UNWITNESSED | FAILED; result.reasons: [{ code, detail }]
```

From the CLI:

```sh
intentrax verify-proof proof-export.json --trusted-keys keys.json \
  --tlog-trust transparency-log.json --tlog-bundle proof.tlog.json
```

The report gains a `transparency` block and a `TRANSPARENCY` assessment row. The table below shows what each outcome does.

| Outcome | Row | Exit |
|---|---|---|
| `VERIFIED` (witness quorum met) | `VERIFIED` | unchanged |
| `VERIFIED_UNWITNESSED` (quorum 0) | `INSUFFICIENT_EVIDENCE` | unchanged |
| `NOT_PRESENT` (no `--tlog-bundle`) | `NOT_ASSESSED`, "not logged" | unchanged |
| `FAILED`, quorum not met only | `INSUFFICIENT_EVIDENCE` | non-zero |
| `FAILED`, anything else | `FAILED` (verdict `VERIFICATION_FAILED`) | non-zero |

Without `--tlog-trust`, the report and exit code are exactly as before.

## What inclusion does and does not show

**It shows:**

- the record was in the log by the stated tree size;
- with witnesses, everyone who checks sees the same history.

**It does not show:**

- **When the record was logged.** That rests on the published maximum integration delay.
- **That the record's content is true.**

A record without a bundle is "not logged". It is never presented as logged.

## Conformance

`verifyBundleOffline` must give the same status and reason codes as the Go verifier for every case in `engine/internal/transparencylog/testdata/inclusion-bundle-vectors.v0.json`. The test `tlog/test/vectors.test.mjs` replays them.
