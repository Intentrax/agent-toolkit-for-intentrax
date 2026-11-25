# `intentrax approve` (signed pre-approval, local)

Signs an `intentrax.approval/0.1` envelope (spec
`docs/architecture/specs/02-approval-record.md`) with a **local, human
`APPROVER` key** (identity method `TENANT_KEY`). Before anything is signed it
shows you the exact request:

- the tenant, server, tool, policy rule and constraint;
- amount, currency and payee/resource. These come from the tenant fact map
  when you pass `--fact-map`; otherwise they are picked by common argument
  names and labelled "detected by name";
- every argument value, one JSON Pointer per line, and the canonical
  (RFC 8785) bytes that `arguments_hash` covers. Non-ASCII, control and
  bidirectional characters are shown as `\uXXXX`, so a value cannot disguise
  itself;
- `admission_request_hash` and `arguments_hash`, both recomputed locally.

**Local only.** Nothing is sent anywhere. The signed approval and the openings
of its commitments are written to files. You attach the approval to the
resubmitted request yourself. Hosted submission comes later.

## Refused before signing

| Code | When |
| --- | --- |
| `ADMISSION_REQUEST_HASH_MISMATCH` | The request does not hash (spec 01 §3.2) to the pending approval request's hash, or to the hash on the command line |
| `ARGUMENTS_HASH_MISMATCH` | The arguments do not hash (spec 01 §4.1) to the request's or the approval request's `arguments_hash` |
| `ARGUMENTS_NOT_CANONICALISABLE` | Duplicate names, lone surrogates, non-finite numbers, or integers beyond ±(2^53−1). Same rule as the Go engine |
| `ARGUMENTS_REQUIRED` | No arguments to look at. You approve exact arguments, never a bare hash |
| `APPROVER_NOT_HUMAN`, `KEY_PURPOSE_MISMATCH` | The key is not a `HUMAN` `APPROVER` key (approvers are human-only in v0.1, spec 02 §2.1) |
| `APPROVER_IS_CALLER` | You are the request's caller principal (separation of duties) |
| `APPROVER_KEY_NOT_REGISTERED`, `DIRECTORY_INVALID` | The tenant key directory does not register this exact key for you |
| `APPROVER_KEY_REVOKED`, `APPROVER_KEY_RETIRED`, `APPROVER_KEY_NOT_VALID` | The directory revokes the key (at or before now, or ever for `KEY_COMPROMISE`), retires it (from `valid_until`, else `recorded_at`), or now is outside its `valid_from`/`valid_until` |
| `APPROVER_SET_NOT_IN_FORCE`, `APPROVER_NOT_AUTHORISED` | With `--approver-set`: the set is not the one in force, or it does not let you approve this constraint and policy with `TENANT_KEY` |
| `APPROVAL_REQUEST_EXPIRED`, `TENANT_MISMATCH`, `VALIDITY_INVALID` | As named. Validity defaults to 900 s; the hard cap is 86 400 s |

Without `--yes`, you confirm by typing the first 8 characters of
`arguments_hash`. Without a terminal and without `--yes`, nothing is signed.

The approval is `single_use: true` and expires at `not_after`. At execution,
the gate recomputes `arguments_hash` over what it actually sends and refuses
any difference (spec 01 §4.3). An approval therefore covers these exact
arguments only.

## Usage

```
node approve/cli.mjs keygen --tenant-id tenant-acme --principal-id approver:acme:7f3c \
  --key-id acme-approver-jlee-2026 --out ~/.intentrax/approver-key.json \
  --registration-out registration.json

node approve/cli.mjs --request envelope.json --approval-request pending.json \
  --key ~/.intentrax/approver-key.json --directory tenant-key-directory.json \
  [--approver-set approver-set.json] [--fact-map fact-map.json] [--reject --reason "..."] \
  --out approval.json
```

- `keygen` writes the private key file (mode 0600, never overwritten) and a
  public registration request. The registration request carries the proof of
  possession over `INTENTRAX_KEY_POP_V0_1\n || JCS({key, tenant_id})`.
- `--directory` is an `intentrax.trust.tenant_key_directory/0.1` snapshot. It
  gives the `envelope_hash` of your key's `REGISTER` entry, which the
  `subject_commitment` opens to, and the approver set in force.
- `--disclosures-out` (default `<out>.disclosures.json`) holds the commitment
  openings, as `COMMITMENT_OPENING` disclosures.

`intentrax approve` is a subcommand of the SDK CLI since `@intentrax/sdk`
1.10.0 (`npx @intentrax/sdk approve …`). From a checkout of this repository,
`node approve/cli.mjs` in `sdk/typescript` takes the same arguments.

## Tests

```
node --test approve/test/approve.test.mjs
```

They reproduce spec vector 02's `TENANT_KEY` approval and rejection
envelopes byte for byte from the vector 01 request, the vector 04 directory
and the publicly derivable vector key.
