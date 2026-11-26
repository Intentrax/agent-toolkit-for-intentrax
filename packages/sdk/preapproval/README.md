# Pre-approval verifier pieces (`sdk/typescript/preapproval`)

`verify-proof` support for specs 01–03 (`docs/architecture/specs/`, approved
2026-11-21 and amended 2026-11-22). It is a port of the Go offline verifier
(PR #564), with the same rules, invalid-field names, consistency codes,
reasons, limitation texts and statement wording.

| Module | What |
| --- | --- |
| `admission.mjs` | Strict parser for `aep.admission_binding` (`intentrax.aep.admission_binding/0.1`). Covers PLAINTEXT/COMMITTED, strict times, `execute_before` and `execute_recheck` (`intentrax.execute_recheck/0.1`, ADMITTED only), tool/server rules and the caller-statement envelope. Also `checkAdmissionConsistency` (spec 01 §8.2, 02 §5.1, 03 §6.2–§6.3), `decisionOutcome` and the statement in words |
| `policy-binding.mjs` | Strict parser for `policy_binding/1.2`: `ENFORCED`, `REJECTED`, the `ADMISSION` lane, request facts, withheld commitments, `fact_map_hash`. Also the ADMISSION-lane re-check event and profile, and the statement. 1.1 stays with verify-proof's existing parser, unchanged |
| `assessment.mjs` | The assessment for records carrying these members (rules below). For any other proof it equals `buildLegacyVerificationAssessment` exactly |

How the assessment behaves:
- An approval that is not verified never upgrades AUTHORIZATION. A 1.2 constraint whose approval was not checked is reported as `APPROVAL_EVIDENCE_NOT_SUPPLIED:<id>`.
- An authentic `ENFORCED` refusal is `VERIFIED`, never `CONTRADICTED`.
- A `DENIED` record has `decision_outcome: DENY`, and its execution and effect dimensions are `NOT_APPLICABLE`.
- An `ADMITTED` record carries `EXECUTE_RECHECK_NOT_ATTESTED`.

| `directory.mjs` | The tenant key directory (port of `trustlayer/tenantkeydir`, #558): strict entries, chain checks (signature, sequence, links, recorded_at, proof of possession, key lifecycle including the KEY_COMPROMISE-escalation-only rule), snapshots at a head, the approver set (strict decode, rules, hash) |
| `approvals.mjs` | The approval evidence re-check of spec 02 §5 (port of the Go verifier, #569). It matches attachments to the sealed `evidence_hash` and checks them in Go's order: record-only checks first, then directory trust (`PINNED_HEAD` or `VOUCHED_BY_INTENTRAX`), approver set, signer, human-only, authority, separation of duties and quorum. Outcomes are VERIFIED, NOT_SUPPLIED, NOT_RECHECKED or INVALID (AUTHORIZATION FAILED) |

| `disclosures.mjs` | The export's `attachments`/`disclosures` split off the lookup result (`result_hash` unchanged). Disclosed arguments are re-hashed and must equal the sealed or opened hash (fail closed). Also opens `tool_commitment`, withheld facts and the event salt (a bad opening fails closed), which makes the ADMISSION re-check run on withheld facts |
| `factmap.mjs` | Fact re-derivation (spec 03 §4.2, §6.5; port of Go #600). With disclosed arguments and a `FACT_MAP` that hashes to the sealed `fact_map_hash`, the request facts are re-derived from the arguments' JCS-ANY form and must equal the re-checked event: `FACTS_REDERIVED`, and `POLICY_FACTS_DERIVED_FROM_ADMITTED_ARGUMENTS` replaces `POLICY_EVENT_SELF_REPORTED`. Facts that do not re-derive fail closed. No map, another hash, or unopened withheld facts: nothing re-derived, nothing fails |
| `receipt.mjs` | `matchReceiptToRecord` (spec 01 §8.5; port of Go #600): an MCP receipt reference (`intentrax.mcp.receipt_ref/0.1`) against the sealed tool name, `arguments_hash` and tool manifest digest. `CONSISTENT`, `INCONSISTENT` (with the fields that differ) or `WITHHELD` (COMMITTED records); never a verdict |
| `keyset.mjs` | `published_key_set/1.2` key rules: purposes, strict windows, revocation consistency. `envelopeKeys(set, purpose)` pins envelope signers. AEP signers are pinned only by `AEP_RECORD` anchors (`SIGNER_PURPOSE_MISMATCH`) |

Since `@intentrax/sdk` 1.10.0, `intentrax verify-proof` uses these modules
(flags `--tenant-keys`, `--approver-set`, `--pin-directory-head`; see
`intentrax --help`). Since 1.12.0 it also re-derives policy facts from a
disclosed `FACT_MAP` and compares an MCP receipt reference given with
`--receipt-ref`. They load only when a proof, key set or flag needs them,
so copies of the CLI without this directory keep working on every other
proof. `test/verify-proof.test.mjs` runs the CLI end to end on
`test-fixtures/preapproval/`. Those exports were made by the engine's own
proof pipeline under sandbox keys and carry the spec vectors' sealed members.
Session B's shared Go↔TS fixture file will be replayed here once it exists.

```
node --test preapproval/test/bindings.test.mjs preapproval/test/assessment.test.mjs preapproval/test/approvals.test.mjs preapproval/test/disclosures.test.mjs preapproval/test/factmap.test.mjs preapproval/test/verify-proof.test.mjs
```
