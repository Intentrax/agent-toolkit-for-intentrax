# Engine-computed output binding (`sdk/typescript/outputbinding`)

Spec 10 (`docs/architecture/specs/10-engine-computed-output-binding.md`).

A proof's signed AEP can seal `aep.output_binding`, the
`intentrax-content/1.0` hash of an answer. Its `binding_source` says who
computed that hash:

| `binding_source` | Meaning |
| --- | --- |
| `ENGINE_COMPUTED` | Intentrax hashed the answer text itself at issuance (execute request `/1.2`) |
| `PRODUCER_DECLARED_AT_ISSUANCE` | The company declared the hash; Intentrax never saw the text (`/1.1`) |

`OUTPUT_BINDING_STATEMENTS` says the same in words, byte for byte with the Go
offline verifier (`persistence.OutputBindingStatement`). A producer-declared
binding never reads as computed by Intentrax. A text match says the text is
the bound answer; it says nothing about whether the answer is correct.

| Export | What |
| --- | --- |
| `sealedOutputBinding(canonical_aep_json)` | Strict parser for the sealed member (mirrors Go `OutputBindingFromCanonicalAEP`). Call it only on signature-verified AEP bytes |
| `outputBindingStatement`, `checkAnswerAgainstBinding`, `checkQuoteInAnswer`, `checkAnswerAndQuote` | The statement and the answer and quote checks (`MATCH` / `MISMATCH`; `QUOTE_IN_ANSWER` / `QUOTE_NOT_IN_ANSWER`; `NOT_CHECKABLE` after a mismatch) |
| `engineBindIntentExecuteOutput`, `validateIntentExecuteRequestV12` | Execute request `/1.2` (`output_text`). The engine accepts it only while `output_binding_engine_computed_enabled` is on, which is off by default |
| `savedAnswerLink`, `readSavedAnswerFragment`, `buildSavedAnswer` | Saved answers: a link to the verify site's check page (`/verify/proof/{id}/check`) with the answer in the URL fragment (never sent to a server), or an `intentrax.saved_answer/0.1` file |
| `chatAnswerRegionHTML` | One answer as a convention v1.1 scoped region |

Tests: `node --test outputbinding/test/*.test.mjs`. They include the Go/TS
parity vector in `test-fixtures/output-binding/`: proofs signed by the
engine's own pipeline, and the values the Go verifier reports for them.

## In the SDK (1.11.0)

Shipped in `@intentrax/sdk` 1.11.0:

- the `./outputbinding` export;
- `verify-proof` reports `output_binding` and `output_binding_statement`
  whenever the signed AEP seals a binding (an out-of-contract binding fails
  closed, exit 2);
- `--answer-file <file>` and `--quote-file <file>` add `answer_check` and
  `quote_check`. A mismatch is status `ANSWER_MISMATCH` (exit 1, or 3 when the
  signers are not trusted either); a proof with no binding refuses
  `--answer-file`; a quote needs the answer;
- the console's vendored verifier carries `outputbinding/index.mjs`.

The optional `/1.2` acceptance in the main `validateIntentExecuteRequest`
(`index.js`) is not part of this release; use `validateIntentExecuteRequestV12`
from this module.
