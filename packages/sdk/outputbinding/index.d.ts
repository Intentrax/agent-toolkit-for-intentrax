// Engine-computed output binding (spec 10). See README.md.
export type OutputBindingSource = "ENGINE_COMPUTED" | "PRODUCER_DECLARED_AT_ISSUANCE";
export declare const OUTPUT_BINDING_SOURCE_ENGINE_COMPUTED: "ENGINE_COMPUTED";
export declare const OUTPUT_BINDING_SOURCE_PRODUCER_DECLARED: "PRODUCER_DECLARED_AT_ISSUANCE";
export declare const OUTPUT_BINDING_STATEMENTS: Readonly<Record<OutputBindingSource, string>>;
export declare const ANSWER_CHECK_MATCH: "MATCH";
export declare const ANSWER_CHECK_MISMATCH: "MISMATCH";
export declare const QUOTE_CHECK_IN_ANSWER: "QUOTE_IN_ANSWER";
export declare const QUOTE_CHECK_NOT_IN_ANSWER: "QUOTE_NOT_IN_ANSWER";
export declare const QUOTE_CHECK_NOT_CHECKABLE: "NOT_CHECKABLE";

export interface SealedOutputBinding {
  readonly binding_source: OutputBindingSource;
  readonly content_hash: string;
  readonly hash_algorithm: "SHA-256";
  readonly normalization: "intentrax-content/1.0";
}
export interface AnswerCheck {
  readonly status: "MATCH" | "MISMATCH";
  readonly computed_content_hash: string;
  readonly sealed_content_hash: string;
  readonly binding_source: string;
}
export interface QuoteCheck {
  readonly status: "QUOTE_IN_ANSWER" | "QUOTE_NOT_IN_ANSWER" | "NOT_CHECKABLE";
  readonly reason?: string;
}

export declare function sealedOutputBinding(canonicalAEPJSON: string): { binding: SealedOutputBinding | null; invalid: string[] };
export declare function outputBindingStatement(binding: { readonly binding_source?: string } | null | undefined): string | null;
export declare function checkAnswerAgainstBinding(answer: string, binding: { readonly content_hash?: string; readonly binding_source?: string } | null | undefined): AnswerCheck;
export declare function checkQuoteInAnswer(answer: string, quote: string): "QUOTE_IN_ANSWER" | "QUOTE_NOT_IN_ANSWER";
export declare function checkAnswerAndQuote(
  binding: { readonly content_hash?: string; readonly binding_source?: string } | null | undefined,
  answer: string,
  quote?: string | null,
): { answer_check: AnswerCheck; quote_check: QuoteCheck | null };

export declare const INTENT_EXECUTE_REQUEST_SCHEMA_VERSION_V12: "intentrax.runtime.intent_execute.request/1.2";
export declare const INTENT_EXECUTE_MAX_REQUEST_BYTES_V12: 40960;
export declare const INTENT_EXECUTE_MAX_OUTPUT_TEXT_BYTES: 32768;
export interface IntentExecuteRequestV12 {
  schema_version: "intentrax.runtime.intent_execute.request/1.2";
  intent_id: string;
  tenant_id: string;
  action: string;
  idempotency_key: string;
  proof_chain_fixture_ref: string;
  output_text: string;
}
export declare function engineBindIntentExecuteOutput(request: Record<string, unknown>, outputText: string): IntentExecuteRequestV12;
export declare function isEngineHashableOutputText(value: unknown): boolean;
export declare function validateIntentExecuteRequestV12(request: unknown): string[];

export declare const SAVED_ANSWER_SCHEMA_VERSION: "intentrax.saved_answer/0.1";
export declare const SAVED_ANSWER_LINK_MAX_BYTES: 16384;
export declare const SAVED_ANSWER_VERIFY_BASE_URL: "https://verify.intentrax.com";
export interface SavedAnswer {
  readonly schema_version: "intentrax.saved_answer/0.1";
  readonly proof_id: string;
  readonly verify_url: string;
  readonly answer_text: string;
  readonly proof_export?: unknown;
}
export declare function isSafeProofId(value: unknown): boolean;
export declare function savedAnswerLink(proofId: string, answer: string, base?: string): string | null;
export declare function readSavedAnswerFragment(fragment: string): string | null;
export declare function buildSavedAnswer(input: { readonly proof_id: string; readonly answer_text: string; readonly proof_export?: unknown }): SavedAnswer | null;
export declare function chatAnswerRegionHTML(proofId: string, answer: string): string | null;
