/// <reference types="node" />

export type JcsProfile = "JCS-ANY" | "JCS-INT";
export declare const PROFILE_ANY: "JCS-ANY";
export declare const PROFILE_INT: "JCS-INT";

export declare class JcsError extends Error {
  readonly path: string;
}

export type JsonValue = null | boolean | number | string | JsonValue[] | { [name: string]: JsonValue };
export type JsonInput = string | Uint8Array;

/** Strict JSON parse (duplicate names, lone surrogates, trailing data rejected; BOM stripped). */
export declare function parseJson(raw: JsonInput, profile?: JcsProfile): JsonValue;
/** RFC 8785 text of raw JSON. */
export declare function canonicalize(raw: JsonInput, profile?: JcsProfile): string;
/** RFC 8785 text of an in-memory JSON value. */
export declare function serialize(value: unknown, profile?: JcsProfile): string;
/** ECMAScript Number-to-String; -0 is "0". */
export declare function formatNumber(n: number, profile?: JcsProfile, path?: string): string;

export declare const SCHEMA_VERSION: "intentrax.signed_envelope/1.0";
export declare const SIGNING_PREFIX: "INTENTRAX_SIGNED_ENVELOPE_V1\n";
export declare const DOMAIN_ENVELOPE: "INTENTRAX_ENVELOPE_CONTENT_V1";
export declare const DOMAIN_FACT_COMMITMENT: "INTENTRAX_FACT_COMMITMENT_V0_1";
export declare const ALG_ED25519: "ED25519";
export declare const REVOCATION_KEY_COMPROMISE: "KEY_COMPROMISE";

export type KeyPurpose =
  | "AEP_RECORD"
  | "TENANT_KEY_DIRECTORY"
  | "CALLER_REQUEST"
  | "APPROVER"
  | "APPROVAL_SERVICE"
  | "EXECUTOR_ATTESTATION"
  | "EFFECT_VERIFIER";
export declare const PURPOSE: Readonly<{ [P in KeyPurpose]: P }>;

export type EnvelopeCode =
  | "ENVELOPE_MALFORMED"
  | "ENVELOPE_PAYLOAD_SCHEMA_MISMATCH"
  | "ENVELOPE_SIGNING_TIME_INVALID"
  | "ENVELOPE_SIGNATURE_INVALID"
  | "SIGNER_NOT_PINNED"
  | "SIGNER_KEY_MISMATCH"
  | "SIGNER_PURPOSE_MISMATCH"
  | "SIGNER_KEY_NOT_VALID_AT_SIGNING_TIME"
  | "SIGNER_KEY_REVOKED"
  | "ENVELOPE_PAYLOAD_TYPE_UNEXPECTED"
  | "COMMITMENT_MISMATCH"
  | "COMMITMENT_OPENING_MALFORMED";
export declare const CODE: Readonly<{
  MALFORMED: "ENVELOPE_MALFORMED";
  SCHEMA_MISMATCH: "ENVELOPE_PAYLOAD_SCHEMA_MISMATCH";
  SIGNING_TIME_INVALID: "ENVELOPE_SIGNING_TIME_INVALID";
  SIGNATURE_INVALID: "ENVELOPE_SIGNATURE_INVALID";
  SIGNER_NOT_PINNED: "SIGNER_NOT_PINNED";
  SIGNER_KEY_MISMATCH: "SIGNER_KEY_MISMATCH";
  SIGNER_PURPOSE_MISMATCH: "SIGNER_PURPOSE_MISMATCH";
  SIGNER_KEY_NOT_VALID_AT_TIME: "SIGNER_KEY_NOT_VALID_AT_SIGNING_TIME";
  SIGNER_KEY_REVOKED: "SIGNER_KEY_REVOKED";
  PAYLOAD_TYPE_UNEXPECTED: "ENVELOPE_PAYLOAD_TYPE_UNEXPECTED";
  COMMITMENT_MISMATCH: "COMMITMENT_MISMATCH";
  COMMITMENT_OPENING_MALFORMED: "COMMITMENT_OPENING_MALFORMED";
}>;

export type Authenticity = "TRUSTED" | "NOT_PINNED" | "FAILED";
export declare const AUTHENTICITY: Readonly<{ TRUSTED: "TRUSTED"; NOT_PINNED: "NOT_PINNED"; FAILED: "FAILED" }>;

export declare class EnvelopeError extends Error {
  readonly code: EnvelopeCode;
  readonly reason: string;
}
export declare function codeOf(err: unknown): EnvelopeCode | "";

/** D(domain, value) = SHA-256(UTF-8(domain) || JCS(value)), 64 lowercase hex. value must be an object. */
export declare function digest(domain: string, value: JsonInput | object, profile?: JcsProfile): string;
/** 64 lowercase hex digits, not one repeated digit. */
export declare function validHash(s: unknown): boolean;
/** Spec 00 §6 timestamp → nanoseconds since the Unix epoch. Throws on anything else. */
export declare function parseTime(s: string): bigint;
/** Throws EnvelopeError (COMMITMENT_*) unless the opening matches. */
export declare function verifyCommitment(commitment: string, opening: JsonInput | object): void;

export interface EnvelopeSignature {
  alg: "ED25519";
  keyId: string;
  keyVersion: string;
  publicKeyHex: string;
  signatureHex: string;
}

export interface ParsedEnvelope {
  payloadType: string;
  payload: { [name: string]: JsonValue };
  /** JCS-INT text of the payload. */
  payloadJcs: string;
  signature: EnvelopeSignature;
  /** Exact signed bytes, rebuilt from payload_type and payload. */
  message: Buffer;
  /** D("INTENTRAX_ENVELOPE_CONTENT_V1", {payload, payload_type}); independent of signatures. */
  envelopeHash: string;
}
export declare function parseEnvelope(raw: JsonInput): ParsedEnvelope;

export interface PinnedKey {
  keyId: string;
  keyVersion: string;
  publicKeyHex: string;
  purpose: KeyPurpose | string;
  validFrom?: string | bigint;
  validUntil?: string | bigint;
  revokedAt?: string | bigint;
  revocationReason?: string;
}
export interface KeyResolver {
  resolveKey(keyId: string, keyVersion: string): (PinnedKey & { validFrom?: bigint; validUntil?: bigint; revokedAt?: bigint }) | undefined;
}
export declare function pinnedKeys(keys: readonly PinnedKey[]): KeyResolver;

export interface Expectation {
  payloadType: string;
  purpose: KeyPurpose | string;
  signingTimeField: string;
}

export interface VerifyResult {
  envelope: ParsedEnvelope;
  /** Signer's self-asserted signing time, nanoseconds since the epoch. */
  signedAt: bigint;
  signedAtText: string;
  /** The signature verifies under the key the envelope carries. */
  integrityOk: boolean;
  authenticity: Authenticity;
  /** Explains a NOT_PINNED or FAILED outcome; "" when trusted. */
  code: EnvelopeCode | "";
  /** integrityOk and a pinned key with the right purpose, valid at signedAt. */
  trusted: boolean;
}
export declare function verifyEnvelope(raw: JsonInput, want: Expectation, keys: KeyResolver): VerifyResult;
export declare function ed25519Verify(publicKeyHex: string, message: Uint8Array, signatureHex: string): boolean;
