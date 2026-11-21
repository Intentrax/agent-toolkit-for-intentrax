/// <reference types="node" />

export declare const INCLUSION_BUNDLE_FORMAT_V0: "intentrax.tlog.inclusion-bundle/v0";
export declare const TRUST_DOCUMENT_SCHEMA_V0: "intentrax.trust.transparency_log/0";
export declare const SIG_TYPE_ED25519: 1;
export declare const SIG_TYPE_COSIGNATURE_V1: 4;

export type TLogStatus = "VERIFIED" | "VERIFIED_UNWITNESSED" | "FAILED";
export declare const STATUS: Readonly<{ VERIFIED: "VERIFIED"; VERIFIED_UNWITNESSED: "VERIFIED_UNWITNESSED"; FAILED: "FAILED" }>;

export type TLogReasonCode =
  | "POLICY_INVALID"
  | "CHECKPOINT_MALFORMED"
  | "ORIGIN_MISMATCH"
  | "LOG_SIGNATURE_MISSING"
  | "LOG_SIGNATURE_INVALID"
  | "WITNESS_SIGNATURE_INVALID"
  | "WITNESS_QUORUM_NOT_MET"
  | "CHECKPOINT_STALE"
  | "PROOF_MALFORMED"
  | "PROOF_TREE_SIZE_MISMATCH"
  | "INCLUSION_ROOT_MISMATCH"
  | "RECORD_HASH_MISMATCH";
export declare const REASON: Readonly<Record<TLogReasonCode, TLogReasonCode>>;

export declare class TLogMalformedError extends Error {}

export interface VerifierKey {
  readonly name: string;
  readonly keyID: number;
  readonly type: 1 | 4;
  readonly publicKey: Buffer;
}

export interface InclusionBundle {
  readonly recordHash: Buffer;
  readonly leafIndex: number;
  readonly treeSize: number;
  readonly hashes: readonly Buffer[];
  readonly checkpoint: Buffer;
}

export interface TrustDocument {
  readonly origin: string;
  readonly logKey: VerifierKey;
  readonly witnesses: readonly VerifierKey[];
  readonly witnessQuorum: number;
  readonly maxIntegrationDelaySeconds: number;
}

export interface Reason {
  code: string;
  detail: string;
}

export interface WitnessResult {
  name: string;
  key_id: string;
  status: "VALID" | "MISSING" | "INVALID";
  timestamp?: number | string;
}

export interface InclusionResult {
  status: TLogStatus;
  ok: boolean;
  record_hash: string;
  leaf_index: number;
  tree_size: number;
  origin?: string;
  checkpoint_root?: string;
  inclusion: "PASS" | "FAIL" | "NOT_CHECKED";
  checkpoint: {
    ok: boolean;
    log_signature: "PASS" | "FAIL" | "NOT_CHECKED";
    witness_quorum: number;
    valid_witnesses: number;
    witnesses: WitnessResult[];
    unknown_signatures: number;
    reasons: Reason[];
  };
  reasons: Reason[];
}

export declare function leafHash(leaf: Uint8Array): Buffer;
export declare function nodeHash(left: Uint8Array, right: Uint8Array): Buffer;
export declare function emptyRoot(): Buffer;
export declare function recordLeaf(recordHash: Uint8Array): Buffer;
export declare function recordLeafHash(recordHash: Uint8Array): Buffer;
export declare function parseHashHex(value: string): Buffer;
export declare function rootFromInclusionProof(leafIndex: number, treeSize: number, leaf: Buffer, proof: readonly Buffer[]): Buffer;
export declare function verifyConsistency(first: number, second: number, firstRoot: Buffer, secondRoot: Buffer, proof: readonly Buffer[]): void;
export declare function keyID(name: string, sigType: number, publicKey: Uint8Array): number;
export declare function parseVerifierKey(value: string): VerifierKey;
export declare function verifierKeyString(key: VerifierKey): string;
export declare function parseNote(bytes: Uint8Array | string): { text: string; sigs: { name: string; keyID: number; sig: Buffer }[] };
export declare function parseCheckpoint(text: string): { origin: string; size: number; hash: Buffer };
export declare function parseInclusionBundle(input: string | Uint8Array): InclusionBundle;
export declare function parseTrustDocument(input: string | Uint8Array): TrustDocument;
export declare function trustDocumentPolicy(doc: TrustDocument): {
  origin: string;
  logKey: VerifierKey;
  witnesses: readonly VerifierKey[];
  witnessQuorum: number;
  allowUnwitnessed: boolean;
};
export declare function trustDocumentWire(doc: TrustDocument): {
  schema_version: "intentrax.trust.transparency_log/0";
  origin: string;
  log_key: string;
  witnesses: string[];
  witness_quorum: number;
  max_integration_delay_seconds: number;
};
export declare function verifyBundleOffline(recordHash: Buffer | string, bundle: InclusionBundle, trustDocument: TrustDocument): InclusionResult;

export declare const DIMENSION_TRANSPARENCY: "TRANSPARENCY";
export type TransparencyStatus = "VERIFIED" | "VERIFIED_UNWITNESSED" | "NOT_PRESENT" | "FAILED";
export declare const TRANSPARENCY: Readonly<Record<TransparencyStatus, TransparencyStatus>>;
export declare const TRANSPARENCY_LIMITATION_TEXT: Readonly<Record<"RECORD_NOT_SHOWN_LOGGED" | "LOG_CHECKPOINT_NOT_WITNESSED" | "LOG_INCLUSION_TIMING_NOT_PROVEN", string>>;

export interface TransparencyReport {
  status: TransparencyStatus;
  trust_document_hash: string;
  origin: string;
  witness_quorum: number;
  max_integration_delay_seconds: number;
  bundle_present: boolean;
  leaf_index?: number;
  tree_size?: number;
  checkpoint_root?: string;
  valid_witnesses: number;
  witnesses: WitnessResult[];
  reasons: Reason[];
}

export declare function transparencyReport(input: {
  proofRecordHash: string;
  trustDocument: string | Uint8Array;
  bundle?: string | Uint8Array | null;
}): TransparencyReport;

export declare function transparencyAssessment(tr: TransparencyReport): {
  dimension: "TRANSPARENCY";
  result: string;
  provenance: string | null;
  reasons: string[];
  limitations: string[];
};
