// Types for receipt-meta.mjs: unauthenticated receipt references in
// CallToolResult._meta["com.intentrax/receipt"]. A reference is a claim to
// check, never evidence.

import type { JsonValue } from "./canonical.js";
import type { Digest } from "./tool-manifest.js";

export const RECEIPT_META_KEY: "com.intentrax/receipt";
export const RECEIPT_REF_SCHEMA: "intentrax.mcp.receipt_ref/0.1";
export const ARGUMENTS_DIGEST_DOMAIN: "INTENTRAX_MCP_TOOL_ARGUMENTS_V0_1";
export const DEFAULT_VERIFY_HOSTS: readonly string[];
export const RECEIPT_LIMITATIONS: readonly string[];

export interface ReceiptRef {
  schema: typeof RECEIPT_REF_SCHEMA;
  proof_id: string;
  verify_url: string;
  record_kind: "decision_record";
  tool_name: string;
  arguments_digest: Digest;
  tool_manifest_digest?: Digest;
  limitations: string[];
}

export interface CallToolResultLike {
  content: Array<{ [key: string]: JsonValue }>;
  structuredContent?: { [key: string]: JsonValue };
  isError?: boolean;
  _meta?: { [key: string]: JsonValue };
  [key: string]: JsonValue | undefined;
}

export type ReadReceiptResult =
  | { status: "ABSENT" }
  | { status: "MALFORMED"; reasons: string[] }
  | { status: "UNVERIFIED_REFERENCE"; ref: ReceiptRef };

export function argumentsDigest(args: { [key: string]: JsonValue }): Digest;

export function buildReceiptRef(options: {
  proofId: string;
  verifyUrl: string;
  toolName: string;
  args: { [key: string]: JsonValue };
  toolManifestDigest?: Digest;
  allowedHosts?: readonly string[];
}): ReceiptRef;

/** Returns a NEW result; never changes content, structuredContent or isError; refuses to overwrite a receipt. */
export function attachReceiptMeta<T extends CallToolResultLike>(result: T, ref: ReceiptRef, options?: { resourceLink?: boolean }): T;

/** Client side. Never returns a "verified" state. */
export function readReceiptMeta(result: unknown, options?: { allowedHosts?: readonly string[] }): ReadReceiptResult;

/** Cheap local consistency check against the call the client made. A match proves nothing on its own. */
export function matchReceiptToCall(ref: ReceiptRef, call: { toolName: string; args: { [key: string]: JsonValue } }): {
  consistent: boolean;
  mismatches: Array<"tool_name" | "arguments_digest">;
};
