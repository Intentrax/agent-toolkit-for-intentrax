// matchReceiptToRecord (docs/architecture/specs/01-admission-request-v1.1.md
// §8.5). Port of the Go verifier (offlineproof/receipt.go, PR #600).
//
// An MCP receipt reference (result._meta["com.intentrax/receipt"], schema
// intentrax.mcp.receipt_ref/0.1, written by the server) points at a proof.
// It is unauthenticated: anyone can write any _meta. Matching compares what
// the reference claims about the call with what the verified record seals:
// the arguments digest against arguments_hash, the tool name, and the tool
// manifest digest when the reference states one. The outcome is CONSISTENT,
// INCONSISTENT or WITHHELD; it is never a verdict and never changes one.

import { goStringFields } from "./disclosures.mjs";

export const RECEIPT_REF_SCHEMA = "intentrax.mcp.receipt_ref/0.1";
export const RECEIPT_MATCH = Object.freeze({
  CONSISTENT: "CONSISTENT",
  INCONSISTENT: "INCONSISTENT",
  // The record seals the tool and arguments hash as a commitment (COMMITTED
  // disclosure), so they cannot be compared publicly.
  WITHHELD: "WITHHELD",
});

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const REF_STRINGS = ["schema", "tool_name", "arguments_digest", "tool_manifest_digest"];

// matchReceiptToRecord compares a receipt reference (a parsed JSON value)
// with the admission binding of a verified record (null when the record has
// none). Returns {status, mismatches?}; mismatches is present only when
// INCONSISTENT.
export function matchReceiptToRecord(receiptRef, admission) {
  // Read as the Go verifier's json.Unmarshal into string fields does
  // (member names ignore case, the last match wins, null is skipped, any
  // other non-string is an error).
  const ref = isObject(receiptRef) ? goStringFields(receiptRef, REF_STRINGS) : null;
  if (ref === null || ref.typeError || ref.values.schema !== RECEIPT_REF_SCHEMA) {
    return { status: RECEIPT_MATCH.INCONSISTENT, mismatches: ["schema"] };
  }
  const text = (k) => ref.values[k];
  // Only an admission decision record seals the call a receipt names.
  if (admission === null || admission === undefined) return { status: RECEIPT_MATCH.INCONSISTENT, mismatches: ["admission_binding"] };
  if (!isObject(admission.tool) || typeof admission.arguments_hash !== "string" || admission.arguments_hash === "") {
    return { status: RECEIPT_MATCH.WITHHELD };
  }
  const mismatches = [];
  if (text("tool_name") !== admission.tool.tool_name) mismatches.push("tool_name");
  if (text("arguments_digest") !== `sha256:${admission.arguments_hash}`) mismatches.push("arguments_digest");
  const manifest = text("tool_manifest_digest");
  if (manifest !== "" && manifest !== (admission.tool.tool_manifest_digest ?? "")) mismatches.push("tool_manifest_digest");
  return mismatches.length > 0 ? { status: RECEIPT_MATCH.INCONSISTENT, mismatches } : { status: RECEIPT_MATCH.CONSISTENT };
}
