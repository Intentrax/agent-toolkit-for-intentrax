// Canonical JSON for MCP tool manifests (RFC 8785 / JCS profile).
//
// The SDK's `canonicalJson` (sdk/typescript/index.ts) accepts integers only,
// because every Intentrax-signed structure is integer-only. MCP tool
// definitions are third-party JSON Schema and routinely carry non-integer
// numbers (`"minimum": 0.5`), so this module uses the full RFC 8785 rule
// instead (this file is ported unchanged in behaviour from
// examples/mcp-trust-receipts/src/canonical.mjs):
//   - object keys sorted by UTF-16 code unit (JS default sort);
//   - no insignificant whitespace;
//   - strings via JSON.stringify (ES2019 well-formed escaping);
//   - numbers via the ECMAScript Number-to-String rule (JSON.stringify),
//     which is exactly the RFC 8785 number serialization; -0 becomes 0;
//   - NaN, Infinity, undefined, functions, symbols, bigint and non-plain
//     objects are rejected (fail closed: an unhashable manifest is an error,
//     never a silent partial digest).
//
// For integer-only input this produces the same bytes as the SDK rule.

import { createHash } from "node:crypto";

export function canonicalJson(value) {
  if (value === null) {
    return "null";
  }
  if (Array.isArray(value)) {
    return "[" + value.map((item) => canonicalJson(item)).join(",") + "]";
  }
  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        throw new Error("canonical_json: non-finite number");
      }
      return JSON.stringify(value === 0 ? 0 : value);
    case "object": {
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) {
        throw new Error("canonical_json: only plain objects are allowed");
      }
      return "{" + Object.keys(value).sort().map((key) => {
        const member = value[key];
        if (member === undefined) {
          throw new Error("canonical_json: undefined member " + JSON.stringify(key));
        }
        return JSON.stringify(key) + ":" + canonicalJson(member);
      }).join(",") + "}";
    }
    default:
      throw new Error("canonical_json: unsupported value of type " + typeof value);
  }
}

export function sha256Hex(data) {
  return createHash("sha256").update(data).digest("hex");
}

// Domain-separated digest: sha256(domain || canonical_json(value)), returned
// as "sha256:<hex>". The domain string stops a digest computed for one
// purpose being replayed as another (same pattern as the SDK's
// *_HASH_DOMAIN constants).
export function domainDigest(domain, value) {
  if (typeof domain !== "string" || domain.length === 0) {
    throw new Error("domain_digest: domain is required");
  }
  return "sha256:" + sha256Hex(Buffer.from(domain + canonicalJson(value), "utf8"));
}
