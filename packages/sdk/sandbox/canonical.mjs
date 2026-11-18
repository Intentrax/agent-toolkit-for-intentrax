// Canonical JSON + digests for the local assurance sandbox.
//
// Ported from examples/effect-assurance-demo/src/canonical.mjs (PRs #449,
// #477) without behavioural change. Same rule as `canonicalJson` in
// sdk/typescript/index.ts: object keys sorted by UTF-16 code unit, no
// whitespace, strings via JSON.stringify, integers only (no floats, NaN or
// Infinity), `undefined` rejected. Every signature and digest in the sandbox
// is computed over these bytes.

import { createHash } from "node:crypto";

export function canonicalJson(value) {
  if (value === null) {
    return "null";
  }
  if (Array.isArray(value)) {
    return "[" + value.map((item) => canonicalJson(item)).join(",") + "]";
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error("canonical_json: only safe integers are allowed");
    }
    return String(value);
  }
  if (typeof value === "object") {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      throw new Error("canonical_json: only plain objects are allowed");
    }
    return "{" + Object.keys(value).sort().map((key) => {
      const member = value[key];
      if (member === undefined) {
        throw new Error("canonical_json: undefined member " + key);
      }
      return JSON.stringify(key) + ":" + canonicalJson(member);
    }).join(",") + "}";
  }
  throw new Error("canonical_json: unsupported value of type " + typeof value);
}

export function sha256Hex(data) {
  return createHash("sha256").update(data).digest("hex");
}

// digest(value) -> "sha256:<hex>" over the canonical JSON bytes.
export function digest(value) {
  return "sha256:" + sha256Hex(Buffer.from(canonicalJson(value), "utf8"));
}

// True when `value` can be represented in canonical JSON.
export function isCanonicalizable(value) {
  try {
    canonicalJson(value);
    return true;
  } catch {
    return false;
  }
}
