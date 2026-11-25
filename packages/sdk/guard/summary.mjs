// What a guard record keeps about a tool call: a short, redacted summary for
// humans, and `arguments_hash` for machines.
//
// arguments_hash follows the published rule (docs/architecture/specs/
// 01-admission-request-v1.1.md §4):
//   hex(SHA-256("INTENTRAX_MCP_TOOL_ARGUMENTS_V0_1" || JCS(arguments)))
// computed here over Claude Code's `tool_input`. For an MCP tool that object
// is the `arguments` the server receives, so the value matches the SDK
// `mcp/` module's arguments_digest byte for byte. A later execute-time check
// can recompute it over the input actually executed.
//
// The summary never stores a whole tool input: commands are cut to 160
// characters after likely credentials are replaced with [redacted], file
// tools keep the path only, MCP tools keep the tool name only.

import { ARGUMENTS_DIGEST_DOMAIN } from "../mcp/receipt-meta.mjs";
import { domainDigest } from "../mcp/canonical.mjs";

export const ARGUMENTS_HASH_RULE = "spec-01-4:" + ARGUMENTS_DIGEST_DOMAIN;
const MAX = 160;

export function argumentsHash(toolInput) {
  try {
    return { hash: domainDigest(ARGUMENTS_DIGEST_DOMAIN, toolInput ?? {}).slice("sha256:".length), rule: ARGUMENTS_HASH_RULE };
  } catch {
    return { hash: null, rule: "ARGUMENTS_NOT_CANONICALISABLE" };
  }
}

const SECRET_NAME = "[A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|PWD|AUTH|CREDENTIAL|COOKIE|SESSION|PRIVATE)[A-Za-z0-9_]*";

export function redact(text) {
  return String(text)
    // NAME=value and NAME: value for secret-looking names
    .replace(new RegExp(`\\b(${SECRET_NAME})(\\s*[=:]\\s*)(?:(?:bearer|basic|token)\\s+)?("[^"]*"|'[^']*'|[^\\s'"]+)`, "gi"), "$1$2[redacted]")
    // --password x, --token=x, -p<pw> for db clients
    .replace(/(--?(?:password|passwd|token|api-key|apikey|secret|auth|key)(?:=|\s+))("[^"]*"|'[^']*'|\S+)/gi, "$1[redacted]")
    // Authorization / bearer headers
    .replace(/((?:authorization|x-api-key|api-key|cookie)\s*:\s*)(?:bearer\s+|basic\s+|token\s+)?("[^"]*"|'[^']*'|[^\s"']+)/gi, "$1[redacted]")
    .replace(/\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, "$1 [redacted]")
    // user:pass@ in URLs
    .replace(/(\b[a-z][a-z0-9+.-]*:\/\/)[^/\s:@]+:[^/\s@]+@/gi, "$1[redacted]@")
    // well-known key formats and long opaque strings
    .replace(/\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}\b/g, "[redacted]")
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abposr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})\b/g, "[redacted]")
    .replace(/\b[A-Za-z0-9+/_-]{40,}={0,2}/g, "[redacted]");
}

function clip(s) {
  const one = String(s).replace(/\s+/g, " ").trim();
  return one.length > MAX ? one.slice(0, MAX - 1) + "…" : one;
}

export function summarize(input) {
  const name = String(input?.tool_name ?? "");
  const i = input?.tool_input ?? {};
  if ((name === "Bash" || name === "PowerShell") && typeof i.command === "string") return clip(redact(i.command));
  for (const k of ["file_path", "notebook_path", "path"]) {
    if (typeof i[k] === "string") return clip(i[k]);
  }
  if (name.startsWith("mcp__")) return clip(name);
  if (typeof i.url === "string") return clip(redact(i.url.replace(/\?.*$/, "?…")));
  if (typeof i.pattern === "string") return clip(i.pattern);
  return clip(name);
}
