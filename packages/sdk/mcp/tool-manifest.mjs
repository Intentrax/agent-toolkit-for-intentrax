// Tool-manifest pinning for MCP servers (R1b). Ported unchanged in behaviour
// from examples/mcp-trust-receipts/src/tool-manifest.mjs.
//
// WHAT A MANIFEST DIGEST SHOWS: the tool definitions a client received from
// `tools/list` at one moment were byte-for-byte (after canonicalization) the
// ones that were pinned. Nothing more.
//
// WHAT IT DOES NOT SHOW: that the server's code, its upstream APIs, or what a
// tool actually does at call time are unchanged. A server can keep an
// identical manifest and change its behaviour. A manifest digest detects
// "rug-pull" edits to descriptions, schemas and annotations — the text and
// hints the model and the host's permission UI act on — and nothing else.
//
// This module is pure: no I/O, no network, no clock. It signs nothing and
// asserts no verdict.

import { canonicalJson, domainDigest } from "./canonical.mjs";

export const TOOL_MANIFEST_PROFILE = "intentrax.mcp.tool_manifest/0.1";
export const TOOL_DIGEST_DOMAIN = "INTENTRAX_MCP_TOOL_DEFINITION_V0_1";
export const TOOL_MANIFEST_DIGEST_DOMAIN = "INTENTRAX_MCP_TOOL_MANIFEST_V0_1";

// `_meta` is excluded: the MCP spec reserves it for implementation metadata
// that servers may legitimately vary (trace ids, cache hints). Every other
// field, known or unknown, is included, so a field added by a future spec
// revision is covered by default instead of silently ignored.
export const EXCLUDED_TOOL_FIELDS = Object.freeze(["_meta"]);

// Field -> change category, used only to explain a diff. Unknown fields fall
// into "other".
const FIELD_CATEGORY = Object.freeze({
  name: "identity",
  title: "model_visible_text",
  description: "model_visible_text",
  inputSchema: "input_schema",
  outputSchema: "output_schema",
  annotations: "annotations",
  icons: "presentation",
  execution: "execution",
});

const TOOL_NAME_MAX = 128;

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

// normalizeToolDefinition -> the exact object that is hashed for one tool.
export function normalizeToolDefinition(tool) {
  if (!isPlainObject(tool)) {
    throw new Error("tool_manifest: tool definition must be an object");
  }
  if (typeof tool.name !== "string" || tool.name.length === 0 || tool.name.length > TOOL_NAME_MAX) {
    throw new Error("tool_manifest: tool name must be a non-empty string of at most " + TOOL_NAME_MAX + " characters");
  }
  // Null prototype: an own "__proto__" member (possible in JSON.parse output)
  // must be stored as data and hashed, not routed to the prototype setter.
  const normalized = Object.create(null);
  for (const key of Object.keys(tool)) {
    if (EXCLUDED_TOOL_FIELDS.includes(key)) continue;
    if (tool[key] === undefined) continue;
    normalized[key] = tool[key];
  }
  // Throws on anything non-canonical (NaN, functions, class instances).
  canonicalJson(normalized);
  return normalized;
}

export function toolDefinitionDigest(tool) {
  return domainDigest(TOOL_DIGEST_DOMAIN, normalizeToolDefinition(tool));
}

// toolManifestDigest(tools) — `tools` is the COMPLETE list across every
// `tools/list` page (follow `nextCursor` before calling this). Order does not
// matter; duplicate names are an error because a client cannot tell which
// definition the model will be shown.
export function toolManifestDigest(tools) {
  if (!Array.isArray(tools)) {
    throw new Error("tool_manifest: tools must be an array");
  }
  const entries = tools.map((tool) => ({ name: normalizeToolDefinition(tool).name, digest: toolDefinitionDigest(tool) }));
  const seen = new Set();
  for (const entry of entries) {
    if (seen.has(entry.name)) {
      throw new Error("tool_manifest: duplicate tool name " + JSON.stringify(entry.name));
    }
    seen.add(entry.name);
  }
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return {
    profile: TOOL_MANIFEST_PROFILE,
    excluded_fields: [...EXCLUDED_TOOL_FIELDS],
    tool_count: entries.length,
    tools: entries,
    manifest_digest: domainDigest(TOOL_MANIFEST_DIGEST_DOMAIN, { profile: TOOL_MANIFEST_PROFILE, tools: entries }),
  };
}

// A change that makes a tool look safer to the host's permission UI than it
// was when pinned. Annotations are untrusted hints, but hosts use them to
// decide what to auto-approve, so flipping them is the most security-relevant
// drift a manifest can show.
function annotationWeakenings(before, after) {
  const a = isPlainObject(before) ? before : {};
  const b = isPlainObject(after) ? after : {};
  const out = [];
  if (a.readOnlyHint !== true && b.readOnlyHint === true) out.push("readOnlyHint became true");
  if (a.destructiveHint !== false && b.destructiveHint === false) out.push("destructiveHint became false");
  if (a.idempotentHint !== true && b.idempotentHint === true) out.push("idempotentHint became true");
  if (a.openWorldHint !== false && b.openWorldHint === false) out.push("openWorldHint became false");
  return out;
}

// diffToolManifests(pinnedTools, currentTools) — explains drift between two
// complete tool lists. Returns { drift, manifest_digest_pinned,
// manifest_digest_current, added[], removed[], changed[] }.
export function diffToolManifests(pinnedTools, currentTools) {
  const pinned = toolManifestDigest(pinnedTools);
  const current = toolManifestDigest(currentTools);
  const pinnedByName = new Map(pinnedTools.map((tool) => [tool.name, normalizeToolDefinition(tool)]));
  const currentByName = new Map(currentTools.map((tool) => [tool.name, normalizeToolDefinition(tool)]));

  const added = [...currentByName.keys()].filter((name) => !pinnedByName.has(name)).sort();
  const removed = [...pinnedByName.keys()].filter((name) => !currentByName.has(name)).sort();
  const changed = [];
  for (const [name, before] of [...pinnedByName.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    const after = currentByName.get(name);
    if (!after) continue;
    const fields = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
    const changedFields = fields.filter((field) => {
      const x = field in before ? canonicalJson(before[field]) : null;
      const y = field in after ? canonicalJson(after[field]) : null;
      return x !== y;
    });
    if (changedFields.length === 0) continue;
    changed.push({
      name,
      fields: changedFields,
      categories: [...new Set(changedFields.map((field) => (Object.hasOwn(FIELD_CATEGORY, field) ? FIELD_CATEGORY[field] : "other")))].sort(),
      annotation_weakenings: annotationWeakenings(before.annotations, after.annotations),
    });
  }
  return {
    profile: TOOL_MANIFEST_PROFILE,
    drift: pinned.manifest_digest !== current.manifest_digest,
    manifest_digest_pinned: pinned.manifest_digest,
    manifest_digest_current: current.manifest_digest,
    added,
    removed,
    changed,
  };
}
