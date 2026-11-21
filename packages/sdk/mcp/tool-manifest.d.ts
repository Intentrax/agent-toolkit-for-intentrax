// Types for tool-manifest.mjs: MCP tool-manifest digests and drift diffs.
// A manifest digest shows the tools/list definitions matched a pin. It does
// not show that the server's code or behaviour is unchanged.

import type { JsonValue } from "./canonical.js";

export const TOOL_MANIFEST_PROFILE: "intentrax.mcp.tool_manifest/0.1";
export const TOOL_DIGEST_DOMAIN: "INTENTRAX_MCP_TOOL_DEFINITION_V0_1";
export const TOOL_MANIFEST_DIGEST_DOMAIN: "INTENTRAX_MCP_TOOL_MANIFEST_V0_1";
export const EXCLUDED_TOOL_FIELDS: readonly ["_meta"];

export type Digest = `sha256:${string}`;

/** An MCP Tool definition as received from tools/list (any extra fields are hashed too). */
export interface McpToolDefinition {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: { [key: string]: JsonValue };
  outputSchema?: { [key: string]: JsonValue };
  annotations?: {
    title?: string;
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
    [key: string]: JsonValue | undefined;
  };
  _meta?: { [key: string]: JsonValue };
  [key: string]: JsonValue | undefined;
}

export interface ManifestDigest {
  profile: typeof TOOL_MANIFEST_PROFILE;
  excluded_fields: string[];
  tool_count: number;
  tools: Array<{ name: string; digest: Digest }>;
  manifest_digest: Digest;
}

export type ChangeCategory =
  | "identity"
  | "model_visible_text"
  | "input_schema"
  | "output_schema"
  | "annotations"
  | "presentation"
  | "execution"
  | "other";

export interface ToolChange {
  name: string;
  fields: string[];
  categories: ChangeCategory[];
  /** e.g. "readOnlyHint became true": the tool now looks safer to a host's permission UI. */
  annotation_weakenings: string[];
}

export interface ManifestDiff {
  profile: typeof TOOL_MANIFEST_PROFILE;
  drift: boolean;
  manifest_digest_pinned: Digest;
  manifest_digest_current: Digest;
  added: string[];
  removed: string[];
  changed: ToolChange[];
}

/** The exact object hashed for one tool: every field except `_meta`. Throws on non-canonical input. */
export function normalizeToolDefinition(tool: McpToolDefinition): { [key: string]: JsonValue };
export function toolDefinitionDigest(tool: McpToolDefinition): Digest;
/** `tools` must be the COMPLETE list across every tools/list page. Duplicate names throw. */
export function toolManifestDigest(tools: McpToolDefinition[]): ManifestDigest;
export function diffToolManifests(pinnedTools: McpToolDefinition[], currentTools: McpToolDefinition[]): ManifestDiff;
