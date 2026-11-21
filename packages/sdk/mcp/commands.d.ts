// Types for commands.mjs: `intentrax mcp pin` and `intentrax mcp check` as
// functions returning structured results plus exit codes.

import type { ClientOptions, ListedTools, ServerInput, ServerSpec } from "./client.js";
import type { Digest, McpToolDefinition, ToolChange, TOOL_MANIFEST_PROFILE } from "./tool-manifest.js";

export const PIN_FILE_SCHEMA: "intentrax.mcp.pin/0.1";
export const CHECK_REPORT_SCHEMA: "intentrax.mcp.check_report/0.1";
export const PIN_REPORT_SCHEMA: "intentrax.mcp.pin_report/0.1";
export const DEFAULT_PINS_PATH: ".intentrax/mcp-pins.json";
export const EXIT_MATCH: 0;
export const EXIT_USAGE: 1;
export const EXIT_UNCHECKED: 2;
export const EXIT_DRIFT: 10;
/** Fixed last line of every report. */
export const LIMITATION: "Covers tool definitions only. It does not show that the server's code or behaviour is unchanged.";
export const CLOAKING_NOTE: string;
export const UNSIGNED_NOTE: string;

export class PinFileError extends Error {
  constructor(code: "pins_missing" | "pins_invalid" | "pins_inconsistent" | "pins_ambiguous", message: string);
  readonly code: "pins_missing" | "pins_invalid" | "pins_inconsistent" | "pins_ambiguous";
}

/** One server in `.intentrax/mcp-pins.json` (assessment §5.A fields plus each tool's definition). */
export interface PinEntry {
  profile: typeof TOOL_MANIFEST_PROFILE;
  server: {
    registry_name?: string;
    transport: "stdio" | "streamable-http";
    url?: string;
    headers?: Record<string, string>;
    command?: string[];
    env?: Record<string, string>;
    cwd?: string;
    server_info?: { name?: string; version?: string };
  };
  protocol_version: string;
  manifest_digest: Digest;
  tools: Array<{ name: string; digest: Digest; definition: McpToolDefinition }>;
  pinned_at: string;
  pinned_by: "local";
}

export interface PinFile {
  schema: typeof PIN_FILE_SCHEMA;
  note?: string;
  servers: Record<string, PinEntry>;
}

export interface CommandResult<R extends string, Report> {
  exitCode: 0 | 1 | 2 | 10;
  result: R;
  /** Human report. Line 1 is the verdict (CHANGED / UNCHECKED / MATCH / PINNED / ...); the last line is LIMITATION. */
  lines: string[];
  /** --json report. */
  report: Report;
}

export interface CheckServerReport {
  name: string;
  result: "MATCH" | "CHANGED" | "UNCHECKED";
  server?: string;
  protocol_version?: string;
  pinned_at?: string;
  pinned_tool_count?: number;
  current_tool_count?: number;
  pages?: number;
  manifest_digest_pinned?: Digest;
  manifest_digest_current?: Digest;
  added?: string[];
  removed?: string[];
  changed?: ToolChange[];
  error?: string;
}

export interface CheckReport {
  schema: typeof CHECK_REPORT_SCHEMA;
  result: "MATCH" | "CHANGED" | "UNCHECKED" | "USAGE";
  exit_code?: number;
  pins?: string;
  servers?: CheckServerReport[];
  notes?: string[];
  limitation?: string;
  error?: string;
}

export interface CommandOptions extends Pick<ClientOptions, "timeoutMs" | "log" | "allowInsecureHttp"> {
  cwd?: string;
  env?: Record<string, string | undefined>;
  /** Injectable for tests; defaults to listServerTools. */
  listTools?: (spec: ServerSpec, options: ClientOptions) => Promise<ListedTools>;
}

/** exit 0 = match, 10 = drift (line 1 starts with "CHANGED"), 2 = could not check (fail closed), 1 = usage. */
export function check(options?: CommandOptions & { pins?: string; name?: string; server?: ServerInput }): Promise<CommandResult<"MATCH" | "CHANGED" | "UNCHECKED" | "USAGE", CheckReport>>;

export function pin(options?: CommandOptions & {
  server?: ServerInput;
  name?: string;
  out?: string;
  /** Re-pin only these tools (changed, new or removed), on purpose. */
  accept?: string[];
  /** Re-pin the whole server. */
  replace?: boolean;
  registryName?: string;
  now?: () => Date;
}): Promise<CommandResult<"PINNED" | "UNCHANGED" | "REPINNED" | "CHANGED" | "UNPINNED" | "USAGE", Record<string, unknown>> & { written: string | null }>;

export function validatePinEntry(name: string, entry: unknown): McpToolDefinition[];
export function loadPinFile(path: string): PinFile;
export function loadPinnedServer(pinsPath: string, name?: string): { name: string; entry: PinEntry; definitions: McpToolDefinition[]; spec: ServerSpec };
export function summarizeDiff(diff: { added: string[]; removed: string[]; changed: ToolChange[] }): string;
