// Types for client.mjs: the minimal, dependency-free MCP client used by
// `intentrax mcp pin|check|proxy`.

import type { McpToolDefinition } from "./tool-manifest.js";

export const MODERN_PROTOCOL_VERSION: "2026-07-28";
export const LEGACY_PROTOCOL_VERSIONS: readonly ["2025-11-25", "2025-06-18", "2025-03-26"];
export const SUPPORTED_PROTOCOL_VERSIONS: readonly ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"];
export type ProtocolVersion = (typeof SUPPORTED_PROTOCOL_VERSIONS)[number];
export const DEFAULT_TIMEOUT_MS: number;
export const DEFAULT_DISCOVER_TIMEOUT_MS: number;
export const DEFAULT_MAX_PAGES: number;
export const MAX_MESSAGE_BYTES: number;
export const CLIENT_INFO: Readonly<{ name: string; version: string }>;
export const META_PROTOCOL_VERSION: "io.modelcontextprotocol/protocolVersion";
export const META_CLIENT_CAPABILITIES: "io.modelcontextprotocol/clientCapabilities";
export const META_CLIENT_INFO: "io.modelcontextprotocol/clientInfo";
export const META_SERVER_INFO: "io.modelcontextprotocol/serverInfo";

export type McpClientErrorCode =
  | "invalid_spec"
  | "env_missing"
  | "spawn_failed"
  | "transport_closed"
  | "unreachable"
  | "timeout"
  | "http_status"
  | "protocol"
  | "pagination"
  | "rpc_error"
  | "unsupported_version";

/** Messages never contain expanded ${ENV} values, URL queries, user-info or header values. */
export class McpClientError extends Error {
  constructor(code: McpClientErrorCode, message: string, details?: unknown);
  readonly code: McpClientErrorCode;
  readonly details?: { status?: number; rpc?: { code?: number; message?: string } };
}

/** UNEXPANDED server spec. `${NAME}` placeholders are expanded from the environment only when connecting. */
export type StdioServerSpec = { transport: "stdio"; command: string[]; env?: Record<string, string>; cwd?: string };
export type HttpServerSpec = { transport: "streamable-http"; url: string; headers?: Record<string, string> };
export type ServerSpec = StdioServerSpec | HttpServerSpec;
/** A URL, a command line, an argv array, or a spec object. */
export type ServerInput = string | string[] | ServerSpec | { url: string; headers?: Record<string, string> } | { command: string | string[]; env?: Record<string, string>; cwd?: string };

export interface ClientOptions {
  env?: Record<string, string | undefined>;
  timeoutMs?: number;
  discoverTimeoutMs?: number;
  protocolVersions?: readonly ProtocolVersion[];
  clientInfo?: { name: string; version: string };
  /** Diagnostics (never contain credentials). The CLI points this at stderr. */
  log?: (line: string) => void;
  /** Allow plain http:// to a non-loopback host. Default false. */
  allowInsecureHttp?: boolean;
  /** stdio server stderr: "ignore" (default), "inherit", or a sink. */
  stderr?: "ignore" | "inherit" | ((chunk: Buffer) => void);
  fetchImpl?: typeof fetch;
  maxPages?: number;
}

export function splitCommandLine(line: string): string[];
export function parseServerSpec(input: ServerInput): ServerSpec;
export function expandEnv(text: string, env?: Record<string, string | undefined>): string;
/** Log-safe description of an UNEXPANDED spec (query, user-info and secret-looking arguments redacted). */
export function describeServer(input: ServerInput): string;
/** Credentials that would be WRITTEN to a pin file (names only), plus warnings. */
export function findStoredSecrets(input: ServerInput): { problems: string[]; warnings: string[] };
export function createLineSplitter(onLine: (line: string) => void, options?: { maxBytes?: number; onOverflow?: () => void }): (chunk: string | Buffer) => void;

export interface Transport {
  readonly kind: "stdio" | "streamable-http";
  start(): Promise<void>;
  send(message: unknown): Promise<void>;
  close(): Promise<void>;
  onmessage: ((message: unknown) => void) | null;
  onclose: ((info: { code: number | null; signal: string | null; error?: string }) => void) | null;
  onnoise: ((kind: string) => void) | null;
  openNotificationStream?(): Promise<boolean>;
}
export class StdioTransport implements Transport {
  constructor(spec: StdioServerSpec, options?: ClientOptions);
  readonly kind: "stdio";
  start(): Promise<void>;
  send(message: unknown): Promise<void>;
  close(): Promise<void>;
  onmessage: ((message: unknown) => void) | null;
  onclose: ((info: { code: number | null; signal: string | null; error?: string }) => void) | null;
  onnoise: ((kind: string) => void) | null;
}
export class HttpTransport implements Transport {
  constructor(spec: HttpServerSpec, options?: ClientOptions);
  readonly kind: "streamable-http";
  readonly sessionId: string | null;
  readonly negotiatedVersion: string | null;
  start(): Promise<void>;
  send(message: unknown): Promise<void>;
  close(): Promise<void>;
  openNotificationStream(): Promise<boolean>;
  onmessage: ((message: unknown) => void) | null;
  onclose: ((info: { code: number | null; signal: string | null; error?: string }) => void) | null;
  onnoise: ((kind: string) => void) | null;
}
export function openTransport(input: ServerInput, options?: ClientOptions): Promise<Transport>;

export class McpClient {
  constructor(transport: Transport, options?: ClientOptions & { meta?: Record<string, unknown> });
  era: "modern" | "legacy" | null;
  protocolVersion: ProtocolVersion | null;
  serverInfo: { name?: string; version?: string; [key: string]: unknown } | null;
  serverCapabilities: Record<string, unknown> | null;
  request(method: string, params?: Record<string, unknown>, options?: { timeoutMs?: number; modern?: boolean }): Promise<any>;
  notify(method: string, params?: Record<string, unknown>): Promise<void>;
  onNotification(handler: (message: { method: string; params?: unknown }) => void): () => void;
  close(): Promise<void>;
}

/** 2026-07-28 `server/discover`, falling back to legacy `initialize`. */
export function connect(server: ServerInput, options?: ClientOptions): Promise<McpClient>;
/** Follows every nextCursor; a partial, looping or malformed list throws. */
export function listAllTools(client: Pick<McpClient, "request">, options?: { maxPages?: number; timeoutMs?: number }): Promise<{ tools: McpToolDefinition[]; pages: number }>;

export interface ListedTools {
  tools: McpToolDefinition[];
  pages: number;
  era: "modern" | "legacy";
  protocolVersion: ProtocolVersion;
  serverInfo: { name?: string; version?: string; [key: string]: unknown } | null;
}
export function listServerTools(server: ServerInput, options?: ClientOptions): Promise<ListedTools>;
