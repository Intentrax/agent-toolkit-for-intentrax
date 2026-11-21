// Types for proxy.mjs: the stdio MCP proxy that enforces a tool pin.

import type { ServerInput } from "./client.js";

/** JSON-RPC error code the proxy uses when it refuses a tools/call. */
export const PROXY_BLOCKED_CODE: -32090;
export const ON_DRIFT_MODES: readonly ["block", "warn"];

export interface ProxyOptions {
  /** Pin file (default .intentrax/mcp-pins.json, relative to cwd). */
  pins?: string;
  /** Pin entry name; optional when the file has one server. */
  name?: string;
  /** Upstream override; defaults to the pinned server spec. */
  server?: ServerInput;
  cwd?: string;
  /** "block" (default): hide changed/new tools and refuse calls to them. "warn": log only. */
  onDrift?: "block" | "warn";
  input?: NodeJS.ReadableStream;
  output?: NodeJS.WritableStream;
  /** Logs go here only (default process.stderr), never to `output`. */
  errorOutput?: { write(chunk: string | Uint8Array): unknown };
  env?: Record<string, string | undefined>;
  timeoutMs?: number;
  allowInsecureHttp?: boolean;
}

export interface ProxyState {
  onDrift: "block" | "warn";
  /** Latest definition seen on this connection per tool: matches the pin, or not. */
  observed: Map<string, "match" | "drift">;
  checks: number;
  lastCheck: "MATCH" | "CHANGED" | "UNCHECKED" | null;
  blockedCalls: string[];
  hostEra: "modern" | "legacy" | null;
}

export interface ProxyHandle {
  /** Resolves with the exit code: 0 when the host closes stdin, 2 when the pin or upstream is unusable, 1 on usage errors. */
  done: Promise<number>;
  state: ProxyState | null;
  close(): Promise<void>;
  recheck?(reason: string): Promise<void>;
}

export function startProxy(options?: ProxyOptions): Promise<ProxyHandle>;
export function runProxy(options?: ProxyOptions): Promise<number>;
