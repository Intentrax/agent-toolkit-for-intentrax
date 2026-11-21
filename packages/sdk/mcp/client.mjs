// Minimal, dependency-free MCP client for R1b (`intentrax mcp pin|check|proxy`).
//
// It does exactly what pinning needs and nothing more:
//   - transports: stdio (spawn a command, newline-delimited JSON-RPC) and
//     Streamable HTTP (POST via fetch; JSON or SSE responses; optional GET
//     stream for server notifications);
//   - protocol: MCP 2026-07-28 via `server/discover` (stateless, `_meta` on
//     every request), falling back to the legacy `initialize` handshake for
//     2025-11-25, 2025-06-18 and 2025-03-26;
//   - `tools/list` following every `nextCursor` (a partial list is an error);
//   - a timeout on every request.
//
// Credentials: a server spec may carry `${ENV_VAR}` placeholders in the URL,
// headers, command arguments and env values. They are expanded only when the
// transport opens and are never written to logs, errors or pin files:
// describeServer() works on the UNEXPANDED spec and redacts query strings,
// URL user-info and secret-looking arguments.
//
// Nothing here writes to stdout. Diagnostics go through an optional `log`
// callback, which the CLI points at stderr.

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, statSync } from "node:fs";
import { basename, delimiter, extname, isAbsolute, join } from "node:path";

export const MODERN_PROTOCOL_VERSION = "2026-07-28";
export const LEGACY_PROTOCOL_VERSIONS = Object.freeze(["2025-11-25", "2025-06-18", "2025-03-26"]);
export const SUPPORTED_PROTOCOL_VERSIONS = Object.freeze([MODERN_PROTOCOL_VERSION, ...LEGACY_PROTOCOL_VERSIONS]);
export const DEFAULT_TIMEOUT_MS = 15_000;
export const DEFAULT_DISCOVER_TIMEOUT_MS = 5_000;
export const DEFAULT_MAX_PAGES = 100;
export const MAX_MESSAGE_BYTES = 16 * 1024 * 1024;
export const CLIENT_INFO = Object.freeze({ name: "intentrax-mcp-check", version: "0.1.0" });

export const META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion";
export const META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities";
export const META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo";
export const META_SERVER_INFO = "io.modelcontextprotocol/serverInfo";

const METHOD_NOT_FOUND = -32601;
const SENSITIVE_NAME = /(?:api[-_]?key|auth|cookie|password|passwd|private[-_]?key|secret|token|credential|session|bearer|signature|sig\b)/i;
const SECRET_PREFIX = /^(?:ghp_|gho_|ghs_|github_pat_|sk-|sk_live_|sk_test_|xox[abpr]-|AKIA|ya29\.|glpat-)/;
const PLACEHOLDER = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

export class McpClientError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = "McpClientError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function clip(text, max = 200) {
  const s = String(text);
  return s.length > max ? s.slice(0, max) + "…" : s;
}

// ---------------------------------------------------------------------------
// Server specs
// ---------------------------------------------------------------------------

// splitCommandLine("node server.mjs --flag 'a b'") -> ["node", "server.mjs", "--flag", "a b"].
// Plain quoting only: no globbing, no variable expansion, no operators.
export function splitCommandLine(line) {
  const out = [];
  let current = "";
  let quote = null;
  let started = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (quote) {
      if (ch === quote) quote = null;
      else if (ch === "\\" && quote === '"' && (line[i + 1] === '"' || line[i + 1] === "\\")) current += line[++i];
      else current += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      started = true;
    } else if (/\s/.test(ch)) {
      if (started) out.push(current);
      current = "";
      started = false;
    } else {
      current += ch;
      started = true;
    }
  }
  if (quote) throw new McpClientError("invalid_spec", "server command has an unterminated quote");
  if (started) out.push(current);
  return out;
}

// parseServerSpec(input) -> a normalized, UNEXPANDED spec:
//   { transport: "stdio", command: [file, ...args], env?: {}, cwd? }
//   { transport: "streamable-http", url, headers?: {} }
// `input` is a URL string, a command line string, an argv array, or a spec object.
export function parseServerSpec(input) {
  if (typeof input === "string") {
    const trimmed = input.trim();
    if (trimmed === "") throw new McpClientError("invalid_spec", "server is required");
    if (/^https?:\/\//i.test(trimmed)) return parseServerSpec({ transport: "streamable-http", url: trimmed });
    return parseServerSpec({ transport: "stdio", command: splitCommandLine(trimmed) });
  }
  if (Array.isArray(input)) return parseServerSpec({ transport: "stdio", command: input });
  if (!isPlainObject(input)) throw new McpClientError("invalid_spec", "server must be a command, a URL or a spec object");
  const transport = input.transport ?? (input.url !== undefined ? "streamable-http" : "stdio");
  if (transport === "stdio") {
    const command = typeof input.command === "string" ? splitCommandLine(input.command) : input.command;
    if (!Array.isArray(command) || command.length === 0 || !command.every((part) => typeof part === "string") || command[0] === "") {
      throw new McpClientError("invalid_spec", "stdio server needs a non-empty command");
    }
    const spec = { transport: "stdio", command: [...command] };
    if (input.env !== undefined) spec.env = stringMap(input.env, "env");
    if (input.cwd !== undefined) {
      if (typeof input.cwd !== "string" || input.cwd === "") throw new McpClientError("invalid_spec", "cwd must be a string");
      spec.cwd = input.cwd;
    }
    return spec;
  }
  if (transport === "streamable-http" || transport === "http") {
    if (typeof input.url !== "string" || !/^https?:\/\//i.test(input.url)) {
      throw new McpClientError("invalid_spec", "HTTP server needs an http(s) URL");
    }
    const spec = { transport: "streamable-http", url: input.url };
    if (input.headers !== undefined) spec.headers = stringMap(input.headers, "headers");
    return spec;
  }
  throw new McpClientError("invalid_spec", "unsupported transport " + JSON.stringify(clip(transport, 40)));
}

function stringMap(value, label) {
  if (!isPlainObject(value)) throw new McpClientError("invalid_spec", label + " must be an object of strings");
  const out = {};
  for (const key of Object.keys(value).sort()) {
    if (typeof value[key] !== "string") throw new McpClientError("invalid_spec", label + " values must be strings");
    out[key] = value[key];
  }
  return out;
}

// expandEnv("Bearer ${TOKEN}", env). A missing variable is an error that names
// the variable, never a value.
export function expandEnv(text, env = process.env) {
  return text.replace(PLACEHOLDER, (_, name) => {
    const value = env[name];
    if (typeof value !== "string" || value === "") {
      throw new McpClientError("env_missing", "environment variable " + name + " is not set");
    }
    return value;
  });
}

function hasPlaceholder(text) {
  PLACEHOLDER.lastIndex = 0;
  const found = PLACEHOLDER.test(text);
  PLACEHOLDER.lastIndex = 0;
  return found;
}

function looksSecret(arg) {
  if (hasPlaceholder(arg)) return false;
  if (SECRET_PREFIX.test(arg)) return true;
  return arg.length >= 24 && /^[A-Za-z0-9_\-+=.]+$/.test(arg) && /[0-9]/.test(arg) && /[A-Za-z]/.test(arg);
}

function redactArgs(args) {
  const out = [];
  let redactNext = false;
  for (const arg of args) {
    if (redactNext && !hasPlaceholder(arg)) {
      out.push("[redacted]");
      redactNext = false;
      continue;
    }
    redactNext = false;
    const eq = arg.indexOf("=");
    if (arg.startsWith("-") && eq > 0) {
      const flag = arg.slice(0, eq);
      const value = arg.slice(eq + 1);
      out.push(SENSITIVE_NAME.test(flag) || looksSecret(value) ? flag + "=[redacted]" : arg);
    } else if (arg.startsWith("-")) {
      out.push(arg);
      if (SENSITIVE_NAME.test(arg)) redactNext = true;
    } else {
      out.push(looksSecret(arg) ? "[redacted]" : arg);
    }
  }
  return out;
}

function redactUrl(raw) {
  let text = String(raw);
  const hadQuery = /[?#]/.test(text);
  text = text.replace(/[?#].*$/, "");
  text = text.replace(/^(https?:\/\/)[^@/]*@/i, "$1");
  return hadQuery ? text + "?[redacted]" : text;
}

// describeServer(spec) -> a short, log-safe description of an UNEXPANDED spec.
export function describeServer(specInput) {
  let spec;
  try {
    spec = parseServerSpec(specInput);
  } catch {
    return "[invalid server spec]";
  }
  if (spec.transport === "streamable-http") return redactUrl(spec.url);
  const [file, ...args] = spec.command;
  return [basename(file), ...redactArgs(args)].join(" ");
}

// Secrets that would be WRITTEN to a pin file: literal values in sensitive
// headers, env entries or URL query parameters, and URL user-info. Returns a
// list of problems (names only). Stdio arguments are only warned about, since
// they cannot be classified reliably.
export function findStoredSecrets(specInput) {
  const spec = parseServerSpec(specInput);
  const problems = [];
  const warnings = [];
  if (spec.transport === "streamable-http") {
    if (/^https?:\/\/[^/]*@/i.test(spec.url)) problems.push("URL user-info (user:password@)");
    const query = spec.url.includes("?") ? spec.url.slice(spec.url.indexOf("?") + 1).replace(/#.*$/, "") : "";
    for (const part of query.split("&").filter(Boolean)) {
      const [key, value = ""] = part.split("=");
      if ((SENSITIVE_NAME.test(key) || looksSecret(value)) && !hasPlaceholder(value)) problems.push("URL query parameter " + clip(key, 40));
    }
    for (const [key, value] of Object.entries(spec.headers ?? {})) {
      if (SENSITIVE_NAME.test(key) && !hasPlaceholder(value)) problems.push("header " + clip(key, 40));
    }
  } else {
    for (const [key, value] of Object.entries(spec.env ?? {})) {
      if ((SENSITIVE_NAME.test(key) || looksSecret(value)) && !hasPlaceholder(value)) problems.push("env " + clip(key, 40));
    }
    const redacted = redactArgs(spec.command.slice(1));
    if (redacted.some((arg) => arg.includes("[redacted]"))) warnings.push("a command argument looks like a credential; prefer ${ENV_VAR}");
  }
  return { problems, warnings };
}

// ---------------------------------------------------------------------------
// Line framing (stdio) and SSE parsing (HTTP)
// ---------------------------------------------------------------------------

export function createLineSplitter(onLine, { maxBytes = MAX_MESSAGE_BYTES, onOverflow } = {}) {
  let buffer = "";
  // One decoder for the whole stream: a multibyte UTF-8 character split across
  // two chunks is held back, not replaced with U+FFFD.
  const decoder = new TextDecoder("utf-8");
  return (chunk) => {
    buffer += typeof chunk === "string" ? chunk : decoder.decode(chunk, { stream: true });
    let index;
    while ((index = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, index).replace(/\r$/, "");
      buffer = buffer.slice(index + 1);
      if (line.trim() !== "") onLine(line);
    }
    if (buffer.length > maxBytes) {
      buffer = "";
      if (onOverflow) onOverflow();
    }
  };
}

async function readSse(body, onData, { maxBytes = MAX_MESSAGE_BYTES } = {}) {
  const decoder = new TextDecoder();
  let buffer = "";
  let data = [];
  let dataBytes = 0;
  const flushLine = (line) => {
    if (line === "") {
      if (data.length > 0) onData(data.join("\n"));
      data = [];
      dataBytes = 0;
      return;
    }
    if (line.startsWith(":")) return;
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "data") {
      dataBytes += value.length;
      if (dataBytes > maxBytes) throw new McpClientError("protocol", "SSE event exceeds the size limit");
      data.push(value);
    }
  };
  for await (const chunk of body) {
    buffer += decoder.decode(chunk, { stream: true });
    for (;;) {
      const match = /\r\n|\r|\n/.exec(buffer);
      if (!match) break;
      // A trailing "\r" may be the first half of "\r\n": wait for more bytes.
      if (match[0] === "\r" && match.index === buffer.length - 1) break;
      flushLine(buffer.slice(0, match.index));
      buffer = buffer.slice(match.index + match[0].length);
    }
    if (buffer.length > maxBytes) throw new McpClientError("protocol", "SSE line exceeds the size limit");
  }
  buffer += decoder.decode();
  if (buffer !== "") flushLine(buffer.replace(/\r$/, ""));
  flushLine("");
}

function isRequest(message) {
  return isPlainObject(message) && typeof message.method === "string" && Object.hasOwn(message, "id");
}

function isResponse(message) {
  return isPlainObject(message) && typeof message.method !== "string" && Object.hasOwn(message, "id") && (Object.hasOwn(message, "result") || Object.hasOwn(message, "error"));
}

function modernVersionOf(message) {
  const meta = isPlainObject(message) && isPlainObject(message.params) && isPlainObject(message.params._meta) ? message.params._meta : null;
  return meta && typeof meta[META_PROTOCOL_VERSION] === "string" ? meta[META_PROTOCOL_VERSION] : null;
}

// ---------------------------------------------------------------------------
// Transports. Interface: { kind, start(), send(message), close(), onmessage,
// onclose, onnoise }. send() throws McpClientError on transport failure.
// ---------------------------------------------------------------------------

function findOnPath(command, env) {
  const pathVar = env.PATH ?? env.Path ?? "";
  const exts = (env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean);
  const candidates = extname(command) ? [command] : exts.map((ext) => command + ext.toLowerCase());
  const dirs = isAbsolute(command) || command.includes("\\") || command.includes("/") ? [""] : pathVar.split(delimiter).filter(Boolean);
  for (const dir of dirs) {
    for (const candidate of candidates) {
      const full = dir === "" ? candidate : join(dir, candidate);
      try {
        if (existsSync(full) && statSync(full).isFile()) return full;
      } catch {
        // keep looking
      }
    }
  }
  return null;
}

// On Windows, npm-style shims (`npx`, `uvx.cmd`) are batch files that
// CreateProcess cannot start. They run through cmd.exe, with every argument
// checked for characters cmd.exe would interpret (fail closed, no injection).
function resolveSpawn(command, args, env) {
  if (process.platform !== "win32") return { file: command, args, options: {} };
  const resolved = findOnPath(command, env);
  if (!resolved || !/\.(cmd|bat)$/i.test(resolved)) return { file: resolved ?? command, args, options: {} };
  for (const arg of [resolved, ...args]) {
    if (/[&|<>^%!"\r\n]/.test(arg)) {
      throw new McpClientError("invalid_spec", "a command argument contains a character cmd.exe would interpret");
    }
  }
  const quote = (arg) => (arg === "" || /\s/.test(arg) ? '"' + arg + '"' : arg);
  const line = '"' + [resolved, ...args].map(quote).join(" ") + '"';
  return { file: env.ComSpec ?? "cmd.exe", args: ["/d", "/s", "/c", line], options: { windowsVerbatimArguments: true } };
}

export class StdioTransport {
  constructor(spec, { env = process.env, stderr = "ignore", maxBytes = MAX_MESSAGE_BYTES } = {}) {
    this.kind = "stdio";
    this.spec = spec;
    this.env = env;
    this.stderrMode = stderr;
    this.maxBytes = maxBytes;
    this.onmessage = null;
    this.onclose = null;
    this.onnoise = null;
    this.child = null;
    this.closed = false;
    this.exitInfo = null;
  }

  start() {
    const [command, ...rawArgs] = this.spec.command.map((part) => expandEnv(part, this.env));
    const extraEnv = {};
    for (const [key, value] of Object.entries(this.spec.env ?? {})) extraEnv[key] = expandEnv(value, this.env);
    const childEnv = { ...this.env, ...extraEnv };
    const { file, args, options } = resolveSpawn(command, rawArgs, childEnv);
    const stderrMode = typeof this.stderrMode === "function" ? "pipe" : this.stderrMode;
    return new Promise((resolve, reject) => {
      let child;
      try {
        child = spawn(file, args, {
          ...options,
          cwd: this.spec.cwd,
          env: childEnv,
          stdio: ["pipe", "pipe", stderrMode],
          shell: false,
          windowsHide: true,
        });
      } catch (error) {
        reject(new McpClientError("spawn_failed", "could not start the server command (" + clip(error.code ?? error.message, 60) + ")"));
        return;
      }
      this.child = child;
      let spawned = false;
      child.once("spawn", () => {
        spawned = true;
        resolve();
      });
      child.once("error", (error) => {
        if (!spawned) reject(new McpClientError("spawn_failed", "could not start the server command (" + clip(error.code ?? "error", 60) + ")"));
        this.#finish({ code: null, signal: null, error: error.code ?? "error" });
      });
      child.once("exit", (code, signal) => this.#finish({ code, signal }));
      child.stdin.on("error", () => {}); // EPIPE after exit: reported through "exit"
      if (typeof this.stderrMode === "function") {
        child.stderr.on("data", (chunk) => this.stderrMode(chunk));
      }
      const split = createLineSplitter((line) => this.#line(line), {
        maxBytes: this.maxBytes,
        onOverflow: () => this.onnoise?.("oversized_line"),
      });
      child.stdout.on("data", split);
    });
  }

  #line(line) {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      this.onnoise?.("non_json_line");
      return;
    }
    this.onmessage?.(message);
  }

  #finish(info) {
    if (this.closed) return;
    this.closed = true;
    this.exitInfo = info;
    this.onclose?.(info);
  }

  async send(message) {
    if (this.closed || !this.child || this.child.stdin.destroyed) {
      throw new McpClientError("transport_closed", "the server process is not running");
    }
    const text = JSON.stringify(message) + "\n";
    await new Promise((resolve, reject) => {
      this.child.stdin.write(text, (error) => (error ? reject(new McpClientError("transport_closed", "could not write to the server process")) : resolve()));
    });
  }

  async close() {
    const child = this.child;
    if (!child || this.closed) return;
    const exited = new Promise((resolve) => child.once("exit", resolve));
    const wait = (ms) => Promise.race([exited.then(() => true), new Promise((resolve) => setTimeout(() => resolve(false), ms).unref())]);
    try {
      child.stdin.end();
    } catch {
      // already closed
    }
    if (await wait(1_000)) return;
    child.kill();
    if (await wait(1_000)) return;
    child.kill("SIGKILL");
    await wait(1_000);
  }
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

export class HttpTransport {
  constructor(spec, { env = process.env, timeoutMs = DEFAULT_TIMEOUT_MS, fetchImpl = globalThis.fetch, allowInsecureHttp = false, maxBytes = MAX_MESSAGE_BYTES } = {}) {
    this.kind = "streamable-http";
    this.spec = spec;
    this.env = env;
    this.timeoutMs = timeoutMs;
    this.fetchImpl = fetchImpl;
    this.allowInsecureHttp = allowInsecureHttp;
    this.maxBytes = maxBytes;
    this.onmessage = null;
    this.onclose = null;
    this.onnoise = null;
    this.sessionId = null;
    this.negotiatedVersion = null;
    this.initializeIds = new Set();
    this.controllers = new Set();
    this.closed = false;
    this.description = describeServer(spec);
  }

  start() {
    const url = expandEnv(this.spec.url, this.env);
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      throw new McpClientError("invalid_spec", "server URL is not valid");
    }
    if (parsed.username !== "" || parsed.password !== "") {
      throw new McpClientError("invalid_spec", "server URL carries user-info; pass credentials in a header with ${ENV_VAR}");
    }
    if (parsed.protocol === "http:" && !LOOPBACK_HOSTS.has(parsed.hostname) && !this.allowInsecureHttp) {
      throw new McpClientError("invalid_spec", "plain http is only allowed for localhost; use https");
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new McpClientError("invalid_spec", "server URL must be http(s)");
    }
    this.url = parsed.toString();
    this.headers = {};
    for (const [key, value] of Object.entries(this.spec.headers ?? {})) this.headers[key] = expandEnv(value, this.env);
    return Promise.resolve();
  }

  #headersFor(message) {
    const headers = { ...this.headers, "content-type": "application/json", accept: "application/json, text/event-stream" };
    const modern = modernVersionOf(message);
    if (modern) {
      headers["mcp-protocol-version"] = modern;
      if (typeof message.method === "string") headers["mcp-method"] = message.method;
      const params = isPlainObject(message.params) ? message.params : {};
      if ((message.method === "tools/call" || message.method === "prompts/get") && typeof params.name === "string") headers["mcp-name"] = params.name;
      if (message.method === "resources/read" && typeof params.uri === "string") headers["mcp-name"] = params.uri;
    } else if (this.negotiatedVersion) {
      headers["mcp-protocol-version"] = this.negotiatedVersion;
    }
    if (this.sessionId) headers["mcp-session-id"] = this.sessionId;
    return headers;
  }

  #deliver(message, pendingIds) {
    if (Array.isArray(message)) {
      for (const item of message) this.#deliver(item, pendingIds);
      return;
    }
    if (isResponse(message)) {
      pendingIds?.delete(message.id);
      if (this.initializeIds.has(message.id)) {
        this.initializeIds.delete(message.id);
        if (isPlainObject(message.result) && typeof message.result.protocolVersion === "string") {
          this.negotiatedVersion = message.result.protocolVersion;
        }
      }
    }
    this.onmessage?.(message);
  }

  async #readText(response) {
    const reader = response.body?.getReader();
    if (!reader) return "";
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > this.maxBytes) {
        reader.cancel().catch(() => {});
        throw new McpClientError("protocol", "server response exceeds the size limit");
      }
      chunks.push(value);
    }
    return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8");
  }

  async send(message) {
    if (this.closed) throw new McpClientError("transport_closed", "the HTTP transport is closed");
    if (isRequest(message) && message.method === "initialize") this.initializeIds.add(message.id);
    const controller = new AbortController();
    this.controllers.add(controller);
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response;
    try {
      response = await this.fetchImpl(this.url, {
        method: "POST",
        headers: this.#headersFor(message),
        body: JSON.stringify(message),
        redirect: "error",
        signal: controller.signal,
      });
    } catch (error) {
      clearTimeout(timer);
      this.controllers.delete(controller);
      if (controller.signal.aborted && !this.closed) throw new McpClientError("timeout", "no HTTP response from " + this.description + " within " + this.timeoutMs + " ms");
      throw new McpClientError("unreachable", "could not reach " + this.description + " (" + clip(error?.cause?.code ?? error?.name ?? "fetch failed", 40) + ")");
    }
    const sid = response.headers.get("mcp-session-id");
    if (sid && isRequest(message) && message.method === "initialize") this.sessionId = sid;
    const contentType = (response.headers.get("content-type") ?? "").toLowerCase();
    const pendingIds = new Set(isRequest(message) ? [message.id] : []);
    try {
      if (response.status === 202 || response.status === 204) {
        clearTimeout(timer);
        await response.body?.cancel().catch(() => {});
        return;
      }
      if (response.ok && contentType.includes("text/event-stream")) {
        // The stream may legitimately stay open (server notifications); the
        // request-level timeout lives in McpClient, not here.
        clearTimeout(timer);
        this.#pump(response, controller, pendingIds, message);
        return;
      }
      const text = await this.#readText(response);
      clearTimeout(timer);
      let parsed = null;
      try {
        parsed = text === "" ? null : JSON.parse(text);
      } catch {
        parsed = null;
      }
      const isRpc = (value) => isPlainObject(value) && value.jsonrpc === "2.0";
      if (parsed !== null && (isRpc(parsed) || (Array.isArray(parsed) && parsed.every(isRpc)))) {
        this.#deliver(parsed, pendingIds);
        return;
      }
      if (!response.ok) {
        const hint = response.status === 404 && this.sessionId ? " (session expired)" : "";
        throw new McpClientError("http_status", "HTTP " + response.status + " from " + this.description + hint, { status: response.status });
      }
      if (isRequest(message)) throw new McpClientError("protocol", "server answered with a non-JSON-RPC body");
    } finally {
      if (!contentType.includes("text/event-stream")) this.controllers.delete(controller);
      clearTimeout(timer);
    }
  }

  #pump(response, controller, pendingIds, message) {
    readSse(response.body, (data) => {
      let parsed;
      try {
        parsed = JSON.parse(data);
      } catch {
        this.onnoise?.("non_json_event");
        return;
      }
      this.#deliver(parsed, pendingIds);
    }, { maxBytes: this.maxBytes })
      .catch(() => {})
      .finally(() => {
        this.controllers.delete(controller);
        if (!this.closed && pendingIds.size > 0 && isRequest(message)) {
          // The stream ended without answering: answer with an error so the
          // caller does not hang (a proxied host would otherwise wait forever).
          this.onmessage?.({ jsonrpc: "2.0", id: message.id, error: { code: -32603, message: "upstream stream ended without a response" } });
        }
      });
  }

  // Optional GET stream for server-initiated messages (legacy Streamable
  // HTTP). Returns true when a stream was opened; a 405 means the server has
  // none, which is allowed.
  async openNotificationStream() {
    if (this.closed) return false;
    const controller = new AbortController();
    this.controllers.add(controller);
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const headers = { ...this.headers, accept: "text/event-stream" };
      if (this.negotiatedVersion) headers["mcp-protocol-version"] = this.negotiatedVersion;
      if (this.sessionId) headers["mcp-session-id"] = this.sessionId;
      const response = await this.fetchImpl(this.url, { method: "GET", headers, redirect: "error", signal: controller.signal });
      clearTimeout(timer);
      if (!response.ok || !(response.headers.get("content-type") ?? "").toLowerCase().includes("text/event-stream")) {
        await response.body?.cancel().catch(() => {});
        this.controllers.delete(controller);
        return false;
      }
      this.#pump(response, controller, new Set(), null);
      return true;
    } catch {
      clearTimeout(timer);
      this.controllers.delete(controller);
      return false;
    }
  }

  async close() {
    if (this.closed) return;
    this.closed = true;
    for (const controller of this.controllers) controller.abort();
    this.controllers.clear();
    if (this.sessionId && this.url) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 2_000);
      try {
        const headers = { ...this.headers, "mcp-session-id": this.sessionId };
        if (this.negotiatedVersion) headers["mcp-protocol-version"] = this.negotiatedVersion;
        const response = await this.fetchImpl(this.url, { method: "DELETE", headers, redirect: "error", signal: controller.signal });
        await response.body?.cancel().catch(() => {});
      } catch {
        // best effort
      } finally {
        clearTimeout(timer);
      }
    }
    this.onclose?.({ code: null, signal: null });
  }
}

export async function openTransport(specInput, options = {}) {
  const spec = parseServerSpec(specInput);
  const transport = spec.transport === "stdio" ? new StdioTransport(spec, options) : new HttpTransport(spec, options);
  await transport.start();
  return transport;
}

// ---------------------------------------------------------------------------
// JSON-RPC client
// ---------------------------------------------------------------------------

export class McpClient {
  constructor(transport, { timeoutMs = DEFAULT_TIMEOUT_MS, clientInfo = CLIENT_INFO, log = () => {}, meta } = {}) {
    this.transport = transport;
    this.timeoutMs = timeoutMs;
    this.clientInfo = clientInfo;
    this.log = log;
    this.extraMeta = meta;
    this.era = null;
    this.protocolVersion = null;
    this.serverInfo = null;
    this.serverCapabilities = null;
    this.idPrefix = "intentrax-" + randomBytes(6).toString("hex") + "-";
    this.nextId = 1;
    this.pending = new Map();
    this.notificationHandlers = new Set();
    this.closeInfo = null;
    transport.onmessage = (message) => this.#dispatch(message);
    transport.onclose = (info) => this.#closed(info);
    transport.onnoise = (kind) => this.log("ignored " + kind.replace(/_/g, " ") + " from the server");
  }

  onNotification(handler) {
    this.notificationHandlers.add(handler);
    return () => this.notificationHandlers.delete(handler);
  }

  #closed(info) {
    this.closeInfo = info ?? {};
    const detail = info && info.code !== null && info.code !== undefined ? " (exit code " + info.code + ")" : info?.signal ? " (signal " + info.signal + ")" : "";
    for (const { reject, timer, method } of this.pending.values()) {
      clearTimeout(timer);
      reject(new McpClientError("transport_closed", "server closed the connection before answering " + method + detail));
    }
    this.pending.clear();
  }

  #dispatch(message) {
    if (Array.isArray(message)) {
      for (const item of message) this.#dispatch(item);
      return;
    }
    if (isResponse(message)) {
      const entry = this.pending.get(message.id);
      if (!entry) return;
      this.pending.delete(message.id);
      clearTimeout(entry.timer);
      if (Object.hasOwn(message, "error")) {
        const error = isPlainObject(message.error) ? message.error : {};
        entry.reject(new McpClientError("rpc_error", entry.method + " failed: " + (Number.isInteger(error.code) ? error.code + " " : "") + clip(error.message ?? "error"), { rpc: { code: error.code, message: clip(error.message ?? "") } }));
      } else {
        entry.resolve(message.result);
      }
      return;
    }
    if (isRequest(message)) {
      // Server -> client requests: answer ping, refuse everything else. This
      // client offers no sampling, roots or elicitation.
      const reply = message.method === "ping"
        ? { jsonrpc: "2.0", id: message.id, result: {} }
        : { jsonrpc: "2.0", id: message.id, error: { code: METHOD_NOT_FOUND, message: "Method not found" } };
      this.transport.send(reply).catch(() => {});
      return;
    }
    if (isPlainObject(message) && typeof message.method === "string") {
      for (const handler of this.notificationHandlers) {
        try {
          handler(message);
        } catch {
          // a handler failure must not break the client
        }
      }
    }
  }

  #withMeta(params, modern) {
    const base = isPlainObject(params) ? { ...params } : {};
    if (!modern) return base;
    const meta = isPlainObject(base._meta) ? { ...base._meta } : {};
    meta[META_PROTOCOL_VERSION] = MODERN_PROTOCOL_VERSION;
    if (!isPlainObject(meta[META_CLIENT_CAPABILITIES])) meta[META_CLIENT_CAPABILITIES] = {};
    if (!isPlainObject(meta[META_CLIENT_INFO])) meta[META_CLIENT_INFO] = { ...this.clientInfo };
    if (isPlainObject(this.extraMeta)) Object.assign(meta, this.extraMeta);
    base._meta = meta;
    return base;
  }

  request(method, params = {}, { timeoutMs = this.timeoutMs, modern = this.era === "modern" } = {}) {
    if (this.closeInfo) return Promise.reject(new McpClientError("transport_closed", "server connection is closed"));
    const id = this.idPrefix + this.nextId++;
    const message = { jsonrpc: "2.0", id, method, params: this.#withMeta(params, modern) };
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new McpClientError("timeout", method + " got no answer within " + timeoutMs + " ms"));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer, method });
      this.transport.send(message).catch((error) => {
        if (!this.pending.has(id)) return;
        this.pending.delete(id);
        clearTimeout(timer);
        reject(error instanceof McpClientError ? error : new McpClientError("transport_closed", "could not send " + method));
      });
    });
  }

  async notify(method, params = undefined) {
    const message = { jsonrpc: "2.0", method };
    if (params !== undefined) message.params = params;
    await this.transport.send(message);
  }

  async close() {
    for (const { reject, timer, method } of this.pending.values()) {
      clearTimeout(timer);
      reject(new McpClientError("transport_closed", "client closed before " + method + " was answered"));
    }
    this.pending.clear();
    await this.transport.close();
  }
}

// ---------------------------------------------------------------------------
// Connect (2026-07-28 discover, legacy initialize fallback) and list tools
// ---------------------------------------------------------------------------

const DISCOVER_FALLBACK_CODES = new Set(["rpc_error", "timeout", "http_status", "transport_closed", "protocol"]);

// connect(server, options) -> McpClient with era ("modern" | "legacy"),
// protocolVersion, serverInfo and serverCapabilities set.
export async function connect(server, options = {}) {
  const spec = parseServerSpec(server);
  const versions = options.protocolVersions ?? SUPPORTED_PROTOCOL_VERSIONS;
  for (const version of versions) {
    if (!SUPPORTED_PROTOCOL_VERSIONS.includes(version)) throw new McpClientError("invalid_spec", "unsupported protocol version " + clip(version, 20));
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const discoverTimeoutMs = options.discoverTimeoutMs ?? Math.min(timeoutMs, DEFAULT_DISCOVER_TIMEOUT_MS);
  const open = async () => new McpClient(await openTransport(spec, { ...options, timeoutMs }), { ...options, timeoutMs });
  let client = await open();
  try {
    if (versions.includes(MODERN_PROTOCOL_VERSION)) {
      try {
        const result = await client.request("server/discover", {}, { timeoutMs: discoverTimeoutMs, modern: true });
        if (isPlainObject(result) && Array.isArray(result.supportedVersions) && result.supportedVersions.includes(MODERN_PROTOCOL_VERSION)) {
          client.era = "modern";
          client.protocolVersion = MODERN_PROTOCOL_VERSION;
          const info = isPlainObject(result._meta) ? result._meta[META_SERVER_INFO] : undefined;
          client.serverInfo = isPlainObject(info) ? info : isPlainObject(result.serverInfo) ? result.serverInfo : null;
          client.serverCapabilities = isPlainObject(result.capabilities) ? result.capabilities : null;
          return client;
        }
        client.log("server/discover did not offer " + MODERN_PROTOCOL_VERSION + "; using initialize");
      } catch (error) {
        if (!(error instanceof McpClientError) || !DISCOVER_FALLBACK_CODES.has(error.code)) throw error;
        client.log("server/discover unavailable (" + error.code + "); using initialize");
        if (error.code === "transport_closed") {
          // The process died on an unknown method: start it once more.
          await client.close().catch(() => {});
          client = await open();
        }
      }
    }
    const legacy = LEGACY_PROTOCOL_VERSIONS.filter((version) => versions.includes(version));
    if (legacy.length === 0) throw new McpClientError("unsupported_version", "server does not support MCP " + MODERN_PROTOCOL_VERSION);
    const result = await client.request("initialize", {
      protocolVersion: legacy[0],
      capabilities: {},
      clientInfo: { ...client.clientInfo },
    }, { modern: false });
    if (!isPlainObject(result) || typeof result.protocolVersion !== "string") {
      throw new McpClientError("protocol", "initialize result has no protocolVersion");
    }
    if (!legacy.includes(result.protocolVersion)) {
      throw new McpClientError("unsupported_version", "server chose protocol version " + clip(result.protocolVersion, 20) + ", which this client does not support (supported: " + versions.join(", ") + ")");
    }
    client.era = "legacy";
    client.protocolVersion = result.protocolVersion;
    client.serverInfo = isPlainObject(result.serverInfo) ? result.serverInfo : null;
    client.serverCapabilities = isPlainObject(result.capabilities) ? result.capabilities : null;
    await client.notify("notifications/initialized");
    return client;
  } catch (error) {
    await client.close().catch(() => {});
    throw error;
  }
}

// listAllTools(client) -> { tools, pages }. Follows every nextCursor. Anything
// short of a complete, well-formed list is an error: pinning or checking a
// partial list would let a server hide a tool on a later page.
export async function listAllTools(client, { maxPages = DEFAULT_MAX_PAGES, timeoutMs } = {}) {
  const tools = [];
  const seenCursors = new Set();
  const names = new Set();
  let cursor;
  let pages = 0;
  for (;;) {
    pages += 1;
    if (pages > maxPages) throw new McpClientError("pagination", "tools/list returned more than " + maxPages + " pages");
    const params = cursor === undefined ? {} : { cursor };
    let result;
    try {
      result = await client.request("tools/list", params, timeoutMs === undefined ? {} : { timeoutMs });
    } catch (error) {
      if (pages > 1 && error instanceof McpClientError) {
        throw new McpClientError(error.code, "tools/list page " + pages + " failed, so the list is incomplete: " + error.message);
      }
      throw error;
    }
    if (!isPlainObject(result)) throw new McpClientError("protocol", "tools/list result is not an object");
    if (result.resultType !== undefined && result.resultType !== "complete") {
      throw new McpClientError("protocol", "tools/list result is not complete (resultType " + clip(String(result.resultType), 30) + ")");
    }
    if (!Array.isArray(result.tools)) throw new McpClientError("protocol", "tools/list result has no tools array");
    for (const tool of result.tools) {
      if (!isPlainObject(tool) || typeof tool.name !== "string" || tool.name === "") {
        throw new McpClientError("protocol", "tools/list returned a tool without a name");
      }
      if (names.has(tool.name)) throw new McpClientError("protocol", "tools/list returned the tool name " + JSON.stringify(clip(tool.name, 64)) + " twice");
      names.add(tool.name);
      tools.push(tool);
    }
    const next = result.nextCursor;
    if (next === undefined || next === null) break;
    if (typeof next !== "string" || next === "") throw new McpClientError("pagination", "tools/list returned an invalid nextCursor");
    if (seenCursors.has(next)) throw new McpClientError("pagination", "tools/list repeated a cursor (pagination loop)");
    seenCursors.add(next);
    cursor = next;
  }
  return { tools, pages };
}

// listServerTools(server, options) -> { tools, pages, era, protocolVersion, serverInfo }.
export async function listServerTools(server, options = {}) {
  const client = await connect(server, options);
  try {
    const { tools, pages } = await listAllTools(client, options);
    return { tools, pages, era: client.era, protocolVersion: client.protocolVersion, serverInfo: client.serverInfo };
  } finally {
    await client.close().catch(() => {});
  }
}
