// `intentrax mcp proxy`: a stdio MCP proxy that enforces a tool pin (R1b).
//
//   host (stdio) <-> proxy <-> upstream server (stdio command or Streamable HTTP)
//
// It forwards JSON-RPC both ways and:
//   - re-checks the upstream tool list on connect (once the host's handshake
//     is done, on the host's own session, so it sees what the host is sent)
//     and on every `notifications/tools/list_changed`;
//   - compares every `tools/list` response the HOST receives, tool by tool,
//     against the pin. This is what defeats cloaking: the decision is made on
//     the exact definitions the host is about to show its model;
//   - onDrift "block": changed and new tools are removed from the host's
//     `tools/list`, and `tools/call` to any tool whose latest observed
//     definition is not the pinned one is refused with a clear JSON-RPC error.
//     While a re-check is running, calls wait for it. If the tools cannot be
//     listed, calls are refused (fail closed);
//   - onDrift "warn": forwards everything unchanged and only logs.
//
// Logs go to stderr only (`errorOutput`), never to the protocol stream.
// Messages from the host are re-serialized after parsing, so the upstream sees
// exactly what the proxy evaluated (no duplicate-key smuggling).
//
// Covers tool definitions only. It does not show that the server's code or
// behaviour is unchanged.

import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import { createLineSplitter, describeServer, listAllTools, McpClientError, META_PROTOCOL_VERSION, MODERN_PROTOCOL_VERSION, openTransport, parseServerSpec } from "./client.mjs";
import { DEFAULT_PINS_PATH, EXIT_UNCHECKED, EXIT_USAGE, LIMITATION, loadPinnedServer, summarizeDiff } from "./commands.mjs";
import { diffToolManifests, toolDefinitionDigest } from "./tool-manifest.mjs";

export const PROXY_BLOCKED_CODE = -32090;
export const ON_DRIFT_MODES = Object.freeze(["block", "warn"]);
const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_QUEUED_CALLS = 256;

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isResponse(message) {
  return isPlainObject(message) && typeof message.method !== "string" && Object.hasOwn(message, "id") && (Object.hasOwn(message, "result") || Object.hasOwn(message, "error"));
}

function isRequest(message) {
  return isPlainObject(message) && typeof message.method === "string" && Object.hasOwn(message, "id");
}

function idKey(id) {
  return typeof id + ":" + String(id);
}

function safeDigest(tool) {
  try {
    return toolDefinitionDigest(tool);
  } catch {
    return null;
  }
}

// startProxy(options) -> { done: Promise<exitCode>, state, close() }
//   options: { pins?, name?, server?, cwd?, onDrift?, input?, output?,
//              errorOutput?, env?, timeoutMs?, allowInsecureHttp? }
export async function startProxy(options = {}) {
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;
  const errorOutput = options.errorOutput ?? process.stderr;
  const onDrift = options.onDrift ?? "block";
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const cwd = options.cwd ?? process.cwd();
  const pinsPath = resolve(cwd, options.pins ?? DEFAULT_PINS_PATH);
  const log = (line) => errorOutput.write("intentrax mcp proxy: " + line + "\n");
  const finished = (exitCode) => ({ done: Promise.resolve(exitCode), state: null, close: async () => {} });

  if (!ON_DRIFT_MODES.includes(onDrift)) {
    log("USAGE --on-drift must be block or warn");
    return finished(EXIT_USAGE);
  }

  let pinned = null;
  try {
    pinned = loadPinnedServer(pinsPath, options.name);
  } catch (error) {
    if (onDrift === "block") {
      log("UNCHECKED cannot enforce a pin: " + error.message + " (refusing to start in block mode)");
      return finished(EXIT_UNCHECKED);
    }
    log("WARN no usable pin (" + error.message + "); forwarding everything and logging every tool as unpinned");
  }
  const pinName = pinned?.name ?? options.name ?? "server";
  let spec;
  try {
    spec = parseServerSpec(options.server ?? pinned?.spec);
  } catch (error) {
    log("USAGE " + (options.server === undefined && !pinned ? "--server is required without a pin" : error.message));
    return finished(EXIT_USAGE);
  }
  const pinnedDigests = new Map((pinned?.entry.tools ?? []).map((tool) => [tool.name, tool.digest]));
  const pinnedDefinitions = pinned?.definitions ?? [];

  let transport;
  try {
    transport = await openTransport(spec, {
      env: options.env ?? process.env,
      timeoutMs,
      allowInsecureHttp: options.allowInsecureHttp,
      stderr: (chunk) => errorOutput.write(chunk),
    });
  } catch (error) {
    log("UNCHECKED cannot start upstream " + describeServer(spec) + ": " + (error instanceof McpClientError ? error.message : "error"));
    return finished(EXIT_UNCHECKED);
  }
  log("proxying " + describeServer(spec) + " with pin " + JSON.stringify(pinName) + " (on drift: " + onDrift + ")");

  const state = {
    onDrift,
    observed: new Map(), // tool name -> "match" | "drift" (latest definition seen on this connection)
    checks: 0,
    lastCheck: null, // "MATCH" | "CHANGED" | "UNCHECKED"
    blockedCalls: [],
    hostEra: null, // "modern" | "legacy"
    hostMeta: null,
    legacyReady: false,
  };

  const ownPrefix = "intentrax-proxy-" + randomBytes(6).toString("hex") + "-";
  let ownNext = 1;
  const ownPending = new Map();
  const hostToolsList = new Set();
  let checking = null;
  let rerun = false;
  let closed = false;
  let resolveDone;
  const done = new Promise((resolveFn) => {
    resolveDone = resolveFn;
  });

  const writeHost = (message) => {
    if (!closed) output.write(JSON.stringify(message) + "\n");
  };
  const hostError = (id, code, message, data) => {
    const error = { code, message };
    if (data !== undefined) error.data = data;
    writeHost({ jsonrpc: "2.0", id, error });
  };

  // The proxy's own requests on the shared upstream connection.
  const ownClient = {
    request(method, params = {}) {
      const id = ownPrefix + ownNext++;
      const body = { ...params };
      if (state.hostEra === "modern" && state.hostMeta) body._meta = { ...state.hostMeta };
      return new Promise((resolveFn, reject) => {
        const timer = setTimeout(() => {
          ownPending.delete(id);
          reject(new McpClientError("timeout", method + " got no answer within " + timeoutMs + " ms"));
        }, timeoutMs);
        ownPending.set(id, { resolve: resolveFn, reject, timer, method });
        transport.send({ jsonrpc: "2.0", id, method, params: body }).catch((error) => {
          if (!ownPending.has(id)) return;
          ownPending.delete(id);
          clearTimeout(timer);
          reject(error instanceof McpClientError ? error : new McpClientError("transport_closed", "could not send " + method));
        });
      });
    },
  };

  function applyFullList(tools) {
    const observed = new Map();
    for (const tool of tools) {
      const digest = safeDigest(tool);
      observed.set(tool.name, digest !== null && pinnedDigests.get(tool.name) === digest ? "match" : "drift");
    }
    state.observed = observed;
  }

  // recheck(reason, after?) — `after` is a promise the check waits for first
  // (the forwarded notifications/initialized), so it is registered at once and
  // a tool call that arrives meanwhile waits for it.
  function recheck(reason, after = undefined) {
    if (checking) {
      rerun = true;
      return checking;
    }
    state.checks += 1;
    checking = (async () => {
      try {
        if (after) await after;
        const { tools, pages } = await listAllTools(ownClient, { timeoutMs });
        applyFullList(tools);
        let diff;
        try {
          diff = diffToolManifests(pinnedDefinitions, tools);
        } catch (error) {
          state.lastCheck = "UNCHECKED";
          state.observed = new Map();
          log("UNCHECKED " + pinName + " (" + reason + "): server tools cannot be hashed: " + error.message);
          return;
        }
        if (diff.drift) {
          state.lastCheck = "CHANGED";
          log("CHANGED " + pinName + " (" + reason + "): " + summarizeDiff(diff) + (onDrift === "block" ? " [changed and new tools are blocked]" : " [warn only]"));
        } else {
          state.lastCheck = "MATCH";
          log("MATCH " + pinName + " (" + reason + "): " + tools.length + " tools on " + pages + " page" + (pages === 1 ? "" : "s") + " match the pin");
        }
      } catch (error) {
        state.lastCheck = "UNCHECKED";
        // Fail closed: nothing counts as observed-matching until a list succeeds.
        state.observed = new Map();
        log("UNCHECKED " + pinName + " (" + reason + "): could not list tools: " + (error instanceof McpClientError ? error.message : "error") + (onDrift === "block" ? " [tool calls are refused until a list succeeds]" : ""));
      }
    })().finally(() => {
      checking = null;
      if (rerun && !closed) {
        rerun = false;
        recheck("tools changed during check");
      }
    });
    return checking;
  }

  async function settled() {
    while (checking) await checking;
  }

  function callVerdict(name) {
    if (!pinnedDigests.has(name)) return { allowed: false, reason: "not_pinned", text: "it is not in the pin" };
    // Fail closed: a host's tools/list page cannot vouch for a tool until the
    // proxy's own complete (all pages) listing has succeeded.
    // (Block mode always waits for a check, so lastCheck is never null there.)
    if (state.lastCheck === "UNCHECKED") {
      return { allowed: false, reason: "unchecked", text: "the server's complete tool list could not be checked against the pin" };
    }
    const seen = state.observed.get(name);
    if (seen === "match") return { allowed: true };
    if (seen === "drift") return { allowed: false, reason: "changed", text: "its definition changed since it was pinned" };
    return { allowed: false, reason: "unchecked", text: "its current definition has not been checked against the pin" };
  }

  let queuedCalls = 0;
  async function gateCall(message) {
    const name = isPlainObject(message.params) && typeof message.params.name === "string" ? message.params.name : "";
    if (onDrift === "block") {
      if (queuedCalls >= MAX_QUEUED_CALLS) {
        hostError(message.id, PROXY_BLOCKED_CODE, "Intentrax proxy: too many tool calls waiting for a tool check");
        return;
      }
      queuedCalls += 1;
      try {
        if (state.checks === 0) recheck("first tool call");
        await settled();
      } finally {
        queuedCalls -= 1;
      }
    }
    const verdict = callVerdict(name);
    if (verdict.allowed) {
      forward(message);
      return;
    }
    if (onDrift === "warn") {
      log("WARN tools/call " + JSON.stringify(name) + ": " + verdict.text + "; forwarded (warn mode)");
      forward(message);
      return;
    }
    state.blockedCalls.push(name);
    log("BLOCKED tools/call " + JSON.stringify(name) + ": " + verdict.text);
    hostError(
      message.id,
      PROXY_BLOCKED_CODE,
      "Intentrax proxy blocked tools/call " + JSON.stringify(name) + ": " + verdict.text + ". " +
        "A person can review the change and re-pin it with: intentrax mcp pin --name " + pinName + " --accept " + name,
      { intentrax: { reason: verdict.reason, tool: name, pin: pinName } },
    );
  }

  function forward(message) {
    transport.send(message).catch((error) => {
      if (isRequest(message)) {
        hostError(message.id, -32603, "Intentrax proxy: upstream unavailable (" + (error instanceof McpClientError ? error.message : "error") + ")");
      }
    });
  }

  function filterToolsList(message) {
    if (!isPlainObject(message.result) || !Array.isArray(message.result.tools)) return message;
    const kept = [];
    const hidden = [];
    for (const tool of message.result.tools) {
      const name = isPlainObject(tool) && typeof tool.name === "string" ? tool.name : null;
      const digest = name === null ? null : safeDigest(tool);
      const matches = digest !== null && pinnedDigests.get(name) === digest;
      if (name !== null) state.observed.set(name, matches ? "match" : "drift");
      if (matches) kept.push(tool);
      else hidden.push((name === null ? "(unnamed)" : JSON.stringify(name)) + (name !== null && pinnedDigests.has(name) ? " changed" : " new"));
    }
    if (hidden.length === 0) return message;
    if (onDrift === "warn") {
      log("WARN tools/list sent to the host includes tools that differ from the pin: " + hidden.join(", "));
      return message;
    }
    log("BLOCKED tools/list: hid " + hidden.join(", "));
    return { ...message, result: { ...message.result, tools: kept } };
  }

  function onHostMessage(message) {
    if (Array.isArray(message)) {
      hostError(null, -32600, "Intentrax proxy: JSON-RPC batches are not supported");
      return;
    }
    if (!isPlainObject(message) || message.jsonrpc !== "2.0") {
      hostError(null, -32600, "Intentrax proxy: invalid JSON-RPC message");
      return;
    }
    const params = isPlainObject(message.params) ? message.params : null;
    const meta = params && isPlainObject(params._meta) ? params._meta : null;
    let connectCheck = false;
    if (meta && meta[META_PROTOCOL_VERSION] === MODERN_PROTOCOL_VERSION) {
      const first = state.hostEra !== "modern";
      state.hostEra = "modern";
      const { progressToken, ...rest } = meta; // never reuse a host progress token
      state.hostMeta = rest;
      // A tools/call as the first message is gated (and starts the check) below.
      connectCheck = first && message.method !== "tools/call";
    }
    if (isRequest(message)) {
      if (message.method === "tools/call") {
        gateCall(message);
        return;
      }
      // Registered before forwarding, so the response is filtered even when
      // tools/list is a modern host's first message.
      if (message.method === "tools/list") hostToolsList.add(idKey(message.id));
      forward(message);
      if (connectCheck) recheck("connect");
      return;
    }
    if (connectCheck) {
      forward(message);
      recheck("connect");
      return;
    }
    if (message.method === "notifications/initialized" && state.hostEra !== "modern") {
      state.hostEra = "legacy";
      state.legacyReady = true;
      const sent = transport.send(message).catch(() => {});
      recheck("connect", sent);
      sent.then(() => transport.openNotificationStream?.());
      return;
    }
    forward(message);
  }

  function onUpstreamMessage(message) {
    if (Array.isArray(message)) {
      for (const item of message) onUpstreamMessage(item);
      return;
    }
    if (isResponse(message) && typeof message.id === "string" && message.id.startsWith(ownPrefix)) {
      const entry = ownPending.get(message.id);
      if (!entry) return;
      ownPending.delete(message.id);
      clearTimeout(entry.timer);
      if (Object.hasOwn(message, "error")) {
        const error = isPlainObject(message.error) ? message.error : {};
        entry.reject(new McpClientError("rpc_error", entry.method + " failed: " + (Number.isInteger(error.code) ? error.code + " " : "") + String(error.message ?? "error").slice(0, 200)));
      } else {
        entry.resolve(message.result);
      }
      return;
    }
    if (isResponse(message)) {
      const key = idKey(message.id);
      if (hostToolsList.delete(key)) {
        writeHost(filterToolsList(message));
        return;
      }
      writeHost(message);
      return;
    }
    if (isPlainObject(message) && message.method === "notifications/tools/list_changed") {
      writeHost(message);
      if (state.hostEra !== null) recheck("list_changed");
      return;
    }
    writeHost(message);
  }

  transport.onmessage = onUpstreamMessage;
  transport.onnoise = (kind) => log("ignored " + kind.replace(/_/g, " ") + " from the upstream server");

  async function close(exitCode = 0) {
    if (closed) return;
    closed = true;
    for (const entry of ownPending.values()) {
      clearTimeout(entry.timer);
      entry.reject(new McpClientError("transport_closed", "proxy closed"));
    }
    ownPending.clear();
    await transport.close().catch(() => {});
    log("stopped (" + state.checks + " check" + (state.checks === 1 ? "" : "s") + ", " + state.blockedCalls.length + " blocked call" + (state.blockedCalls.length === 1 ? "" : "s") + "). " + LIMITATION);
    resolveDone(exitCode);
  }

  transport.onclose = (info) => {
    if (closed) return;
    const detail = info && info.code !== null && info.code !== undefined ? " (exit code " + info.code + ")" : "";
    log("upstream closed" + detail);
    close(info && info.code ? EXIT_UNCHECKED : 0);
  };

  const split = createLineSplitter((line) => {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      hostError(null, -32700, "Intentrax proxy: parse error");
      return;
    }
    onHostMessage(message);
  }, { onOverflow: () => hostError(null, -32600, "Intentrax proxy: message too large") });
  input.on("data", split);
  input.on("end", () => close(0));
  input.on("close", () => close(0));

  return { done, state, close: () => close(0), recheck };
}

export async function runProxy(options = {}) {
  const proxy = await startProxy(options);
  return proxy.done;
}
