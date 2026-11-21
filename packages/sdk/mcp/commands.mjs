// `intentrax mcp pin` and `intentrax mcp check` as functions (R1b).
//
// Each command returns { exitCode, result, lines, report } and never prints
// or exits: the CLI prints `lines` (or `report` with --json) and exits with
// `exitCode`.
//
//   check  exit 0  = every pinned server's tools match its pin      (MATCH)
//          exit 10 = drift; first line starts with "CHANGED"          (CHANGED)
//          exit 2  = could not check: tools not listable, pin file
//                    missing/invalid (fail closed)                     (UNCHECKED)
//          exit 1  = usage error
//   pin    exit 0  = pinned / already matching / accepted with no drift left
//          exit 10 = existing pin differs and was NOT re-pinned (or drift
//                    remains after --accept)
//          exit 2  = could not list tools, or the pin file is unreadable
//          exit 1  = usage error (bad name, credential in the spec, ...)
//
// The pin file (`.intentrax/mcp-pins.json`, schema intentrax.mcp.pin/0.1) is
// the user's own, UNSIGNED file. Each entry has the assessment §5.A fields
// plus each tool's normalized definition, so a later check can say which
// fields changed and not just that a digest differs. On load, every
// definition is re-hashed against its digest and the manifest digest, so a
// hand-edited entry is reported as inconsistent rather than trusted.

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import {
  TOOL_MANIFEST_PROFILE,
  diffToolManifests,
  normalizeToolDefinition,
  toolDefinitionDigest,
  toolManifestDigest,
} from "./tool-manifest.mjs";
import { McpClientError, describeServer, findStoredSecrets, listServerTools, parseServerSpec } from "./client.mjs";

export const PIN_FILE_SCHEMA = "intentrax.mcp.pin/0.1";
export const CHECK_REPORT_SCHEMA = "intentrax.mcp.check_report/0.1";
export const PIN_REPORT_SCHEMA = "intentrax.mcp.pin_report/0.1";
export const DEFAULT_PINS_PATH = ".intentrax/mcp-pins.json";

export const EXIT_MATCH = 0;
export const EXIT_USAGE = 1;
export const EXIT_UNCHECKED = 2;
export const EXIT_DRIFT = 10;

export const LIMITATION = "Covers tool definitions only. It does not show that the server's code or behaviour is unchanged.";
export const CLOAKING_NOTE =
  "This check sees the tools the server sent to this client. A server can send different tools to other clients (cloaking); " +
  "only a check made on the same connection as the host, such as `intentrax mcp proxy`, sees what the host is sent.";
export const UNSIGNED_NOTE = "Unsigned v0.1 pin file: it records what you approved locally; it is not a signed statement by anyone.";

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

export class PinFileError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PinFileError";
    this.code = code;
  }
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function isoSeconds(date) {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function plain(definition) {
  // normalizeToolDefinition returns a null-prototype object; store a plain copy.
  return JSON.parse(JSON.stringify(definition));
}

// ---------------------------------------------------------------------------
// Pin file
// ---------------------------------------------------------------------------

export function validatePinEntry(name, entry) {
  const where = "pin entry " + JSON.stringify(name);
  if (!NAME_RE.test(name)) throw new PinFileError("pins_invalid", where + " has an invalid name");
  if (!isPlainObject(entry)) throw new PinFileError("pins_invalid", where + " is not an object");
  if (entry.profile !== TOOL_MANIFEST_PROFILE) throw new PinFileError("pins_invalid", where + " has an unknown profile");
  if (!isPlainObject(entry.server)) throw new PinFileError("pins_invalid", where + " has no server");
  try {
    parseServerSpec(serverSpecOf(entry));
  } catch (error) {
    throw new PinFileError("pins_invalid", where + " has an invalid server spec: " + error.message);
  }
  if (typeof entry.manifest_digest !== "string" || !DIGEST_RE.test(entry.manifest_digest)) throw new PinFileError("pins_invalid", where + " has no manifest_digest");
  if (!Array.isArray(entry.tools)) throw new PinFileError("pins_invalid", where + " has no tools array");
  const definitions = [];
  for (const tool of entry.tools) {
    if (!isPlainObject(tool) || typeof tool.name !== "string" || typeof tool.digest !== "string" || !isPlainObject(tool.definition)) {
      throw new PinFileError("pins_invalid", where + " has a malformed tool");
    }
    let digest;
    try {
      if (tool.definition.name !== tool.name) throw new Error("name mismatch");
      digest = toolDefinitionDigest(tool.definition);
    } catch {
      throw new PinFileError("pins_inconsistent", where + ": tool " + JSON.stringify(tool.name) + " has an unusable definition");
    }
    if (digest !== tool.digest) {
      throw new PinFileError("pins_inconsistent", where + ": tool " + JSON.stringify(tool.name) + " definition does not match its digest (file edited?)");
    }
    definitions.push(tool.definition);
  }
  let manifest;
  try {
    manifest = toolManifestDigest(definitions);
  } catch (error) {
    throw new PinFileError("pins_inconsistent", where + ": " + error.message);
  }
  if (manifest.manifest_digest !== entry.manifest_digest) {
    throw new PinFileError("pins_inconsistent", where + ": manifest_digest does not match its tools (file edited?)");
  }
  return definitions;
}

export function loadPinFile(path) {
  if (!existsSync(path)) throw new PinFileError("pins_missing", "pin file not found: " + path);
  let doc;
  try {
    doc = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new PinFileError("pins_invalid", "pin file is not valid JSON: " + path);
  }
  if (!isPlainObject(doc) || doc.schema !== PIN_FILE_SCHEMA || !isPlainObject(doc.servers)) {
    throw new PinFileError("pins_invalid", "pin file is not " + PIN_FILE_SCHEMA + ": " + path);
  }
  return doc;
}

function serverSpecOf(entry) {
  const server = entry.server;
  if (server.transport === "streamable-http") {
    return { transport: "streamable-http", url: server.url, ...(server.headers ? { headers: server.headers } : {}) };
  }
  return { transport: "stdio", command: server.command, ...(server.env ? { env: server.env } : {}), ...(server.cwd ? { cwd: server.cwd } : {}) };
}

function storedServer(spec, { serverInfo, registryName }) {
  const server = {};
  if (registryName) server.registry_name = registryName;
  server.transport = spec.transport;
  if (spec.transport === "streamable-http") {
    server.url = spec.url;
    if (spec.headers) server.headers = spec.headers;
  } else {
    server.command = spec.command;
    if (spec.env) server.env = spec.env;
    if (spec.cwd) server.cwd = spec.cwd;
  }
  if (isPlainObject(serverInfo)) {
    const info = {};
    if (typeof serverInfo.name === "string") info.name = serverInfo.name.slice(0, 128);
    if (typeof serverInfo.version === "string") info.version = serverInfo.version.slice(0, 64);
    server.server_info = info;
  }
  return server;
}

function buildEntry({ server, definitions, protocolVersion, pinnedAt }) {
  const manifest = toolManifestDigest(definitions);
  const byName = new Map(definitions.map((definition) => [definition.name, plain(normalizeToolDefinition(definition))]));
  return {
    profile: TOOL_MANIFEST_PROFILE,
    server,
    protocol_version: protocolVersion,
    manifest_digest: manifest.manifest_digest,
    tools: manifest.tools.map((tool) => ({ name: tool.name, digest: tool.digest, definition: byName.get(tool.name) })),
    pinned_at: pinnedAt,
    pinned_by: "local",
  };
}

function writePinFile(path, doc) {
  const servers = {};
  for (const key of Object.keys(doc.servers).sort()) servers[key] = doc.servers[key];
  const out = { schema: PIN_FILE_SCHEMA, note: UNSIGNED_NOTE, servers };
  mkdirSync(dirname(path), { recursive: true });
  const tmp = path + "." + randomBytes(4).toString("hex") + ".tmp";
  writeFileSync(tmp, JSON.stringify(out, null, 2) + "\n", { encoding: "utf8", mode: 0o644 });
  renameSync(tmp, path);
}

// ---------------------------------------------------------------------------
// Report formatting
// ---------------------------------------------------------------------------

function describeChange(change) {
  const parts = [change.categories.join(", ")];
  if (change.annotation_weakenings.length > 0) parts.push(change.annotation_weakenings.join(", "));
  return change.name + " (" + parts.join("; ") + ")";
}

// One-line summary of a diff: "changed a (annotations; readOnlyHint became true); new b; removed c".
export function summarizeDiff(diff) {
  const parts = [];
  if (diff.changed.length > 0) parts.push("changed " + diff.changed.map(describeChange).join(", "));
  if (diff.added.length > 0) parts.push("new " + diff.added.join(", "));
  if (diff.removed.length > 0) parts.push("removed " + diff.removed.join(", "));
  return parts.join("; ");
}

function diffDetailLines(diff) {
  const lines = [];
  for (const change of diff.changed) {
    let line = "  changed  " + change.name + ": " + change.categories.join(", ") + " (fields: " + change.fields.join(", ") + ")";
    if (change.annotation_weakenings.length > 0) line += "; looks safer now: " + change.annotation_weakenings.join(", ");
    lines.push(line);
  }
  for (const name of diff.added) lines.push("  new      " + name + " (not in the pin)");
  for (const name of diff.removed) lines.push("  removed  " + name);
  return lines;
}

function driftedNames(diff) {
  return [...diff.changed.map((change) => change.name), ...diff.added, ...diff.removed].sort();
}

function errorText(error) {
  if (error instanceof McpClientError || error instanceof PinFileError) return error.message;
  return "unexpected error (" + (error?.name ?? "Error") + ")";
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

// check({ pins, name?, server?, cwd?, env?, timeoutMs?, listTools? })
export async function check(options = {}) {
  const cwd = options.cwd ?? process.cwd();
  const pinsPath = resolve(cwd, options.pins ?? DEFAULT_PINS_PATH);
  const listTools = options.listTools ?? listServerTools;
  const clientOptions = { env: options.env ?? process.env, timeoutMs: options.timeoutMs, log: options.log, allowInsecureHttp: options.allowInsecureHttp };

  let doc;
  try {
    doc = loadPinFile(pinsPath);
  } catch (error) {
    return unchecked([{ name: options.name ?? "*", error: errorText(error) }], pinsPath);
  }
  let names = Object.keys(doc.servers).sort();
  if (options.name !== undefined) {
    if (!Object.hasOwn(doc.servers, options.name)) {
      return unchecked([{ name: options.name, error: "no pin named " + JSON.stringify(options.name) + " in " + pinsPath }], pinsPath);
    }
    names = [options.name];
  }
  if (names.length === 0) return unchecked([{ name: "*", error: "the pin file has no servers" }], pinsPath);
  if (options.server !== undefined && names.length !== 1) {
    return usage("--server needs --name when the pin file has more than one server");
  }

  const servers = [];
  for (const name of names) {
    const entry = doc.servers[name];
    const item = { name, result: "UNCHECKED" };
    servers.push(item);
    let pinnedDefinitions;
    try {
      pinnedDefinitions = validatePinEntry(name, entry);
    } catch (error) {
      item.error = errorText(error);
      continue;
    }
    item.pinned_at = entry.pinned_at;
    item.manifest_digest_pinned = entry.manifest_digest;
    item.pinned_tool_count = pinnedDefinitions.length;
    let spec;
    try {
      spec = parseServerSpec(options.server ?? serverSpecOf(entry));
    } catch (error) {
      item.error = errorText(error);
      continue;
    }
    item.server = describeServer(spec);
    let listed;
    try {
      listed = await listTools(spec, clientOptions);
    } catch (error) {
      item.error = "could not list tools: " + errorText(error);
      continue;
    }
    let diff;
    try {
      diff = diffToolManifests(pinnedDefinitions, listed.tools);
    } catch (error) {
      item.error = "server tools cannot be hashed: " + clipText(error.message);
      continue;
    }
    item.protocol_version = listed.protocolVersion;
    item.manifest_digest_current = diff.manifest_digest_current;
    item.current_tool_count = listed.tools.length;
    item.pages = listed.pages;
    item.added = diff.added;
    item.removed = diff.removed;
    item.changed = diff.changed;
    item.result = diff.drift ? "CHANGED" : "MATCH";
  }
  return finishCheck(servers, pinsPath);
}

function clipText(text) {
  const s = String(text);
  return s.length > 200 ? s.slice(0, 200) + "…" : s;
}

function usage(message) {
  return { exitCode: EXIT_USAGE, result: "USAGE", lines: ["USAGE " + message], report: { schema: CHECK_REPORT_SCHEMA, result: "USAGE", error: message } };
}

function unchecked(items, pinsPath) {
  return finishCheck(items.map((item) => ({ ...item, result: "UNCHECKED" })), pinsPath);
}

function finishCheck(servers, pinsPath) {
  const changed = servers.filter((item) => item.result === "CHANGED");
  const failed = servers.filter((item) => item.result === "UNCHECKED");
  const matched = servers.filter((item) => item.result === "MATCH");
  // Drift outranks "could not check": both fail closed (non-zero), and the
  // drift is the finding a person must act on.
  const result = changed.length > 0 ? "CHANGED" : failed.length > 0 ? "UNCHECKED" : "MATCH";
  const exitCode = result === "CHANGED" ? EXIT_DRIFT : result === "UNCHECKED" ? EXIT_UNCHECKED : EXIT_MATCH;

  const lines = [];
  if (changed.length > 0) lines.push("CHANGED " + changed.map((item) => item.name + ": " + summarizeDiff(item)).join(" | "));
  if (failed.length > 0) lines.push("UNCHECKED " + failed.map((item) => item.name + ": " + item.error).join(" | "));
  if (matched.length > 0) {
    lines.push("MATCH " + matched.map((item) => item.name + ": " + item.current_tool_count + " tools match the pin from " + item.pinned_at).join(" | "));
  }
  for (const item of servers) {
    if (item.result === "UNCHECKED" && item.manifest_digest_pinned === undefined) continue;
    lines.push("server " + item.name + (item.server ? ": " + item.server : "") + (item.protocol_version ? " (MCP " + item.protocol_version + ")" : ""));
    if (item.manifest_digest_pinned) lines.push("  pinned   " + item.pinned_tool_count + " tools at " + item.pinned_at + ", " + item.manifest_digest_pinned);
    if (item.manifest_digest_current) lines.push("  current  " + item.current_tool_count + " tools, " + item.manifest_digest_current);
    if (item.result === "CHANGED") {
      lines.push(...diffDetailLines(item));
      lines.push("  to accept after review: intentrax mcp pin --name " + item.name + " --accept " + driftedNames(item).join(","));
    }
  }
  lines.push("note: " + CLOAKING_NOTE);
  lines.push(LIMITATION);
  return {
    exitCode,
    result,
    lines,
    report: { schema: CHECK_REPORT_SCHEMA, result, exit_code: exitCode, pins: pinsPath, servers, notes: [CLOAKING_NOTE], limitation: LIMITATION },
  };
}

// ---------------------------------------------------------------------------
// pin
// ---------------------------------------------------------------------------

// pin({ server?, name?, out?, accept?, replace?, registryName?, cwd?, env?, now?, timeoutMs?, listTools? })
//   - first pin of a name: lists every page and writes the entry;
//   - same name, tools unchanged: no write (exit 0);
//   - same name, tools changed: no write, exit 10, unless `accept` names the
//     tools to re-pin on purpose (or `replace` re-pins everything);
//   - accept: [names] re-pins only those tools (changed, new or removed);
//     every other tool keeps its old pinned definition.
export async function pin(options = {}) {
  const cwd = options.cwd ?? process.cwd();
  const outPath = resolve(cwd, options.out ?? DEFAULT_PINS_PATH);
  const listTools = options.listTools ?? listServerTools;
  const now = options.now ?? (() => new Date());
  const clientOptions = { env: options.env ?? process.env, timeoutMs: options.timeoutMs, log: options.log, allowInsecureHttp: options.allowInsecureHttp };
  const accept = options.accept === undefined ? undefined : [...new Set(options.accept)].sort();
  const fail = (exitCode, result, line, extra = {}) => ({
    exitCode,
    result,
    lines: [line, LIMITATION],
    report: { schema: PIN_REPORT_SCHEMA, result, exit_code: exitCode, pins: outPath, ...extra, limitation: LIMITATION },
    written: null,
  });

  if (options.name !== undefined && !NAME_RE.test(options.name)) {
    return fail(EXIT_USAGE, "USAGE", "USAGE --name must match " + NAME_RE.source);
  }
  if (accept !== undefined && (accept.length === 0 || accept.some((tool) => typeof tool !== "string" || tool === ""))) {
    return fail(EXIT_USAGE, "USAGE", "USAGE --accept needs one or more tool names");
  }
  if (accept !== undefined && options.replace) return fail(EXIT_USAGE, "USAGE", "USAGE use --accept or --replace, not both");

  let doc = { schema: PIN_FILE_SCHEMA, servers: {} };
  if (existsSync(outPath)) {
    try {
      doc = loadPinFile(outPath);
    } catch (error) {
      return fail(EXIT_UNCHECKED, "UNPINNED", "UNPINNED " + errorText(error) + " (not overwritten)");
    }
  }

  if (accept !== undefined && options.name === undefined) {
    const names = Object.keys(doc.servers);
    if (names.length !== 1) return fail(EXIT_USAGE, "USAGE", "USAGE --accept needs --name");
    options = { ...options, name: names[0] };
  }
  let existing = options.name !== undefined && Object.hasOwn(doc.servers, options.name) ? doc.servers[options.name] : undefined;
  let pinnedDefinitions;
  if (existing) {
    try {
      pinnedDefinitions = validatePinEntry(options.name, existing);
    } catch (error) {
      if (!options.replace) return fail(EXIT_UNCHECKED, "UNPINNED", "UNPINNED " + errorText(error) + " (use --replace to pin afresh)");
      existing = undefined;
    }
  }
  if (accept !== undefined && !existing) {
    return fail(EXIT_USAGE, "USAGE", "USAGE nothing is pinned under " + JSON.stringify(options.name ?? "") + " yet; pin it first without --accept");
  }

  let spec;
  try {
    spec = parseServerSpec(options.server ?? (existing ? serverSpecOf(existing) : undefined));
  } catch (error) {
    return fail(EXIT_USAGE, "USAGE", "USAGE " + (options.server === undefined && !existing ? "--server is required" : errorText(error)));
  }
  const { problems, warnings } = findStoredSecrets(spec);
  if (problems.length > 0) {
    return fail(EXIT_USAGE, "USAGE", "USAGE the pin file would store a credential (" + problems.join(", ") + "); use ${ENV_VAR} placeholders instead");
  }

  let listed;
  try {
    listed = await listTools(spec, clientOptions);
  } catch (error) {
    return fail(EXIT_UNCHECKED, "UNPINNED", "UNPINNED " + (options.name ?? describeServer(spec)) + ": could not list tools: " + errorText(error));
  }
  let currentManifest;
  try {
    currentManifest = toolManifestDigest(listed.tools);
  } catch (error) {
    return fail(EXIT_UNCHECKED, "UNPINNED", "UNPINNED server tools cannot be hashed: " + clipText(error.message));
  }

  const name = options.name ?? (typeof listed.serverInfo?.name === "string" ? listed.serverInfo.name : undefined);
  if (name === undefined || !NAME_RE.test(name)) {
    return fail(EXIT_USAGE, "USAGE", "USAGE the server did not give a usable name; pass --name");
  }
  if (options.name === undefined && Object.hasOwn(doc.servers, name) && !options.replace) {
    existing = doc.servers[name];
    try {
      pinnedDefinitions = validatePinEntry(name, existing);
    } catch (error) {
      return fail(EXIT_UNCHECKED, "UNPINNED", "UNPINNED " + errorText(error) + " (use --replace to pin afresh)");
    }
  }

  const pinnedAt = isoSeconds(now());
  const warningLines = warnings.map((warning) => "warning: " + warning);
  const base = { name, server: describeServer(spec), protocol_version: listed.protocolVersion, pages: listed.pages };

  if (!existing || options.replace) {
    const entry = buildEntry({
      server: storedServer(spec, { serverInfo: listed.serverInfo, registryName: options.registryName }),
      definitions: listed.tools,
      protocolVersion: listed.protocolVersion,
      pinnedAt,
    });
    doc.servers[name] = entry;
    writePinFile(outPath, doc);
    return {
      exitCode: EXIT_MATCH,
      result: "PINNED",
      lines: [
        "PINNED " + name + ": " + entry.tools.length + " tools (" + listed.pages + " page" + (listed.pages === 1 ? "" : "s") + "), " + entry.manifest_digest + " -> " + outPath,
        ...warningLines,
        "note: " + UNSIGNED_NOTE,
        LIMITATION,
      ],
      report: { schema: PIN_REPORT_SCHEMA, result: "PINNED", exit_code: EXIT_MATCH, pins: outPath, ...base, manifest_digest: entry.manifest_digest, tool_count: entry.tools.length, limitation: LIMITATION },
      written: outPath,
    };
  }

  const diff = diffToolManifests(pinnedDefinitions, listed.tools);
  if (accept === undefined) {
    if (!diff.drift) {
      return {
        exitCode: EXIT_MATCH,
        result: "UNCHANGED",
        lines: ["UNCHANGED " + name + ": " + currentManifest.tool_count + " tools already match the pin from " + existing.pinned_at, ...warningLines, LIMITATION],
        report: { schema: PIN_REPORT_SCHEMA, result: "UNCHANGED", exit_code: EXIT_MATCH, pins: outPath, ...base, manifest_digest: existing.manifest_digest, limitation: LIMITATION },
        written: null,
      };
    }
    return {
      exitCode: EXIT_DRIFT,
      result: "CHANGED",
      lines: [
        "CHANGED " + name + ": " + summarizeDiff(diff),
        ...diffDetailLines(diff),
        "not re-pinned: review the changes, then run intentrax mcp pin --name " + name + " --accept " + driftedNames(diff).join(","),
        ...warningLines,
        LIMITATION,
      ],
      report: { schema: PIN_REPORT_SCHEMA, result: "CHANGED", exit_code: EXIT_DRIFT, pins: outPath, ...base, added: diff.added, removed: diff.removed, changed: diff.changed, limitation: LIMITATION },
      written: null,
    };
  }

  const pinnedByName = new Map(pinnedDefinitions.map((definition) => [definition.name, definition]));
  const currentByName = new Map(listed.tools.map((tool) => [tool.name, tool]));
  const unknown = accept.filter((tool) => !pinnedByName.has(tool) && !currentByName.has(tool));
  if (unknown.length > 0) {
    return fail(EXIT_USAGE, "USAGE", "USAGE not pinned and not offered by the server: " + unknown.join(", "));
  }
  const drifted = new Set(driftedNames(diff));
  const accepted = accept.filter((tool) => drifted.has(tool));
  const alreadyMatching = accept.filter((tool) => !drifted.has(tool));
  const next = new Map(pinnedByName);
  for (const tool of accepted) {
    if (currentByName.has(tool)) next.set(tool, currentByName.get(tool));
    else next.delete(tool);
  }
  const definitions = [...next.values()];
  const entry = buildEntry({
    server: options.server !== undefined ? storedServer(spec, { serverInfo: listed.serverInfo, registryName: options.registryName ?? existing.server.registry_name }) : existing.server,
    definitions,
    protocolVersion: listed.protocolVersion,
    pinnedAt,
  });
  if (accepted.length > 0) {
    doc.servers[name] = entry;
    writePinFile(outPath, doc);
  }
  const remaining = diffToolManifests(definitions, listed.tools);
  const lines = [
    (accepted.length > 0 ? "REPINNED " + name + ": accepted " + accepted.join(", ") : "UNCHANGED " + name + ": nothing to accept") +
      (alreadyMatching.length > 0 ? " (already matching: " + alreadyMatching.join(", ") + ")" : "") +
      "; " + entry.tools.length + " tools, " + entry.manifest_digest,
  ];
  if (remaining.drift) {
    lines.push("CHANGED " + name + " (not accepted): " + summarizeDiff(remaining));
    lines.push(...diffDetailLines(remaining));
  }
  lines.push(...warningLines, LIMITATION);
  const exitCode = remaining.drift ? EXIT_DRIFT : EXIT_MATCH;
  return {
    exitCode,
    result: accepted.length > 0 ? "REPINNED" : "UNCHANGED",
    lines,
    report: {
      schema: PIN_REPORT_SCHEMA,
      result: accepted.length > 0 ? "REPINNED" : "UNCHANGED",
      exit_code: exitCode,
      pins: outPath,
      ...base,
      accepted,
      manifest_digest: entry.manifest_digest,
      remaining: { added: remaining.added, removed: remaining.removed, changed: remaining.changed },
      limitation: LIMITATION,
    },
    written: accepted.length > 0 ? outPath : null,
  };
}

// For the proxy: the pinned definitions for one server, validated.
export function loadPinnedServer(pinsPath, name) {
  const doc = loadPinFile(pinsPath);
  const names = Object.keys(doc.servers).sort();
  const chosen = name ?? (names.length === 1 ? names[0] : undefined);
  if (chosen === undefined) throw new PinFileError("pins_ambiguous", "the pin file has " + names.length + " servers; pass --name");
  if (!Object.hasOwn(doc.servers, chosen)) throw new PinFileError("pins_missing", "no pin named " + JSON.stringify(chosen));
  const definitions = validatePinEntry(chosen, doc.servers[chosen]);
  return { name: chosen, entry: doc.servers[chosen], definitions, spec: serverSpecOf(doc.servers[chosen]) };
}
