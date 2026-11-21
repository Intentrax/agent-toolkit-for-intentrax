// `intentrax mcp pin|check|proxy`: the command-line front end for the R1b
// tool-pinning functions in commands.mjs and proxy.mjs.
//
// Exit codes (from commands.mjs): 0 match / pinned, 10 drift (CHANGED),
// 2 could not check (fail closed), 1 usage.
//
// `proxy` keeps stdout for JSON-RPC only; every log line goes to stderr.

import { EXIT_USAGE, check, pin } from "./commands.mjs";
import { ON_DRIFT_MODES, runProxy } from "./proxy.mjs";

const VALUE_FLAGS = new Map([
  ["--server", "server"],
  ["--name", "name"],
  ["--out", "out"],
  ["--pins", "pins"],
  ["--accept", "accept"],
  ["--registry-name", "registryName"],
  ["--timeout-ms", "timeoutMs"],
  ["--on-drift", "onDrift"],
]);
const REPEAT_FLAGS = new Map([
  ["--header", "headers"],
  ["--env", "env"],
]);
const BOOL_FLAGS = new Map([
  ["--replace", "replace"],
  ["--json", "json"],
  ["--help", "help"],
  ["-h", "help"],
]);
const ALLOWED = {
  pin: new Set(["server", "name", "out", "accept", "registryName", "timeoutMs", "headers", "env", "replace", "json", "command"]),
  check: new Set(["server", "name", "pins", "timeoutMs", "headers", "env", "json", "command"]),
  proxy: new Set(["server", "name", "pins", "timeoutMs", "headers", "env", "onDrift", "command"]),
};
const FLAG_NAME = {
  server: "--server", name: "--name", out: "--out", pins: "--pins", accept: "--accept", registryName: "--registry-name",
  timeoutMs: "--timeout-ms", onDrift: "--on-drift", headers: "--header", env: "--env", replace: "--replace", json: "--json",
  command: "-- <command>",
};

class UsageError extends Error {}

export function usage(invokedAs = "intentrax mcp") {
  return `Usage:
  ${invokedAs} pin   --server <cmd|url> [--name <name>] [--out .intentrax/mcp-pins.json] [--json]
  ${invokedAs} pin   --name <name> -- <command> [args...]        (stdio server given as argv)
  ${invokedAs} pin   --name <name> --accept <tool,...>             re-pin the named tools on purpose
  ${invokedAs} pin   --name <name> --replace                       re-pin everything
  ${invokedAs} check [--pins .intentrax/mcp-pins.json] [--name <name>] [--json]
  ${invokedAs} proxy [--pins .intentrax/mcp-pins.json] [--name <name>] [--on-drift block|warn]

Server options (pin; check/proxy use the pinned server unless given):
  --server <cmd|url>      a command line, or an https:// (or loopback http://) MCP URL
  --header 'Name: value'  HTTP header (repeatable); put credentials in '\${ENV_VAR}' placeholders
  --env KEY=value         stdio environment entry (repeatable); \${ENV_VAR} placeholders too
  --registry-name <name>  MCP Registry name to record with the pin (pin only)
  --timeout-ms <ms>       per-request timeout (default 15000)

Credentials are never stored: a literal secret in a header, env entry or URL
is refused. Placeholders are expanded only when connecting, never logged.

check exit codes:
  0   MATCH      every pinned server's tools match the pin
  10  CHANGED    a tool definition changed, was added or removed (line 1 lists them)
  2   UNCHECKED  the tools could not be listed, or the pin file is missing or invalid
  1   USAGE      bad arguments

proxy is a stdio MCP proxy for your host's config. --on-drift block (default)
hides changed and new tools and refuses calls to them (JSON-RPC error -32090);
warn forwards everything and only logs to stderr.

Covers tool definitions only. It does not show that the server's code or behaviour is unchanged.`;
}

export function parseMcpArgs(argv) {
  const [sub, ...rest] = argv;
  if (sub === undefined || sub === "--help" || sub === "-h" || sub === "help") return { sub: "help", opts: {} };
  if (!Object.hasOwn(ALLOWED, sub)) throw new UsageError(`unknown subcommand ${JSON.stringify(sub)} (expected pin, check or proxy)`);
  const opts = {};
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (arg === "--") {
      const command = rest.slice(i + 1);
      if (command.length === 0) throw new UsageError("-- must be followed by a command");
      opts.command = command;
      break;
    }
    const eq = arg.startsWith("--") ? arg.indexOf("=") : -1;
    const flag = eq > 0 ? arg.slice(0, eq) : arg;
    const inline = eq > 0 ? arg.slice(eq + 1) : undefined;
    const takeValue = () => {
      if (inline !== undefined) return inline;
      const value = rest[i + 1];
      if (value === undefined || (value.startsWith("-") && value !== "-")) throw new UsageError(`${flag} requires a value`);
      i += 1;
      return value;
    };
    if (BOOL_FLAGS.has(flag)) {
      if (inline !== undefined) throw new UsageError(`${flag} takes no value`);
      opts[BOOL_FLAGS.get(flag)] = true;
    } else if (VALUE_FLAGS.has(flag)) {
      const key = VALUE_FLAGS.get(flag);
      if (Object.hasOwn(opts, key)) throw new UsageError(`${flag} given twice`);
      opts[key] = takeValue();
    } else if (REPEAT_FLAGS.has(flag)) {
      const key = REPEAT_FLAGS.get(flag);
      (opts[key] ??= []).push(takeValue());
    } else {
      throw new UsageError(arg.startsWith("-") ? `unknown option ${arg}` : `unexpected argument ${JSON.stringify(arg)}`);
    }
  }
  if (opts.help) return { sub: "help", opts: {} };
  for (const key of Object.keys(opts)) {
    if (!ALLOWED[sub].has(key)) throw new UsageError(`${FLAG_NAME[key]} is not an option of ${sub}`);
  }
  return { sub, opts: normalize(sub, opts) };
}

function normalize(sub, opts) {
  const out = {};
  for (const key of ["name", "out", "pins", "registryName"]) if (opts[key] !== undefined) out[key] = opts[key];
  if (opts.timeoutMs !== undefined) {
    const n = Number(opts.timeoutMs);
    if (!/^\d+$/.test(opts.timeoutMs) || !Number.isSafeInteger(n) || n < 1 || n > 600000) {
      throw new UsageError("--timeout-ms must be an integer from 1 to 600000");
    }
    out.timeoutMs = n;
  }
  if (opts.onDrift !== undefined) {
    if (!ON_DRIFT_MODES.includes(opts.onDrift)) throw new UsageError("--on-drift must be block or warn");
    out.onDrift = opts.onDrift;
  }
  if (opts.accept !== undefined) {
    const names = opts.accept.split(",").map((s) => s.trim()).filter((s) => s !== "");
    if (names.length === 0) throw new UsageError("--accept needs at least one tool name");
    out.accept = names;
  }
  if (opts.replace) out.replace = true;
  if (opts.json) out.json = true;
  if (opts.server !== undefined && opts.command !== undefined) throw new UsageError("give --server or -- <command>, not both");
  const base = opts.command ?? opts.server;
  if (opts.headers !== undefined || opts.env !== undefined) {
    if (base === undefined) throw new UsageError("--header and --env need --server (or -- <command>)");
  }
  if (base !== undefined) out.server = buildServer(base, opts.headers, opts.env);
  return out;
}

function buildServer(base, headers, env) {
  const isUrl = typeof base === "string" && /^https?:\/\//i.test(base.trim());
  if (headers === undefined && env === undefined) return base;
  if (isUrl) {
    if (env !== undefined) throw new UsageError("--env applies to stdio servers; use --header for an HTTP server");
    return { transport: "streamable-http", url: base.trim(), headers: pairs(headers, ":", "--header", "Name: value") };
  }
  if (headers !== undefined) throw new UsageError("--header applies to HTTP servers; use --env for a stdio server");
  return { transport: "stdio", command: base, env: pairs(env, "=", "--env", "KEY=value") };
}

function pairs(list, sep, flag, shape) {
  const map = {};
  for (const item of list) {
    const at = item.indexOf(sep);
    const key = at > 0 ? item.slice(0, at).trim() : "";
    if (key === "") throw new UsageError(`${flag} must look like "${shape}"`);
    if (Object.hasOwn(map, key)) throw new UsageError(`${flag} ${key} given twice`);
    map[key] = item.slice(at + 1).trim();
  }
  return map;
}

/**
 * Run `intentrax mcp ...`. Resolves to the exit code.
 * io: { out, err, cwd, env, invokedAs, input, output } (defaults: process streams).
 */
export async function mcpMain(argv = [], io = {}) {
  const out = io.out ?? ((text) => process.stdout.write(text));
  const err = io.err ?? ((text) => process.stderr.write(text));
  const invokedAs = io.invokedAs ?? "intentrax mcp";
  let parsed;
  try {
    parsed = parseMcpArgs(argv);
  } catch (error) {
    if (!(error instanceof UsageError)) throw error;
    err(`intentrax mcp: ${error.message}\n\n${usage(invokedAs)}\n`);
    return EXIT_USAGE;
  }
  const { sub, opts } = parsed;
  if (sub === "help") {
    out(usage(invokedAs) + "\n");
    return 0;
  }
  const base = { cwd: io.cwd ?? process.cwd(), env: io.env ?? process.env };
  if (sub === "proxy") {
    // stdout belongs to JSON-RPC; startProxy logs to stderr only.
    return runProxy({
      ...base,
      pins: opts.pins,
      name: opts.name,
      server: opts.server,
      onDrift: opts.onDrift,
      timeoutMs: opts.timeoutMs,
      ...(io.input ? { input: io.input } : {}),
      ...(io.output ? { output: io.output } : {}),
      ...(io.errorOutput ? { errorOutput: io.errorOutput } : {}),
    });
  }
  const { json, ...fnOpts } = opts;
  const result = sub === "pin" ? await pin({ ...base, ...fnOpts }) : await check({ ...base, ...fnOpts });
  out((json ? JSON.stringify(result.report, null, 2) : result.lines.join("\n")) + "\n");
  return result.exitCode;
}
