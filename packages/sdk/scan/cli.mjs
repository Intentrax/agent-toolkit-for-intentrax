#!/usr/bin/env node
// `intentrax scan`: what could your agent break?
//
//   intentrax scan [dir] [--json] [--include-tests] [--max-files N]
//
// Local and static: reads files under [dir] (default: the current directory),
// never runs or imports them, makes no network call and needs no account.
// Credentials are reported by name and location only, never by value.
//
// Exit codes: 0 no findings, 20 findings, 2 scan error (including bad usage).
//
// From a repository checkout, `node sdk/typescript/scan/cli.mjs [args]` runs
// the same thing. The SDK 1.8.0 integration step wires
// `intentrax scan ...` (cli/intentrax.mjs) to `scanMain`.

import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { scanProject, ScanError, SCAN_NOTE } from "./scan.mjs";
import { EXIT_CODES, exitCodeFor, formatJson, formatText } from "./report.mjs";

class UsageError extends Error {}

export function usage(invokedAs = "intentrax scan") {
  return [
    `Usage: ${invokedAs} [dir] [--json] [--include-tests] [--max-files N]`,
    "",
    "Lists the destructive or consequential actions an AI agent can reach in a",
    "project (MCP servers and tools, OpenAI/Anthropic tool definitions,",
    "LangChain/LangGraph and Vercel AI SDK tools, shell tools), and flags broad",
    "credentials (EXPOSED), missing gates (UNGATED) and success reported without",
    "a read-back (SELF-REPORTED). Local and static: nothing is run or sent.",
    "",
    "  --json            machine-readable output",
    "  --include-tests   also scan test and fixture directories",
    "  --max-files N     stop after N files (default 20000)",
    "",
    "Exit codes: 0 no findings, 20 findings, 2 scan error.",
    SCAN_NOTE,
  ].join("\n");
}

function parseArgs(argv) {
  const opts = { dir: null, json: false, includeTests: false, maxFiles: undefined, help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--help" || a === "-h") opts.help = true;
    else if (a === "--json") opts.json = true;
    else if (a === "--include-tests") opts.includeTests = true;
    else if (a === "--max-files") {
      const n = Number(argv[i + 1]);
      if (!Number.isSafeInteger(n) || n < 1) throw new UsageError("--max-files requires a positive integer");
      opts.maxFiles = n;
      i += 1;
    } else if (a.startsWith("-")) throw new UsageError(`unknown option ${a}`);
    else if (opts.dir === null) opts.dir = a;
    else throw new UsageError(`unexpected argument ${a}`);
  }
  return opts;
}

export function scanMain(argv = [], io = {}) {
  const out = io.out ?? ((s) => process.stdout.write(s));
  const err = io.err ?? ((s) => process.stderr.write(s));
  const cwd = io.cwd ?? process.cwd();
  const invokedAs = io.invokedAs ?? "intentrax scan";
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    err(`intentrax scan: ${e.message}\n${usage(invokedAs)}\n`);
    return EXIT_CODES.SCAN_ERROR;
  }
  if (opts.help) {
    out(usage(invokedAs) + "\n");
    return EXIT_CODES.NO_FINDINGS;
  }
  let result;
  try {
    result = scanProject(opts.dir ? resolve(cwd, opts.dir) : cwd, { includeTests: opts.includeTests, maxFiles: opts.maxFiles });
  } catch (e) {
    const message = e instanceof ScanError ? e.message : `unexpected error: ${e?.message ?? e}`;
    if (opts.json) out(JSON.stringify({ schema: "intentrax.scan.v1", error: message, note: SCAN_NOTE }, null, 2) + "\n");
    err(`intentrax scan: ${message}\n`);
    return EXIT_CODES.SCAN_ERROR;
  }
  out(opts.json ? formatJson(result) : formatText(result));
  return exitCodeFor(result);
}

function invokedDirectly() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  process.exitCode = scanMain(process.argv.slice(2), { invokedAs: "node sdk/typescript/scan/cli.mjs" });
}
