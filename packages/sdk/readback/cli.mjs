// `intentrax readback`: read the outcome back before reporting success, from
// the command line. A thin front end for confirmThenReport with a { module }
// check, which always runs in a worker thread (same runner as
// `intentrax sandbox --check`).
//
// Exit codes (aligned with the sandbox): 0 CONFIRMED, 10 PENDING,
// 11 UNKNOWN, 12 CONTRADICTED (CAUGHT), 64 usage.
//
// Every result is SELF_REPORTED: the check is code you configured. It is not
// an Intentrax attestation.

import { isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { confirmThenReport, STATUS } from "./confirm.mjs";

export const EXIT_CODES = Object.freeze({
  [STATUS.CONFIRMED]: 0,
  [STATUS.PENDING]: 10,
  [STATUS.UNKNOWN]: 11,
  [STATUS.CONTRADICTED]: 12,
});
export const USAGE_EXIT_CODE = 64;

class UsageError extends Error {}

const VALUE_FLAGS = new Map([
  ["--check", "check"],
  ["--expected", "expected"],
  ["--claimed", "claimed"],
  ["--pending", "pending"],
  ["--retries", "retries"],
  ["--interval-ms", "intervalMs"],
  ["--timeout-ms", "timeoutMs"],
  ["--resource", "resource"],
  ["--source", "source"],
  ["--actor", "actor"],
]);
const BOOL_FLAGS = new Map([
  ["--retry-on-mismatch", "retryOnMismatch"],
  ["--json", "json"],
  ["--help", "help"],
  ["-h", "help"],
]);

export function usage(invokedAs = "intentrax readback") {
  return `Usage:
  ${invokedAs} --check <read-only-check.mjs> --expected <json> [--claimed <json>]
      [--pending <json>] [--retries N] [--interval-ms N] [--timeout-ms N]
      [--retry-on-mismatch] [--resource <label>] [--source <label>] [--actor <who>] [--json]

Reads the system of record with your read-only check and compares the fields
that matter, before anyone reports success. The check module's default export
is called (in a worker thread) with { resource, fields } and returns an object.

  --expected '["status"]'              compare these fields with --claimed
  --expected '{"status":"succeeded"}'  require these values
  --claimed  '{"status":"processed"}'  what the agent reported
  --pending  '{"status":["pending"]}'  values that mean "not final yet" (re-read)

Exit codes:
  0   CONFIRMED     the read matches
  12  CONTRADICTED  the read differs (first line starts with CAUGHT)
  10  PENDING       still not final after the retries
  11  UNKNOWN       the check failed, timed out, or a field is missing
  64  usage

Self-reported: the check is code you configured. Not an Intentrax attestation.`;
}

function parseJson(flag, text) {
  try {
    return JSON.parse(text);
  } catch {
    throw new UsageError(`${flag} must be valid JSON`);
  }
}

function parseInt10(flag, text) {
  if (!/^\d+$/.test(text)) throw new UsageError(`${flag} must be a non-negative integer`);
  return Number(text);
}

export function parseReadbackArgs(argv, cwd = process.cwd()) {
  const raw = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const eq = arg.startsWith("--") ? arg.indexOf("=") : -1;
    const flag = eq > 0 ? arg.slice(0, eq) : arg;
    const inline = eq > 0 ? arg.slice(eq + 1) : undefined;
    if (BOOL_FLAGS.has(flag)) {
      if (inline !== undefined) throw new UsageError(`${flag} takes no value`);
      raw[BOOL_FLAGS.get(flag)] = true;
    } else if (VALUE_FLAGS.has(flag)) {
      const key = VALUE_FLAGS.get(flag);
      if (Object.hasOwn(raw, key)) throw new UsageError(`${flag} given twice`);
      let value = inline;
      if (value === undefined) {
        value = argv[i + 1];
        if (value === undefined) throw new UsageError(`${flag} requires a value`);
        i += 1;
      }
      raw[key] = value;
    } else {
      throw new UsageError(arg.startsWith("-") ? `unknown option ${arg}` : `unexpected argument ${JSON.stringify(arg)}`);
    }
  }
  if (raw.help) return { help: true };
  if (raw.check === undefined) throw new UsageError("--check <read-only-check.mjs> is required");
  if (raw.expected === undefined) throw new UsageError("--expected is required");
  const modulePath = /^file:/i.test(raw.check) ? raw.check : pathToFileURL(isAbsolute(raw.check) ? raw.check : resolve(cwd, raw.check)).href;
  const input = { check: { module: modulePath }, expected: parseJson("--expected", raw.expected) };
  if (raw.claimed !== undefined) input.claimed = parseJson("--claimed", raw.claimed);
  if (raw.pending !== undefined) input.pending = parseJson("--pending", raw.pending);
  for (const key of ["retries", "intervalMs", "timeoutMs"]) {
    if (raw[key] !== undefined) input[key] = parseInt10("--" + key.replace(/[A-Z]/g, (c) => "-" + c.toLowerCase()), raw[key]);
  }
  for (const key of ["resource", "source", "actor"]) if (raw[key] !== undefined) input[key] = raw[key];
  if (raw.retryOnMismatch) input.retryOnMismatch = true;
  return { input, json: Boolean(raw.json) };
}

/** Run `intentrax readback ...`. Resolves to the exit code. io: { out, err, cwd, invokedAs }. */
export async function readbackMain(argv = [], io = {}) {
  const out = io.out ?? ((text) => process.stdout.write(text));
  const err = io.err ?? ((text) => process.stderr.write(text));
  const invokedAs = io.invokedAs ?? "intentrax readback";
  let parsed;
  try {
    parsed = parseReadbackArgs(argv, io.cwd ?? process.cwd());
  } catch (error) {
    if (!(error instanceof UsageError)) throw error;
    err(`intentrax readback: ${error.message}\n\n${usage(invokedAs)}\n`);
    return USAGE_EXIT_CODE;
  }
  if (parsed.help) {
    out(usage(invokedAs) + "\n");
    return 0;
  }
  let result;
  try {
    result = await confirmThenReport(parsed.input);
  } catch (error) {
    // confirmThenReport throws TypeError for caller mistakes, before any read.
    if (!(error instanceof TypeError)) throw error;
    err(`intentrax readback: ${error.message}\n\n${usage(invokedAs)}\n`);
    return USAGE_EXIT_CODE;
  }
  out((parsed.json ? JSON.stringify(result, null, 2) : result.firstLine + "\n" + result.detail.note) + "\n");
  return EXIT_CODES[result.status] ?? EXIT_CODES[STATUS.UNKNOWN];
}
