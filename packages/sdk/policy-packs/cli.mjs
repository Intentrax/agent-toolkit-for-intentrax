#!/usr/bin/env node
// `intentrax policy`: open policy packs.
//
//   intentrax policy list [--json]
//   intentrax policy show <pack> [--json]
//   intentrax policy hash <pack | pack.json> [--json]
//   intentrax policy validate [policy.jsonc | pack.json] [--json]
//   intentrax policy init --from-scan [dir] [--out <file>] [--environment PROD|STAGING|DEV] [--force] [--include-tests] [--json]
//   intentrax policy check --tool <name> [--input <json>] [--policy <file> | --pack <pack>]... [--environment E] [--pin-status S] [--json]
//
// Local and static: nothing is run or sent, no account. From a repository
// checkout, `node sdk/typescript/policy-packs/cli.mjs <subcommand> ...` runs
// the same thing.
//
// Exit codes: 0 success (validate: valid), 1 invalid (validate, hash of an
// invalid pack), 2 usage or I/O error (including refusing to overwrite).

import { existsSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ScanError } from "../scan/scan.mjs";
import {
  ENVIRONMENTS,
  PACK_SCHEMA_VERSION,
  POLICY_FILE_SCHEMA_VERSION,
  PolicyPackError,
  evaluateToolCall,
  getPack,
  listPacks,
  loadPolicyFile,
  parseJsonc,
  policyFromPacks,
  validatePack,
} from "./index.mjs";
import { initFromScan } from "./init.mjs";

export const EXIT = Object.freeze({ OK: 0, INVALID: 1, USAGE: 2 });
export const DEFAULT_POLICY_PATH = ".intentrax/policy.jsonc";

class UsageError extends Error {}

export function usage(invokedAs = "intentrax policy") {
  return [
    `Usage: ${invokedAs} <list|show|hash|validate|init|check> ...`,
    "",
    `  ${invokedAs} list [--json]                 the built-in packs`,
    `  ${invokedAs} show <pack> [--json]          what a pack does, its decisions and limits`,
    `  ${invokedAs} hash <pack|pack.json> [--json] the pack's content hash (pack_hash)`,
    `  ${invokedAs} validate [file] [--json]      check a policy file (default ${DEFAULT_POLICY_PATH}) or a pack file`,
    `  ${invokedAs} init --from-scan [dir] [--out <file>] [--environment PROD|STAGING|DEV] [--force] [--include-tests]`,
    "      run intentrax scan on dir (default .) and write a draft policy file with a",
    `      comment on every pack it selects (default <dir>/${DEFAULT_POLICY_PATH})`,
    `  ${invokedAs} check --tool <name> [--input <json>] [--policy <file> | --pack <pack>...] [--environment E] [--pin-status S]`,
    "      what the packs decide for one tool call (allow, ask, block or none)",
    "",
    "Local and static: nothing is run or sent. Facts are read from the tool input on this",
    "machine (self-reported); the decision is the C2 policy's and can be re-checked from its hash.",
    "Exit codes: 0 ok, 1 invalid, 2 usage or I/O error.",
  ].join("\n");
}

function parseArgs(argv) {
  const [sub, ...rest] = argv;
  const opts = { sub, positional: [], json: false, force: false, includeTests: false, fromScan: false, packs: [], help: false };
  const takeValue = (i, flag) => {
    const v = rest[i + 1];
    if (v === undefined || v.startsWith("--")) throw new UsageError(`${flag} needs a value`);
    return v;
  };
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === "--help" || a === "-h") opts.help = true;
    else if (a === "--json") opts.json = true;
    else if (a === "--force") opts.force = true;
    else if (a === "--include-tests") opts.includeTests = true;
    else if (a === "--from-scan") opts.fromScan = true;
    else if (a === "--out") opts.out = takeValue(i++, a);
    else if (a === "--environment") opts.environment = takeValue(i++, a);
    else if (a === "--tool") opts.tool = takeValue(i++, a);
    else if (a === "--input") opts.input = takeValue(i++, a);
    else if (a === "--policy") opts.policy = takeValue(i++, a);
    else if (a === "--pack") opts.packs.push(takeValue(i++, a));
    else if (a === "--pin-status") opts.pinStatus = takeValue(i++, a);
    else if (a.startsWith("-")) throw new UsageError(`unknown option ${a}`);
    else opts.positional.push(a);
  }
  if (opts.environment !== undefined && !ENVIRONMENTS.includes(opts.environment)) throw new UsageError("--environment must be PROD, STAGING or DEV");
  return opts;
}

function onePositional(opts, what, { optional = false } = {}) {
  if (opts.positional.length > 1) throw new UsageError(`unexpected argument ${opts.positional[1]}`);
  if (!optional && opts.positional.length === 0) throw new UsageError(`${what} is required`);
  return opts.positional[0];
}

function readJsonFile(path) {
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch (e) {
    throw new PolicyPackError("FILE_UNREADABLE", `cannot read ${path}: ${e.code ?? e.message}`);
  }
  return parseJsonc(raw);
}

// A built-in id, or a path to a pack JSON file. Pack files are plain JSON (no
// comments), read exactly as a policy file's "path" entry reads them, so the
// hash printed here is the hash the pin check computes.
function resolvePackArg(arg, cwd) {
  const path = resolve(cwd, arg);
  if (/\.json$/i.test(arg) || (existsSync(path) && statSync(path).isFile())) {
    let raw;
    try {
      raw = readFileSync(path, "utf8");
    } catch (e) {
      throw new PolicyPackError("FILE_UNREADABLE", `cannot read ${arg}: ${e.code ?? e.message}`);
    }
    try {
      return { pack: JSON.parse(raw), file: arg };
    } catch (e) {
      throw new PolicyPackError("PACK_INVALID", `${arg} is not JSON (pack files take no comments): ${e.message}`);
    }
  }
  return { pack: getPack(arg), file: null };
}

function cmdList(opts, out) {
  const packs = listPacks();
  if (opts.json) {
    out(JSON.stringify({ schema_version: PACK_SCHEMA_VERSION, packs }, null, 2) + "\n");
    return EXIT.OK;
  }
  const lines = packs.map((p) => `${p.pack_id.padEnd(34)} ${p.category.padEnd(15)} ${p.decisions.join("/").padEnd(15)} ${p.pack_hash.slice(0, 12)}  ${p.title}`);
  out([`${"PACK".padEnd(34)} ${"SCAN CATEGORY".padEnd(15)} ${"DECISIONS".padEnd(15)} ${"HASH".padEnd(12)}  TITLE`, ...lines, "", `${packs.length} packs. intentrax policy show <pack> for details.`].join("\n") + "\n");
  return EXIT.OK;
}

function cmdShow(opts, out, cwd) {
  const { pack } = resolvePackArg(onePositional(opts, "a pack"), cwd);
  const check = validatePack(pack, { builtIn: pack.pack_id?.startsWith("intentrax.") });
  if (!check.ok) throw new PolicyPackError("PACK_INVALID", check.errors.join("; "));
  if (opts.json) {
    out(JSON.stringify({ pack_hash: check.pack_hash, source_policy_hash: check.source_policy_hash, pack }, null, 2) + "\n");
    return EXIT.OK;
  }
  const lines = [
    `${pack.pack_id} ${pack.pack_version}: ${pack.title}`,
    pack.summary,
    "",
    `pack_hash           ${check.pack_hash}`,
    `source_policy_hash  ${check.source_policy_hash} (default params)`,
    `scan                ${pack.scan.rule_ids.join(", ")}${pack.scan.name_tokens ? ` (names with: ${pack.scan.name_tokens.join(", ")})` : ""}`,
    `approval            ${pack.approval.constraint_id} (${pack.approval.type}): ${pack.approval.approver_hint}`,
    "",
    "Actions:",
    ...Object.entries(pack.actions).map(([a, s]) => `  ${a.padEnd(34)} ${s.decisions.join("/").padEnd(16)} ${s.why}`),
  ];
  const params = Object.entries(pack.params);
  if (params.length) {
    lines.push("", "Params:");
    for (const [n, p] of params) lines.push(`  ${n} = ${JSON.stringify(p.default)} (${p.type}${p.type === "INTEGER" ? `, ${p.min}..${p.max}` : ""}): ${p.description}`);
  }
  lines.push("", "Limits:", ...pack.limits.map((l) => `  - ${l}`));
  out(lines.join("\n") + "\n");
  return EXIT.OK;
}

function cmdHash(opts, out, cwd) {
  const { pack, file } = resolvePackArg(onePositional(opts, "a pack"), cwd);
  const check = validatePack(pack, { builtIn: !file });
  if (!check.ok) {
    if (opts.json) out(JSON.stringify({ valid: false, errors: check.errors }, null, 2) + "\n");
    else out(`invalid pack: ${check.errors.join("; ")}\n`);
    return EXIT.INVALID;
  }
  if (opts.json) {
    out(JSON.stringify({ pack_id: pack.pack_id, pack_version: pack.pack_version, pack_hash: check.pack_hash, source_policy_hash: check.source_policy_hash }, null, 2) + "\n");
  } else {
    out(`${check.pack_hash}  ${pack.pack_id}@${pack.pack_version}\n`);
  }
  return EXIT.OK;
}

function cmdValidate(opts, out, cwd) {
  const arg = onePositional(opts, "a file", { optional: true }) ?? DEFAULT_POLICY_PATH;
  const path = resolve(cwd, arg);
  const doc = readJsonFile(path);
  let report;
  if (doc?.schema_version === PACK_SCHEMA_VERSION) {
    const check = validatePack(doc);
    report = check.ok
      ? { valid: true, kind: "pack", pack_id: doc.pack_id, pack_hash: check.pack_hash, source_policy_hash: check.source_policy_hash }
      : { valid: false, kind: "pack", errors: check.errors };
  } else {
    try {
      const policy = loadPolicyFile(path);
      report = {
        valid: true,
        kind: "policy_file",
        environment: policy.environment ?? null,
        packs: policy.entries.map((e) => ({ pack_id: e.pack.pack_id, pack_version: e.pack.pack_version, pack_hash: e.pack_hash, source_policy_hash: e.compiled.source_policy_hash, params: e.params })),
      };
    } catch (e) {
      if (!(e instanceof PolicyPackError)) throw e;
      report = { valid: false, kind: doc?.schema_version === POLICY_FILE_SCHEMA_VERSION ? "policy_file" : "unknown", errors: [`${e.code}: ${e.message}`] };
    }
  }
  if (opts.json) out(JSON.stringify(report, null, 2) + "\n");
  else if (!report.valid) out(`INVALID ${arg}\n${report.errors.map((e) => `  ${e}`).join("\n")}\n`);
  else if (report.kind === "pack") out(`VALID pack ${report.pack_id}: pack_hash ${report.pack_hash}, source_policy_hash ${report.source_policy_hash}\n`);
  else out(`VALID policy file ${arg}: ${report.packs.length} pack(s), environment ${report.environment ?? "not set"}\n${report.packs.map((p) => `  ${p.pack_id}@${p.pack_version} ${p.pack_hash.slice(0, 12)} policy ${p.source_policy_hash.slice(0, 12)}`).join("\n")}${report.packs.length ? "\n" : ""}`);
  return report.valid ? EXIT.OK : EXIT.INVALID;
}

function cmdInit(opts, out, err, cwd) {
  if (!opts.fromScan) throw new UsageError("init needs --from-scan (the only source in this version)");
  const dir = resolve(cwd, onePositional(opts, "a directory", { optional: true }) ?? ".");
  const target = opts.out ? resolve(cwd, opts.out) : join(dir, DEFAULT_POLICY_PATH);
  if (existsSync(target) && !opts.force) {
    err(`intentrax policy init: ${target} already exists; pass --force to overwrite it\n`);
    return EXIT.USAGE;
  }
  const { scan, selections, text } = initFromScan(dir, { environment: opts.environment ?? "PROD", includeTests: opts.includeTests });
  // The draft must load: a file that fails its own validation is never written.
  parseJsonc(text);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, text);
  loadPolicyFile(target);
  const rel = relative(cwd, target);
  const shown = rel && !rel.startsWith("..") ? rel : target;
  if (opts.json) {
    out(JSON.stringify({
      written: shown,
      environment: opts.environment ?? "PROD",
      scan_summary: scan.summary,
      packs: selections.map((s) => ({ pack_id: s.pack.pack_id, pack_hash: s.summary.pack_hash, selected_by: s.hits.map((h) => ({ action: h.action.displayName ?? h.action.name, location: h.action.location, why: h.why, findings: h.types })) })),
    }, null, 2) + "\n");
  } else {
    const lines = [`Wrote a draft policy to ${shown} with ${selections.length} pack(s):`];
    for (const s of selections) lines.push(`  ${s.pack.pack_id.padEnd(34)} ${s.hits.length} matching action(s)${s.exposed.length ? `, ${s.exposed.length} EXPOSED finding(s)` : ""}`);
    lines.push("Review the comments in the file, then: intentrax policy validate " + shown);
    out(lines.join("\n") + "\n");
  }
  return EXIT.OK;
}

function cmdCheck(opts, out, cwd) {
  if (!opts.tool) throw new UsageError("check needs --tool <name>");
  let input = {};
  if (opts.input !== undefined) {
    try {
      input = JSON.parse(opts.input);
    } catch (e) {
      throw new UsageError(`--input is not JSON: ${e.message}`);
    }
  }
  if (opts.pinStatus !== undefined && !["MATCH", "CHANGED", "NEW", "UNPINNED"].includes(opts.pinStatus)) throw new UsageError("--pin-status must be MATCH, CHANGED, NEW or UNPINNED");
  let policy;
  if (opts.packs.length) {
    if (opts.policy) throw new UsageError("use --policy or --pack, not both");
    policy = policyFromPacks(opts.packs, { environment: opts.environment });
  } else {
    const path = resolve(cwd, opts.policy ?? DEFAULT_POLICY_PATH);
    if (!opts.policy && !existsSync(path)) policy = policyFromPacks(listPacks().map((p) => p.pack_id), { environment: opts.environment });
    else {
      policy = loadPolicyFile(path);
      if (opts.environment) policy = { ...policy, environment: opts.environment };
    }
  }
  const result = evaluateToolCall(policy, { tool_name: opts.tool, tool_input: input, context: opts.pinStatus ? { mcp_pin_status: opts.pinStatus } : {} });
  if (opts.json) out(JSON.stringify(result, null, 2) + "\n");
  else out(`${result.decision.toUpperCase()} ${result.reason}\n`);
  return EXIT.OK;
}

export function policyMain(argv = [], io = {}) {
  const out = io.out ?? ((s) => process.stdout.write(s));
  const err = io.err ?? ((s) => process.stderr.write(s));
  const cwd = io.cwd ?? process.cwd();
  const invokedAs = io.invokedAs ?? "intentrax policy";
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    err(`intentrax policy: ${e.message}\n${usage(invokedAs)}\n`);
    return EXIT.USAGE;
  }
  if (!opts.sub || opts.sub === "--help" || opts.sub === "-h" || opts.help) {
    out(usage(invokedAs) + "\n");
    return EXIT.OK;
  }
  try {
    switch (opts.sub) {
      case "list": return cmdList(opts, out);
      case "show": return cmdShow(opts, out, cwd);
      case "hash": return cmdHash(opts, out, cwd);
      case "validate": return cmdValidate(opts, out, cwd);
      case "init": return cmdInit(opts, out, err, cwd);
      case "check": return cmdCheck(opts, out, cwd);
      default:
        throw new UsageError(`unknown subcommand ${opts.sub}`);
    }
  } catch (e) {
    if (e instanceof UsageError) {
      err(`intentrax policy: ${e.message}\n${usage(invokedAs)}\n`);
      return EXIT.USAGE;
    }
    if (e instanceof PolicyPackError || e instanceof ScanError) {
      err(`intentrax policy: ${e.code ? `${e.code}: ` : ""}${e.message}\n`);
      return e.code === "PACK_INVALID" || e.code === "POLICY_INVALID" ? EXIT.INVALID : EXIT.USAGE;
    }
    throw e;
  }
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
  process.exitCode = policyMain(process.argv.slice(2), { invokedAs: "node sdk/typescript/policy-packs/cli.mjs" });
}
