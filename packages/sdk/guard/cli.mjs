#!/usr/bin/env node
// `intentrax guard`: a local, no-account gate for Claude Code tool calls, with
// a local hash-chained record of every decision.
//
//   intentrax guard claude-code [--dir <dir>] [--local] [--mcp] [--dry-run] [--json]
//   intentrax guard status      [--dir <dir>] [--json]
//   intentrax guard verify      [--dir <dir>] [--json]
//   intentrax guard explain     --command '<shell command>' | --tool <name> [--input '<json>']
//   intentrax guard uninstall   [--dir <dir>] [--local] [--purge] [--dry-run]
//
// Exit codes: 0 ok; 2 verify found a broken chain, or the install or
// self-test failed; 1 usage.
//
// From a repository checkout, `node sdk/typescript/guard/cli.mjs <args>` runs
// the same thing.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { GUARD_DIR_REL, HOOK_MARKER, InstallError, MCP_ORIGINALS_REL, PINS_REL, RUNTIME_DIR_REL, checkRuntime, install, isProxiedEntry, settingsHasGuard, uninstall, wireMcp } from "./install.mjs";
import { NOT_TRUST_BEARING, VERIFY_STATUS, readRecords, verifyRecords } from "./records.mjs";
import { loadGuardPolicy, loadPackPolicy, packOptions } from "./policy.mjs";
import { classifyToolCall, protectedSet } from "./classify.mjs";

export const EXIT = Object.freeze({ OK: 0, USAGE: 1, FAILED: 2 });

// The one place the upgrade wording lives. Kept to what is true today.
// Switch to free-key wording ONLY once self-serve free keys (#556) are ON in
// production AND an admission returns a signed record. Until both hold, a free
// key does not turn these local records into signed, hosted-verifiable proofs,
// so this line must not say it does.
export const UPGRADE_LINE =
  "These records are local and not trust-bearing: anyone with access to this machine can rewrite them. " +
  "To have gated calls admitted and recorded by the hosted Intentrax engine instead, request a key: " +
  "https://www.intentrax.com/request-architectural-review";

class UsageError extends Error {}

export function usage(invokedAs = "intentrax guard") {
  return `Usage:
  ${invokedAs} claude-code [--dir <dir>] [--local] [--mcp] [--dry-run] [--json]
  ${invokedAs} status      [--dir <dir>] [--json]
  ${invokedAs} verify      [--dir <dir>] [--json]
  ${invokedAs} explain     --command '<shell command>' [--dir <dir>]
  ${invokedAs} explain     --tool <name> [--input '<json tool_input>'] [--dir <dir>]
  ${invokedAs} uninstall   [--dir <dir>] [--local] [--purge] [--dry-run]

claude-code installs a Claude Code PreToolUse hook (matcher "*") in
.claude/settings.json (--local: .claude/settings.local.json). Other settings
and hooks are kept. Each tool call is classified with the scan rules:
  block  denied, with the reason shown to Claude (force-push, rm -rf of a root
         or home, DROP/TRUNCATE, terraform destroy, edits to the guard itself...)
  ask    Claude Code asks you (git push, deploys, publishes, recursive deletes,
         SQL writes, consequential MCP tools...)
  allow  no objection; Claude Code's own permission rules still apply
No account, no network. If the hook cannot classify a call, it fails closed.

Every decision is appended to ${GUARD_DIR_REL}/records.jsonl, hash-chained and
signed with a key generated on this machine. verify checks the chain offline.
${NOT_TRUST_BEARING}

Policy: the built-in rules, plus policy packs in .intentrax/policy.jsonc
(\`intentrax policy init --from-scan\`) and guard rules in
${GUARD_DIR_REL}/policy.json (schema intentrax.guard.policy/v1). They can
tighten anything and relax a built-in "ask"; nothing relaxes a built-in "block".

--mcp also pins each stdio MCP server in .mcp.json (it starts each one once
to list its tools) and routes it through \`intentrax mcp proxy --on-drift
block\`, which refuses changed or new tools.

Exit codes: 0 ok, 2 broken chain or failed install/self-test, 1 usage.`;
}

const VALUE = new Set(["--dir", "--command", "--tool", "--input"]);
const BOOL = new Set(["--local", "--mcp", "--dry-run", "--json", "--purge", "--no-self-test", "--help", "-h"]);
const ALLOWED = {
  "claude-code": new Set(["--dir", "--local", "--mcp", "--dry-run", "--json", "--no-self-test"]),
  status: new Set(["--dir", "--json"]),
  verify: new Set(["--dir", "--json"]),
  explain: new Set(["--dir", "--command", "--tool", "--input", "--json"]),
  uninstall: new Set(["--dir", "--local", "--purge", "--dry-run", "--json"]),
};

export function parseGuardArgs(argv) {
  const [sub, ...rest] = argv;
  if (sub === undefined || sub === "--help" || sub === "-h" || sub === "help") return { sub: "help", opts: {} };
  if (!Object.hasOwn(ALLOWED, sub)) throw new UsageError(`unknown subcommand ${JSON.stringify(sub)} (expected claude-code, status, verify, explain or uninstall)`);
  const opts = {};
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a === "--help" || a === "-h") return { sub: "help", opts: {} };
    if (VALUE.has(a)) {
      if (rest[i + 1] === undefined) throw new UsageError(`${a} needs a value`);
      opts[a.slice(2)] = rest[i + 1];
      i += 1;
    } else if (BOOL.has(a)) opts[a.slice(2)] = true;
    else throw new UsageError(`unknown option ${a}`);
    if (!ALLOWED[sub].has(a)) throw new UsageError(`${a} is not an option of guard ${sub}`);
  }
  return { sub, opts };
}

function selfTest(projectDir) {
  const hook = join(projectDir, HOOK_MARKER);
  const input = {
    session_id: "intentrax-guard-self-test",
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: "git push --force origin main", description: "intentrax guard self-test (not run)" },
    tool_use_id: "intentrax-guard-self-test",
  };
  const run = spawnSync(process.execPath, [hook], { input: JSON.stringify(input), encoding: "utf8", env: { ...process.env, CLAUDE_PROJECT_DIR: projectDir }, timeout: 30_000 });
  let out = null;
  try {
    out = JSON.parse(run.stdout);
  } catch {
    // reported below
  }
  const ok = run.status === 0 && out?.hookSpecificOutput?.permissionDecision === "deny";
  return { ok, status: run.status, stderr: (run.stderr ?? "").trim(), output: out };
}

async function cmdInstall(projectDir, opts, io) {
  const started = Date.now();
  const res = install(projectDir, { local: Boolean(opts.local), dryRun: Boolean(opts["dry-run"]) });
  const lines = [...res.lines];
  let mcp = null;
  if (opts.mcp) {
    mcp = await wireMcp(projectDir, { dryRun: Boolean(opts["dry-run"]) });
    lines.push(...mcp.lines);
  }
  if (opts["dry-run"]) {
    const report = { schema: "intentrax.guard.install/v1", dry_run: true, project: projectDir, actions: lines, settings_file: res.plan.settingsRel, settings_after: JSON.parse(res.plan.after) };
    if (opts.json) io.out(JSON.stringify(report, null, 2) + "\n");
    else io.out(["intentrax guard (dry run; nothing written)", ...lines.map((l) => "  " + l), "", `${res.plan.settingsRel} would become:`, res.plan.after].join("\n"));
    return EXIT.OK;
  }
  let test = null;
  let verify = null;
  if (!opts["no-self-test"]) {
    test = selfTest(projectDir);
    verify = verifyRecords(join(projectDir, GUARD_DIR_REL));
  }
  const elapsedMs = Date.now() - started;
  const ok = !test || (test.ok && verify.status === VERIFY_STATUS.VALID);
  const report = {
    schema: "intentrax.guard.install/v1",
    dry_run: false,
    project: projectDir,
    actions: lines,
    settings_file: res.plan.settingsRel,
    self_test: test && { ok: test.ok, decision: test.output?.hookSpecificOutput?.permissionDecision ?? null, exit: test.status },
    first_record: verify && { status: verify.status, records: verify.records, last_seq: verify.last_seq ?? null },
    elapsed_ms: elapsedMs,
    trust_bearing: false,
    note: NOT_TRUST_BEARING,
  };
  if (opts.json) {
    io.out(JSON.stringify(report, null, 2) + "\n");
  } else {
    const out = ["intentrax guard: installed for Claude Code", ...lines.map((l) => "  " + l)];
    if (test) {
      out.push(test.ok
        ? `  self-test: \`git push --force origin main\` -> deny (not run); local record #${verify.last_seq} written, chain ${verify.status}`
        : `  self-test FAILED: hook exit ${test.status}${test.stderr ? ": " + test.stderr : ""}`);
    }
    out.push(
      "",
      `Done in ${(elapsedMs / 1000).toFixed(1)} s. Restart Claude Code (or open /hooks) so it loads the hook.`,
      "  npx @intentrax/sdk guard status     counts, chain and policy",
      "  npx @intentrax/sdk guard verify     re-check the local record chain offline",
      "  npx @intentrax/sdk guard uninstall  remove the hook (run it yourself; the guard blocks the agent from doing it)",
      "",
      UPGRADE_LINE,
      "",
    );
    io.out(out.join("\n"));
  }
  return ok ? EXIT.OK : EXIT.FAILED;
}

export async function statusReport(projectDir) {
  const guardDir = join(projectDir, GUARD_DIR_REL);
  const settings = {};
  const hooksDisabledBy = [];
  for (const rel of [".claude/settings.json", ".claude/settings.local.json"]) {
    const p = join(projectDir, rel);
    const text = existsSync(p) ? readFileSync(p, "utf8") : null;
    settings[rel] = text !== null && settingsHasGuard(text);
    try {
      if (text !== null && JSON.parse(text).disableAllHooks === true) hooksDisabledBy.push(rel);
    } catch {
      // reported by settingsHasGuard as not installed
    }
  }
  const runtime = checkRuntime(projectDir);
  const { policy, warnings } = loadGuardPolicy(projectDir);
  const packPolicy = await loadPackPolicy(projectDir);
  const verify = verifyRecords(guardDir);
  const records = readRecords(guardDir).filter(Boolean);
  const counts = { allow: 0, ask: 0, block: 0 };
  const rules = {};
  for (const r of records) {
    const v = r.decision?.verdict;
    if (Object.hasOwn(counts, v)) counts[v] += 1;
    if (v && v !== "allow") rules[r.decision.rule] = (rules[r.decision.rule] ?? 0) + 1;
  }
  let mcpProxied = 0;
  try {
    const mcp = JSON.parse(readFileSync(join(projectDir, ".mcp.json"), "utf8"));
    mcpProxied = Object.values(mcp.mcpServers ?? {}).filter(isProxiedEntry).length;
  } catch {
    // no .mcp.json
  }
  const last = records[records.length - 1] ?? null;
  return {
    schema: "intentrax.guard.status/v1",
    project: projectDir,
    hook_installed: Object.values(settings).some(Boolean),
    settings,
    hooks_disabled_by: hooksDisabledBy,
    runtime,
    policy: { name: policy.name, source: policy.source, rules: policy.rules.length, warnings: [...warnings, ...(packPolicy?.warnings ?? [])] },
    pack_policy: packPolicy && { source: packPolicy.source, applied: typeof packPolicy.evaluate === "function", packs: packPolicy.packs ?? [] },
    records: { total: records.length, ...counts, by_rule: rules },
    chain: { status: verify.status, problems: verify.problems },
    last: last && { seq: last.seq, recorded_at: last.recorded_at, tool_name: last.tool_name, verdict: last.decision?.verdict, rule: last.decision?.rule },
    mcp: { proxied_servers: mcpProxied, pins: existsSync(join(projectDir, PINS_REL)) ? PINS_REL : null, originals: existsSync(join(projectDir, MCP_ORIGINALS_REL)) },
    trust_bearing: false,
    note: NOT_TRUST_BEARING,
    upgrade: UPGRADE_LINE,
  };
}

async function cmdStatus(projectDir, opts, io) {
  const s = await statusReport(projectDir);
  if (opts.json) {
    io.out(JSON.stringify(s, null, 2) + "\n");
    return EXIT.OK;
  }
  const where = Object.entries(s.settings).filter(([, v]) => v).map(([k]) => k).join(", ");
  const top = Object.entries(s.records.by_rule).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, v]) => `${k} ${v}`).join(", ");
  const out = [
    "intentrax guard status (LOCAL, NOT TRUST-BEARING)",
    `  hook:     ${s.hook_installed ? `installed (${where}, PreToolUse, matcher *)` : "NOT installed (run: npx @intentrax/sdk guard claude-code)"}`,
    ...s.hooks_disabled_by.map((rel) => `            WARNING: ${rel} sets "disableAllHooks": true, so Claude Code runs no hooks and the guard is off`),
    `  runtime:  ${!s.runtime.installed ? "not installed" : s.runtime.intact ? `${RUNTIME_DIR_REL}/ intact (sdk ${s.runtime.sdk_version})` : `MODIFIED: ${s.runtime.problems.join(", ")} (reinstall with guard claude-code)`}`,
    `  policy:   ${s.policy.source === "built-in" ? "built-in default" : `${s.policy.source} (${s.policy.name}, ${s.policy.rules} rules)`}`,
    ...(s.pack_policy ? [`  packs:    ${s.pack_policy.applied ? `${s.pack_policy.source} (${s.pack_policy.packs.join(", ") || "no packs"})` : `${s.pack_policy.source} NOT applied (see warning)`}`] : []),
    ...s.policy.warnings.map((w) => `            warning: ${w}`),
    `  records:  ${s.records.total} (block ${s.records.block}, ask ${s.records.ask}, allow ${s.records.allow})${top ? `; top rules: ${top}` : ""}`,
    `  chain:    ${s.chain.status}${s.chain.problems.length ? ` (${s.chain.problems[0].message}; run guard verify)` : ""}`,
  ];
  if (s.last) out.push(`  last:     #${s.last.seq} ${s.last.recorded_at} ${s.last.tool_name} ${s.last.verdict} (${s.last.rule})`);
  if (s.mcp.proxied_servers) out.push(`  mcp:      ${s.mcp.proxied_servers} server(s) behind intentrax mcp proxy (pins ${s.mcp.pins ?? "missing"})`);
  out.push("", s.upgrade, "");
  io.out(out.join("\n"));
  return EXIT.OK;
}

function cmdVerify(projectDir, opts, io) {
  const v = verifyRecords(join(projectDir, GUARD_DIR_REL));
  const broken = v.status === VERIFY_STATUS.BROKEN;
  if (opts.json) io.out(JSON.stringify({ schema: "intentrax.guard.verify/v1", ...v, trust_bearing: false }, null, 2) + "\n");
  else if (broken) {
    io.out([`${v.status}: ${v.records} record(s) check out, then:`, ...v.problems.map((p) => `  line ${p.line}: ${p.message}`), NOT_TRUST_BEARING, ""].join("\n"));
  } else {
    io.out(`${v.status}: ${v.records} record(s), hashes, chain, signatures and head check out.\n${NOT_TRUST_BEARING}\n`);
  }
  return broken ? EXIT.FAILED : EXIT.OK;
}

async function cmdExplain(projectDir, opts, io) {
  let call;
  if (opts.command !== undefined) call = { tool_name: opts.tool ?? "Bash", tool_input: { command: opts.command } };
  else if (opts.tool !== undefined) {
    let input = {};
    if (opts.input !== undefined) {
      try {
        input = JSON.parse(opts.input);
      } catch (e) {
        throw new UsageError(`--input is not valid JSON (${e.message})`);
      }
    }
    call = { tool_name: opts.tool, tool_input: input };
  } else throw new UsageError("explain needs --command or --tool");
  const { policy, warnings } = loadGuardPolicy(projectDir);
  const packPolicy = await loadPackPolicy(projectDir);
  if (packPolicy) warnings.push(...packPolicy.warnings);
  const d = classifyToolCall(call, packOptions(packPolicy, policy, projectDir, protectedSet));
  if (opts.json) io.out(JSON.stringify({ ...d, policy: policy.source, warnings }, null, 2) + "\n");
  else io.out(`${d.verdict.toUpperCase()} (${d.rule}, ${d.category}): ${d.reason}\n  policy: ${policy.source}${packPolicy?.evaluate ? ` + ${packPolicy.source}` : ""}; nothing was run or recorded\n`);
  return EXIT.OK;
}

export async function guardMain(argv = [], io = {}) {
  const out = io.out ?? ((s) => process.stdout.write(s));
  const err = io.err ?? ((s) => process.stderr.write(s));
  const invokedAs = io.invokedAs ?? "intentrax guard";
  let parsed;
  try {
    parsed = parseGuardArgs(argv);
  } catch (e) {
    err(`intentrax guard: ${e.message}\n${usage(invokedAs)}\n`);
    return EXIT.USAGE;
  }
  if (parsed.sub === "help") {
    out(usage(invokedAs) + "\n");
    return EXIT.OK;
  }
  const { sub, opts } = parsed;
  const projectDir = resolve(io.cwd ?? process.cwd(), opts.dir ?? ".");
  try {
    switch (sub) {
      case "claude-code":
        return await cmdInstall(projectDir, opts, { out, err });
      case "status":
        return await cmdStatus(projectDir, opts, { out, err });
      case "verify":
        return cmdVerify(projectDir, opts, { out, err });
      case "explain":
        return await cmdExplain(projectDir, opts, { out, err });
      case "uninstall": {
        const r = uninstall(projectDir, { local: Boolean(opts.local), purge: Boolean(opts.purge), dryRun: Boolean(opts["dry-run"]) });
        if (opts.json) out(JSON.stringify({ schema: "intentrax.guard.uninstall/v1", actions: r.lines }, null, 2) + "\n");
        else out(["intentrax guard uninstall" + (opts["dry-run"] ? " (dry run)" : ""), ...r.lines.map((l) => "  " + l), ""].join("\n"));
        return EXIT.OK;
      }
      default:
        return EXIT.USAGE;
    }
  } catch (e) {
    if (e instanceof UsageError) {
      err(`intentrax guard: ${e.message}\n`);
      return EXIT.USAGE;
    }
    err(`intentrax guard ${sub}: ${e instanceof InstallError ? e.message : `unexpected error: ${e?.message ?? e}`}\n`);
    return EXIT.FAILED;
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
  process.exitCode = await guardMain(process.argv.slice(2), { invokedAs: "node sdk/typescript/guard/cli.mjs" });
}
