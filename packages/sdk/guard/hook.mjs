#!/usr/bin/env node
// Claude Code PreToolUse hook for `intentrax guard`.
//
// `guard claude-code` copies this file and the modules it needs into
// <project>/.intentrax/guard/runtime/ and registers
//   node "$CLAUDE_PROJECT_DIR/.intentrax/guard/runtime/guard/hook.mjs"
// as a PreToolUse command hook (matcher "*").
//
// Contract (Claude Code hooks): the tool call arrives as JSON on stdin.
//   block -> stdout {"hookSpecificOutput":{"hookEventName":"PreToolUse",
//            "permissionDecision":"deny","permissionDecisionReason":...}}
//   ask   -> the same with "ask" (Claude Code asks the user)
//   allow -> no output, exit 0: no objection, and Claude Code's own
//            permission rules and modes apply unchanged (the guard never
//            auto-approves anything)
// Every decision is appended to .intentrax/guard/records.jsonl (local, signed
// with a local key, NOT trust-bearing).
//
// Fails closed. If the input cannot be read or the call cannot be classified,
// it exits 2: Claude Code treats that as a block and shows stderr to Claude.
// Other modules load through dynamic import inside the try, so a missing or
// broken runtime file also exits 2 and does not fail open (a non-2 crash would
// let the call through). If the record cannot be written, a block or ask still
// stands. An allow still passes, with a warning on stderr.
//
// Extension point (T4): `decide()` returns the decision before output. A
// later step can require a valid signed approval for block/ask-class calls and
// re-check `arguments_hash` (spec 01 §4, computed here over tool_input) at
// execute time, without changing the output contract.

import { readFileSync, realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const HOOK_EVENT = "PreToolUse";
const FAIL_CLOSED_EXIT = 2;

export function hookOutput(decision, seq) {
  if (decision.verdict === "allow") return null;
  const where = seq ? ` [intentrax guard: local record #${seq}, not trust-bearing]` : " [intentrax guard]";
  const prefix = decision.verdict === "block" ? "Blocked by intentrax guard: " : "intentrax guard asks: ";
  return {
    hookSpecificOutput: {
      hookEventName: HOOK_EVENT,
      permissionDecision: decision.verdict === "block" ? "deny" : "ask",
      permissionDecisionReason: `${prefix}${decision.reason} (rule ${decision.rule})${where}`,
    },
  };
}

// The runtime lives at <guardDir>/runtime/guard/hook.mjs; in the SDK package
// (tests, `guard test`) the caller passes guardDir explicitly.
export function defaultGuardDir() {
  return resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
}

// decide(input, { guardDir, projectDir }) -> { decision, record, recordError }
export async function decide(input, { guardDir, projectDir, now, importPacks } = {}) {
  const { classifyToolCall, protectedSet } = await import("./classify.mjs");
  const { loadGuardPolicy, loadPackPolicy, packOptions } = await import("./policy.mjs");
  const { appendRecord } = await import("./records.mjs");
  const { summarize, argumentsHash } = await import("./summary.mjs");

  const { policy, warnings } = loadGuardPolicy(projectDir);
  const packPolicy = await loadPackPolicy(projectDir, importPacks ? { importPacks } : undefined);
  if (packPolicy) warnings.push(...packPolicy.warnings);
  const decision = classifyToolCall(input, packOptions(packPolicy, policy, projectDir, protectedSet));
  let record = null;
  let recordError = null;
  try {
    const args = argumentsHash(input.tool_input ?? {});
    record = appendRecord(guardDir, {
      source: "claude-code.PreToolUse",
      session_id: typeof input.session_id === "string" ? input.session_id.slice(0, 200) : null,
      tool_use_id: typeof input.tool_use_id === "string" ? input.tool_use_id.slice(0, 200) : null,
      tool_name: String(input.tool_name).slice(0, 200),
      arguments_hash: args.hash,
      arguments_hash_rule: args.rule,
      summary: summarize(input),
      decision: {
        verdict: decision.verdict,
        category: decision.category,
        rule: decision.rule,
        reason: decision.reason,
        builtin_verdict: decision.builtin.verdict,
        policy_name: policy.name,
        policy_source: policy.source,
        policy_hash: policy.hash,
        ...(packPolicy ? { pack_policy_source: packPolicy.source, pack_policy_applied: typeof packPolicy.evaluate === "function" } : {}),
        ...(decision.packs ? { packs: decision.packs } : {}),
      },
      hook_output: decision.verdict === "allow" ? "none" : decision.verdict === "block" ? "deny" : "ask",
    }, now ? { now } : undefined);
  } catch (e) {
    recordError = e;
  }
  return { decision, record, recordError, warnings };
}

export async function runHook({ stdinText, guardDir = defaultGuardDir(), projectDir, out = (s) => process.stdout.write(s), err = (s) => process.stderr.write(s), now, importPacks } = {}) {
  // The project is the directory that holds .intentrax/guard, wherever the
  // agent has cd'ed to.
  const project = projectDir ?? resolve(guardDir, "..", "..");
  let input;
  try {
    input = JSON.parse(stdinText);
    if (!input || typeof input !== "object" || typeof input.tool_name !== "string") throw new Error("missing tool_name");
  } catch (e) {
    err(`intentrax guard: could not read the PreToolUse input (${e.message}); failing closed.\n`);
    return FAIL_CLOSED_EXIT;
  }
  let result;
  try {
    result = await decide(input, { guardDir, projectDir: project, now, importPacks });
  } catch (e) {
    err(`intentrax guard: could not classify ${String(input.tool_name).slice(0, 80)} (${e?.message ?? e}); failing closed. Run \`npx @intentrax/sdk guard status\`.\n`);
    return FAIL_CLOSED_EXIT;
  }
  const { decision, record, recordError, warnings } = result;
  for (const w of warnings) err(`intentrax guard: policy warning: ${w}\n`);
  if (recordError) err(`intentrax guard: could not write the local record (${recordError.message}); the ${decision.verdict} decision still applies.\n`);
  const output = hookOutput(decision, record?.seq);
  if (output) out(JSON.stringify(output) + "\n");
  return 0;
}

function invokedDirectly() {
  try {
    return Boolean(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  const failClosed = (e) => {
    try {
      process.stderr.write(`intentrax guard: internal error (${e?.message ?? e}); failing closed.\n`);
    } finally {
      process.exit(FAIL_CLOSED_EXIT);
    }
  };
  process.on("uncaughtException", failClosed);
  process.on("unhandledRejection", failClosed);
  let stdinText = "";
  try {
    stdinText = readFileSync(0, "utf8");
  } catch (e) {
    failClosed(e);
  }
  runHook({ stdinText }).then((code) => {
    process.exitCode = code;
  }, failClosed);
}
