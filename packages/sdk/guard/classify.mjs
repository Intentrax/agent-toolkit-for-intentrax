// classifyToolCall: one Claude Code tool call -> allow / ask / block.
//
//   Bash, PowerShell          shell.mjs command rules
//   Edit, Write, MultiEdit,   path rules (guard self-protection, secrets,
//   NotebookEdit, Read        .git internals, outside the project)
//   mcp__<server>__<tool>     scan/classify.mjs classifyAction on the tool name
//                             (the same rules `intentrax scan` uses), plus SQL
//                             found in the tool's string arguments
//   anything else             allow (no objection)
//
// "allow" means no objection: the hook emits no decision, so Claude Code's
// own permission rules and modes still apply unchanged.
//
// Then the project policy (policy.mjs): rules can tighten anything; a rule
// with verdict "allow" can lower a built-in "ask"; nothing lowers a built-in
// "block".

import { realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { CATEGORIES, classifyAction } from "../scan/classify.mjs";
import { tokenize } from "../scan/text.mjs";
import { CLAUDE_SETTINGS, GUARD_PROTECTED, VERDICT_RANK, classifyCommandLine, classifySqlText, isReadOnlySegment, splitCommandLine, stricter, words } from "./shell.mjs";
import { COMPILED_DEFAULT } from "./policy.mjs";

export const SHELL_TOOLS = new Set(["Bash", "PowerShell"]);
export const WRITE_TOOLS = new Set(["Edit", "Write", "MultiEdit", "NotebookEdit"]);
export const READ_TOOLS = new Set(["Read"]);

const SECRET_PATH = /(?:^|\/)(?:\.env(?:\.[^/]*)?|\.envrc|\.npmrc|\.pypirc|\.netrc|\.git-credentials|credentials(?:\.json)?|id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|[^/]*\.(?:pem|key|p12|pfx|jks|keystore))$|(?:^|\/)\.(?:aws|ssh|gnupg|kube|docker)\//i;

const MONEY_NOUNS = new Set(["refund", "payment", "transfer", "payout", "charge", "invoice", "subscription", "withdrawal", "wire", "disbursement", "remittance", "transaction", "checkout"]);

const ALLOW = Object.freeze({ verdict: "allow", category: "read", rule: "default-allow", reason: "no guard objection" });

function D(verdict, category, rule, reason) {
  return { verdict, category, rule, reason };
}

export function parseMcpToolName(name) {
  const m = /^mcp__(.+?)__(.+)$/.exec(String(name));
  return m ? { server: m[1], tool: m[2] } : null;
}

function filePathOf(input) {
  const i = input ?? {};
  for (const k of ["file_path", "notebook_path", "path"]) if (typeof i[k] === "string" && i[k]) return i[k];
  return null;
}

// Project-relative path with / separators, or null when outside the project.
export function projectRelative(projectDir, p) {
  if (!projectDir || typeof p !== "string") return null;
  const abs = isAbsolute(p) ? p : resolve(projectDir, p);
  const rel = relative(projectDir, abs).replace(/\\/g, "/");
  if (rel === "" ) return ".";
  if (rel.startsWith("../") || rel === ".." || isAbsolute(rel) || /^[A-Za-z]:/.test(rel)) return null;
  return rel;
}

// The path the filesystem will actually touch: `.` and `..` resolved against
// the project, and symlinks resolved through the deepest existing ancestor
// (the target itself may not exist yet for a Write). Separators are `/`.
export function canonicalPath(projectDir, raw) {
  const abs = resolve(projectDir ?? process.cwd(), raw);
  let existing = abs;
  const rest = [];
  for (let i = 0; i < 64; i += 1) {
    try {
      const real = realpathSync(existing);
      return (rest.length ? join(real, ...rest.reverse()) : real).replace(/\\/g, "/");
    } catch {
      const parent = dirname(existing);
      if (parent === existing) break;
      rest.push(basename(existing));
      existing = parent;
    }
  }
  return abs.replace(/\\/g, "/");
}

const SELF_PROTECTION = D("block", "destructive", "guard-self-protection", "changes the Intentrax guard's own files (hook runtime, record, keys, guard rules), the pack policy, a pack it references or the MCP pins; make that change yourself, outside the agent");

// Canonical, comparable form of a set of absolute paths (case-folded on
// Windows and macOS default filesystems, where case does not distinguish).
function pathKey(p) {
  return process.platform === "win32" || process.platform === "darwin" ? p.toLowerCase() : p;
}

export function protectedSet(projectDir, paths = []) {
  return new Set(paths.map((p) => pathKey(canonicalPath(projectDir, p))));
}

// A shell line that writes to, moves or deletes one of `extra` (canonical
// keys): any word naming such a path in a command that is not read-only.
function shellTouchesProtected(command, projectDir, extra) {
  if (!extra || extra.size === 0) return false;
  const { segments, nested } = splitCommandLine(command);
  for (const seg of [...segments, ...nested]) {
    const hits = words(seg)
      .map((w) => w.replace(/^(?:\d*|&)>>?\|?/, ""))
      .filter((w) => w && !w.startsWith("-") && /[./\\]/.test(w))
      .some((w) => extra.has(pathKey(canonicalPath(projectDir, w))));
    if (hits && !isReadOnlySegment(seg)) return true;
  }
  return false;
}

function classifyPath(toolName, input, projectDir, extraProtected) {
  const raw = filePathOf(input);
  if (raw === null) return null;
  // Check both the literal path and the canonical one, so `.intentrax/./guard`,
  // `x/../.claude/settings.json` or a symlink into the guard cannot slip past.
  const canon = canonicalPath(projectDir, raw);
  const forms = [raw.replace(/\\/g, "/"), canon];
  const norm = canon;
  const write = WRITE_TOOLS.has(toolName);
  if (write && extraProtected?.has(pathKey(canon))) return SELF_PROTECTION;
  if (write && forms.some((p) => GUARD_PROTECTED.some((re) => re.test(p)))) {
    return D("block", "destructive", "guard-self-protection", "changes the Intentrax guard's own files (hook runtime, record, keys, guard rules), the pack policy or the MCP pins; make that change yourself, outside the agent");
  }
  if (write && forms.some((p) => CLAUDE_SETTINGS.some((re) => re.test(p)))) {
    return D("ask", "access", "claude-settings-change", "changes the Claude Code settings or .mcp.json that wire in the Intentrax guard (and your permission rules or MCP servers)");
  }
  if (forms.some((p) => SECRET_PATH.test(p))) {
    return D("ask", write ? "write" : "read", write ? "secret-file-write" : "secret-file-read", write ? "writes a credentials or key file" : "reads a credentials or key file into the agent's context");
  }
  if (write && /(?:^|\/)\.git\/(?!COMMIT_EDITMSG$|MERGE_MSG$)/.test(norm)) {
    return D("ask", "destructive", "git-internals-write", "writes inside .git (repository internals)");
  }
  // Outside the project by its literal path, or by where it really lands (a
  // symlinked folder inside the project that points elsewhere).
  if (write && projectDir && (projectRelative(projectDir, raw) === null || projectRelative(canonicalPath(projectDir, "."), canon) === null)) {
    return D("ask", "write", "write-outside-project", "writes a file outside the project directory");
  }
  return null;
}

// String values of an MCP tool's arguments (two levels deep, capped).
// String values of an MCP tool's arguments (two levels deep, capped). With
// `onlySqlKeys`, only values under keys that name a query or statement, so a
// chat message that mentions "DROP TABLE" is not read as SQL.
const SQL_KEYS = /^(?:sql|query|queries|statement|statements|command|cmd|script|stmt|q|body)$|sql|query|statement/i;

function stringValues(input, { onlySqlKeys = false } = {}, out = [], depth = 0, key = null) {
  if (out.length > 200 || depth > 2) return out;
  if (typeof input === "string") {
    if (!onlySqlKeys || (key !== null && SQL_KEYS.test(key))) out.push(input);
  } else if (Array.isArray(input)) for (const v of input) stringValues(v, { onlySqlKeys }, out, depth + 1, key);
  else if (input && typeof input === "object") for (const [k, v] of Object.entries(input)) stringValues(v, { onlySqlKeys }, out, depth + 1, k);
  return out;
}

const SQL_TOOL_WORDS = new Set(["sql", "query", "queries", "execute", "exec", "run", "statement", "db", "database", "postgres", "postgresql", "pg", "mysql", "mariadb", "sqlite", "mssql", "mongo", "mongodb", "redis", "supabase", "neon", "snowflake", "bigquery", "clickhouse", "dynamodb", "cockroach", "turso", "planetscale", "prisma"]);

function classifyMcp(name, input, policy) {
  const parsed = parseMcpToolName(name);
  if (!parsed) return null;
  let c = classifyAction({ name: parsed.tool });
  // scan reads "refund" in "create_refund" as a noun (so "get_refund" stays
  // read-only). For a gate, a write-class tool whose name names money is
  // financial.
  if (c.category === "write" || c.category === "unclassified") {
    const money = tokenize(parsed.tool).find((t) => MONEY_NOUNS.has(t) || MONEY_NOUNS.has(t.replace(/s$/, "")));
    if (money) c = { ...c, category: "financial", label: CATEGORIES.financial.label, reasons: [`name mentions "${money}" with a write verb`] };
  }
  const verdict = policy.categories[c.category] ?? "allow";
  let best = D(verdict, c.category, `mcp-${c.category}`, `MCP tool ${parsed.tool} on server ${parsed.server} ${c.label} (${c.reasons[0] ?? "heuristic"})`);
  const prod = /prod|production|live/i.test(parsed.server);
  // Database-like servers or tools: every string argument may be SQL. Others:
  // only arguments whose key names a query or statement.
  const sqlTool = c.category === "database" || c.category === "shell" || tokenize(`${parsed.server} ${parsed.tool}`).some((t) => SQL_TOOL_WORDS.has(t));
  for (const s of stringValues(input, { onlySqlKeys: !sqlTool })) {
    const sql = classifySqlText(s, { prodHint: prod });
    if (sql) best = stricter(best, { ...sql, reason: sql.reason + ` (in the arguments of MCP tool ${parsed.tool})` });
  }
  return best;
}

function ruleMatches(rule, toolName, input, projectDir) {
  if (!rule.tools.some((re) => re.test(toolName))) return false;
  if (rule.command) {
    const cmd = input?.command;
    if (typeof cmd !== "string") return false;
    const { segments, nested } = splitCommandLine(cmd);
    if (![cmd, ...segments, ...nested].some((s) => rule.command.test(s))) return false;
  }
  if (rule.paths) {
    const raw = filePathOf(input);
    if (raw === null) return false;
    const rel = projectRelative(projectDir, raw) ?? raw.replace(/\\/g, "/");
    if (!rule.paths.some((re) => re.test(rel))) return false;
  }
  if (rule.input) {
    for (const [field, re] of rule.input) {
      const v = input?.[field];
      const s = typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : null;
      if (s === null || !re.test(s)) return false;
    }
  }
  return true;
}

// How far a set of allow rules covers the ask-class parts of a command line:
//   "single"    one simple command and no substitution: a whole-call allow
//               applies to exactly that command
//   "covered"   several commands; every one that asks is matched by an allow
//               rule on its own
//   "uncovered" anything else, including any $(...) or backtick substitution
//               and asks that come from the line as a whole (`curl … | sh`)
const INNER_SHELL = /(?:^|[\s;|&(])(?:(?:ba|z|da|k|fi)?sh|pwsh|powershell|cmd)(?:\.exe)?\s+(?:\S+\s+)*?(?:-\w*c\b|-command\b|\/c\b)|(?:^|\s)(?:eval|xargs|iex|invoke-expression)(?:\s|$)/i;

export function shellAskCoverage(command, allowRules = []) {
  const { segments, nested } = splitCommandLine(command);
  if (nested.length > 0) return "uncovered";
  // A shell body (`bash -c '…'`, `eval`, `xargs`, `cmd /c`) hides further
  // commands inside one segment: never relaxed.
  if (segments.some((s) => INNER_SHELL.test(s))) return "uncovered";
  if (segments.length <= 1) return "single";
  const asking = segments.filter((s) => classifyCommandLine(s)?.verdict === "ask");
  if (asking.length === 0) return "uncovered";
  const covered = asking.every((s) => allowRules.some((r) => r.command && r.command.test(s)));
  return covered ? "covered" : "uncovered";
}

// classifyToolCall({ tool_name, tool_input }, { policy, projectDir, evaluatePacks })
//   -> { verdict, category, rule, reason, builtin, packs? }
// evaluatePacks: optional, from policy.mjs loadPackPolicy(); a throw propagates
// (the hook then fails closed).
export function classifyToolCall(call, { policy = COMPILED_DEFAULT, projectDir = null, evaluatePacks = null, packDegraded = null, extraProtected = null } = {}) {
  if (!call || typeof call !== "object") throw new TypeError("tool call must be an object");
  const toolName = call.tool_name;
  if (typeof toolName !== "string" || toolName.length === 0) throw new TypeError("tool_name is required");
  const input = call.tool_input && typeof call.tool_input === "object" ? call.tool_input : {};

  let builtin = null;
  if (SHELL_TOOLS.has(toolName)) {
    if (typeof input.command !== "string") throw new TypeError(`${toolName}: tool_input.command must be a string`);
    builtin = classifyCommandLine(input.command);
    if (shellTouchesProtected(input.command, projectDir, extraProtected)) builtin = stricter(builtin, SELF_PROTECTION);
  } else if (WRITE_TOOLS.has(toolName) || READ_TOOLS.has(toolName)) {
    builtin = classifyPath(toolName, input, projectDir, extraProtected);
  } else if (toolName.startsWith("mcp__")) {
    builtin = classifyMcp(toolName, input, policy);
  }
  builtin = builtin ?? ALLOW;

  // Policy rules: strictest match, and whether any matching rule allows.
  let fromPolicy = null;
  let policyAllows = null;
  const allowRules = [];
  for (const rule of policy.rules) {
    if (!ruleMatches(rule, toolName, input, projectDir)) continue;
    const d = { verdict: rule.verdict, category: builtin.category, rule: `policy:${rule.id}`, reason: rule.reason };
    if (rule.verdict === "allow") {
      policyAllows = policyAllows ?? d;
      allowRules.push(rule);
    } else fromPolicy = stricter(fromPolicy, d);
  }

  // Policy packs: evaluated by the policy-packs module (C2 policies). "none"
  // means no pack matched: no opinion.
  let packs = null;
  let packAllows = null;
  if (typeof evaluatePacks === "function") {
    const out = evaluatePacks({ tool_name: toolName, tool_input: input });
    packs = (out.results ?? []).map(packRecord);
    if (out.decision !== "none") {
      const first = (out.results ?? []).find((r) => r.decision === out.decision);
      const d = { verdict: out.decision, category: builtin.category, rule: first ? `pack:${first.pack_id}/${first.matcher_id}` : "pack", reason: out.reason };
      if (out.decision === "allow") packAllows = d;
      else fromPolicy = stricter(fromPolicy, d);
    }
  }

  // An allow lowers a built-in ask only for what it actually covers. On a
  // shell line with several commands, each ask-class command needs its own
  // allow rule: an exception for `git push origin feature/x` must not let
  // `&& rm -rf data` through. Packs judge the whole call, so a pack allow
  // counts only for a single simple command.
  let relax = null;
  if (builtin.verdict === "ask" && !fromPolicy && (policyAllows || packAllows)) {
    if (!SHELL_TOOLS.has(toolName)) relax = policyAllows ?? packAllows;
    else {
      const cover = shellAskCoverage(input.command, allowRules);
      if (cover === "single") relax = policyAllows ?? packAllows;
      else if (cover === "covered") relax = policyAllows;
    }
  }

  let final = builtin;
  if (relax) final = relax;
  if (fromPolicy && VERDICT_RANK[fromPolicy.verdict] > VERDICT_RANK[final.verdict]) final = fromPolicy;
  // The project has a pack policy that cannot be applied (edited pack, hash
  // mismatch, missing module): never quietly fall back to the built-in rules.
  // Every consequential call asks until the policy loads again.
  if (packDegraded && final.verdict === "allow" && (SHELL_TOOLS.has(toolName) || WRITE_TOOLS.has(toolName) || toolName.startsWith("mcp__"))) {
    final = D("ask", builtin.category, "pack-policy-unavailable",
      "the project's pack policy (.intentrax/policy.jsonc) cannot be applied (" + String(packDegraded).slice(0, 200) +
      "), so the guard asks before every shell, write and MCP call; fix the policy or run `intentrax policy check`");
  }
  const result = {
    verdict: final.verdict,
    category: final.category,
    rule: final.rule,
    reason: final.reason,
    builtin: { verdict: builtin.verdict, rule: builtin.rule },
  };
  if (packs) result.packs = packs;
  return result;
}

// What a guard record keeps about each matched pack: enough to re-check the
// decision from the event and source_policy_hash (the fact derivation itself is
// local and self-reported: facts_source LOCAL_GUARD_DERIVED).
function packRecord(r) {
  const s = (v) => (typeof v === "string" ? v : null);
  return {
    pack_id: s(r.pack_id),
    pack_version: s(r.pack_version),
    pack_hash: s(r.pack_hash),
    source_policy_hash: s(r.source_policy_hash),
    compiled_policy_hash: s(r.compiled_policy_hash),
    matcher_id: s(r.matcher_id),
    action: s(r.action),
    decision: s(r.decision),
    vm_decision: s(r.evaluation?.decision),
    rule_id: s(r.evaluation?.rule_id),
    execution_event_hash: s(r.evaluation?.execution_event_hash),
    evaluation_hash: s(r.evaluation?.evaluation_hash),
    facts_source: s(r.facts_source),
  };
}
