// Guard policy: the built-in default and the loader for project policy files.
//
// Data only. A policy file is JSON and nothing in it is evaluated as code, so
// a policy pack cannot ship code into the vendored hook runtime.
//
// Two optional sources, both applied:
//   .intentrax/guard/policy.json   hand-written guard rules,
//                                  schema intentrax.guard.policy/v1 (below)
//   .intentrax/policy.jsonc        policy packs (intentrax.policy_file/0.1,
//                                  written by `intentrax policy init
//                                  --from-scan`), evaluated by the SDK's
//                                  policy-packs module: each decision comes
//                                  from a C2 policy with pack_hash,
//                                  source_policy_hash and evaluation hashes
//
// Combination rule (see classify.mjs): the strictest verdict wins, except that
// an "allow" from a rule or pack may lower a built-in "ask". Nothing lowers a
// built-in "block". A source that cannot be loaded is skipped with a warning;
// the built-in rules always apply.

import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { createHash } from "node:crypto";

export const GUARD_POLICY_SCHEMA = "intentrax.guard.policy/v1";
export const VERDICTS = Object.freeze(["allow", "ask", "block"]);
export const POLICY_PATHS = Object.freeze([".intentrax/guard/policy.json"]);
export const PACK_POLICY_PATH = ".intentrax/policy.jsonc";

// MCP tools are classified by scan/classify.mjs into these categories. The
// default verdict per category; projects override it with `categories`.
export const DEFAULT_CATEGORY_VERDICTS = Object.freeze({
  destructive: "ask",
  financial: "ask",
  shell: "ask",
  database: "ask",
  infrastructure: "ask",
  deploy: "ask",
  communication: "ask",
  access: "ask",
  browser: "allow",
  write: "allow",
  unknown: "allow",
  read: "allow",
  unclassified: "allow",
});

export class GuardPolicyError extends Error {}

export const DEFAULT_POLICY = Object.freeze({
  schema: GUARD_POLICY_SCHEMA,
  name: "intentrax-default",
  categories: DEFAULT_CATEGORY_VERDICTS,
  rules: Object.freeze([]),
});

function isObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

// `*` glob over tool names (no other metacharacters).
export function toolGlob(pattern) {
  const re = "^" + String(pattern).split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*") + "$";
  return new RegExp(re);
}

// Path glob: `**` any depth, `*` within one segment, `?` one char.
export function pathGlob(pattern) {
  let re = "";
  const p = String(pattern).replace(/\\/g, "/");
  for (let i = 0; i < p.length; i += 1) {
    const c = p[i];
    if (c === "*" && p[i + 1] === "*") {
      if (p[i + 2] === "/") {
        re += "(?:.*/)?";
        i += 2;
      } else {
        re += ".*";
        i += 1;
      }
    } else if (c === "*") re += "[^/]*";
    else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp("^" + re + "$", "i");
}

function compileRegex(src, where) {
  if (typeof src !== "string" || src.length === 0 || src.length > 2000) throw new GuardPolicyError(where + " must be a non-empty regex string (max 2000 chars)");
  try {
    return new RegExp(src, "i");
  } catch (e) {
    throw new GuardPolicyError(where + " is not a valid regex: " + e.message);
  }
}

// normalizeGuardPolicy(doc) -> compiled policy. Throws GuardPolicyError on a
// bad shape: a malformed policy is never half-applied.
export function normalizeGuardPolicy(doc, { source = "inline" } = {}) {
  if (!isObject(doc)) throw new GuardPolicyError("policy must be a JSON object");
  if (doc.schema !== GUARD_POLICY_SCHEMA) throw new GuardPolicyError(`policy schema must be ${GUARD_POLICY_SCHEMA}`);
  const categories = { ...DEFAULT_CATEGORY_VERDICTS };
  if (doc.categories !== undefined) {
    if (!isObject(doc.categories)) throw new GuardPolicyError("categories must be an object");
    for (const [k, v] of Object.entries(doc.categories)) {
      if (!Object.hasOwn(DEFAULT_CATEGORY_VERDICTS, k)) throw new GuardPolicyError(`unknown category ${JSON.stringify(k)}`);
      if (!VERDICTS.includes(v)) throw new GuardPolicyError(`category ${k}: verdict must be allow, ask or block`);
      categories[k] = v;
    }
  }
  const rules = [];
  if (doc.rules !== undefined) {
    if (!Array.isArray(doc.rules)) throw new GuardPolicyError("rules must be an array");
    if (doc.rules.length > 500) throw new GuardPolicyError("at most 500 rules");
    doc.rules.forEach((r, i) => {
      const where = `rules[${i}]`;
      if (!isObject(r)) throw new GuardPolicyError(`${where} must be an object`);
      if (typeof r.id !== "string" || !/^[A-Za-z0-9._-]{1,80}$/.test(r.id)) throw new GuardPolicyError(`${where}.id must match [A-Za-z0-9._-]{1,80}`);
      if (!VERDICTS.includes(r.verdict)) throw new GuardPolicyError(`${where}.verdict must be allow, ask or block`);
      if (!Array.isArray(r.tools) || r.tools.length === 0 || !r.tools.every((t) => typeof t === "string" && t.length > 0)) {
        throw new GuardPolicyError(`${where}.tools must be a non-empty array of tool names or * globs`);
      }
      const rule = {
        id: r.id,
        verdict: r.verdict,
        reason: typeof r.reason === "string" ? r.reason.slice(0, 300) : `policy rule ${r.id}`,
        tools: r.tools.map(toolGlob),
        command: r.command_regex === undefined ? null : compileRegex(r.command_regex, `${where}.command_regex`),
        paths: null,
        input: null,
      };
      if (r.path_glob !== undefined) {
        const globs = typeof r.path_glob === "string" ? [r.path_glob] : r.path_glob;
        if (!Array.isArray(globs) || globs.length === 0 || !globs.every((g) => typeof g === "string" && g)) throw new GuardPolicyError(`${where}.path_glob must be a string or array of strings`);
        rule.paths = globs.map(pathGlob);
      }
      if (r.input_regex !== undefined) {
        if (!isObject(r.input_regex) || Object.keys(r.input_regex).length === 0) throw new GuardPolicyError(`${where}.input_regex must be an object of field -> regex`);
        rule.input = Object.entries(r.input_regex).map(([field, src]) => [field, compileRegex(src, `${where}.input_regex.${field}`)]);
      }
      rules.push(Object.freeze(rule));
    });
  }
  const hash = createHash("sha256").update(JSON.stringify(doc)).digest("hex");
  return Object.freeze({ name: typeof doc.name === "string" ? doc.name.slice(0, 80) : "unnamed", source, hash, categories: Object.freeze(categories), rules: Object.freeze(rules) });
}

export const COMPILED_DEFAULT = normalizeGuardPolicy({ schema: GUARD_POLICY_SCHEMA, name: "intentrax-default" }, { source: "built-in" });

// loadGuardPolicy(projectDir) -> { policy, source, warnings }. Never throws:
// a missing file means the built-in default; a malformed one means the
// built-in default plus a warning (the built-in blocks always apply).
export function loadGuardPolicy(projectDir) {
  const warnings = [];
  for (const rel of POLICY_PATHS) {
    const path = join(projectDir, rel);
    if (!existsSync(path)) continue;
    let doc;
    try {
      doc = JSON.parse(readFileSync(path, "utf8"));
    } catch (e) {
      warnings.push(`${rel}: not valid JSON (${e.message}); using the built-in policy`);
      return { policy: COMPILED_DEFAULT, source: "built-in", warnings };
    }
    try {
      return { policy: normalizeGuardPolicy(doc, { source: rel }), source: rel, warnings };
    } catch (e) {
      warnings.push(`${rel}: ${e.message}; using the built-in policy`);
      return { policy: COMPILED_DEFAULT, source: "built-in", warnings };
    }
  }
  return { policy: COMPILED_DEFAULT, source: "built-in", warnings };
}

// loadPackPolicy(projectDir, { importPacks })
//   -> { evaluate, degraded, reason, source, packs, protectedPaths, warnings } | null
//
// Policy packs are evaluated by the policy-packs module itself (no
// re-implementation here). The module ships with the SDK and is copied into
// the hook runtime when present; `importPacks` is injectable for tests.
// Returns null when the project has no pack policy file.
//
// Never throws. When the file exists but cannot be applied (no module in this
// runtime, a parse error, a pack_hash mismatch after a pack was edited...),
// `degraded` is true: the project asked for pack enforcement and cannot get
// it, so classify.mjs asks before every consequential call instead of quietly
// running with the built-in rules only. `protectedPaths` lists the custom
// pack files the policy references (`packs[].path`), which the agent may not
// change.
export async function loadPackPolicy(projectDir, { importPacks = () => import("../policy-packs/index.mjs") } = {}) {
  const path = join(projectDir, PACK_POLICY_PATH);
  if (!existsSync(path)) return null;
  const warnings = [];
  const degraded = (reason, protectedPaths = []) => {
    warnings.push(`${PACK_POLICY_PATH}: ${reason}; the pack policy is not applied, so the guard asks before every shell, write and MCP call until this is fixed`);
    return { evaluate: null, degraded: true, reason, source: PACK_POLICY_PATH, packs: [], protectedPaths, warnings };
  };
  let mod;
  try {
    mod = await importPacks();
  } catch {
    return degraded("this guard runtime has no policy-packs module (reinstall the guard with an SDK that includes policy packs)");
  }
  let protectedPaths = [];
  try {
    const doc = typeof mod.parseJsonc === "function" ? mod.parseJsonc(readFileSync(path, "utf8")) : null;
    protectedPaths = (Array.isArray(doc?.packs) ? doc.packs : [])
      .map((ref) => (ref && typeof ref.path === "string" ? resolve(dirname(path), ref.path) : null))
      .filter(Boolean);
  } catch {
    // reported by loadPolicyFile below
  }
  try {
    const loaded = mod.loadPolicyFile(path);
    return {
      evaluate: (call) => mod.evaluateToolCall(loaded, call),
      degraded: false,
      reason: null,
      source: PACK_POLICY_PATH,
      packs: (loaded.entries ?? []).map((e) => e.pack?.pack_id ?? e.pack_id).filter(Boolean),
      protectedPaths,
      warnings,
    };
  } catch (e) {
    return degraded(e.message, protectedPaths);
  }
}

// The classifyToolCall options a loaded pack policy contributes.
export function packOptions(packPolicy, policy, projectDir, protectedSet) {
  return {
    policy,
    projectDir,
    evaluatePacks: packPolicy?.evaluate ?? null,
    packDegraded: packPolicy?.degraded ? packPolicy.reason ?? "unknown error" : null,
    extraProtected: packPolicy?.protectedPaths?.length ? protectedSet(projectDir, packPolicy.protectedPaths) : null,
  };
}
