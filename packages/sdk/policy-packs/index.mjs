// Open policy packs: one pack per `intentrax scan` category, each a C2 DSL
// tenant policy (spec 03 vocabulary) plus local matchers that turn an agent's
// tool call into the facts that policy is evaluated over.
//
// A pack has a stable content hash (pack_hash), so a guard or a proof can say
// exactly which pack ran. The policy decision is computed by the SDK's port of
// the Go policy engine (C2.1 -> C2.4, `compilePolicyDocument` and
// `evaluateCompiledPolicy` in ../index.js), so the decision can be re-checked
// from the event and source_policy_hash. The facts are derived locally from
// the agent's tool input: that derivation is self-reported, not
// engine-derived, and the results say so.
//
// Local and static: no network call, no new dependencies.
//
// Format: policy-packs/README.md (and the format note shared with the guard).

import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { compilePolicyDocument, evaluateCompiledPolicy } from "../index.js";

export const PACK_SCHEMA_VERSION = "intentrax.policy_pack/0.1";
export const POLICY_FILE_SCHEMA_VERSION = "intentrax.policy_file/0.1";
export const PACK_HASH_DOMAIN = "INTENTRAX_POLICY_PACK_V0_1";
export const FACTS_SOURCE = "LOCAL_GUARD_DERIVED";

// Spec 03 §7: the tenant request-event field profile (never eeo.commitment_salt).
export const TENANT_REQUEST_EVENT_FIELDS = Object.freeze([
  "eeo.execution_domain.lane",
  "eeo.execution_domain.mutation_performed",
  "eeo.request.amount_minor",
  "eeo.request.currency",
  "eeo.request.environment",
  "eeo.request.resource",
  "eeo.request.tool",
]);

export const ENVIRONMENTS = Object.freeze(["PROD", "STAGING", "DEV"]);
export const GUARD_DECISIONS = Object.freeze(["allow", "ask", "block"]);
const DECISION_RANK = Object.freeze({ none: 0, allow: 1, ask: 2, block: 3 });
const DERIVABLE_FACTS = new Set(["amount_minor", "currency", "resource"]);
const CONTEXT_VALUES = Object.freeze({ mcp_pin_status: ["MATCH", "CHANGED", "NEW", "UNPINNED"] });

export const SCAN_CATEGORIES = Object.freeze([
  "destructive", "financial", "shell", "database", "infrastructure", "deploy", "communication", "access", "browser", "write", "unknown",
]);
export const SCAN_RULE_IDS = Object.freeze([
  ...SCAN_CATEGORIES.map((c) => `scan.category.${c}`),
  "scan.finding.EXPOSED",
  "scan.finding.UNGATED",
  "scan.finding.SELF-REPORTED",
  "scan.kind.mcp-server",
  "scan.any",
]);

export class PolicyPackError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PolicyPackError";
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new PolicyPackError(code, message);
};

// ---------------------------------------------------------------------------
// Canonical JSON (RFC 8785 JCS for the value space packs allow: strings,
// booleans, safe integers, arrays and objects) and the pack hash.
// ---------------------------------------------------------------------------

export function jcs(value) {
  if (typeof value === "string") {
    if (/[\ud800-\udfff]/.test(value.replace(/[\ud800-\udbff][\udc00-\udfff]/g, ""))) fail("PACK_ENCODING_UNSUPPORTED", "lone surrogate in a string");
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail("PACK_ENCODING_UNSUPPORTED", "only safe integers are allowed in a pack");
    return String(value);
  }
  if (Array.isArray(value)) return "[" + value.map(jcs).join(",") + "]";
  if (value !== null && typeof value === "object") {
    // JCS sorts keys by UTF-16 code units, which is JavaScript's default sort.
    const keys = Object.keys(value).sort();
    return "{" + keys.map((k) => {
      if (value[k] === undefined) fail("PACK_ENCODING_UNSUPPORTED", `undefined member ${k}`);
      return JSON.stringify(k) + ":" + jcs(value[k]);
    }).join(",") + "}";
  }
  fail("PACK_ENCODING_UNSUPPORTED", "null and other values are not allowed in a pack");
}

// pack_hash = SHA-256(UTF-8("INTENTRAX_POLICY_PACK_V0_1") || JCS(pack)), as hex.
export function packHash(pack) {
  return createHash("sha256").update(PACK_HASH_DOMAIN, "utf8").update(jcs(pack), "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// Tokens, JSON pointers and regexes.
// ---------------------------------------------------------------------------

const isAlnum = (c) => (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || (c >= "0" && c <= "9");
const camelBreak = (prev, cur) => ((prev >= "a" && prev <= "z") || (prev >= "0" && prev <= "9")) && cur >= "A" && cur <= "Z";

// Maximal runs of ASCII letters and digits, split where a lower-case letter or
// digit is followed by an upper-case letter, lower-cased. The same rule as the
// C2.1 forbidden-literal check.
export function tokens(text) {
  const out = [];
  const s = String(text ?? "");
  for (let i = 0; i < s.length;) {
    if (!isAlnum(s[i])) {
      i += 1;
      continue;
    }
    let j = i + 1;
    while (j < s.length && isAlnum(s[j]) && !camelBreak(s[j - 1], s[j])) j += 1;
    out.push(s.slice(i, j).toLowerCase());
    i = j;
  }
  return out;
}

export function resolvePointer(document, pointer) {
  if (pointer === "") return { found: true, value: document };
  if (typeof pointer !== "string" || !pointer.startsWith("/")) return { found: false };
  let current = document;
  for (const raw of pointer.slice(1).split("/")) {
    const part = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(current)) {
      if (!/^(0|[1-9][0-9]*)$/.test(part) || Number(part) >= current.length) return { found: false };
      current = current[Number(part)];
    } else if (current !== null && typeof current === "object" && Object.hasOwn(current, part)) {
      current = current[part];
    } else {
      return { found: false };
    }
  }
  return { found: true, value: current };
}

// Pack regexes are a subset both JavaScript and RE2 (Go) accept: no
// lookaround, no backreferences, no named groups. The only flag is "i".
const NON_RE2 = /\(\?<?[=!]|\(\?<[A-Za-z]|\\[1-9]|\\k</;
const regexCache = new Map();

function compileRegex(source, flags, where) {
  const key = `${flags ?? ""}/${source}`;
  const cached = regexCache.get(key);
  if (cached) return cached;
  if (typeof source !== "string" || source === "") fail("PACK_INVALID", `${where}: regex must be a non-empty string`);
  if (NON_RE2.test(source)) fail("PACK_INVALID", `${where}: regex uses lookaround, a backreference or a named group (not RE2-compatible)`);
  if (flags !== undefined && flags !== "i") fail("PACK_INVALID", `${where}: regex_flags may only be "i"`);
  let re;
  try {
    re = new RegExp(source, flags ?? "");
  } catch (error) {
    return fail("PACK_INVALID", `${where}: regex does not compile: ${error.message}`);
  }
  if (regexCache.size < 4096) regexCache.set(key, re);
  return re;
}

// ---------------------------------------------------------------------------
// Validation and compilation.
// ---------------------------------------------------------------------------

const PACK_MEMBERS = ["schema_version", "pack_id", "pack_version", "title", "summary", "scan", "params", "param_rules", "matchers", "actions", "policy", "approval", "limits", "examples"];
const REQUIRED_PACK_MEMBERS = ["schema_version", "pack_id", "pack_version", "title", "summary", "scan", "params", "matchers", "actions", "policy", "approval", "limits", "examples"];
const PACK_ID_RE = /^intentrax\.[a-z0-9]+(?:-[a-z0-9]+)*$/;
const CUSTOM_PACK_ID_RE = /^[a-z0-9][a-z0-9.-]{2,95}$/;
const SEMVER_RE = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const ACTION_RE = /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/;
const MATCHER_ID_RE = /^[a-z0-9][a-z0-9-]{1,63}$/;
const PARAM_RE = /^[a-z][a-z0-9_]{0,47}$/;

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isNonEmptyString = (v) => typeof v === "string" && v.trim() !== "" && v.trim() === v;
const onlyMembers = (obj, allowed, where) => {
  for (const k of Object.keys(obj)) if (!allowed.includes(k)) fail("PACK_INVALID", `${where}: unknown member "${k}"`);
};

function checkStringList(list, where, { min = 0 } = {}) {
  if (!Array.isArray(list) || list.length < min || !list.every(isNonEmptyString)) fail("PACK_INVALID", `${where} must be a list of strings${min ? ` (at least ${min})` : ""}`);
}

function validateParams(params, paramRules) {
  if (!isObject(params)) fail("PACK_INVALID", "params must be an object");
  for (const [name, spec] of Object.entries(params)) {
    const where = `params.${name}`;
    if (!PARAM_RE.test(name)) fail("PACK_INVALID", `${where}: invalid name`);
    if (!isObject(spec)) fail("PACK_INVALID", `${where} must be an object`);
    onlyMembers(spec, ["type", "default", "min", "max", "description"], where);
    if (!isNonEmptyString(spec.description)) fail("PACK_INVALID", `${where}.description is required`);
    if (spec.type === "INTEGER") {
      for (const k of ["min", "max"]) if (!Number.isSafeInteger(spec[k])) fail("PACK_INVALID", `${where}.${k} must be a safe integer`);
      if (spec.min > spec.max) fail("PACK_INVALID", `${where}: min > max`);
    } else if (spec.type === "STRING") {
      if (spec.min !== undefined || spec.max !== undefined) fail("PACK_INVALID", `${where}: min/max apply to INTEGER params only`);
    } else {
      fail("PACK_INVALID", `${where}.type must be INTEGER or STRING`);
    }
    checkParamValue(name, spec, spec.default, `${where}.default`);
  }
  if (paramRules !== undefined) {
    if (!Array.isArray(paramRules)) fail("PACK_INVALID", "param_rules must be a list");
    for (const [i, rule] of paramRules.entries()) {
      if (!isObject(rule)) fail("PACK_INVALID", `param_rules[${i}] must be an object`);
      onlyMembers(rule, ["less_than"], `param_rules[${i}]`);
      const pair = rule.less_than;
      if (!Array.isArray(pair) || pair.length !== 2 || !pair.every((p) => params[p]?.type === "INTEGER")) fail("PACK_INVALID", `param_rules[${i}].less_than must name two INTEGER params`);
    }
  }
}

function checkParamValue(name, spec, value, where) {
  if (spec.type === "INTEGER") {
    if (!Number.isSafeInteger(value) || value < spec.min || value > spec.max) fail("PARAM_INVALID", `${where}: ${name} must be an integer from ${spec.min} to ${spec.max}`);
  } else if (!isNonEmptyString(value) || value.length > 256) {
    fail("PARAM_INVALID", `${where}: ${name} must be a non-empty string of at most 256 characters`);
  }
}

// Merges the given params over the pack defaults; refuses unknown or invalid ones.
export function resolveParams(pack, given = {}) {
  if (!isObject(given)) fail("PARAM_INVALID", "params must be an object");
  for (const name of Object.keys(given)) if (!Object.hasOwn(pack.params, name)) fail("PARAM_INVALID", `${pack.pack_id} has no param "${name}"`);
  const out = {};
  for (const [name, spec] of Object.entries(pack.params)) {
    const value = Object.hasOwn(given, name) ? given[name] : spec.default;
    checkParamValue(name, spec, value, `${pack.pack_id} params`);
    out[name] = value;
  }
  for (const rule of pack.param_rules ?? []) {
    const [a, b] = rule.less_than;
    if (!(out[a] < out[b])) fail("PARAM_INVALID", `${pack.pack_id}: ${a} (${out[a]}) must be less than ${b} (${out[b]})`);
  }
  return out;
}

const isParamRef = (v) => isObject(v) && Object.keys(v).length === 1 && typeof v.param === "string";

function substitute(value, params, used) {
  if (isParamRef(value)) {
    if (!Object.hasOwn(params, value.param)) fail("PACK_INVALID", `policy refers to unknown param "${value.param}"`);
    used.add(value.param);
    return params[value.param];
  }
  if (Array.isArray(value)) return value.map((v) => substitute(v, params, used));
  if (isObject(value)) return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, substitute(v, params, used)]));
  return value;
}

// The pack's policy with params substituted, as a plain C2 DSL document.
export function instantiatePolicy(pack, params = {}) {
  const resolved = resolveParams(pack, params);
  const used = new Set();
  const document = substitute(pack.policy, resolved, used);
  return { document, params: resolved, used };
}

// Validates (C2.1) and compiles (C2.3) the instantiated policy with the spec 03
// tenant field profile.
export function compilePack(pack, params = {}) {
  const { document, params: resolved } = instantiatePolicy(pack, params);
  try {
    const compiled = compilePolicyDocument(JSON.stringify(document), [...TENANT_REQUEST_EVENT_FIELDS]);
    return { compiled, document, params: resolved };
  } catch (error) {
    return fail("POLICY_INVALID", `${pack.pack_id}: policy is not valid C2 DSL: ${error.message}`);
  }
}

function validateToolMatcher(tool, where) {
  if (!isObject(tool)) fail("PACK_INVALID", `${where} must be an object`);
  onlyMembers(tool, ["equals", "regex", "regex_flags", "token_groups", "tokens_none"], where);
  const keys = Object.keys(tool).filter((k) => k !== "regex_flags" && k !== "tokens_none");
  if (keys.length === 0) fail("PACK_INVALID", `${where} needs equals, regex or token_groups`);
  if (tool.equals !== undefined) checkStringList(tool.equals, `${where}.equals`, { min: 1 });
  if (tool.regex !== undefined) compileRegex(tool.regex, tool.regex_flags, `${where}.regex`);
  else if (tool.regex_flags !== undefined) fail("PACK_INVALID", `${where}.regex_flags without regex`);
  if (tool.token_groups !== undefined) {
    if (!Array.isArray(tool.token_groups) || tool.token_groups.length === 0) fail("PACK_INVALID", `${where}.token_groups must be a non-empty list`);
    tool.token_groups.forEach((g, i) => checkTokenList(g, `${where}.token_groups[${i}]`, 1));
  }
  if (tool.tokens_none !== undefined) checkTokenList(tool.tokens_none, `${where}.tokens_none`, 1);
}

function checkTokenList(list, where, min) {
  checkStringList(list, where, { min });
  for (const t of list) if (!/^[a-z0-9]+$/.test(t)) fail("PACK_INVALID", `${where}: "${t}" is not a lower-case token`);
}

function validateMatcher(m, i, actions) {
  const where = `matchers[${i}]`;
  if (!isObject(m)) fail("PACK_INVALID", `${where} must be an object`);
  onlyMembers(m, ["matcher_id", "tool", "input", "context", "action", "facts"], where);
  if (typeof m.matcher_id !== "string" || !MATCHER_ID_RE.test(m.matcher_id)) fail("PACK_INVALID", `${where}.matcher_id invalid`);
  validateToolMatcher(m.tool, `${where}.tool`);
  const inputs = m.input ?? [];
  if (!Array.isArray(inputs)) fail("PACK_INVALID", `${where}.input must be a list`);
  inputs.forEach((entry, j) => {
    const at = `${where}.input[${j}]`;
    if (!isObject(entry)) fail("PACK_INVALID", `${at} must be an object`);
    onlyMembers(entry, ["pointer", "regex", "regex_flags", "equals"], at);
    if (typeof entry.pointer !== "string" || !entry.pointer.startsWith("/")) fail("PACK_INVALID", `${at}.pointer must be a JSON pointer`);
    if ((entry.regex === undefined) === (entry.equals === undefined)) fail("PACK_INVALID", `${at} needs exactly one of regex or equals`);
    if (entry.regex !== undefined) compileRegex(entry.regex, entry.regex_flags, `${at}.regex`);
    else if (entry.regex_flags !== undefined) fail("PACK_INVALID", `${at}.regex_flags without regex`);
    if (entry.equals !== undefined && !["string", "boolean", "number"].includes(typeof entry.equals)) fail("PACK_INVALID", `${at}.equals must be a string, boolean or integer`);
  });
  if (m.context !== undefined) {
    if (!isObject(m.context)) fail("PACK_INVALID", `${where}.context must be an object`);
    for (const [k, values] of Object.entries(m.context)) {
      if (!Object.hasOwn(CONTEXT_VALUES, k)) fail("PACK_INVALID", `${where}.context: unknown key "${k}"`);
      checkStringList(values, `${where}.context.${k}`, { min: 1 });
      for (const v of values) if (!CONTEXT_VALUES[k].includes(v)) fail("PACK_INVALID", `${where}.context.${k}: unknown value "${v}"`);
    }
  }
  if (typeof m.action !== "string" || !ACTION_RE.test(m.action)) fail("PACK_INVALID", `${where}.action invalid`);
  if (!Object.hasOwn(actions, m.action)) fail("PACK_INVALID", `${where}.action "${m.action}" is not declared in actions`);
  const facts = m.facts ?? {};
  if (!isObject(facts)) fail("PACK_INVALID", `${where}.facts must be an object`);
  for (const [name, spec] of Object.entries(facts)) {
    const at = `${where}.facts.${name}`;
    if (!DERIVABLE_FACTS.has(name)) fail("PACK_INVALID", `${at}: only amount_minor, currency and resource are derived (environment comes from the policy file)`);
    if (!isObject(spec)) fail("PACK_INVALID", `${at} must be an object`);
    onlyMembers(spec, ["pointers", "type", "capture", "input", "email_domain", "required"], at);
    if (spec.required !== undefined && typeof spec.required !== "boolean") fail("PACK_INVALID", `${at}.required must be a boolean`);
    const sources = ["pointers", "capture", "email_domain"].filter((k) => spec[k] !== undefined);
    if (sources.length !== 1) fail("PACK_INVALID", `${at} needs exactly one of pointers, capture or email_domain`);
    if (spec.pointers !== undefined) {
      checkStringList(spec.pointers, `${at}.pointers`, { min: 1 });
      if (!["INTEGER", "STRING", "CURRENCY"].includes(spec.type)) fail("PACK_INVALID", `${at}.type must be INTEGER, STRING or CURRENCY`);
    } else if (spec.type !== undefined) {
      fail("PACK_INVALID", `${at}.type applies to pointers only`);
    }
    if (spec.capture !== undefined) {
      const inputIndex = spec.input ?? 0;
      if (!Number.isSafeInteger(spec.capture) || spec.capture < 1) fail("PACK_INVALID", `${at}.capture must be a group number`);
      if (!Number.isSafeInteger(inputIndex) || !inputs[inputIndex]?.regex) fail("PACK_INVALID", `${at}.input must name an input entry with a regex`);
    } else if (spec.input !== undefined) {
      fail("PACK_INVALID", `${at}.input applies to capture only`);
    }
    if (spec.email_domain !== undefined) checkStringList(spec.email_domain, `${at}.email_domain`, { min: 1 });
    if (name === "amount_minor" && spec.pointers && spec.type !== "INTEGER") fail("PACK_INVALID", `${at}: amount_minor must be INTEGER`);
    if (name === "currency" && spec.pointers && spec.type !== "CURRENCY") fail("PACK_INVALID", `${at}: currency must be CURRENCY`);
    if (name === "amount_minor" && !spec.pointers) fail("PACK_INVALID", `${at}: amount_minor comes from pointers only`);
  }
}

// Validates a pack document. Returns { ok, errors, pack_hash, source_policy_hash }.
export function validatePack(pack, { builtIn = false } = {}) {
  try {
    checkPack(pack, { builtIn });
    const { compiled } = compilePack(pack);
    probeMatchers(pack, compiled);
    return { ok: true, errors: [], pack_hash: packHash(pack), source_policy_hash: compiled.source_policy_hash };
  } catch (error) {
    if (error instanceof PolicyPackError) return { ok: false, errors: [`${error.code}: ${error.message}`] };
    throw error;
  }
}

// Every matcher must lead to a rule, never to an evaluation ERROR or the
// default DENY, with only the facts it always supplies (required facts set,
// optional facts absent) and in every environment. A numeric comparison on a
// fact that can be absent errors in the VM (ERR_TYPE_MISMATCH), so the rule
// for that case must come first.
function probeMatchers(pack, compiled) {
  for (const m of pack.matchers) {
    const facts = {};
    for (const [name, spec] of Object.entries(m.facts ?? {})) {
      if (spec.required) facts[name] = name === "amount_minor" ? 0 : name === "currency" ? "USD" : "x";
    }
    for (const environment of [undefined, ...ENVIRONMENTS]) {
      const evaluation = evaluateCompiledPolicy(compiled, buildEvent(m.action, facts, environment));
      const at = `matcher ${m.matcher_id} (environment ${environment ?? "absent"})`;
      if (evaluation.decision === "ERROR") fail("POLICY_INVALID", `${at}: the policy errors (${evaluation.error_code}) when the matcher's optional facts are absent; put the rule for that case first`);
      if (evaluation.rule_id === "__default__") fail("POLICY_INVALID", `${at}: no rule covers action ${m.action}`);
      const decision = guardDecision(evaluation);
      if (!pack.actions[m.action].decisions.includes(decision)) fail("POLICY_INVALID", `${at}: the policy decides ${decision}, which actions.${m.action}.decisions does not declare`);
    }
  }
}

function checkPack(pack, { builtIn }) {
  if (!isObject(pack)) fail("PACK_INVALID", "a pack must be a JSON object");
  onlyMembers(pack, PACK_MEMBERS, "pack");
  for (const k of REQUIRED_PACK_MEMBERS) if (pack[k] === undefined) fail("PACK_INVALID", `pack.${k} is required`);
  jcs(pack); // value space check (no floats, no null)
  if (pack.schema_version !== PACK_SCHEMA_VERSION) fail("PACK_INVALID", `schema_version must be ${PACK_SCHEMA_VERSION}`);
  if (typeof pack.pack_id !== "string" || !(builtIn ? PACK_ID_RE : CUSTOM_PACK_ID_RE).test(pack.pack_id)) fail("PACK_INVALID", "pack_id invalid");
  if (!builtIn && pack.pack_id.startsWith("intentrax.")) fail("PACK_INVALID", "the intentrax. prefix is reserved for built-in packs");
  if (typeof pack.pack_version !== "string" || !SEMVER_RE.test(pack.pack_version)) fail("PACK_INVALID", "pack_version must be MAJOR.MINOR.PATCH");
  for (const k of ["title", "summary"]) if (!isNonEmptyString(pack[k])) fail("PACK_INVALID", `${k} must be a non-empty string`);
  if (!isObject(pack.scan)) fail("PACK_INVALID", "scan must be an object");
  onlyMembers(pack.scan, ["category", "rule_ids", "name_tokens"], "scan");
  if (!SCAN_CATEGORIES.includes(pack.scan.category)) fail("PACK_INVALID", "scan.category must be an intentrax scan category");
  checkStringList(pack.scan.rule_ids, "scan.rule_ids", { min: 1 });
  for (const id of pack.scan.rule_ids) if (!SCAN_RULE_IDS.includes(id)) fail("PACK_INVALID", `scan.rule_ids: unknown rule id "${id}"`);
  if (!pack.scan.rule_ids.includes(`scan.category.${pack.scan.category}`) && !pack.scan.rule_ids.includes("scan.any")) fail("PACK_INVALID", "scan.rule_ids must include the pack's own category");
  if (pack.scan.name_tokens !== undefined) checkTokenList(pack.scan.name_tokens, "scan.name_tokens", 1);
  validateParams(pack.params, pack.param_rules);

  if (!isObject(pack.actions) || Object.keys(pack.actions).length === 0) fail("PACK_INVALID", "actions must be a non-empty object");
  for (const [action, spec] of Object.entries(pack.actions)) {
    if (!ACTION_RE.test(action)) fail("PACK_INVALID", `actions: invalid action class "${action}"`);
    if (!isObject(spec)) fail("PACK_INVALID", `actions.${action} must be an object`);
    onlyMembers(spec, ["decisions", "why"], `actions.${action}`);
    checkStringList(spec.decisions, `actions.${action}.decisions`, { min: 1 });
    for (const d of spec.decisions) if (!GUARD_DECISIONS.includes(d)) fail("PACK_INVALID", `actions.${action}: unknown decision "${d}"`);
    if (new Set(spec.decisions).size !== spec.decisions.length) fail("PACK_INVALID", `actions.${action}: duplicate decision`);
    if (!isNonEmptyString(spec.why)) fail("PACK_INVALID", `actions.${action}.why is required`);
  }
  if (!Array.isArray(pack.matchers) || pack.matchers.length === 0) fail("PACK_INVALID", "matchers must be a non-empty list");
  const ids = new Set();
  pack.matchers.forEach((m, i) => {
    validateMatcher(m, i, pack.actions);
    if (ids.has(m.matcher_id)) fail("PACK_INVALID", `matchers[${i}]: duplicate matcher_id`);
    ids.add(m.matcher_id);
  });
  for (const action of Object.keys(pack.actions)) {
    if (!pack.matchers.some((m) => m.action === action)) fail("PACK_INVALID", `actions.${action} has no matcher`);
  }

  if (!isObject(pack.approval)) fail("PACK_INVALID", "approval must be an object");
  onlyMembers(pack.approval, ["constraint_id", "type", "approver_hint"], "approval");
  if (pack.approval.type !== "REQUIRE_APPROVAL") fail("PACK_INVALID", "approval.type must be REQUIRE_APPROVAL (spec 02)");
  if (!isNonEmptyString(pack.approval.constraint_id) || !/^constraint\.[a-z0-9.-]+$/.test(pack.approval.constraint_id)) fail("PACK_INVALID", "approval.constraint_id must look like constraint.<name>");
  if (!isNonEmptyString(pack.approval.approver_hint)) fail("PACK_INVALID", "approval.approver_hint is required");

  // The policy: its id/version follow the pack, every action class is
  // covered by a rule on eeo.request.tool, and the only constraint used is the
  // pack's REQUIRE_APPROVAL (spec 03 §5: anything else cannot be enforced).
  const policy = pack.policy;
  if (!isObject(policy)) fail("PACK_INVALID", "policy must be an object");
  if (policy.policy_id !== pack.pack_id) fail("PACK_INVALID", "policy.policy_id must equal pack_id");
  if (policy.policy_version !== pack.pack_version) fail("PACK_INVALID", "policy.policy_version must equal pack_version");
  if (!Array.isArray(policy.rules)) fail("PACK_INVALID", "policy.rules must be a list");
  const covered = new Set();
  for (const rule of policy.rules) {
    if (!isObject(rule) || !Array.isArray(rule.conditions ?? []) || !Array.isArray(rule.constraints ?? [])) fail("PACK_INVALID", "policy.rules entries must be rule objects");
    for (const c of rule.conditions ?? []) {
      if (!isObject(c)) fail("PACK_INVALID", `policy rule ${rule.rule_id}: conditions must be objects`);
      if (c.field === "eeo.request.tool" && c.operator === "EQUALS") {
        if (!Object.hasOwn(pack.actions, c.value)) fail("PACK_INVALID", `policy rule ${rule.rule_id} names undeclared action "${c.value}"`);
        covered.add(c.value);
      }
    }
    if (!(rule.conditions ?? []).some((c) => c.field === "eeo.request.tool" && c.operator === "EQUALS")) fail("PACK_INVALID", `policy rule ${rule.rule_id} must test eeo.request.tool`);
    for (const k of rule.constraints ?? []) {
      if (k.type !== "REQUIRE_APPROVAL" || k.constraint_id !== pack.approval.constraint_id || k.value !== true) fail("PACK_INVALID", `policy rule ${rule.rule_id}: the only constraint allowed is the pack's REQUIRE_APPROVAL with value true`);
    }
  }
  for (const action of Object.keys(pack.actions)) if (!covered.has(action)) fail("PACK_INVALID", `action "${action}" is not covered by any policy rule`);
  const { used } = instantiatePolicy(pack);
  for (const name of Object.keys(pack.params)) if (!used.has(name)) fail("PACK_INVALID", `param "${name}" is not used by the policy`);

  checkStringList(pack.limits, "limits", { min: 1 });
  if (!Array.isArray(pack.examples) || pack.examples.length < 2) fail("PACK_INVALID", "examples must list at least one matching and one non-matching case");
  pack.examples.forEach((ex, i) => {
    const at = `examples[${i}]`;
    if (!isObject(ex)) fail("PACK_INVALID", `${at} must be an object`);
    onlyMembers(ex, ["name", "tool_name", "tool_input", "context", "params", "environment", "expect"], at);
    if (!isNonEmptyString(ex.name) || !isNonEmptyString(ex.tool_name) || !isObject(ex.tool_input)) fail("PACK_INVALID", `${at} needs name, tool_name and tool_input`);
    if (![...GUARD_DECISIONS, "none"].includes(ex.expect)) fail("PACK_INVALID", `${at}.expect must be allow, ask, block or none`);
    if (ex.environment !== undefined && !ENVIRONMENTS.includes(ex.environment)) fail("PACK_INVALID", `${at}.environment invalid`);
  });
  if (!pack.examples.some((ex) => ex.expect === "none")) fail("PACK_INVALID", "examples need at least one non-matching case (expect none)");
  if (!pack.examples.some((ex) => ex.expect !== "none")) fail("PACK_INVALID", "examples need at least one matching case");
}

// ---------------------------------------------------------------------------
// Built-in packs.
// ---------------------------------------------------------------------------

const PACKS_DIR = join(dirname(fileURLToPath(import.meta.url)), "packs");
let builtInCache = null;

function builtIns() {
  if (builtInCache) return builtInCache;
  const map = new Map();
  for (const file of readdirSync(PACKS_DIR).filter((f) => f.endsWith(".json")).sort()) {
    const pack = JSON.parse(readFileSync(join(PACKS_DIR, file), "utf8"));
    const result = validatePack(pack, { builtIn: true });
    if (!result.ok) fail("PACK_INVALID", `built-in pack ${file} is invalid: ${result.errors.join("; ")}`);
    if (`${pack.pack_id.slice("intentrax.".length)}.json` !== file) fail("PACK_INVALID", `built-in pack ${file} must be named after its pack_id`);
    map.set(pack.pack_id, Object.freeze({ pack, file, pack_hash: result.pack_hash, source_policy_hash: result.source_policy_hash }));
  }
  builtInCache = map;
  return map;
}

export function listPacks() {
  return [...builtIns().values()].map(({ pack, pack_hash, source_policy_hash }) => ({
    pack_id: pack.pack_id,
    pack_version: pack.pack_version,
    title: pack.title,
    summary: pack.summary,
    category: pack.scan.category,
    rule_ids: [...pack.scan.rule_ids],
    decisions: [...new Set(Object.values(pack.actions).flatMap((a) => a.decisions))].sort((a, b) => DECISION_RANK[a] - DECISION_RANK[b]),
    pack_hash,
    source_policy_hash,
  }));
}

// Accepts "intentrax.shell-destructive" or "shell-destructive".
export function getPack(id) {
  const map = builtIns();
  const key = map.has(id) ? id : `intentrax.${id}`;
  const entry = map.get(key);
  if (!entry) fail("PACK_NOT_FOUND", `no built-in pack "${id}" (intentrax policy list shows them)`);
  return structuredClone(entry.pack);
}

// ---------------------------------------------------------------------------
// Evaluating a tool call.
// ---------------------------------------------------------------------------

function toolMatches(tool, name) {
  if (tool.equals && !tool.equals.includes(name)) return false;
  if (tool.regex && !compileRegex(tool.regex, tool.regex_flags, "tool").test(name)) return false;
  if (tool.token_groups || tool.tokens_none) {
    const set = new Set(tokens(name));
    if (tool.token_groups && !tool.token_groups.every((g) => g.some((t) => set.has(t)))) return false;
    if (tool.tokens_none && tool.tokens_none.some((t) => set.has(t))) return false;
  }
  return true;
}

function emailDomain(document, pointers) {
  const addresses = [];
  // Any recipient in a shape we do not recognise makes the domain unknown
  // (absent), so the email is asked about: never silently dropped.
  let unknown = false;
  const collect = (v) => {
    if (typeof v === "string") v.split(/[,;]/).map((s) => s.trim()).filter(Boolean).forEach((s) => addresses.push(s));
    else if (Array.isArray(v)) v.forEach(collect);
    else if (isObject(v) && typeof (v.email ?? v.address) === "string") collect(v.email ?? v.address);
    else unknown = true;
  };
  for (const p of pointers) {
    const r = resolvePointer(document, p);
    if (r.found && r.value !== null) collect(r.value);
  }
  if (unknown) return undefined;
  if (addresses.length === 0) return undefined;
  const domains = new Set();
  for (const a of addresses) {
    const m = /@([A-Za-z0-9.-]+\.[A-Za-z]{2,})>?$/.exec(a);
    if (!m) return undefined;
    domains.add(m[1].toLowerCase());
  }
  return domains.size === 1 ? [...domains][0] : undefined;
}

class DerivationError extends Error {}

function deriveFact(spec, input, captures) {
  if (spec.capture !== undefined) {
    const v = captures[spec.input ?? 0]?.[spec.capture];
    return typeof v === "string" && v !== "" ? v.slice(0, 256) : undefined;
  }
  if (spec.email_domain) return emailDomain(input, spec.email_domain);
  for (const p of spec.pointers) {
    const r = resolvePointer(input, p);
    if (!r.found || r.value === null) continue;
    const v = r.value;
    if (spec.type === "INTEGER") {
      if (!Number.isSafeInteger(v) || v < 0) throw new DerivationError(`${p} is not a non-negative integer in minor units`);
    } else if (spec.type === "CURRENCY") {
      if (typeof v !== "string" || !/^[A-Z]{3}$/.test(v)) throw new DerivationError(`${p} is not three upper-case letters`);
    } else if (typeof v !== "string" || v.length < 1 || v.length > 256) {
      throw new DerivationError(`${p} is not a string of 1-256 characters`);
    }
    return v;
  }
  return undefined;
}

// Tries one matcher. Returns null (no match) or { facts } or { derivationError }.
function tryMatcher(m, call) {
  if (!toolMatches(m.tool, call.tool_name)) return null;
  for (const [k, values] of Object.entries(m.context ?? {})) {
    if (!values.includes(call.context?.[k])) return null;
  }
  const captures = [];
  for (const entry of m.input ?? []) {
    const r = resolvePointer(call.tool_input, entry.pointer);
    if (!r.found) return null;
    if (entry.equals !== undefined) {
      if (r.value !== entry.equals) return null;
      captures.push(null);
    } else {
      if (typeof r.value !== "string") return null;
      const match = compileRegex(entry.regex, entry.regex_flags, "input").exec(r.value);
      if (!match) return null;
      captures.push(match);
    }
  }
  const facts = {};
  try {
    for (const [name, spec] of Object.entries(m.facts ?? {})) {
      const v = deriveFact(spec, call.tool_input, captures);
      if (v === undefined) {
        if (spec.required) return null;
        continue;
      }
      facts[name] = v;
    }
  } catch (error) {
    if (error instanceof DerivationError) return { facts, derivationError: error.message };
    throw error;
  }
  return { facts };
}

export function buildEvent(action, facts, environment) {
  const request = { tool: action, ...facts };
  if (environment) request.environment = environment;
  return { eeo: { execution_domain: { lane: "ADMISSION", mutation_performed: false }, request } };
}

// VM result -> guard decision (spec 03 §5, read locally).
export function guardDecision(evaluation) {
  if (evaluation.decision === "COMPLIANT") {
    if (evaluation.constraints.length === 0) return "allow";
    return evaluation.constraints.every((c) => c.type === "REQUIRE_APPROVAL") ? "ask" : "block";
  }
  return "block";
}

function describe(result) {
  const facts = Object.entries(result.facts).map(([k, v]) => `${k}=${v}`).join(", ");
  const what = `${result.pack_id} matched ${result.action}${facts ? ` (${facts})` : ""}`;
  if (result.derivation_error) return `${what}: fact derivation failed (${result.derivation_error}); blocked, fail closed`;
  if (result.evaluation.decision === "ERROR") return `${what}: policy evaluation error ${result.evaluation.error_code}; blocked, fail closed`;
  const rule = result.evaluation.rule_id === "__default__" ? "no rule matched (default DENY)" : `rule ${result.evaluation.rule_id}`;
  const verdict = { allow: "allowed", ask: "needs approval", block: "blocked" }[result.decision];
  return `${what}: ${verdict} by ${rule}. ${result.why}`;
}

function evaluateEntry(entry, call, environment) {
  const { pack } = entry;
  for (const m of pack.matchers) {
    const hit = tryMatcher(m, call);
    if (!hit) continue;
    const base = {
      pack_id: pack.pack_id,
      pack_version: pack.pack_version,
      pack_hash: entry.pack_hash,
      source_policy_hash: entry.compiled.source_policy_hash,
      compiled_policy_hash: entry.compiled.compiled_policy_hash,
      params: entry.params,
      matcher_id: m.matcher_id,
      action: m.action,
      facts: hit.facts,
      facts_source: FACTS_SOURCE,
      why: pack.actions[m.action].why,
    };
    const event = buildEvent(m.action, hit.facts, environment);
    if (hit.derivationError) {
      const result = { ...base, event, evaluation: { decision: "ERROR", rule_id: "", constraints: [], error_code: "FACT_DERIVATION_ERROR" }, derivation_error: hit.derivationError, decision: "block" };
      return { ...result, reason: describe(result) };
    }
    const evaluation = evaluateCompiledPolicy(entry.compiled, event);
    const result = {
      ...base,
      event,
      evaluation: {
        decision: evaluation.decision,
        rule_id: evaluation.rule_id,
        constraints: evaluation.constraints,
        error_code: evaluation.error_code,
        execution_event_hash: evaluation.execution_event_hash,
        evaluation_hash: evaluation.evaluation_hash,
      },
      decision: guardDecision(evaluation),
    };
    return { ...result, reason: describe(result) };
  }
  return null;
}

// Evaluates one tool call against a loaded policy (loadPolicyFile /
// parsePolicyFile / policyFromPacks). The strictest pack decision wins.
export function evaluateToolCall(policy, call) {
  if (!policy || !Array.isArray(policy.entries)) fail("POLICY_FILE_INVALID", "evaluateToolCall needs a loaded policy");
  if (!call || typeof call.tool_name !== "string" || call.tool_name === "") fail("CALL_INVALID", "tool_name is required");
  const normalized = { tool_name: call.tool_name, tool_input: isObject(call.tool_input) ? call.tool_input : {}, context: isObject(call.context) ? call.context : {} };
  const results = [];
  for (const entry of policy.entries) {
    const r = evaluateEntry(entry, normalized, policy.environment);
    if (r) results.push(r);
  }
  let decision = "none";
  for (const r of results) if (DECISION_RANK[r.decision] > DECISION_RANK[decision]) decision = r.decision;
  const deciding = results.filter((r) => r.decision === decision);
  return {
    decision,
    reason: deciding.length ? deciding.map((r) => r.reason).join(" | ") : "no policy pack matched this tool call",
    results,
    facts_source: FACTS_SOURCE,
  };
}

// ---------------------------------------------------------------------------
// Policy files.
// ---------------------------------------------------------------------------

// JSON with // and /* */ comments and trailing commas.
export function parseJsonc(text) {
  const raw = String(text).replace(/^﻿/, "");
  let out = "";
  let inString = false;
  // Index in `out` of a comma (outside strings) followed so far only by
  // whitespace and comments: dropped if a } or ] comes next. Commas inside
  // strings are never touched.
  let pendingComma = -1;
  for (let i = 0; i < raw.length; i += 1) {
    const c = raw[i];
    if (inString) {
      out += c;
      if (c === "\\") {
        out += raw[i + 1] ?? "";
        i += 1;
      } else if (c === '"') {
        inString = false;
      }
      continue;
    }
    if (c === "/" && raw[i + 1] === "/") {
      while (i < raw.length && raw[i] !== "\n") i += 1;
      out += "\n";
    } else if (c === "/" && raw[i + 1] === "*") {
      const end = raw.indexOf("*/", i + 2);
      if (end < 0) fail("POLICY_FILE_INVALID", "unterminated /* comment");
      i = end + 1;
    } else if (c === " " || c === "\t" || c === "\n" || c === "\r") {
      out += c;
    } else {
      if ((c === "}" || c === "]") && pendingComma >= 0) out = out.slice(0, pendingComma) + " " + out.slice(pendingComma + 1);
      pendingComma = c === "," ? out.length : -1;
      if (c === '"') inString = true;
      out += c;
    }
  }
  try {
    return JSON.parse(out);
  } catch (error) {
    return fail("POLICY_FILE_INVALID", `not valid JSON (comments allowed): ${error.message}`);
  }
}

function compiledEntry(pack, packHashValue, params) {
  const { compiled, params: resolved } = compilePack(pack, params);
  return { pack, pack_hash: packHashValue, params: resolved, compiled };
}

// A policy from built-in pack ids with default params (tests, `policy check`).
export function policyFromPacks(ids, { environment } = {}) {
  if (environment !== undefined && !ENVIRONMENTS.includes(environment)) fail("POLICY_FILE_INVALID", "environment must be PROD, STAGING or DEV");
  return {
    environment,
    entries: ids.map((id) => {
      const pack = getPack(id);
      return compiledEntry(pack, packHash(pack), {});
    }),
  };
}

// Parses and checks a policy file. Fails closed on any problem.
export function parsePolicyFile(text, { baseDir = process.cwd() } = {}) {
  const doc = typeof text === "string" ? parseJsonc(text) : text;
  if (!isObject(doc)) fail("POLICY_FILE_INVALID", "a policy file must be a JSON object");
  for (const k of Object.keys(doc)) if (!["schema_version", "environment", "packs"].includes(k)) fail("POLICY_FILE_INVALID", `unknown member "${k}"`);
  if (doc.schema_version !== POLICY_FILE_SCHEMA_VERSION) fail("POLICY_FILE_INVALID", `schema_version must be ${POLICY_FILE_SCHEMA_VERSION}`);
  if (doc.environment !== undefined && !ENVIRONMENTS.includes(doc.environment)) fail("POLICY_FILE_INVALID", "environment must be PROD, STAGING or DEV (or left out)");
  if (!Array.isArray(doc.packs)) fail("POLICY_FILE_INVALID", "packs must be a list");
  const seen = new Set();
  const entries = doc.packs.map((ref, i) => {
    const at = `packs[${i}]`;
    if (!isObject(ref)) fail("POLICY_FILE_INVALID", `${at} must be an object`);
    for (const k of Object.keys(ref)) if (!["pack", "path", "pack_hash", "params"].includes(k)) fail("POLICY_FILE_INVALID", `${at}: unknown member "${k}"`);
    if ((ref.pack === undefined) === (ref.path === undefined)) fail("POLICY_FILE_INVALID", `${at} needs exactly one of pack or path`);
    if (typeof ref.pack_hash !== "string" || !/^[0-9a-f]{64}$/.test(ref.pack_hash)) fail("POLICY_FILE_INVALID", `${at}.pack_hash must be 64 lower-case hex (it pins the pack)`);
    let pack;
    if (ref.pack !== undefined) {
      if (typeof ref.pack !== "string") fail("POLICY_FILE_INVALID", `${at}.pack must be a string`);
      pack = getPack(ref.pack);
    } else {
      if (typeof ref.path !== "string" || ref.path === "") fail("POLICY_FILE_INVALID", `${at}.path must be a string`);
      const file = isAbsolute(ref.path) ? ref.path : resolve(baseDir, ref.path);
      let raw;
      try {
        raw = readFileSync(file, "utf8");
      } catch (error) {
        fail("POLICY_FILE_INVALID", `${at}: cannot read ${ref.path}: ${error.code ?? error.message}`);
      }
      try {
        pack = JSON.parse(raw);
      } catch (error) {
        fail("POLICY_FILE_INVALID", `${at}: ${ref.path} is not JSON: ${error.message}`);
      }
      const check = validatePack(pack);
      if (!check.ok) fail("PACK_INVALID", `${at}: ${ref.path}: ${check.errors.join("; ")}`);
    }
    const actual = packHash(pack);
    if (actual !== ref.pack_hash) fail("PACK_HASH_MISMATCH", `${at}: ${pack.pack_id} has pack_hash ${actual}, but the policy file pins ${ref.pack_hash}. The pack changed: review it, then update pack_hash`);
    if (seen.has(pack.pack_id)) fail("POLICY_FILE_INVALID", `${at}: ${pack.pack_id} is listed twice`);
    seen.add(pack.pack_id);
    return compiledEntry(pack, actual, ref.params ?? {});
  });
  return { schema_version: doc.schema_version, environment: doc.environment, entries };
}

export function loadPolicyFile(path) {
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    fail("POLICY_FILE_UNREADABLE", `cannot read ${path}: ${error.code ?? error.message}`);
  }
  return parsePolicyFile(text, { baseDir: dirname(resolve(path)) });
}
