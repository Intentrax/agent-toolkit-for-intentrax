// Fact re-derivation (docs/architecture/specs/03-enforce-mode-and-policy-facts.md
// §4.2 and §6.5). Port of the Go verifier (offlineproof/factmap.go, PR #600).
//
// When a policy_binding/1.2 seals ENGINE_DERIVED_FROM_ARGUMENTS facts and the
// export discloses the admitted arguments (already checked against
// arguments_hash) and a fact map whose hash is the sealed fact_map_hash, the
// verifier re-derives every request fact and requires it to equal the event
// it re-checked: plaintext facts plus opened withheld facts. That turns
// POLICY_EVENT_SELF_REPORTED into a checked derivation (FACTS_REDERIVED). A
// mismatch, or a derivation the published map cannot perform, fails closed:
// the engine seals no policy binding when derivation fails.
//
// The rules mirror the engine's (runtime/admissionpolicy DeriveFacts): a
// missing pointer leaves the fact absent; amount_minor must be a JSON integer
// literal (in the JCS-ANY form of the arguments) in the safe range, currency
// three upper-case letters, resource a 1–256 character string; tool is always
// the tool name. environment comes from the API key and is not derivable.

import { PROFILE_ANY, PROFILE_INT, digest, parseJson } from "../envelope/index.mjs";
import { FACT_SOURCE } from "./policy-binding.mjs";

export const FACT_MAP_SCHEMA_VERSION = "intentrax.policy.fact_map/0.1";
export const DOMAIN_FACT_MAP = "INTENTRAX_FACT_MAP_V0_1";

const FACT_MAP_TYPES = Object.freeze({ amount_minor: "INTEGER", currency: "CURRENCY", resource: "STRING" });
// A non-empty RFC 6901 pointer.
const FACT_MAP_POINTER = /^(\/([^/~]|~[01])*)+$/;
const CURRENCY = /^[A-Z]{3}$/;
const AMOUNT = "eeo.request.amount_minor";
const CURRENCY_FIELD = "eeo.request.currency";
const ENVIRONMENT = "eeo.request.environment";
const RESOURCE = "eeo.request.resource";
const TOOL = "eeo.request.tool";
const COMPARED = [AMOUNT, CURRENCY_FIELD, RESOURCE, TOOL];

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const exactMembers = (o, names) => Object.keys(o).length === names.length && names.every((k) => own(o, k));

// decodeFactMap strictly checks a fact map (a parsed JSON value) and returns
// {map, hash}; it throws when the map is malformed. Every member is required
// and none may be added. As in Go, `tools` and a tool's `facts` may be null
// (no tools, no facts).
export function decodeFactMap(value) {
  if (!isObject(value) || !exactMembers(value, ["schema_version", "tenant_id", "tools", "version"])) throw new Error("fact map has members outside the schema");
  if (value.schema_version !== FACT_MAP_SCHEMA_VERSION || typeof value.tenant_id !== "string" || value.tenant_id === ""
    || !Number.isSafeInteger(value.version) || value.version < 1) {
    throw new Error("fact map schema_version, tenant_id or version invalid");
  }
  if (value.tools !== null && !Array.isArray(value.tools)) throw new Error("fact map has members outside the schema");
  const tools = [];
  (value.tools ?? []).forEach((tool, i) => {
    if (!isObject(tool) || !exactMembers(tool, ["facts", "server_id", "tool_name"])) throw new Error("fact map has members outside the schema");
    if (typeof tool.server_id !== "string" || typeof tool.tool_name !== "string") throw new Error("fact map has members outside the schema");
    if (tool.server_id === "" || tool.tool_name === "") throw new Error(`fact map tools[${i}] server_id or tool_name missing`);
    if (tool.facts !== null && !isObject(tool.facts)) throw new Error("fact map has members outside the schema");
    const facts = [];
    for (const [name, spec] of Object.entries(tool.facts ?? {})) {
      if (!isObject(spec) || !exactMembers(spec, ["pointer", "type"]) || typeof spec.pointer !== "string" || typeof spec.type !== "string") {
        throw new Error("fact map has members outside the schema");
      }
      if (!own(FACT_MAP_TYPES, name) || spec.type !== FACT_MAP_TYPES[name] || !FACT_MAP_POINTER.test(spec.pointer)) {
        throw new Error(`fact map tools[${i}].facts.${name} invalid`);
      }
      facts.push({ name, pointer: spec.pointer, type: spec.type });
    }
    tools.push({ serverId: tool.server_id, toolName: tool.tool_name, facts });
  });
  return { map: { tools }, hash: digest(DOMAIN_FACT_MAP, value, PROFILE_INT) };
}

// resolveJsonPointer applies an RFC 6901 JSON Pointer to a parsed document.
// Array indexes follow the engine's reading (Go strconv.Atoi after refusing an
// empty token and a leading zero), so "+1" and "-0" select an element there
// too.
export function resolveJsonPointer(document, pointer) {
  let current = document;
  for (const raw of pointer.split("/").slice(1)) {
    const token = raw.replaceAll("~1", "/").replaceAll("~0", "~");
    if (isObject(current)) {
      if (!own(current, token)) return { found: false };
      current = current[token];
    } else if (Array.isArray(current)) {
      if (token === "" || (token.length > 1 && token[0] === "0") || !/^[+-]?[0-9]+$/.test(token)) return { found: false };
      const index = Number(token);
      if (!Number.isSafeInteger(index) || index < 0 || index >= current.length) return { found: false };
      current = current[index];
    } else {
      return { found: false };
    }
  }
  return { found: true, value: current };
}

// deriveFacts reads the mapped facts from the arguments (canonical JCS-ANY
// text). The result holds facts by field path.
export function deriveFacts(map, serverId, toolName, argumentsJcs) {
  const facts = { [TOOL]: toolName };
  const tool = map.tools.find((t) => t.serverId === serverId && t.toolName === toolName);
  if (!tool) return facts;
  let document;
  try {
    document = parseJson(argumentsJcs, PROFILE_ANY);
  } catch {
    throw new Error("arguments unreadable");
  }
  for (const { name, pointer, type } of tool.facts) {
    const { found, value } = resolveJsonPointer(document, pointer);
    if (!found) continue;
    const field = `eeo.request.${name}`;
    if (type === "INTEGER") {
      // The canonical literal (ECMAScript number form, as JCS writes it)
      // must have no fraction or exponent, as Go's json.Number check.
      if (typeof value !== "number" || !/^-?[0-9]+$/.test(String(value))) throw new Error(`${name} is not an integer`);
      if (!Number.isSafeInteger(value)) throw new Error(`${name} is outside the safe-integer range`);
      facts[field] = value === 0 ? 0 : value;
    } else if (type === "CURRENCY") {
      if (typeof value !== "string" || !CURRENCY.test(value)) throw new Error(`${name} is not three upper-case letters`);
      facts[field] = value;
    } else {
      if (typeof value !== "string" || value === "" || [...value].length > 256) throw new Error(`${name} is not a 1-256 character string`);
      facts[field] = value;
    }
  }
  return facts;
}

// sealedEventFacts are the request facts of the re-checked event: plaintext
// facts plus every opened withheld fact. Returns null when a withheld fact
// was not opened, so the event is not fully known.
export function sealedEventFacts(evaluatedFacts, opened) {
  const event = {};
  const request = evaluatedFacts.request;
  if (request) {
    if (Number.isSafeInteger(request.amount_minor)) event[AMOUNT] = request.amount_minor;
    for (const [field, key] of [[CURRENCY_FIELD, "currency"], [RESOURCE, "resource"], [TOOL, "tool"]]) {
      if (typeof request[key] === "string" && request[key] !== "") event[field] = request[key];
    }
  }
  for (const withheld of evaluatedFacts.withheld ?? []) {
    if (!own(opened, withheld.field)) return null;
    if (withheld.field !== ENVIRONMENT) event[withheld.field] = opened[withheld.field];
  }
  return event;
}

// rederiveFacts re-derives the request facts of an admission-lane binding
// from the disclosed arguments and fact map. opened is openDisclosures'
// result. Returns true when the facts were re-derived and equal the event,
// false when the inputs are missing (not a failure), and throws when the
// record's facts do not follow from its own arguments and fact map (fail
// closed).
export function rederiveFacts(policy, opened, factMaps) {
  const evaluated = policy?.evaluated_facts;
  if (!evaluated || evaluated.source !== FACT_SOURCE.ENGINE_DERIVED_FROM_ARGUMENTS || !opened?.report?.arguments_recomputed
    || typeof opened.arguments !== "string" || typeof opened.toolName !== "string" || opened.toolName === "") {
    return false;
  }
  const event = sealedEventFacts(evaluated, opened.facts ?? {});
  if (event === null) return false;
  for (const raw of factMaps ?? []) {
    let decoded;
    try {
      decoded = decodeFactMap(raw);
    } catch {
      continue;
    }
    if (decoded.hash !== policy.fact_map_hash) continue;
    let derived;
    try {
      derived = deriveFacts(decoded.map, opened.serverId ?? "", opened.toolName, opened.arguments);
    } catch (err) {
      throw new Error(`policy facts do not derive from the disclosed arguments: ${err.message}`);
    }
    for (const field of COMPARED) {
      const sealed = own(event, field);
      const got = own(derived, field);
      if (sealed !== got || (sealed && String(event[field]) !== String(derived[field]))) {
        throw new Error(`policy fact ${field} does not re-derive from the disclosed arguments and fact map`);
      }
    }
    return true;
  }
  return false;
}
