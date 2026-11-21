// confirmThenReport: read the outcome back BEFORE reporting success.
//
// An agent or executor says it did something ("refund processed", "email
// sent"). confirmThenReport reads the system of record with a read-only
// check and compares the fields that matter:
//
//   CONFIRMED     the read matches                     firstLine "CONFIRMED …"
//   CONTRADICTED  the read differs                     firstLine "CAUGHT …"
//   PENDING       still in a not-final state after the retries
//                 (eventually-consistent systems)      firstLine "PENDING …"
//   UNKNOWN       the check threw, timed out, returned something that is not
//                 an object, or a field is missing     firstLine "UNKNOWN …"
//
// Contract: nothing but CONFIRMED is ever worded as success. A field the read
// did not return is MISSING (UNKNOWN), never treated as null — the same rule
// as `intentrax sandbox --check`. A null the system did return is a value,
// compared like any other.
//
// Isolation (same approach as the sandbox's check-runner.mjs): a check runs in
// a worker thread that is terminated when it answers or when `timeoutMs`
// passes, so a hung socket cannot keep your process alive. That needs the
// check to be rebuildable on another thread:
//   - a recipe built from plain-data options (a credential string, ids)
//     runs in a worker automatically;
//   - `{ module: "./my-check.mjs" }` runs that module's default export in a
//     worker, as `intentrax sandbox --check` does;
//   - any other function (a closure over your client, an injected fetch) runs
//     in-process, bounded by the same timeout and given an AbortSignal, and
//     `detail.isolation` says "in-process".
//
// Provenance: the check is code YOU configured, so every result is labelled
// SELF_REPORTED. It is evidence for your own pipeline, not an Intentrax
// attestation, and carries no trust on its own.
//
// Redaction: every string is redacted WHOLE (declared secrets, then
// credential-shaped patterns) before any display cut, so a secret can never be
// split by a cut and leave an unredactable prefix behind.

import { Worker } from "node:worker_threads";
import { isAbsolute, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { redact } from "./redact.mjs";
import { RECIPE_META } from "./recipes/_shared.mjs";

export const STATUS = Object.freeze({
  CONFIRMED: "CONFIRMED",
  CONTRADICTED: "CONTRADICTED",
  PENDING: "PENDING",
  UNKNOWN: "UNKNOWN",
});

/** The first word of `firstLine` for each status. */
export const CATCH_WORDS = Object.freeze({
  CONFIRMED: "CONFIRMED",
  CONTRADICTED: "CAUGHT",
  PENDING: "PENDING",
  UNKNOWN: "UNKNOWN",
});

export const PROVENANCE = "SELF_REPORTED";
export const PROVENANCE_NOTE =
  "Read back by a check you configured (SELF_REPORTED). Not an Intentrax attestation; carries no trust on its own.";

const ISOLATION_MODES = new Set(["auto", "worker", "in-process"]);

// ---------------------------------------------------------------------------
// Worker plumbing

/** Run a recipe in a worker; same lifecycle as the sandbox's runCheckWorker. */
export function runRecipeWorker({ href, exportName, options, signal = null }) {
  return runReadbackWorker({ kind: "recipe", href, exportName, options }, signal);
}

/** Run a { module } check's default export in a worker, with the probe. */
function runModuleWorker({ href, probe, signal = null }) {
  return runReadbackWorker({ kind: "module", href, probe }, signal);
}

function runReadbackWorker(workerData, signal) {
  return new Promise((resolvePromise, reject) => {
    if (signal && signal.aborted) {
      reject(signal.reason);
      return;
    }
    const worker = new Worker(new URL("./recipe-worker.mjs", import.meta.url), { workerData });
    let settled = false;
    const onAbort = () => finish(() => reject(signal.reason));
    function finish(settle) {
      if (settled) return;
      settled = true;
      if (signal) signal.removeEventListener("abort", onAbort);
      // Terminate unconditionally: the read may have left handles open.
      worker.terminate().catch(() => {});
      settle();
    }
    worker.once("message", (m) => finish(() => (m && m.ok ? resolvePromise(m.value) : reject(new Error(m && m.error ? m.error : "check failed")))));
    worker.once("error", (err) => finish(() => reject(err)));
    worker.once("exit", (code) => finish(() => reject(new Error("check worker exited with code " + code))));
    if (signal) signal.addEventListener("abort", onAbort, { once: true });
  });
}

function moduleHref(mod) {
  if (mod instanceof URL) return mod.href;
  if (typeof mod !== "string" || mod.length === 0) throw new TypeError("check.module must be a path or URL");
  if (/^file:/i.test(mod)) return mod;
  return pathToFileURL(isAbsolute(mod) ? mod : resolve(process.cwd(), mod)).href;
}

function makeRunner(check, isolation, probe) {
  if (!ISOLATION_MODES.has(isolation)) throw new TypeError('isolation must be "auto", "worker" or "in-process"');
  if (check && typeof check === "object" && !Array.isArray(check) && check.module !== undefined) {
    if (isolation === "in-process") throw new TypeError("a { module } check always runs in a worker");
    const href = moduleHref(check.module);
    const p = check.probe === undefined ? probe : check.probe;
    try {
      structuredClone(p);
    } catch {
      throw new TypeError("check.probe must be plain data");
    }
    return {
      isolation: "worker",
      meta: { resource: check.resource, source: check.source, pending: check.pending, secrets: [] },
      run: (signal) => runModuleWorker({ href, probe: p, signal }),
    };
  }
  if (typeof check !== "function") throw new TypeError("check must be an async function, a read-back recipe, or { module }");
  const recipe = check[RECIPE_META] || null;
  const spec = recipe && recipe.worker;
  const meta = { resource: check.resource, source: check.source, pending: check.pending, secrets: recipe ? recipe.secrets : [] };
  if (isolation === "worker" && !spec) {
    throw new TypeError("this check cannot move to a worker thread (it closes over a client or an injected function); " +
      'use isolation: "in-process", or pass { module } instead');
  }
  if (spec && isolation !== "in-process") {
    return { isolation: "worker", meta, run: (signal) => runRecipeWorker({ ...spec, signal }) };
  }
  return { isolation: "in-process", meta, run: (signal) => Promise.resolve().then(() => check({ signal, ...structuredClone(probe) })) };
}

// ---------------------------------------------------------------------------
// Comparison

const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

function isPlainObject(v) {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/** Structural equality for JSON-like data. */
export function sameValue(a, b) {
  if (a === b) return true;
  if (typeof a === "number" && typeof b === "number") return Number.isNaN(a) && Number.isNaN(b);
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((x, i) => sameValue(x, b[i]));
  if (!isPlainObject(a) || !isPlainObject(b)) return false;
  const ka = Object.keys(a).filter((k) => a[k] !== undefined);
  const kb = Object.keys(b).filter((k) => b[k] !== undefined);
  return ka.length === kb.length && ka.every((k) => hasOwn(b, k) && sameValue(a[k], b[k]));
}

function normalizeTargets(expected, claimed) {
  const claimedObj = claimed === undefined || claimed === null ? null : claimed;
  if (claimedObj !== null && !isPlainObject(claimedObj)) throw new TypeError("claimed must be a plain object of the fields the agent reported");
  const has = (f) => claimedObj !== null && hasOwn(claimedObj, f) && claimedObj[f] !== undefined;
  if (Array.isArray(expected)) {
    if (expected.length === 0) throw new TypeError("expected must list at least one field");
    if (new Set(expected).size !== expected.length) throw new TypeError("expected lists a field twice");
    return expected.map((field) => {
      if (typeof field !== "string" || field.length === 0) throw new TypeError("expected field names must be non-empty strings");
      if (!has(field)) throw new TypeError("claimed has no value for expected field " + JSON.stringify(field));
      return { field, want: claimedObj[field], claimed: claimedObj[field], hasClaimed: true };
    });
  }
  if (isPlainObject(expected)) {
    const fields = Object.keys(expected);
    if (fields.length === 0) throw new TypeError("expected must name at least one field");
    return fields.map((field) => {
      if (expected[field] === undefined) throw new TypeError("expected value for " + JSON.stringify(field) + " is undefined");
      return { field, want: expected[field], claimed: has(field) ? claimedObj[field] : undefined, hasClaimed: has(field) };
    });
  }
  throw new TypeError("expected must be an array of field names (compared with claimed) or an object of { field: value }");
}

function normalizePending(pending) {
  if (pending === undefined || pending === null) return {};
  if (!isPlainObject(pending)) throw new TypeError("pending must be an object of { field: [values that mean not-settled-yet] }");
  for (const [k, v] of Object.entries(pending)) {
    if (!Array.isArray(v)) throw new TypeError("pending." + k + " must be an array of values");
  }
  return pending;
}

function typeName(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "an array";
  return "a " + typeof v;
}

function classify(read, targets, pending, src, timeoutMs) {
  if (!read.ok) {
    return read.timedOut
      ? { outcome: STATUS.UNKNOWN, reason: "check timed out after " + timeoutMs + " ms" }
      : { outcome: STATUS.UNKNOWN, reason: "check failed: " + read.error };
  }
  const obs = read.value;
  if (obs === null || typeof obs !== "object" || Array.isArray(obs)) {
    return { outcome: STATUS.UNKNOWN, reason: src + " read returned " + typeName(obs) + ", not an object of fields" };
  }
  const missing = targets.filter((t) => !hasOwn(obs, t.field) || obs[t.field] === undefined).map((t) => t.field);
  if (missing.length > 0) {
    const shown = missing.slice(0, 3).map((f) => JSON.stringify(f)).join(", ") + (missing.length > 3 ? " and " + (missing.length - 3) + " more" : "");
    return { outcome: STATUS.UNKNOWN, observed: obs, missing, reason: src + " read has no " + shown + " field" + (missing.length > 1 ? "s" : "") + " (missing is not null)" };
  }
  const mismatched = targets.filter((t) => !sameValue(obs[t.field], t.want));
  if (mismatched.length === 0) return { outcome: STATUS.CONFIRMED, observed: obs };
  const isPending = (t) => Array.isArray(pending[t.field]) && pending[t.field].some((v) => sameValue(v, obs[t.field]));
  const terminal = mismatched.filter((t) => !isPending(t));
  if (terminal.length === 0) return { outcome: STATUS.PENDING, observed: obs, mismatched };
  return { outcome: STATUS.CONTRADICTED, observed: obs, mismatched: terminal };
}

// ---------------------------------------------------------------------------
// Messages

/** Longest error text kept in a message, cut AFTER redaction. */
const ERROR_DISPLAY_MAX = 300;
/** Longest value shown in firstLine, cut AFTER redaction. */
const VALUE_DISPLAY_MAX = 80;

function fmtValue(v, secrets) {
  let s;
  try {
    s = typeof v === "bigint" ? String(v) : JSON.stringify(v);
  } catch {
    s = String(v);
  }
  if (s === undefined) s = String(v);
  s = redact(s, secrets);
  return s.length > VALUE_DISPLAY_MAX ? s.slice(0, VALUE_DISPLAY_MAX - 1) + "…" : s;
}

function deepRedact(value, secrets) {
  if (typeof value === "string") return redact(value, secrets);
  if (Array.isArray(value)) return value.map((v) => deepRedact(v, secrets));
  if (value !== null && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = deepRedact(v, secrets);
    return out;
  }
  return value;
}

function firstLineFor(last, { label, src, actor, targets, attempts, secrets }) {
  const multi = targets.length > 1;
  const fmt = (v) => fmtValue(v, secrets);
  const named = (t) => (multi ? t.field + " " : "");
  switch (last.outcome) {
    case STATUS.CONFIRMED: {
      const what = multi ? "all " + targets.length + " expected fields" : fmt(last.observed[targets[0].field]);
      const vs = targets.every((t) => t.hasClaimed) ? "matching the " + actor + "'s report" : "matching the expected state";
      return "CONFIRMED " + label + ": " + src + " shows " + what + ", " + vs + (attempts > 1 ? " (read " + attempts + " times)" : "");
    }
    case STATUS.CONTRADICTED: {
      const t = last.mismatched[0];
      const said = t.hasClaimed ? actor + " reported " + named(t) + fmt(t.claimed) : "expected " + named(t) + fmt(t.want);
      const more = last.mismatched.length > 1 ? " (+" + (last.mismatched.length - 1) + " more field" + (last.mismatched.length > 2 ? "s" : "") + " differ)" : "";
      return "CAUGHT " + label + ": " + said + ", " + src + " shows " + fmt(last.observed[t.field]) + more;
    }
    case STATUS.PENDING: {
      const t = last.mismatched[0];
      return "PENDING " + label + ": " + src + " still shows " + named(t) + fmt(last.observed[t.field]) +
        " after " + attempts + " read" + (attempts > 1 ? "s" : "") + "; not confirmed yet";
    }
    default:
      return "UNKNOWN " + label + ": " + last.reason + "; not confirmed";
  }
}

// ---------------------------------------------------------------------------

function intIn(name, v, lo, hi) {
  if (!Number.isSafeInteger(v) || v < lo || v > hi) throw new TypeError(name + " must be an integer from " + lo + " to " + hi);
  return v;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function readOnce(runner, timeoutMs) {
  const controller = new AbortController();
  let timer;
  try {
    const value = await Promise.race([
      runner.run(controller.signal),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          const timeout = Object.assign(new Error("timeout"), { readbackTimeout: true });
          controller.abort(timeout);
          reject(timeout);
        }, timeoutMs);
      }),
    ]);
    return { ok: true, value };
  } catch (err) {
    if (err && err.readbackTimeout) return { ok: false, timedOut: true };
    // Whole message: the caller redacts it before cutting it to display length.
    return { ok: false, timedOut: false, error: String(err && err.message ? err.message : err) };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Read the outcome back and say what it shows, before anyone reports success.
 *
 * @param {object} input
 * @param {object} [input.claimed]    what the agent/executor reported, e.g. { status: "processed" }
 * @param {Function|{module: string|URL, probe?: object}} input.check  read-only check or recipe
 * @param {string[]|object} input.expected  field names to compare with `claimed`, or { field: value }
 * @param {number} [input.retries=2]        extra reads while PENDING or UNKNOWN (0–20)
 * @param {number} [input.intervalMs=1000]  wait between reads (0–600000)
 * @param {number} [input.timeoutMs=10000]  limit per read (1–600000)
 * @param {object} [input.pending]         { field: [values meaning not-final] }; default: the recipe's
 * @param {boolean} [input.retryOnMismatch=false]  also re-read on a terminal mismatch
 * @param {string} [input.resource]        label, e.g. "refund rf_2291" (default: the recipe's)
 * @param {string} [input.source]          who was read, e.g. "Stripe" (default: the recipe's)
 * @param {string} [input.actor="agent"]   who made the claim
 * @param {string[]} [input.secrets]       extra strings to redact from messages
 * @param {"auto"|"worker"|"in-process"} [input.isolation="auto"]
 * @returns {Promise<{status: string, firstLine: string, detail: object}>}
 * @throws {TypeError} for caller mistakes, before any read
 */
export async function confirmThenReport(input = {}) {
  const {
    claimed, check, expected, retries = 2, intervalMs = 1000, timeoutMs = 10000, pending, retryOnMismatch = false,
    resource, source, actor = "agent", secrets = [], isolation = "auto",
  } = input;
  intIn("retries", retries, 0, 20);
  intIn("intervalMs", intervalMs, 0, 600000);
  intIn("timeoutMs", timeoutMs, 1, 600000);
  if (!Array.isArray(secrets)) throw new TypeError("secrets must be an array of strings");
  if (typeof actor !== "string" || actor.length === 0) throw new TypeError("actor must be a non-empty string");
  const targets = normalizeTargets(expected, claimed);
  const label0 = resource !== undefined ? resource : check && check.resource;
  const probe = { resource: typeof label0 === "string" ? label0 : null, fields: targets.map((t) => t.field).sort() };
  const runner = makeRunner(check, isolation, probe);
  const label = typeof resource === "string" && resource ? resource : typeof runner.meta.resource === "string" && runner.meta.resource ? runner.meta.resource : "read-back";
  const src = typeof source === "string" && source ? source : typeof runner.meta.source === "string" && runner.meta.source ? runner.meta.source : "the system of record";
  const pend = normalizePending(pending !== undefined ? pending : runner.meta.pending);
  const allSecrets = [...secrets, ...(runner.meta.secrets || [])];

  const attempts = [];
  let last;
  for (let i = 0; i <= retries; i++) {
    if (i > 0 && intervalMs > 0) await sleep(intervalMs);
    const started = Date.now();
    const read = await readOnce(runner, timeoutMs);
    if (!read.ok && read.error) read.error = redact(read.error, allSecrets).slice(0, ERROR_DISPLAY_MAX);
    last = classify(read, targets, pend, src, timeoutMs);
    const rec = { attempt: i + 1, outcome: last.outcome, elapsed_ms: Date.now() - started };
    if (last.reason) rec.reason = last.reason;
    if (last.mismatched) rec.differing_fields = last.mismatched.map((t) => t.field);
    if (last.missing) rec.missing_fields = last.missing;
    attempts.push(rec);
    if (last.outcome === STATUS.CONFIRMED) break;
    if (last.outcome === STATUS.CONTRADICTED && !retryOnMismatch) break;
  }

  const fields = {};
  for (const t of targets) {
    const f = { expected: t.want };
    if (t.hasClaimed) f.claimed = t.claimed;
    if (last.observed && hasOwn(last.observed, t.field) && last.observed[t.field] !== undefined) {
      f.observed = last.observed[t.field];
      f.matches = sameValue(f.observed, t.want);
    } else {
      f.observed_missing = true;
      f.matches = null;
    }
    fields[t.field] = f;
  }

  const status = last.outcome;
  const firstLine = redact(firstLineFor(last, { label, src, actor, targets, attempts: attempts.length, secrets: allSecrets }), allSecrets);
  const detail = deepRedact({
    status,
    provenance: PROVENANCE,
    trust_bearing: false,
    note: PROVENANCE_NOTE,
    resource: label,
    source: src,
    isolation: runner.isolation,
    compared_fields: targets.map((t) => t.field),
    fields,
    attempts,
    reason: last.reason || null,
    checked_at: new Date().toISOString(),
  }, allSecrets);
  return { status, firstLine, detail };
}
