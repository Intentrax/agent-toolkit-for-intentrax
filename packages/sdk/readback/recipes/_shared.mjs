// Shared plumbing for read-back recipes.
//
// A recipe is a factory: it takes a read-only credential (or a client the
// caller already built) and returns a `check` function that READS one thing
// and returns a flat object of observed fields.
//
// Rules every recipe follows:
//   - it never writes: HTTP recipes only issue GET with no body and refuse
//     redirects; client recipes only call a read method;
//   - it never logs, and never puts a credential in a thrown message (errors
//     are built from status codes; declared secrets are redacted as a backstop);
//   - a field the system did not return is left OUT of the result, never set
//     to null, so confirmThenReport reports it as missing (UNKNOWN).

import { redact, displayUrl } from "../redact.mjs";

/** Internal: where confirmThenReport finds a recipe's worker spec and secrets. */
export const RECIPE_META = Symbol.for("intentrax.readback.recipe");

const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;

function isCloneable(value) {
  try {
    structuredClone(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Wrap a recipe's read in a `check` function and attach its metadata.
 *
 * When `options` is plain data (a credential string, ids, a base URL, no
 * injected fetch or client), confirmThenReport can rebuild the same check
 * inside a worker thread from `{ href, exportName, options }`. A check built
 * around a caller's client or fetch function runs in-process instead.
 */
export function defineRecipe({ href, exportName, options, secrets, resource, source, pending, read }) {
  const declared = Object.freeze((secrets || []).filter((s) => typeof s === "string" && s.length > 0));
  const check = async function readbackCheck(ctx = {}) {
    try {
      return await read(ctx && typeof ctx === "object" ? ctx : {});
    } catch (err) {
      // Re-throw with a scrubbed message only; drop the original object,
      // whose cause chain may carry request details.
      throw new Error(redact(err && err.message ? err.message : String(err), declared));
    }
  };
  Object.defineProperty(check, "resource", { value: resource, enumerable: true });
  Object.defineProperty(check, "source", { value: source, enumerable: true });
  Object.defineProperty(check, "pending", { value: pending ? Object.freeze(pending) : null, enumerable: true });
  Object.defineProperty(check, RECIPE_META, {
    value: Object.freeze({
      secrets: declared,
      worker: isCloneable(options) ? Object.freeze({ href, exportName, options }) : null,
    }),
    enumerable: false,
  });
  return check;
}

/** Validate a caller's `notFoundAs` observation (plain JSON object or undefined). */
export function checkNotFoundAs(value) {
  if (value === undefined) return undefined;
  if (value === null || typeof value !== "object" || Array.isArray(value) || !isCloneable(value)) {
    throw new TypeError("notFoundAs must be a plain object, e.g. { exists: false }");
  }
  return value;
}

/** Copy only the listed fields the object actually has (missing stays missing). */
export function pick(obj, fields) {
  const out = {};
  if (!obj || typeof obj !== "object") return out;
  for (const f of fields) {
    if (Object.prototype.hasOwnProperty.call(obj, f) && obj[f] !== undefined) out[f] = obj[f];
  }
  return out;
}

export function requireString(name, value, { pattern, max = 500 } = {}) {
  if (typeof value !== "string" || value.length === 0 || value.length > max) {
    throw new TypeError(name + " must be a non-empty string");
  }
  if (pattern && !pattern.test(value)) throw new TypeError(name + " has unexpected characters");
  return value;
}

export function resolveFetch(fetchImpl) {
  if (fetchImpl !== undefined && typeof fetchImpl !== "function") throw new TypeError("fetch must be a function");
  const f = fetchImpl || globalThis.fetch;
  if (typeof f !== "function") throw new TypeError("no fetch implementation available (Node >= 20 has one built in)");
  return f;
}

/**
 * GET a JSON document. Read-only by construction: method GET, no body,
 * redirects refused (so credentials are never replayed to another URL).
 *
 * Returns `{ notFound: true, body: null }` on HTTP 404 when `allowNotFound`,
 * else `{ notFound: false, body }`. Throws an Error whose message names the
 * source and status only.
 */
export async function getJson({ fetchImpl, url, headers, signal, source, allowNotFound = false, maxBytes = DEFAULT_MAX_BYTES }) {
  const where = source + " (" + displayUrl(url) + ")";
  let res;
  try {
    res = await fetchImpl(url, { method: "GET", headers, signal, redirect: "error" });
  } catch (err) {
    if (signal && signal.aborted) throw new Error("read of " + where + " was aborted");
    const code = err && err.cause && err.cause.code ? " [" + err.cause.code + "]" : "";
    throw new Error("could not read " + where + ": " + (err && err.message ? err.message : String(err)) + code);
  }
  if (res.status === 404 && allowNotFound) return { notFound: true, body: null };
  if (!res.ok) {
    throw new Error(where + " answered HTTP " + res.status + (res.status === 401 || res.status === 403 ? " (check the read-only credential and its scope)" : ""));
  }
  const text = await res.text();
  if (text.length > maxBytes) throw new Error(where + " returned more than " + maxBytes + " bytes");
  try {
    return { notFound: false, body: JSON.parse(text) };
  } catch {
    throw new Error(where + " did not return JSON");
  }
}
