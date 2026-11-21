// Read-back recipe: generic HTTP GET of a JSON document, plus field selection.
//
// Minimum scope: whatever read-only credential the API offers for this one
// resource (a read-scoped API key, a viewer role token), or none for a public
// endpoint. The recipe only ever sends GET with no body and refuses redirects.
//
//   const check = httpJson({
//     url: "https://api.example.com/v1/tickets/T-1",
//     token: process.env.EXAMPLE_READONLY_TOKEN,   // sent as `Authorization: Bearer …`
//     select: { status: "data.status", owner: "data.assignee.login" },
//   });
//
// `select` maps output field names to dot paths (`a.b[0].c` and `a.b.0.c`
// both work). A path the response does not contain is left OUT of the result
// (never null), so confirmThenReport reports it as a missing field. Without
// `select` the whole top-level JSON object is returned.

import { checkNotFoundAs, defineRecipe, getJson, requireString, resolveFetch } from "./_shared.mjs";
import { displayUrl } from "../redact.mjs";

const CREDENTIAL_HEADER = /auth|token|key|secret|cookie|session/i;

/** Resolve a dot path; returns { found, value }. */
export function selectPath(root, path) {
  const parts = String(path).replace(/\[(\d+)\]/g, ".$1").split(".").filter((p) => p.length > 0);
  let cur = root;
  for (const p of parts) {
    if (cur === null || typeof cur !== "object" || !Object.prototype.hasOwnProperty.call(cur, p)) {
      return { found: false, value: undefined };
    }
    cur = cur[p];
  }
  return cur === undefined ? { found: false, value: undefined } : { found: true, value: cur };
}

function normalizeSelect(select) {
  if (select === undefined || select === null) return null;
  if (Array.isArray(select)) {
    if (select.length === 0) throw new TypeError("select must not be empty");
    return Object.fromEntries(select.map((p) => [requireString("select path", p), p]));
  }
  if (typeof select === "object") {
    const entries = Object.entries(select);
    if (entries.length === 0) throw new TypeError("select must not be empty");
    for (const [k, p] of entries) {
      requireString("select field name", k);
      requireString("select path for " + k, p);
    }
    return { ...select };
  }
  throw new TypeError("select must be an array of paths or an object of { field: path }");
}

/**
 * @param {object} opts
 * @param {string} opts.url               http(s) URL to GET
 * @param {string} [opts.token]           read-only bearer token
 * @param {Record<string,string>} [opts.headers]  extra headers (credential-looking values are redacted from messages)
 * @param {string[]|Record<string,string>} [opts.select]
 * @param {object} [opts.notFoundAs]      returned as the observation on HTTP 404 (e.g. `{ exists: false }`)
 * @param {string} [opts.resource]        label for messages (default `GET <origin><path>`)
 * @param {string} [opts.source]          name of the system read (default: the URL host)
 * @param {Record<string,unknown[]>} [opts.pending]  field values that mean "not settled yet"
 * @param {Function} [opts.fetch]         injected fetch (runs the check in-process)
 */
export function httpJson(opts = {}) {
  const { url, token, headers = {}, select, notFoundAs, resource, source, pending, fetch: fetchImpl } = opts;
  requireString("url", url, { max: 4000 });
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new TypeError("url must be http(s)");
  if (token !== undefined) requireString("token", token, { max: 10000 });
  if (headers === null || typeof headers !== "object" || Array.isArray(headers)) throw new TypeError("headers must be an object");
  const fields = normalizeSelect(select);
  checkNotFoundAs(notFoundAs);
  const f = resolveFetch(fetchImpl);

  const secrets = [];
  if (token) secrets.push(token);
  for (const [k, v] of Object.entries(headers)) if (CREDENTIAL_HEADER.test(k) && typeof v === "string") secrets.push(v);
  if (parsed.password) secrets.push(decodeURIComponent(parsed.password));

  const sendHeaders = { accept: "application/json", ...headers };
  if (token) sendHeaders.authorization = "Bearer " + token;
  const src = source || parsed.host;

  return defineRecipe({
    href: import.meta.url,
    exportName: "httpJson",
    options: opts,
    secrets,
    resource: resource || "GET " + displayUrl(url),
    source: src,
    pending,
    read: async ({ signal }) => {
      const { notFound, body } = await getJson({ fetchImpl: f, url, headers: sendHeaders, signal, source: src, allowNotFound: notFoundAs !== undefined });
      if (notFound) return structuredClone(notFoundAs);
      if (fields === null) {
        if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error(src + " returned JSON that is not an object; pass `select`");
        return body;
      }
      const out = {};
      for (const [name, path] of Object.entries(fields)) {
        const { found, value } = selectPath(body, path);
        if (found) out[name] = value;
      }
      return out;
    },
  });
}
