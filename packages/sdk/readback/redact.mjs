// Credential redaction for read-back messages.
//
// Every string that confirmThenReport puts in `firstLine` or `detail` (check
// error messages in particular) passes through redact(). Two layers:
//
//   1. exact secrets: values the caller or a recipe declared (an API key, a
//      token). Each occurrence is replaced, whatever its shape.
//   2. shape patterns: common credential formats that may leak through an
//      error message even when nobody declared them (Bearer headers, Stripe
//      / GitHub / SendGrid keys, URL userinfo, credential query parameters).
//
// Redaction is a backstop, not a licence to put secrets in messages: recipes
// build their own error messages from status codes and never include headers.

export const REDACTED = "[REDACTED]";

const PATTERNS = [
  // Authorization header values.
  /\b(Bearer|Basic|token)\s+[A-Za-z0-9._~+/=-]{8,}/gi,
  // Stripe secret, restricted and publishable keys.
  /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{8,}/g,
  // GitHub tokens (classic, fine-grained, app, OAuth, refresh).
  /\bgh[pousr]_[A-Za-z0-9]{16,}/g,
  /\bgithub_pat_[A-Za-z0-9_]{16,}/g,
  // SendGrid API keys.
  /\bSG\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  // Postmark-style server tokens are UUIDs; only redact them next to a
  // credential-looking label so message ids (also UUIDs) stay readable.
  /\b(X-Postmark-(?:Server|Account)-Token["':=\s]+)[0-9a-f-]{36}/gi,
];

// URL userinfo (scheme://user:password@host) and credential query parameters.
const USERINFO = /(\b[a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+:[^\s/@]+@/gi;
const QUERY_SECRET = /([?&](?:access_token|token|api_key|apikey|key|secret|password|signature|sig)=)[^&#\s"']+/gi;

/**
 * Replace declared secrets and credential-shaped substrings in `text`.
 * @param {unknown} text
 * @param {Iterable<string>} [secrets]
 * @returns {string}
 */
export function redact(text, secrets = []) {
  let out = String(text);
  const exact = [...secrets]
    .filter((s) => typeof s === "string" && s.length >= 4)
    // Longest first, so a secret that contains another is removed whole.
    .sort((a, b) => b.length - a.length);
  for (const s of exact) out = out.split(s).join(REDACTED);
  for (const re of PATTERNS) {
    out = out.replace(re, (match, label) =>
      typeof label === "string" && /^X-Postmark/i.test(label) ? label + REDACTED
        : typeof label === "string" && /^(bearer|basic|token)$/i.test(label) ? label + " " + REDACTED
          : REDACTED);
  }
  out = out.replace(USERINFO, "$1" + REDACTED + "@");
  out = out.replace(QUERY_SECRET, "$1" + REDACTED);
  return out;
}

/** A URL for messages: origin + path only, never userinfo, query or fragment. */
export function displayUrl(url) {
  try {
    const u = new URL(url);
    return u.origin + u.pathname;
  } catch {
    return "<invalid url>";
  }
}
