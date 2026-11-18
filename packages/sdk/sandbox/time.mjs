// Strict timestamps for the local assurance sandbox verifier.
//
// Ported from examples/effect-assurance-demo/src/clock.mjs (#491).
// RFC 3339 date-time with an EXPLICIT offset (`Z` or `±hh:mm`). Date.parse()
// alone would accept a timezone-less value in the verifier's local timezone,
// making a result depend on the machine that verifies, and returns NaN for
// garbage, which compares false and can silently pass a time check. Everything
// that verifies a timestamp uses this and treats null as a failure. The
// sandbox's own producers only ever emit `Z` times.

export const RFC3339_WITH_OFFSET = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

// Epoch ms, or null unless `v` is an RFC 3339 string with an explicit offset.
export function isoMs(v) {
  if (typeof v !== "string" || !RFC3339_WITH_OFFSET.test(v)) return null;
  const ms = Date.parse(v);
  return Number.isFinite(ms) ? ms : null;
}
