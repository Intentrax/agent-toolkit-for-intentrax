// Small, dependency-free text helpers for the static scan: line numbers,
// string literals, bracket matching and a tolerant JSON-with-comments parser.
// Nothing here executes or imports the code being scanned.

export function makeLineIndex(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) {
    if (text.charCodeAt(i) === 10) starts.push(i + 1);
  }
  return (index) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
}

// Reads a string literal that starts at or after `index` (after optional
// whitespace). Handles "", '', `` and Python triple quotes and r/b/u/f
// prefixes. Returns { value, start, end } or null.
export function readString(text, index) {
  let i = index;
  while (i < text.length && /\s/.test(text[i])) i += 1;
  const start = i;
  if (/[rRbBuUfF]/.test(text[i] ?? "") && /["']/.test(text[i + 1] ?? "")) i += 1;
  const q = text[i];
  if (q !== '"' && q !== "'" && q !== "`") return null;
  const triple = (q === '"' || q === "'") && text[i + 1] === q && text[i + 2] === q;
  if (triple) {
    const close = text.indexOf(q + q + q, i + 3);
    if (close < 0) return null;
    return { value: text.slice(i + 3, close), start, end: close + 3 };
  }
  let out = "";
  for (let j = i + 1; j < text.length; j += 1) {
    const c = text[j];
    if (c === "\\") {
      out += text[j + 1] ?? "";
      j += 1;
      continue;
    }
    if (c === q) return { value: out, start, end: j + 1 };
    if (c === "\n" && q !== "`") return null;
    out += c;
  }
  return null;
}

const PAIRS = { "{": "}", "(": ")", "[": "]" };

// Given the index of an opening bracket, returns the index of its matching
// close bracket, skipping strings and comments. -1 when not found within
// `limit` characters.
export function matchBracket(text, openIndex, { python = false, limit = 40000 } = {}) {
  const open = text[openIndex];
  const close = PAIRS[open];
  if (!close) return -1;
  let depth = 0;
  const end = Math.min(text.length, openIndex + limit);
  for (let i = openIndex; i < end; i += 1) {
    const c = text[i];
    if (c === '"' || c === "'" || c === "`") {
      const s = readString(text, i);
      if (s) {
        i = s.end - 1;
        continue;
      }
      continue;
    }
    if (!python && c === "/" && text[i + 1] === "/") {
      const nl = text.indexOf("\n", i);
      i = nl < 0 ? end : nl;
      continue;
    }
    if (!python && c === "/" && text[i + 1] === "*") {
      const e = text.indexOf("*/", i + 2);
      i = e < 0 ? end : e + 1;
      continue;
    }
    if (python && c === "#") {
      const nl = text.indexOf("\n", i);
      i = nl < 0 ? end : nl;
      continue;
    }
    if (c === open) depth += 1;
    else if (c === close) {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

// Depth of `target` relative to the bracket opened at `openIndex` (1 means
// directly inside it). String-aware. Returns -1 when target is outside.
export function depthAt(text, openIndex, target) {
  let depth = 0;
  for (let i = openIndex; i < text.length && i <= target; i += 1) {
    if (i === target) return depth;
    const c = text[i];
    if (c === '"' || c === "'" || c === "`") {
      const s = readString(text, i);
      if (s) {
        if (s.end > target) return depth;
        i = s.end - 1;
      }
      continue;
    }
    if (c === "{" || c === "(" || c === "[") depth += 1;
    else if (c === "}" || c === ")" || c === "]") depth -= 1;
    if (depth <= 0 && i > openIndex) return -1;
  }
  return -1;
}

// First `key: "string"` / `key="string"` / `"key": "string"` inside
// text[from, to), optionally only at bracket depth `depth` relative to `open`.
export function findKeyString(text, key, from, to, { open = -1, depth = null } = {}) {
  const re = new RegExp(`["']?\\b${key}["']?\\s*[:=]\\s*`, "g");
  re.lastIndex = from;
  let m;
  while ((m = re.exec(text)) && m.index < to) {
    if (depth !== null && open >= 0 && depthAt(text, open, m.index) !== depth) continue;
    const s = readString(text, m.index + m[0].length);
    if (s && s.start === m.index + m[0].length) return { value: s.value, index: m.index };
  }
  return null;
}

export function parseJsonc(raw) {
  const text = raw.replace(/^\uFEFF/, "");
  try {
    return JSON.parse(text);
  } catch {
    // fall through to the tolerant parse
  }
  let out = "";
  let inStr = false;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (inStr) {
      out += c;
      if (c === "\\") {
        out += text[i + 1] ?? "";
        i += 1;
      } else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') {
      inStr = true;
      out += c;
      continue;
    }
    if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i += 1;
      out += "\n";
      continue;
    }
    if (c === "/" && text[i + 1] === "*") {
      const e = text.indexOf("*/", i + 2);
      i = e < 0 ? text.length : e + 1;
      continue;
    }
    out += c;
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"));
}

// Splits identifiers and prose into lower-case word tokens:
// "deleteVolume" -> ["delete", "volume"], "run_sql" -> ["run", "sql"].
export function tokenize(text) {
  return String(text ?? "")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9']+/)
    .filter(Boolean);
}

export function toPosix(p) {
  return p.split("\\").join("/");
}
