// RFC 8785 JSON Canonicalization Scheme (JCS), as specified for Intentrax in
// docs/architecture/specs/00-common-conventions.md §2.
//
// Port of the Go package engine/internal/determinism/jcs. Both implementations
// are pinned by docs/architecture/specs/vectors/00-canonicalisation.json and
// must produce identical bytes for every input both accept.
//
// Two profiles:
//   - "JCS-ANY": plain RFC 8785, for third-party JSON Intentrax hashes but did
//     not author (MCP arguments, tool definitions). Any finite double.
//   - "JCS-INT": every structure Intentrax or a tenant signs. Numbers must be
//     integers in the safe-integer range and member names must be ASCII.
//
// The parser is our own, so it can reject what RFC 8785 requires and what
// JSON.parse silently accepts: duplicate member names, lone UTF-16 surrogates,
// invalid UTF-8 and trailing data. Zero dependencies.

export const PROFILE_ANY = "JCS-ANY";
export const PROFILE_INT = "JCS-INT";
export const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER; // 2^53 - 1
const MAX_DEPTH = 128;

export class JcsError extends Error {
  constructor(path, message) {
    super(`jcs: invalid input: ${message} at ${path}`);
    this.name = "JcsError";
    this.path = path;
  }
}

function checkProfile(profile) {
  if (profile !== PROFILE_ANY && profile !== PROFILE_INT) {
    throw new TypeError(`unknown JCS profile ${JSON.stringify(profile)}`);
  }
}

const utf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

// toText turns raw input (string, Buffer or Uint8Array) into a string with a
// leading byte-order mark removed (spec 00 §2). Bytes must be valid UTF-8.
export function toText(raw) {
  if (typeof raw === "string") {
    return raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw;
  }
  if (raw instanceof Uint8Array) {
    let bytes = raw;
    if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
      bytes = bytes.subarray(3);
    }
    try {
      return utf8Decoder.decode(bytes);
    } catch {
      throw new JcsError("$", "input is not valid UTF-8");
    }
  }
  throw new TypeError("JSON input must be a string, Buffer or Uint8Array");
}

// ---------------------------------------------------------------- parse

// parseJson parses strict JSON into plain values. Objects are null-prototype
// objects (so a member named "__proto__" is an ordinary member) and keep
// input order; canonicalisation sorts. It rejects duplicate member names, lone
// surrogates, non-finite numbers, trailing data and nesting deeper than 128.
// Profile JCS-INT additionally rejects non-ASCII member names (numbers are
// checked when serialising, as in Go, so paths match).
export function parseJson(raw, profile = PROFILE_ANY) {
  checkProfile(profile);
  const text = toText(raw);
  const parser = new Parser(text, profile);
  parser.skipSpace();
  const value = parser.parseValue("$", 0);
  parser.skipSpace();
  if (parser.pos !== text.length) throw new JcsError("$", "trailing data after JSON value");
  return value;
}

class Parser {
  constructor(text, profile) {
    this.text = text;
    this.pos = 0;
    this.profile = profile;
  }

  skipSpace() {
    const t = this.text;
    while (this.pos < t.length) {
      const c = t.charCodeAt(this.pos);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.pos++;
      else return;
    }
  }

  parseValue(path, depth) {
    if (depth > MAX_DEPTH) throw new JcsError(path, `nesting deeper than ${MAX_DEPTH}`);
    if (this.pos >= this.text.length) throw new JcsError(path, "unexpected end of input");
    const c = this.text[this.pos];
    if (c === "{") return this.parseObject(path, depth);
    if (c === "[") return this.parseArray(path, depth);
    if (c === '"') return this.parseString(path);
    if (c === "t") return this.literal(path, "true", true);
    if (c === "f") return this.literal(path, "false", false);
    if (c === "n") return this.literal(path, "null", null);
    if (c === "-" || (c >= "0" && c <= "9")) return this.parseNumber(path);
    throw new JcsError(path, `unexpected character ${JSON.stringify(c)}`);
  }

  literal(path, word, value) {
    if (!this.text.startsWith(word, this.pos)) throw new JcsError(path, "invalid literal");
    this.pos += word.length;
    return value;
  }

  parseObject(path, depth) {
    this.pos++; // '{'
    const obj = Object.create(null);
    this.skipSpace();
    if (this.text[this.pos] === "}") {
      this.pos++;
      return obj;
    }
    for (;;) {
      this.skipSpace();
      if (this.text[this.pos] !== '"') throw new JcsError(path, "expected member name");
      const name = this.parseString(path);
      const memberPath = `${path}.${name}`;
      if (Object.prototype.hasOwnProperty.call(obj, name)) throw new JcsError(memberPath, "duplicate member name");
      if (this.profile === PROFILE_INT && !isASCII(name)) throw new JcsError(memberPath, "JCS-INT: member name is not ASCII");
      this.skipSpace();
      if (this.text[this.pos] !== ":") throw new JcsError(memberPath, "expected ':'");
      this.pos++;
      this.skipSpace();
      obj[name] = this.parseValue(memberPath, depth + 1);
      this.skipSpace();
      if (this.pos >= this.text.length) throw new JcsError(path, "unterminated object");
      const c = this.text[this.pos++];
      if (c === "}") return obj;
      if (c !== ",") throw new JcsError(path, "expected ',' or '}'");
    }
  }

  parseArray(path, depth) {
    this.pos++; // '['
    const arr = [];
    this.skipSpace();
    if (this.text[this.pos] === "]") {
      this.pos++;
      return arr;
    }
    for (let i = 0; ; i++) {
      this.skipSpace();
      arr.push(this.parseValue(`${path}[${i}]`, depth + 1));
      this.skipSpace();
      if (this.pos >= this.text.length) throw new JcsError(path, "unterminated array");
      const c = this.text[this.pos++];
      if (c === "]") return arr;
      if (c !== ",") throw new JcsError(path, "expected ',' or ']'");
    }
  }

  parseString(path) {
    const t = this.text;
    this.pos++; // opening quote
    let out = "";
    for (;;) {
      if (this.pos >= t.length) throw new JcsError(path, "unterminated string");
      const code = t.charCodeAt(this.pos);
      if (code === 0x22) {
        this.pos++;
        if (hasLoneSurrogate(out)) throw new JcsError(path, "lone UTF-16 surrogate in string");
        return out;
      }
      if (code === 0x5c) {
        if (this.pos + 1 >= t.length) throw new JcsError(path, "unterminated escape");
        const esc = t[this.pos + 1];
        this.pos += 2;
        switch (esc) {
          case '"': case "\\": case "/": out += esc; break;
          case "b": out += "\b"; break;
          case "f": out += "\f"; break;
          case "n": out += "\n"; break;
          case "r": out += "\r"; break;
          case "t": out += "\t"; break;
          case "u": {
            const hex = t.slice(this.pos, this.pos + 4);
            if (hex.length < 4) throw new JcsError(path, "short \\u escape");
            if (!/^[0-9A-Fa-f]{4}$/.test(hex)) throw new JcsError(path, "invalid \\u escape");
            out += String.fromCharCode(parseInt(hex, 16));
            this.pos += 4;
            break;
          }
          default:
            throw new JcsError(path, `invalid escape \\${esc}`);
        }
        continue;
      }
      if (code < 0x20) throw new JcsError(path, "unescaped control character in string");
      // A raw surrogate here can only come from a string input (decoded bytes
      // are valid UTF-8); pairing is checked once the string is complete.
      out += t[this.pos];
      this.pos++;
    }
  }

  parseNumber(path) {
    const t = this.text;
    const start = this.pos;
    const digit = () => this.pos < t.length && t.charCodeAt(this.pos) >= 0x30 && t.charCodeAt(this.pos) <= 0x39;
    if (t[this.pos] === "-") this.pos++;
    if (this.pos >= t.length) throw new JcsError(path, "invalid number");
    if (t[this.pos] === "0") {
      this.pos++;
    } else if (t[this.pos] >= "1" && t[this.pos] <= "9") {
      while (digit()) this.pos++;
    } else {
      throw new JcsError(path, "invalid number");
    }
    if (t[this.pos] === ".") {
      this.pos++;
      if (!digit()) throw new JcsError(path, "invalid number fraction");
      while (digit()) this.pos++;
    }
    if (t[this.pos] === "e" || t[this.pos] === "E") {
      this.pos++;
      if (t[this.pos] === "+" || t[this.pos] === "-") this.pos++;
      if (!digit()) throw new JcsError(path, "invalid number exponent");
      while (digit()) this.pos++;
    }
    const value = Number(t.slice(start, this.pos));
    if (!Number.isFinite(value)) throw new JcsError(path, "number is not a finite IEEE-754 double");
    return value;
  }
}

function isASCII(s) {
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) >= 0x80) return false;
  return true;
}

function hasLoneSurrogate(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        i++;
        continue;
      }
      return true;
    }
    if (c >= 0xdc00 && c <= 0xdfff) return true;
  }
  return false;
}

// ---------------------------------------------------------------- serialise

// canonicalize parses raw JSON and returns its RFC 8785 text under profile.
// Encode the result as UTF-8 for hashing or signing.
export function canonicalize(raw, profile = PROFILE_ANY) {
  return serialize(parseJson(raw, profile), profile);
}

// serialize returns the RFC 8785 text of an in-memory JSON value (as produced
// by parseJson or JSON.parse, or built by code). It applies the same checks as
// canonicalize: finite numbers, no lone surrogates, and under JCS-INT safe
// integers and ASCII member names. Values that are not JSON (undefined,
// functions, symbols, bigints, Dates, class instances) are rejected rather
// than coerced.
export function serialize(value, profile = PROFILE_ANY) {
  checkProfile(profile);
  const parts = [];
  write(parts, value, profile, "$", 0);
  return parts.join("");
}

function write(parts, value, profile, path, depth) {
  if (depth > MAX_DEPTH) throw new JcsError(path, `nesting deeper than ${MAX_DEPTH}`);
  if (value === null) {
    parts.push("null");
    return;
  }
  switch (typeof value) {
    case "boolean":
      parts.push(value ? "true" : "false");
      return;
    case "string":
      if (hasLoneSurrogate(value)) throw new JcsError(path, "lone UTF-16 surrogate in string");
      parts.push(JSON.stringify(value));
      return;
    case "number":
      parts.push(formatNumber(value, profile, path));
      return;
    case "object":
      break;
    default:
      throw new JcsError(path, `unsupported value type ${typeof value}`);
  }
  if (Array.isArray(value)) {
    parts.push("[");
    // An index loop, not forEach: forEach skips holes in a sparse array and
    // would emit ",," (invalid JSON). A hole is not a JSON value: reject it.
    for (let i = 0; i < value.length; i++) {
      if (!Object.prototype.hasOwnProperty.call(value, i)) throw new JcsError(`${path}[${i}]`, "sparse array slot");
      if (i > 0) parts.push(",");
      write(parts, value[i], profile, `${path}[${i}]`, depth + 1);
    }
    parts.push("]");
    return;
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== null && proto !== Object.prototype) {
    throw new JcsError(path, "unsupported object type");
  }
  // Default string comparison orders by UTF-16 code units (RFC 8785 §3.2.3).
  const names = Object.keys(value).sort();
  parts.push("{");
  names.forEach((name, i) => {
    const memberPath = `${path}.${name}`;
    if (profile === PROFILE_INT && !isASCII(name)) throw new JcsError(memberPath, "JCS-INT: member name is not ASCII");
    if (hasLoneSurrogate(name)) throw new JcsError(memberPath, "lone UTF-16 surrogate in member name");
    if (i > 0) parts.push(",");
    parts.push(JSON.stringify(name), ":");
    write(parts, value[name], profile, memberPath, depth + 1);
  });
  parts.push("}");
}

// formatNumber renders a finite double in the ECMAScript Number-to-String
// form RFC 8785 §3.2.2.3 requires (String(n) is exactly that); -0 is "0".
export function formatNumber(n, profile = PROFILE_ANY, path = "$") {
  if (typeof n !== "number" || !Number.isFinite(n)) {
    throw new JcsError(path, "NaN and Infinity are not valid JSON numbers");
  }
  if (profile === PROFILE_INT) {
    if (!Number.isInteger(n)) throw new JcsError(path, "JCS-INT: non-integer");
    if (Math.abs(n) > MAX_SAFE_INTEGER) throw new JcsError(path, "JCS-INT: integer outside the safe range");
  }
  return Object.is(n, -0) ? "0" : String(n);
}
