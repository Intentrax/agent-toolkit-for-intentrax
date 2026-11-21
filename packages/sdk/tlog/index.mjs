// Transparency-log inclusion verification for Intentrax proofs (R7, claim 6;
// rollout step 2 "verifiers learn the format").
//
// A port of the Go package engine/internal/transparencylog, offline and
// dependency-free (node:crypto only):
//   - RFC 9162 Merkle inclusion and consistency verification
//     (leaf = SHA-256(0x00 || 0x01 || proof_record_hash), node = SHA-256(0x01 || l || r));
//   - C2SP signed notes, tlog-checkpoint checkpoints (Ed25519, type 0x01) and
//     tlog-cosignature cosignature/v1 witness cosignatures (type 0x04);
//   - the intentrax.tlog.inclusion-bundle/v0 sidecar and the
//     intentrax.trust.transparency_log/0 trust document, parsed strictly
//     (exact keys, no duplicates, no unknown fields, no trailing data).
//
// verifyBundleOffline must produce the same status and reason codes as the Go
// verifier for every case in
// engine/internal/transparencylog/testdata/inclusion-bundle-vectors.v0.json.
// Nothing here reads the network, the clock or the environment.
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";

export const INCLUSION_BUNDLE_FORMAT_V0 = "intentrax.tlog.inclusion-bundle/v0";
export const TRUST_DOCUMENT_SCHEMA_V0 = "intentrax.trust.transparency_log/0";

export const SIG_TYPE_ED25519 = 0x01;
export const SIG_TYPE_COSIGNATURE_V1 = 0x04;

const HASH_SIZE = 32;
const MAX_SAFE_INTEGER = 2 ** 53 - 1;
const MAX_PROOF_HASHES = 64;
const MAX_NOTE_SIGNATURES = 100;
const MAX_NOTE_SIZE = 64 << 10;
const MAX_WIRE_SIZE = 64 << 10;
const MAX_ORIGIN_LENGTH = 255;
const MAX_JSON_DEPTH = 16;
const RECORD_LEAF_TYPE_V0 = 0x01;
const COSIGNATURE_V1_HEADER = "cosignature/v1\n";
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export const STATUS = Object.freeze({
  VERIFIED: "VERIFIED",
  VERIFIED_UNWITNESSED: "VERIFIED_UNWITNESSED",
  FAILED: "FAILED",
});

export const REASON = Object.freeze({
  POLICY_INVALID: "POLICY_INVALID",
  CHECKPOINT_MALFORMED: "CHECKPOINT_MALFORMED",
  ORIGIN_MISMATCH: "ORIGIN_MISMATCH",
  LOG_SIGNATURE_MISSING: "LOG_SIGNATURE_MISSING",
  LOG_SIGNATURE_INVALID: "LOG_SIGNATURE_INVALID",
  WITNESS_SIGNATURE_INVALID: "WITNESS_SIGNATURE_INVALID",
  WITNESS_QUORUM_NOT_MET: "WITNESS_QUORUM_NOT_MET",
  CHECKPOINT_STALE: "CHECKPOINT_STALE",
  PROOF_MALFORMED: "PROOF_MALFORMED",
  PROOF_TREE_SIZE_MISMATCH: "PROOF_TREE_SIZE_MISMATCH",
  INCLUSION_ROOT_MISMATCH: "INCLUSION_ROOT_MISMATCH",
  RECORD_HASH_MISMATCH: "RECORD_HASH_MISMATCH",
});

/** Thrown for input that does not parse (Go: ErrMalformed). */
export class TLogMalformedError extends Error {
  constructor(message) {
    super(`transparencylog: malformed input: ${message}`);
    this.name = "TLogMalformedError";
  }
}

const malformed = (message) => new TLogMalformedError(message);

// ---------------------------------------------------------------- hashing

function sha256(...parts) {
  const h = createHash("sha256");
  for (const part of parts) h.update(part);
  return h.digest();
}

export function leafHash(leaf) {
  return sha256(Buffer.from([0x00]), leaf);
}

export function nodeHash(left, right) {
  return sha256(Buffer.from([0x01]), left, right);
}

export function emptyRoot() {
  return sha256();
}

/** The log leaf of a proof record: 0x01 || proof_record_hash (33 bytes). */
export function recordLeaf(recordHash) {
  return Buffer.concat([Buffer.from([RECORD_LEAF_TYPE_V0]), recordHash]);
}

export function recordLeafHash(recordHash) {
  return leafHash(recordLeaf(recordHash));
}

/** Parses a 64-character hex hash (either case, as Go's hex.Decode). */
export function parseHashHex(value) {
  if (typeof value !== "string" || value.length !== 2 * HASH_SIZE || !/^[0-9a-fA-F]+$/.test(value)) {
    throw malformed("hex hash must be 64 hex characters");
  }
  return Buffer.from(value, "hex");
}

// Go's base64.StdEncoding.Strict(): padded standard alphabet, zero trailing
// bits; '\r' and '\n' are ignored, as Go's decoder does.
function decodeBase64Strict(value) {
  const s = value.replace(/[\r\n]/g, "");
  if (s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  const out = Buffer.from(s, "base64");
  if (out.toString("base64") !== s) return null;
  return out;
}

// ------------------------------------------------------- Merkle verification

/**
 * Recomputes the root from an inclusion proof (RFC 9162 §2.1.3.2). Indexes
 * are integers no larger than 2^53-1.
 */
export function rootFromInclusionProof(leafIndex, treeSize, leaf, proof) {
  if (!Number.isSafeInteger(treeSize) || !Number.isSafeInteger(leafIndex) || treeSize <= 0 || leafIndex < 0 || leafIndex >= treeSize) {
    throw new Error(`inclusion proof invalid: leaf index ${leafIndex} not in tree size ${treeSize}`);
  }
  let fn = BigInt(leafIndex);
  let sn = BigInt(treeSize - 1);
  let r = leaf;
  for (const p of proof) {
    if (sn === 0n) throw new Error("inclusion proof invalid: proof longer than the path");
    if ((fn & 1n) === 1n || fn === sn) {
      r = nodeHash(p, r);
      if ((fn & 1n) === 0n) {
        while ((fn & 1n) === 0n && fn !== 0n) {
          fn >>= 1n;
          sn >>= 1n;
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  if (sn !== 0n) throw new Error("inclusion proof invalid: proof shorter than the path");
  return r;
}

/**
 * Verifies that `second` extends `first` (RFC 9162 §2.1.4.2). Returns
 * nothing or throws.
 */
export function verifyConsistency(first, second, firstRoot, secondRoot, proof) {
  if (first > second) throw new Error(`consistency proof invalid: first size ${first} exceeds second size ${second}`);
  if (second > MAX_SAFE_INTEGER) throw new Error("consistency proof invalid: tree size too large");
  if (first === second) {
    if (proof.length !== 0) throw new Error("consistency proof invalid: proof between equal sizes must be empty");
    if (!firstRoot.equals(secondRoot)) throw new Error("consistency proof invalid: equal sizes with different roots (fork)");
    return;
  }
  if (first === 0) {
    if (proof.length !== 0) throw new Error("consistency proof invalid: proof from the empty tree must be empty");
    if (!firstRoot.equals(emptyRoot())) throw new Error("consistency proof invalid: empty tree root mismatch");
    return;
  }
  if (proof.length === 0) throw new Error("consistency proof invalid: empty proof");
  let fn = BigInt(first - 1);
  let sn = BigInt(second - 1);
  const path = (BigInt(first) & (BigInt(first) - 1n)) === 0n ? [firstRoot, ...proof] : proof;
  while ((fn & 1n) === 1n) {
    fn >>= 1n;
    sn >>= 1n;
  }
  let fr = path[0];
  let sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0n) throw new Error("consistency proof invalid: proof longer than expected");
    if ((fn & 1n) === 1n || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      if ((fn & 1n) === 0n) {
        while ((fn & 1n) === 0n && fn !== 0n) {
          fn >>= 1n;
          sn >>= 1n;
        }
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  if (sn !== 0n) throw new Error("consistency proof invalid: proof shorter than expected");
  if (!fr.equals(firstRoot)) throw new Error("consistency proof invalid: first root mismatch");
  if (!sr.equals(secondRoot)) throw new Error("consistency proof invalid: second root mismatch");
}

// ------------------------------------------------------------ signed notes

// Go's unicode.IsSpace.
const GO_SPACE = /[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/;

function validKeyName(name) {
  return typeof name === "string" && name !== "" && !GO_SPACE.test(name) && !name.includes("+") && !/[\ud800-\udfff]/.test(name);
}

/** C2SP key ID: the first 4 bytes of SHA-256(name || "\n" || type || key). */
export function keyID(name, sigType, publicKey) {
  return sha256(Buffer.from(name, "utf8"), Buffer.from([0x0a, sigType]), publicKey).readUInt32BE(0);
}

function makeVerifierKey(name, sigType, publicKey) {
  if (!validKeyName(name)) throw malformed(`invalid key name ${JSON.stringify(name)}`);
  if (sigType !== SIG_TYPE_ED25519 && sigType !== SIG_TYPE_COSIGNATURE_V1) throw malformed(`unsupported signature type 0x${sigType.toString(16).padStart(2, "0")}`);
  if (publicKey.length !== 32) throw malformed("Ed25519 public key must be 32 bytes");
  const key = Buffer.from(publicKey);
  return Object.freeze({ name, keyID: keyID(name, sigType, key), type: sigType, publicKey: key });
}

/** Parses a C2SP verifier key string name+hexid+base64(type||key). */
export function parseVerifierKey(value) {
  if (typeof value !== "string") throw malformed("verifier key must be a string");
  if (Buffer.byteLength(value, "utf8") > 1024) throw malformed("verifier key too long");
  const first = value.indexOf("+");
  const second = first < 0 ? -1 : value.indexOf("+", first + 1);
  if (first < 0 || second < 0) throw malformed("verifier key shape");
  const name = value.slice(0, first);
  const idHex = value.slice(first + 1, second);
  const b64 = value.slice(second + 1);
  if (idHex.length !== 8 || !validKeyName(name)) throw malformed("verifier key shape");
  if (!/^[0-9a-f]{8}$/.test(idHex)) throw malformed("verifier key id must be lowercase hex");
  const raw = decodeBase64Strict(b64);
  if (raw === null || raw.length !== 33) throw malformed("verifier key material");
  const key = makeVerifierKey(name, raw[0], raw.subarray(1));
  if (key.keyID !== Number.parseInt(idHex, 16)) throw malformed("verifier key id does not match name and key");
  return key;
}

export function verifierKeyString(key) {
  return `${key.name}+${key.keyID.toString(16).padStart(8, "0")}+${Buffer.concat([Buffer.from([key.type]), key.publicKey]).toString("base64")}`;
}

const EM_DASH_PREFIX = Buffer.from("\u2014 ", "utf8");

/** Parses a C2SP signed note from its bytes. */
export function parseNote(bytes) {
  const msg = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes, "utf8");
  if (msg.length > MAX_NOTE_SIZE) throw malformed(`note larger than ${MAX_NOTE_SIZE} bytes`);
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(msg);
  } catch {
    throw malformed("note contains a control character or invalid UTF-8");
  }
  if (/[\u0000-\u0009\u000b-\u001f\u007f]/.test(text)) throw malformed("note contains a control character or invalid UTF-8");
  const split = msg.lastIndexOf("\n\n");
  if (split < 0) throw malformed("note has no signature block");
  const body = msg.subarray(0, split + 1);
  let sigs = msg.subarray(split + 2);
  if (sigs.length === 0 || sigs[sigs.length - 1] !== 0x0a) throw malformed("note signature block is empty or unterminated");
  const note = { text: body.toString("utf8"), sigs: [] };
  while (sigs.length > 0) {
    const i = sigs.indexOf(0x0a);
    const line = sigs.subarray(0, i);
    sigs = sigs.subarray(i + 1);
    if (note.sigs.length === MAX_NOTE_SIGNATURES) throw malformed(`more than ${MAX_NOTE_SIGNATURES} signatures`);
    if (!line.subarray(0, EM_DASH_PREFIX.length).equals(EM_DASH_PREFIX)) throw malformed("signature line does not start with an em dash");
    const rest = line.subarray(EM_DASH_PREFIX.length).toString("utf8");
    const space = rest.indexOf(" ");
    const name = space < 0 ? "" : rest.slice(0, space);
    const b64 = space < 0 ? "" : rest.slice(space + 1);
    if (space < 0 || !validKeyName(name) || b64 === "") throw malformed("signature line name");
    const blob = decodeBase64Strict(b64);
    if (blob === null || blob.length < 5) throw malformed("signature line base64");
    note.sigs.push({ name, keyID: blob.readUInt32BE(0), sig: blob.subarray(4) });
  }
  return note;
}

function ed25519Verify(publicKey, message, signature) {
  try {
    const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]), format: "der", type: "spki" });
    return verifySignature(null, message, key, signature);
  } catch {
    return false;
  }
}

function verifyNoteSignature(vk, text, sig) {
  return vk.type === SIG_TYPE_ED25519 && sig.name === vk.name && sig.keyID === vk.keyID &&
    sig.sig.length === 64 && ed25519Verify(vk.publicKey, Buffer.from(text, "utf8"), sig.sig);
}

// ------------------------------------------------------------- checkpoints

function checkpointBody(cp) {
  return `${cp.origin}\n${cp.size}\n${cp.hash.toString("base64")}\n`;
}

function parseDecimal(value) {
  if (value === "" || value.length > 16 || (value.length > 1 && value[0] === "0")) throw malformed(`decimal ${JSON.stringify(value)} is not canonical`);
  if (!/^[0-9]+$/.test(value)) throw malformed(`decimal ${JSON.stringify(value)} has a non-digit`);
  const v = Number(value);
  if (!Number.isSafeInteger(v)) throw malformed(`decimal ${JSON.stringify(value)} out of range`);
  return v;
}

/** Parses tlog-checkpoint text: origin, size and base64 root; no extension lines. */
export function parseCheckpoint(text) {
  if (!text.endsWith("\n")) throw malformed("checkpoint text must end in a newline");
  const lines = text.slice(0, -1).split("\n");
  if (lines.length !== 3) throw malformed(`checkpoint must have exactly 3 lines, got ${lines.length}`);
  const size = parseDecimal(lines[1]);
  const hash = decodeBase64Strict(lines[2]);
  if (hash === null || hash.length !== HASH_SIZE) throw malformed("checkpoint root hash must be base64 of 32 bytes");
  const cp = { origin: lines[0], size, hash };
  if (!validKeyName(cp.origin) || Buffer.byteLength(cp.origin, "utf8") > MAX_ORIGIN_LENGTH) throw malformed(`checkpoint origin ${JSON.stringify(cp.origin)}`);
  if (cp.size === 0 && !cp.hash.equals(emptyRoot())) throw malformed("empty checkpoint must carry the empty-tree root");
  return cp;
}

function verifyCosignature(vk, cp, sig) {
  if (vk.type !== SIG_TYPE_COSIGNATURE_V1 || sig.name !== vk.name || sig.keyID !== vk.keyID || sig.sig.length !== 8 + 64) {
    return null;
  }
  const ts = sig.sig.readBigUInt64BE(0);
  const message = Buffer.from(`${COSIGNATURE_V1_HEADER}time ${ts.toString()}\n${checkpointBody(cp)}`, "utf8");
  return ed25519Verify(vk.publicKey, message, sig.sig.subarray(8)) ? ts : null;
}

// ------------------------------------------------------------------ policy

function validatePolicy(p) {
  if (!validKeyName(p.origin) || Buffer.byteLength(p.origin, "utf8") > MAX_ORIGIN_LENGTH) return `origin ${JSON.stringify(p.origin)} is not a valid key name`;
  if (p.logKey.type !== SIG_TYPE_ED25519 || p.logKey.publicKey.length !== 32) return "log key must be an Ed25519 note key";
  if (p.logKey.name !== p.origin) return `log key name ${JSON.stringify(p.logKey.name)} must equal origin ${JSON.stringify(p.origin)}`;
  if (p.logKey.keyID !== keyID(p.logKey.name, p.logKey.type, p.logKey.publicKey)) return "log key id does not match its name and key";
  const names = new Set([p.logKey.name]);
  const keys = new Set([p.logKey.publicKey.toString("hex")]);
  for (const w of p.witnesses) {
    if (w.type !== SIG_TYPE_COSIGNATURE_V1 || w.publicKey.length !== 32) return `witness ${JSON.stringify(w.name)} must be a cosignature/v1 key`;
    if (w.keyID !== keyID(w.name, w.type, w.publicKey)) return `witness ${JSON.stringify(w.name)} key id does not match its name and key`;
    const k = w.publicKey.toString("hex");
    if (names.has(w.name) || keys.has(k)) return `witness ${JSON.stringify(w.name)} duplicates another configured name or key`;
    names.add(w.name);
    keys.add(k);
  }
  if (!Number.isInteger(p.witnessQuorum) || p.witnessQuorum < 0) return `witness quorum ${p.witnessQuorum} is negative`;
  if (p.witnessQuorum === 0 && !p.allowUnwitnessed) return "witness quorum 0 requires AllowUnwitnessed";
  if (p.witnessQuorum > p.witnesses.length) return `witness quorum ${p.witnessQuorum} exceeds ${p.witnesses.length} configured witnesses`;
  return null;
}

// ------------------------------------------------------- strict JSON input

// A strict JSON reader for the wire formats: one top-level object whose keys
// are exactly the allowed names (case-sensitive, no duplicates); values are
// strings, integers, booleans, null or arrays of those (no nested objects).
// JSON.parse cannot be used: it silently keeps the last of duplicate keys.
// Integers are returned as BigInt, so range checks are exact.
function readStrictWireObject(text, allowed) {
  if (Buffer.byteLength(text, "utf8") > MAX_WIRE_SIZE) throw malformed(`input larger than ${MAX_WIRE_SIZE} bytes`);
  let i = 0;
  const ws = () => {
    while (i < text.length && (text[i] === " " || text[i] === "\t" || text[i] === "\n" || text[i] === "\r")) i += 1;
  };
  const string = () => {
    if (text[i] !== "\"") throw malformed("expected a JSON string");
    i += 1;
    let out = "";
    for (;;) {
      if (i >= text.length) throw malformed("unterminated JSON string");
      const c = text[i];
      if (c === "\"") {
        i += 1;
        return out;
      }
      if (c < " ") throw malformed("control character in JSON string");
      if (c !== "\\") {
        out += c;
        i += 1;
        continue;
      }
      const e = text[i + 1];
      i += 2;
      const simple = { "\"": "\"", "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
      if (e in simple) {
        out += simple[e];
      } else if (e === "u") {
        const hex = text.slice(i, i + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw malformed("bad JSON \\u escape");
        i += 4;
        let code = Number.parseInt(hex, 16);
        if (code >= 0xd800 && code <= 0xdbff && text[i] === "\\" && text[i + 1] === "u" && /^[dD][c-fC-F][0-9a-fA-F]{2}$/.test(text.slice(i + 2, i + 6))) {
          const low = Number.parseInt(text.slice(i + 2, i + 6), 16);
          i += 6;
          out += String.fromCodePoint(0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00));
          continue;
        }
        if (code >= 0xd800 && code <= 0xdfff) code = 0xfffd; // lone surrogate, as Go decodes it
        out += String.fromCharCode(code);
      } else {
        throw malformed("bad JSON escape");
      }
    }
  };
  const value = (depth) => {
    if (depth > MAX_JSON_DEPTH) throw malformed("JSON nested too deeply");
    ws();
    const c = text[i];
    if (c === "\"") return string();
    if (c === "[") {
      i += 1;
      const items = [];
      ws();
      if (text[i] === "]") {
        i += 1;
        return items;
      }
      for (;;) {
        items.push(value(depth + 1));
        ws();
        if (text[i] === ",") {
          i += 1;
          continue;
        }
        if (text[i] === "]") {
          i += 1;
          return items;
        }
        throw malformed("bad JSON array");
      }
    }
    if (c === "{") throw malformed("unexpected nested JSON object");
    for (const [word, v] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(word, i)) {
        i += word.length;
        return v;
      }
    }
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(text.slice(i));
    if (!m) throw malformed("bad JSON value");
    i += m[0].length;
    if (m[2] !== undefined || m[3] !== undefined || m[0] === "-0") return { nonInteger: m[0] };
    return BigInt(m[0]);
  };
  ws();
  if (text[i] !== "{") throw malformed("expected a JSON object");
  i += 1;
  const out = new Map();
  ws();
  if (text[i] === "}") {
    i += 1;
  } else {
    for (;;) {
      ws();
      const key = string();
      if (!allowed.includes(key)) throw malformed(`unknown JSON key ${JSON.stringify(key)}`);
      if (out.has(key)) throw malformed(`duplicate JSON key ${JSON.stringify(key)}`);
      ws();
      if (text[i] !== ":") throw malformed("expected ':' in JSON object");
      i += 1;
      out.set(key, value(1));
      ws();
      if (text[i] === ",") {
        i += 1;
        continue;
      }
      if (text[i] === "}") {
        i += 1;
        break;
      }
      throw malformed("bad JSON object");
    }
  }
  ws();
  if (i !== text.length) throw malformed("trailing data after JSON value");
  return out;
}

function field(map, name) {
  const v = map.get(name);
  if (v === undefined || v === null) throw malformed(`missing a required field: ${name}`);
  return v;
}

function stringField(map, name) {
  const v = field(map, name);
  if (typeof v !== "string") throw malformed(`${name} must be a string`);
  return v;
}

// Go decodes into uint64 (non-negative integers) or int.
function integerField(map, name, { signed = false } = {}) {
  const v = field(map, name);
  if (typeof v !== "bigint" || (!signed && v < 0n)) throw malformed(`${name} must be ${signed ? "an integer" : "a non-negative integer"}`);
  return v;
}

function stringArrayField(map, name) {
  const v = field(map, name);
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) throw malformed(`${name} must be an array of strings`);
  return v;
}

function decodeHashes(encoded, limit) {
  if (encoded.length > limit) throw malformed(`proof has ${encoded.length} hashes, limit ${limit}`);
  return encoded.map((s, i) => {
    const raw = decodeBase64Strict(s);
    if (raw === null || raw.length !== HASH_SIZE) throw malformed(`proof hash ${i} is not base64 of 32 bytes`);
    return raw;
  });
}

const toText = (input) => (typeof input === "string" ? input : new TextDecoder("utf-8").decode(input));

/**
 * Strictly parses an intentrax.tlog.inclusion-bundle/v0 sidecar (string or
 * bytes). Throws TLogMalformedError.
 */
export function parseInclusionBundle(input) {
  const map = readStrictWireObject(toText(input), ["format", "record_hash", "leaf_index", "tree_size", "inclusion_path", "checkpoint"]);
  for (const name of ["format", "record_hash", "leaf_index", "tree_size", "inclusion_path", "checkpoint"]) field(map, name);
  if (stringField(map, "format") !== INCLUSION_BUNDLE_FORMAT_V0) throw malformed(`inclusion bundle format ${JSON.stringify(map.get("format"))}`);
  const recordHash = parseHashHex(stringField(map, "record_hash"));
  const index = integerField(map, "leaf_index");
  const size = integerField(map, "tree_size");
  if (size === 0n || size > BigInt(MAX_SAFE_INTEGER) || index >= size) throw malformed(`leaf_index ${index} / tree_size ${size}`);
  const hashes = decodeHashes(stringArrayField(map, "inclusion_path"), MAX_PROOF_HASHES);
  const checkpoint = stringField(map, "checkpoint");
  parseNote(Buffer.from(checkpoint, "utf8"));
  return Object.freeze({ recordHash, leafIndex: Number(index), treeSize: Number(size), hashes, checkpoint: Buffer.from(checkpoint, "utf8") });
}

/**
 * Strictly parses an intentrax.trust.transparency_log/0 trust document
 * (string or bytes): pinned log key, witness keys and quorum. Throws
 * TLogMalformedError.
 */
export function parseTrustDocument(input) {
  const names = ["schema_version", "origin", "log_key", "witnesses", "witness_quorum", "max_integration_delay_seconds"];
  const map = readStrictWireObject(toText(input), names);
  for (const name of names) field(map, name);
  const schema = stringField(map, "schema_version");
  if (schema !== TRUST_DOCUMENT_SCHEMA_V0) throw malformed(`trust document schema_version ${JSON.stringify(schema)}, want ${JSON.stringify(TRUST_DOCUMENT_SCHEMA_V0)}`);
  const origin = stringField(map, "origin");
  const witnessStrings = stringArrayField(map, "witnesses");
  if (witnessStrings.length > MAX_NOTE_SIGNATURES - 1) throw malformed(`trust document lists ${witnessStrings.length} witnesses, limit ${MAX_NOTE_SIGNATURES - 1}`);
  const quorum = integerField(map, "witness_quorum", { signed: true });
  const delay = integerField(map, "max_integration_delay_seconds");
  if (quorum > BigInt(MAX_SAFE_INTEGER) || quorum < -BigInt(MAX_SAFE_INTEGER) || delay > BigInt(MAX_SAFE_INTEGER)) throw malformed("trust document integer out of range");
  const doc = Object.freeze({
    origin,
    logKey: parseVerifierKey(stringField(map, "log_key")),
    witnesses: Object.freeze(witnessStrings.map((s) => parseVerifierKey(s))),
    witnessQuorum: Number(quorum),
    maxIntegrationDelaySeconds: Number(delay),
  });
  const problem = validatePolicy(trustDocumentPolicy(doc));
  if (problem !== null) throw malformed(`trust document: ${problem}`);
  return doc;
}

/** The verification policy a trust document pins (freshness off). */
export function trustDocumentPolicy(doc) {
  return { origin: doc.origin, logKey: doc.logKey, witnesses: doc.witnesses, witnessQuorum: doc.witnessQuorum, allowUnwitnessed: doc.witnessQuorum === 0 };
}

/** The trust document in its wire form (field order as published). */
export function trustDocumentWire(doc) {
  return {
    schema_version: TRUST_DOCUMENT_SCHEMA_V0,
    origin: doc.origin,
    log_key: verifierKeyString(doc.logKey),
    witnesses: doc.witnesses.map(verifierKeyString),
    witness_quorum: doc.witnessQuorum,
    max_integration_delay_seconds: doc.maxIntegrationDelaySeconds,
  };
}

// ------------------------------------------------------------ verification

function verifyCheckpointNote(signed, policy) {
  const res = { ok: false, checkpoint: null, log_signature: "NOT_CHECKED", witness_quorum: policy.witnessQuorum, valid_witnesses: 0, witnesses: [], unknown_signatures: 0, reasons: [] };
  const fail = (code, detail) => res.reasons.push({ code, detail });
  const problem = validatePolicy(policy);
  if (problem !== null) {
    fail(REASON.POLICY_INVALID, problem);
    return res;
  }
  let note;
  let cp;
  try {
    note = parseNote(signed);
    cp = parseCheckpoint(note.text);
  } catch (error) {
    fail(REASON.CHECKPOINT_MALFORMED, error.message);
    return res;
  }
  res.checkpoint = cp;
  if (cp.origin !== policy.origin) fail(REASON.ORIGIN_MISMATCH, `checkpoint origin ${JSON.stringify(cp.origin)}, expected ${JSON.stringify(policy.origin)}`);
  const witnessIndex = new Map();
  policy.witnesses.forEach((w, i) => {
    witnessIndex.set(w.name, i);
    res.witnesses.push({ name: w.name, key_id: w.keyID.toString(16).padStart(8, "0"), status: "MISSING" });
  });
  let logValid = false;
  let logInvalid = false;
  for (const sig of note.sigs) {
    if (sig.name === policy.logKey.name && sig.keyID === policy.logKey.keyID) {
      if (verifyNoteSignature(policy.logKey, note.text, sig)) logValid = true;
      else logInvalid = true;
      continue;
    }
    const i = witnessIndex.get(sig.name);
    if (i === undefined || sig.keyID !== policy.witnesses[i].keyID) {
      res.unknown_signatures += 1;
      continue;
    }
    const wr = res.witnesses[i];
    const ts = verifyCosignature(policy.witnesses[i], cp, sig);
    if (ts === null) {
      wr.status = "INVALID";
      delete wr.timestamp;
      continue;
    }
    if (wr.status === "INVALID") continue;
    // Freshness is off in this port (archived re-verification), so every
    // valid cosignature is VALID; keep the newest.
    if (wr.status === "MISSING" || (wr.status === "VALID" && ts > BigInt(wr.timestamp))) {
      wr.status = "VALID";
      wr.timestamp = Number(ts) <= MAX_SAFE_INTEGER ? Number(ts) : ts.toString();
    }
  }
  if (logInvalid) {
    res.log_signature = "FAIL";
    fail(REASON.LOG_SIGNATURE_INVALID, `a signature claiming the pinned log key ${policy.logKey.name} does not verify`);
  } else if (!logValid) {
    res.log_signature = "FAIL";
    fail(REASON.LOG_SIGNATURE_MISSING, `no signature from the pinned log key ${policy.logKey.name}`);
  } else {
    res.log_signature = "PASS";
  }
  for (const w of res.witnesses) {
    if (w.status === "VALID") res.valid_witnesses += 1;
    else if (w.status === "INVALID") fail(REASON.WITNESS_SIGNATURE_INVALID, `cosignature claiming witness ${w.name} does not verify for this checkpoint`);
  }
  if (res.valid_witnesses < policy.witnessQuorum) {
    fail(REASON.WITNESS_QUORUM_NOT_MET, `${res.valid_witnesses} of ${policy.witnessQuorum} required witness cosignatures valid and fresh (${policy.witnesses.length} configured)`);
  }
  res.ok = res.reasons.length === 0;
  return res;
}

/**
 * Verifies an inclusion bundle (from parseInclusionBundle) for the record
 * hash the caller computed itself from the signed record (a Buffer or hex
 * string), against a trust document (from parseTrustDocument). Fails closed:
 * status is VERIFIED or VERIFIED_UNWITNESSED only when every check ran and
 * passed. Cosignature freshness is not checked (archived re-verification).
 */
export function verifyBundleOffline(recordHash, bundle, trustDocument) {
  const record = typeof recordHash === "string" ? parseHashHex(recordHash) : recordHash;
  const policy = trustDocumentPolicy(trustDocument);
  const res = {
    status: STATUS.FAILED,
    ok: false,
    record_hash: record.toString("hex"),
    leaf_index: bundle.leafIndex,
    tree_size: bundle.treeSize,
    inclusion: "NOT_CHECKED",
    reasons: [],
  };
  const fail = (code, detail) => res.reasons.push({ code, detail });
  const checkpoint = verifyCheckpointNote(bundle.checkpoint, policy);
  res.checkpoint = { ok: checkpoint.ok, log_signature: checkpoint.log_signature, witness_quorum: checkpoint.witness_quorum, valid_witnesses: checkpoint.valid_witnesses, witnesses: checkpoint.witnesses, unknown_signatures: checkpoint.unknown_signatures, reasons: checkpoint.reasons };
  res.reasons.push(...checkpoint.reasons);
  const cp = checkpoint.checkpoint;
  if (cp !== null) {
    res.origin = cp.origin;
    res.checkpoint_root = cp.hash.toString("hex");
    if (bundle.hashes.length > MAX_PROOF_HASHES) {
      res.inclusion = "FAIL";
      fail(REASON.PROOF_MALFORMED, `inclusion proof has ${bundle.hashes.length} hashes`);
    } else if (bundle.treeSize !== cp.size) {
      res.inclusion = "FAIL";
      fail(REASON.PROOF_TREE_SIZE_MISMATCH, `proof is for tree size ${bundle.treeSize}, checkpoint is size ${cp.size}`);
    } else {
      try {
        const root = rootFromInclusionProof(bundle.leafIndex, bundle.treeSize, recordLeafHash(record), bundle.hashes);
        if (!root.equals(cp.hash)) throw new Error(`inclusion proof invalid: recomputed root ${root.toString("hex")} does not match ${cp.hash.toString("hex")}`);
        res.inclusion = "PASS";
      } catch (error) {
        res.inclusion = "FAIL";
        fail(REASON.INCLUSION_ROOT_MISMATCH, error.message);
      }
    }
  }
  if (!bundle.recordHash.equals(record)) {
    fail(REASON.RECORD_HASH_MISMATCH, `bundle is for record ${bundle.recordHash.toString("hex")}, verifier computed ${record.toString("hex")}`);
  }
  res.reasons.sort((a, b) => (a.code < b.code ? -1 : a.code > b.code ? 1 : 0));
  if (res.reasons.length === 0 && res.inclusion === "PASS" && checkpoint.log_signature === "PASS" && checkpoint.ok) {
    res.ok = true;
    res.status = policy.witnessQuorum === 0 ? STATUS.VERIFIED_UNWITNESSED : STATUS.VERIFIED;
  }
  return res;
}

// -------------------------------------------- assurance-model mapping (CLI)

// Mirrors engine/internal/verificationinfra/offlineproof/transparency.go.

export const DIMENSION_TRANSPARENCY = "TRANSPARENCY";

export const TRANSPARENCY = Object.freeze({
  VERIFIED: "VERIFIED",
  VERIFIED_UNWITNESSED: "VERIFIED_UNWITNESSED",
  NOT_PRESENT: "NOT_PRESENT",
  FAILED: "FAILED",
});

export const TRANSPARENCY_LIMITATION_TEXT = Object.freeze({
  RECORD_NOT_SHOWN_LOGGED: "No transparency-log inclusion proof was supplied for this record. Treat it as not logged: nothing shows that it is in the public log.",
  LOG_CHECKPOINT_NOT_WITNESSED: "The log checkpoint is not cosigned by the required independent witnesses, so a log that shows different histories to different verifiers is not ruled out.",
  LOG_INCLUSION_TIMING_NOT_PROVEN: "The log shows this record was included by the stated tree size. It does not prove when the record was logged; that rests on the published maximum integration delay. Inclusion does not make the record's content true.",
});

const BUNDLE_MALFORMED = "BUNDLE_MALFORMED";

// The trust document's hash, identical to the Go verifier's: SHA-256 over
// Go's json.Marshal of the wire form (fields in declaration order, with
// encoding/json's HTML-safe escapes of <, > and & and of U+2028 / U+2029).
function trustDocumentHash(doc) {
  const json = JSON.stringify(trustDocumentWire(doc)).replace(/[<>&\u2028\u2029]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
  return createHash("sha256").update(json, "utf8").digest("hex");
}

/**
 * The transparency block of a verifier report: the bundle (null when none
 * was supplied) checked for proofRecordHash against the pinned trust
 * document text. Throws TLogMalformedError for a malformed trust document;
 * a malformed bundle is a FAILED result, never a throw.
 */
export function transparencyReport({ proofRecordHash, trustDocument, bundle }) {
  const doc = parseTrustDocument(trustDocument);
  const tr = {
    status: TRANSPARENCY.NOT_PRESENT,
    trust_document_hash: trustDocumentHash(doc),
    origin: doc.origin,
    witness_quorum: doc.witnessQuorum,
    max_integration_delay_seconds: doc.maxIntegrationDelaySeconds,
    bundle_present: bundle !== null && bundle !== undefined,
    valid_witnesses: 0,
    witnesses: [],
    reasons: [],
  };
  if (!tr.bundle_present) return tr;
  let parsed;
  try {
    parsed = parseInclusionBundle(bundle);
  } catch (error) {
    tr.status = TRANSPARENCY.FAILED;
    tr.reasons = [{ code: BUNDLE_MALFORMED, detail: error.message }];
    return tr;
  }
  const res = verifyBundleOffline(proofRecordHash, parsed, doc);
  tr.leaf_index = res.leaf_index;
  tr.tree_size = res.tree_size;
  if (res.checkpoint_root !== undefined) tr.checkpoint_root = res.checkpoint_root;
  tr.valid_witnesses = res.checkpoint.valid_witnesses;
  tr.witnesses = res.checkpoint.witnesses;
  tr.reasons = res.reasons;
  tr.status = res.status === STATUS.VERIFIED ? TRANSPARENCY.VERIFIED : res.status === STATUS.VERIFIED_UNWITNESSED ? TRANSPARENCY.VERIFIED_UNWITNESSED : TRANSPARENCY.FAILED;
  return tr;
}

const INSUFFICIENT_ONLY = new Set([REASON.WITNESS_QUORUM_NOT_MET, REASON.CHECKPOINT_STALE]);

/** The TRANSPARENCY dimension row for a transparency block. */
export function transparencyAssessment(tr) {
  const row = { dimension: DIMENSION_TRANSPARENCY, result: "", provenance: null, reasons: [], limitations: [] };
  switch (tr.status) {
    case TRANSPARENCY.VERIFIED:
      return { ...row, result: "VERIFIED", provenance: "VERIFIER_COMPUTED", reasons: ["LOG_INCLUSION_VERIFIED", "WITNESS_QUORUM_MET"], limitations: ["LOG_INCLUSION_TIMING_NOT_PROVEN"] };
    case TRANSPARENCY.VERIFIED_UNWITNESSED:
      return { ...row, result: "INSUFFICIENT_EVIDENCE", provenance: "VERIFIER_COMPUTED", reasons: ["LOG_INCLUSION_VERIFIED", "LOG_CHECKPOINT_UNWITNESSED"], limitations: ["LOG_CHECKPOINT_NOT_WITNESSED", "LOG_INCLUSION_TIMING_NOT_PROVEN"] };
    case TRANSPARENCY.NOT_PRESENT:
      return { ...row, result: "NOT_ASSESSED", reasons: ["NO_TRANSPARENCY_LOG_BUNDLE"], limitations: ["RECORD_NOT_SHOWN_LOGGED"] };
    default: {
      const codes = [...new Set(tr.reasons.map((r) => r.code))].sort();
      const onlyInsufficient = tr.reasons.length > 0 && tr.reasons.every((r) => INSUFFICIENT_ONLY.has(r.code));
      return onlyInsufficient
        ? { ...row, result: "INSUFFICIENT_EVIDENCE", provenance: "VERIFIER_COMPUTED", reasons: codes, limitations: ["LOG_CHECKPOINT_NOT_WITNESSED"] }
        : { ...row, result: "FAILED", provenance: "VERIFIER_COMPUTED", reasons: codes, limitations: [] };
    }
  }
}
