// `intentrax.signed_envelope/1.0` verification and the shared digests of
// docs/architecture/specs/00-common-conventions.md (approved 2026-11-21,
// decisions C-1…C-6).
//
// Port of the Go package engine/internal/verificationinfra/signedenvelope,
// with the same codes and the same hardening:
//   - the signed message is always rebuilt from payload_type and payload; no
//     "signed bytes" member exists (P0-1b);
//   - signer trust comes only from a pinned key with the required purpose,
//     never from the self-asserted public_key_hex (P0-1);
//   - member names are matched exactly (case included); duplicate and unknown
//     members are rejected; a UTF-8 byte-order mark is stripped;
//   - timestamps need an explicit offset in range, and are compared as
//     instants (spec 00 §6).
//
// This module only verifies. It holds no keys and signs nothing.
// Zero dependencies: node:crypto Ed25519 and SHA-256.

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";

import { JcsError, PROFILE_ANY, PROFILE_INT, parseJson, serialize, toText } from "./jcs.mjs";

export { JcsError, PROFILE_ANY, PROFILE_INT, canonicalize, formatNumber, parseJson, serialize } from "./jcs.mjs";

export const SCHEMA_VERSION = "intentrax.signed_envelope/1.0";
export const SIGNING_PREFIX = "INTENTRAX_SIGNED_ENVELOPE_V1\n";
export const DOMAIN_ENVELOPE = "INTENTRAX_ENVELOPE_CONTENT_V1";
export const DOMAIN_FACT_COMMITMENT = "INTENTRAX_FACT_COMMITMENT_V0_1";
export const ALG_ED25519 = "ED25519";

// Key purposes (spec 00 §5). A key has exactly one.
export const PURPOSE = Object.freeze({
  AEP_RECORD: "AEP_RECORD",
  TENANT_KEY_DIRECTORY: "TENANT_KEY_DIRECTORY",
  CALLER_REQUEST: "CALLER_REQUEST",
  APPROVER: "APPROVER",
  APPROVAL_SERVICE: "APPROVAL_SERVICE",
  EXECUTOR_ATTESTATION: "EXECUTOR_ATTESTATION",
  EFFECT_VERIFIER: "EFFECT_VERIFIER",
});

// KEY_COMPROMISE rejects every signature by the key, whatever signing time it
// claims, because signing times are self-asserted.
export const REVOCATION_KEY_COMPROMISE = "KEY_COMPROMISE";

export const CODE = Object.freeze({
  MALFORMED: "ENVELOPE_MALFORMED",
  SCHEMA_MISMATCH: "ENVELOPE_PAYLOAD_SCHEMA_MISMATCH",
  SIGNING_TIME_INVALID: "ENVELOPE_SIGNING_TIME_INVALID",
  SIGNATURE_INVALID: "ENVELOPE_SIGNATURE_INVALID",
  SIGNER_NOT_PINNED: "SIGNER_NOT_PINNED",
  SIGNER_KEY_MISMATCH: "SIGNER_KEY_MISMATCH",
  SIGNER_PURPOSE_MISMATCH: "SIGNER_PURPOSE_MISMATCH",
  SIGNER_KEY_NOT_VALID_AT_TIME: "SIGNER_KEY_NOT_VALID_AT_SIGNING_TIME",
  SIGNER_KEY_REVOKED: "SIGNER_KEY_REVOKED",
  PAYLOAD_TYPE_UNEXPECTED: "ENVELOPE_PAYLOAD_TYPE_UNEXPECTED",
  COMMITMENT_MISMATCH: "COMMITMENT_MISMATCH",
  COMMITMENT_OPENING_MALFORMED: "COMMITMENT_OPENING_MALFORMED",
});

export const AUTHENTICITY = Object.freeze({
  TRUSTED: "TRUSTED",
  NOT_PINNED: "NOT_PINNED",
  FAILED: "FAILED",
});

// EnvelopeError carries a stable code next to a human-readable reason.
export class EnvelopeError extends Error {
  constructor(code, reason) {
    super(`${code}: ${reason}`);
    this.name = "EnvelopeError";
    this.code = code;
    this.reason = reason;
  }
}

const fail = (code, reason) => new EnvelopeError(code, reason);

// codeOf returns the stable code of an error from this module, or "".
export function codeOf(err) {
  return err instanceof EnvelopeError ? err.code : "";
}

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const RFC3339_WITH_OFFSET = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/;

const own = (obj, name) => Object.prototype.hasOwnProperty.call(obj, name);
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const sha256Hex = (data) => createHash("sha256").update(data).digest("hex");

// ---------------------------------------------------------------- digests

// digest computes D(domain, value) = SHA-256(UTF-8(domain) || JCS(value)) and
// returns 64 lowercase hex digits. value is raw JSON (string or bytes) or an
// in-memory value; it must be a JSON object.
export function digest(domain, value, profile = PROFILE_INT) {
  const parsed = typeof value === "string" || value instanceof Uint8Array ? parseJson(value, profile) : value;
  if (!isObject(parsed)) throw new JcsError("$", "digest value must be a JSON object");
  return sha256Hex(Buffer.from(domain + serialize(parsed, profile), "utf8"));
}

// validHash reports whether s is a 64-hex lowercase digest that is not one
// repeated digit (the ValidPolicyBindingHash rule, spec 00 §3).
export function validHash(s) {
  if (typeof s !== "string" || !HEX64.test(s)) return false;
  for (let i = 1; i < s.length; i++) if (s[i] !== s[0]) return true;
  return false;
}

// ---------------------------------------------------------------- time

const daysInMonth = (y, m) => [31, (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0 ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1];

// parseTime parses a timestamp under spec 00 §6 and returns its instant as
// nanoseconds since the Unix epoch (a bigint, so nanosecond fractions compare
// exactly). A value without an explicit offset, with an offset outside
// 00:00–23:59, or with an out-of-range date or time fails closed.
export function parseTime(s) {
  const m = typeof s === "string" ? RFC3339_WITH_OFFSET.exec(s) : null;
  if (!m) throw new Error("timestamp is not RFC 3339 with an explicit offset");
  const [, Y, Mo, D, h, mi, sec, frac, zone, sign, oh, om] = m;
  const year = Number(Y), month = Number(Mo), day = Number(D);
  const hour = Number(h), minute = Number(mi), second = Number(sec);
  if (zone !== "Z" && (Number(oh) > 23 || Number(om) > 59)) throw new Error("timestamp offset is out of range");
  if (month < 1 || month > 12) throw new Error("timestamp month is out of range");
  if (day < 1 || day > daysInMonth(year, month)) throw new Error("timestamp day is out of range");
  if (hour > 23) throw new Error("timestamp hour is out of range");
  if (minute > 59) throw new Error("timestamp minute is out of range");
  if (second > 59) throw new Error("timestamp second is out of range");
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, 0);
  let ns = BigInt(date.getTime()) * 1_000_000n;
  if (frac) ns += BigInt(frac.padEnd(9, "0"));
  if (zone !== "Z") {
    const offsetNs = (BigInt(Number(oh)) * 60n + BigInt(Number(om))) * 60_000_000_000n;
    ns += sign === "+" ? -offsetNs : offsetNs;
  }
  return ns;
}

// ---------------------------------------------------------------- commitments

// verifyCommitment checks a commitment opening {field, salt, value} (spec 00
// §7) against the sealed commitment. opening is raw JSON or an in-memory value.
export function verifyCommitment(commitment, opening) {
  let parsed;
  try {
    parsed = typeof opening === "string" || opening instanceof Uint8Array ? parseJson(opening, PROFILE_ANY) : opening;
    exactMembers(parsed, ["field", "salt", "value"]);
  } catch (err) {
    throw fail(CODE.COMMITMENT_OPENING_MALFORMED, `opening must be exactly {field, salt, value}: ${err.message}`);
  }
  if (typeof parsed.field !== "string" || parsed.field === "") {
    throw fail(CODE.COMMITMENT_OPENING_MALFORMED, "field must be a non-empty string");
  }
  if (typeof parsed.salt !== "string" || !HEX64.test(parsed.salt)) {
    throw fail(CODE.COMMITMENT_OPENING_MALFORMED, "salt must be 64 lowercase hex digits");
  }
  let got;
  try {
    got = digest(DOMAIN_FACT_COMMITMENT, parsed, PROFILE_INT);
  } catch (err) {
    throw fail(CODE.COMMITMENT_OPENING_MALFORMED, err.message);
  }
  if (!validHash(commitment) || got !== commitment) {
    throw fail(CODE.COMMITMENT_MISMATCH, `opening of ${JSON.stringify(parsed.field)} does not match the sealed commitment`);
  }
}

// ---------------------------------------------------------------- envelope

const ENVELOPE_MEMBERS = ["payload", "payload_type", "signatures"];
const SIGNATURE_MEMBERS = ["alg", "key_id", "key_version", "public_key_hex", "signature_hex"];

// exactMembers requires value to be an object whose member names are exactly
// names (byte for byte).
function exactMembers(value, names) {
  if (!isObject(value)) throw new Error("not a JSON object");
  for (const n of names) if (!own(value, n)) throw new Error(`member ${JSON.stringify(n)} is required`);
  for (const n of Object.keys(value)) if (!names.includes(n)) throw new Error(`unknown member ${JSON.stringify(n)}`);
}

// parseEnvelope decodes and validates an envelope's structure. It rejects
// unknown members, duplicate member names, anything but exactly one Ed25519
// signature, a payload that is not JCS-INT, and a payload whose
// schema_version differs from payload_type. Input is raw JSON (string or
// bytes); a leading byte-order mark is stripped.
//
// Returns {payloadType, payload, payloadJcs, signature, message, envelopeHash}
// where message is the exact signed byte string (a Buffer).
export function parseEnvelope(raw) {
  let value;
  try {
    // Parsing first rejects duplicate names and invalid JSON anywhere.
    value = parseJson(toText(raw), PROFILE_ANY);
  } catch (err) {
    throw fail(CODE.MALFORMED, err.message);
  }
  try {
    exactMembers(value, ENVELOPE_MEMBERS);
  } catch (err) {
    throw fail(CODE.MALFORMED, `envelope: ${err.message}`);
  }
  const payloadType = value.payload_type;
  if (typeof payloadType !== "string" || payloadType === "") {
    throw fail(CODE.MALFORMED, "payload_type must be a non-empty string");
  }
  if (!isObject(value.payload)) throw fail(CODE.MALFORMED, "payload must be a JSON object");
  if (!Array.isArray(value.signatures)) throw fail(CODE.MALFORMED, "signatures must be an array");
  if (value.signatures.length !== 1) {
    throw fail(CODE.MALFORMED, `signatures must hold exactly one entry, got ${value.signatures.length}`);
  }
  const signature = parseSignature(value.signatures[0]);

  let payloadJcs;
  try {
    payloadJcs = serialize(value.payload, PROFILE_INT);
  } catch (err) {
    throw fail(CODE.MALFORMED, `payload: ${err.message}`);
  }
  if (!own(value.payload, "schema_version") || typeof value.payload.schema_version !== "string") {
    throw fail(CODE.SCHEMA_MISMATCH, "payload.schema_version is required and must be a string");
  }
  if (value.payload.schema_version !== payloadType) {
    throw fail(CODE.SCHEMA_MISMATCH, `payload.schema_version ${JSON.stringify(value.payload.schema_version)} differs from payload_type ${JSON.stringify(payloadType)}`);
  }
  const content = serialize({ payload: value.payload, payload_type: payloadType }, PROFILE_INT);
  return {
    payloadType,
    payload: value.payload,
    payloadJcs,
    signature,
    message: Buffer.from(SIGNING_PREFIX + content, "utf8"),
    envelopeHash: sha256Hex(Buffer.from(DOMAIN_ENVELOPE + content, "utf8")),
  };
}

function parseSignature(entry) {
  try {
    exactMembers(entry, SIGNATURE_MEMBERS);
  } catch (err) {
    throw fail(CODE.MALFORMED, `signature entry: ${err.message}`);
  }
  for (const name of SIGNATURE_MEMBERS) {
    if (typeof entry[name] !== "string") throw fail(CODE.MALFORMED, `signature entry: ${name} must be a string`);
  }
  const sig = {
    alg: entry.alg,
    keyId: entry.key_id,
    keyVersion: entry.key_version,
    publicKeyHex: entry.public_key_hex,
    signatureHex: entry.signature_hex,
  };
  if (sig.alg !== ALG_ED25519) throw fail(CODE.MALFORMED, `signature alg must be ${ALG_ED25519}`);
  if (sig.keyId === "" || sig.keyVersion === "") throw fail(CODE.MALFORMED, "signature key_id and key_version are required");
  if (!HEX64.test(sig.publicKeyHex) || !HEX128.test(sig.signatureHex)) {
    throw fail(CODE.MALFORMED, "public_key_hex must be 64 and signature_hex 128 lowercase hex digits");
  }
  return sig;
}

// ---------------------------------------------------------------- trust

// ed25519Verify verifies a raw Ed25519 signature; an unusable public key is a
// failed verification, never an exception.
export function ed25519Verify(publicKeyHex, message, signatureHex) {
  try {
    const key = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(publicKeyHex, "hex").toString("base64url") },
      format: "jwk",
    });
    return cryptoVerify(null, message, key, Buffer.from(signatureHex, "hex"));
  } catch {
    return false;
  }
}

// pinnedKeys builds a resolver over an array of pinned keys:
//   {keyId, keyVersion, publicKeyHex, purpose, validFrom?, validUntil?,
//    revokedAt?, revocationReason?}
// Times are RFC 3339 strings (spec 00 §6) or bigint nanoseconds; a malformed
// time throws here, so a pin file with a bad window never loads.
export function pinnedKeys(keys) {
  const normalised = keys.map((k) => ({
    ...k,
    validFrom: pinTime(k.validFrom, "validFrom"),
    validUntil: pinTime(k.validUntil, "validUntil"),
    revokedAt: pinTime(k.revokedAt, "revokedAt"),
  }));
  return {
    resolveKey(keyId, keyVersion) {
      return normalised.find((k) => k.keyId === keyId && k.keyVersion === keyVersion);
    },
  };
}

function pinTime(value, name) {
  if (value === undefined || value === null) return undefined;
  if (typeof value === "bigint") return value;
  try {
    return parseTime(value);
  } catch (err) {
    throw new TypeError(`pinned key ${name}: ${err.message}`);
  }
}

// verifyEnvelope parses raw and checks it against want
// ({payloadType, purpose, signingTimeField}) and a key resolver (see
// pinnedKeys). A malformed envelope, a payload type other than
// want.payloadType or an invalid signing time throws an EnvelopeError.
// Signature and trust outcomes are reported in the result:
//   {envelope, signedAt (bigint ns), signedAtText, integrityOk, authenticity, code, trusted}
export function verifyEnvelope(raw, want, keys) {
  const envelope = parseEnvelope(raw);
  if (envelope.payloadType !== want.payloadType) {
    throw fail(CODE.PAYLOAD_TYPE_UNEXPECTED, `payload_type ${JSON.stringify(envelope.payloadType)}, expected ${JSON.stringify(want.payloadType)}`);
  }
  const { signedAt, signedAtText } = signingTime(envelope.payload, want.signingTimeField);
  const res = { envelope, signedAt, signedAtText, integrityOk: false, authenticity: AUTHENTICITY.FAILED, code: "", trusted: false };

  if (!ed25519Verify(envelope.signature.publicKeyHex, envelope.message, envelope.signature.signatureHex)) {
    res.code = CODE.SIGNATURE_INVALID;
    return res;
  }
  res.integrityOk = true;

  const pinned = keys.resolveKey(envelope.signature.keyId, envelope.signature.keyVersion);
  if (!pinned) {
    res.authenticity = AUTHENTICITY.NOT_PINNED;
    res.code = CODE.SIGNER_NOT_PINNED;
  } else if (pinned.publicKeyHex !== envelope.signature.publicKeyHex) {
    res.code = CODE.SIGNER_KEY_MISMATCH;
  } else if (pinned.purpose !== want.purpose) {
    res.code = CODE.SIGNER_PURPOSE_MISMATCH;
  } else if (revoked(pinned, signedAt)) {
    res.code = CODE.SIGNER_KEY_REVOKED;
  } else if ((pinned.validFrom !== undefined && signedAt < pinned.validFrom) || (pinned.validUntil !== undefined && signedAt >= pinned.validUntil)) {
    res.code = CODE.SIGNER_KEY_NOT_VALID_AT_TIME;
  } else {
    res.authenticity = AUTHENTICITY.TRUSTED;
    res.trusted = true;
  }
  return res;
}

function revoked(key, signedAt) {
  if (key.revocationReason === REVOCATION_KEY_COMPROMISE) return true;
  return key.revokedAt !== undefined && signedAt >= key.revokedAt;
}

function signingTime(payload, field) {
  if (typeof field !== "string" || field === "") throw fail(CODE.SIGNING_TIME_INVALID, "no signing-time field configured");
  if (!own(payload, field)) throw fail(CODE.SIGNING_TIME_INVALID, `payload.${field} is required`);
  const text = payload[field];
  if (typeof text !== "string") throw fail(CODE.SIGNING_TIME_INVALID, `payload.${field} must be a string`);
  try {
    return { signedAt: parseTime(text), signedAtText: text };
  } catch (err) {
    throw fail(CODE.SIGNING_TIME_INVALID, `payload.${field}: ${err.message}`);
  }
}
