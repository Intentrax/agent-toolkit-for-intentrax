// Local, hash-chained, signed decision records for `intentrax guard`.
//
// LOCAL AND NOT TRUST-BEARING. Every record is signed with an Ed25519 key
// generated on this machine (the same local key-set format as the sandbox,
// sandbox/keys.mjs: environment "local", trust_bearing false). The private key
// sits next to the records, so anyone who can write this directory can
// rewrite the whole chain and re-sign it. The chain catches accidental damage
// and naive edits (a changed, inserted, reordered or deleted record; a
// truncated tail, via head.json), not a deliberate forger on this machine.
//
// Layout under <project>/.intentrax/guard/:
//   records.jsonl          one record per line
//   head.json              seq + record_hash of the last record, signed
//   local-key-set.json     public keys (sandbox local key-set schema)
//   keys/local-signing-key.json   private key (gitignored; never needed to verify)
//   records.lock           append lock (transient)

import { closeSync, existsSync, fstatSync, mkdirSync, openSync, readFileSync, readSync, renameSync, statSync, unlinkSync, writeFileSync, writeSync, constants as fsConstants } from "node:fs";
import { createPrivateKey, generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
import { dirname, join } from "node:path";
import { canonicalJson, domainDigest, sha256Hex } from "../mcp/canonical.mjs";
import { LOCAL_ENVIRONMENT, LOCAL_KEY_SET_SCHEMA, LOCAL_KEY_VALIDITY_SECONDS, ROLES, loadLocalKeySet } from "../sandbox/keys.mjs";
import { isoMs } from "../sandbox/time.mjs";

export const RECORD_SCHEMA = "intentrax.guard.local_record/v0.1";
export const HEAD_SCHEMA = "intentrax.guard.local_head/v0.1";
export const SIGNING_KEY_SCHEMA = "intentrax.local.guard_signing_key/0.1";
export const RECORD_DIGEST_DOMAIN = "INTENTRAX_GUARD_LOCAL_RECORD_V0_1";
export const RECORD_SIGNING_PREFIX = "intentrax.guard.local_record.sig.v0.1\n";
export const HEAD_SIGNING_PREFIX = "intentrax.guard.local_head.sig.v0.1\n";
export const GENESIS_PREV = "0".repeat(64);
export const GUARD_PRINCIPAL = "local:guard-decision-service";
export const NOT_TRUST_BEARING =
  "LOCAL RECORD, NOT TRUST-BEARING: signed with a key generated on this machine. Anyone who can write this directory can rewrite and re-sign it.";

export const FILES = Object.freeze({
  records: "records.jsonl",
  head: "head.json",
  keySet: "local-key-set.json",
  signingKey: "keys/local-signing-key.json",
  lock: "records.lock",
});

const LOCK_STALE_MS = 15_000;
const LOCK_WAIT_MS = 20_000; // below the hook's 30 s timeout

function processAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === "EPERM";
  }
}

function isoZ(ms) {
  return new Date(ms).toISOString();
}

function sleepMs(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function writeAtomic(path, text, mode) {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(tmp, text, mode === undefined ? undefined : { mode });
  renameSync(tmp, path);
}

function rawPublicKey(publicKey) {
  const spki = publicKey.export({ format: "der", type: "spki" });
  return Buffer.from(spki.subarray(spki.length - 32)).toString("base64url");
}

// ---------------------------------------------------------------------------
// Keys

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function newSigningKey(nowMs) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pub = rawPublicKey(publicKey);
  return {
    key_id: "local-guard-" + sha256Hex(pub).slice(0, 16),
    alg: "Ed25519",
    role: ROLES.DECISION_SERVICE,
    principal: GUARD_PRINCIPAL,
    public_key: pub,
    valid_from: isoZ(Math.floor(nowMs / 1000) * 1000),
    valid_until: isoZ(Math.floor(nowMs / 1000) * 1000 + LOCAL_KEY_VALIDITY_SECONDS * 1000),
    environment: LOCAL_ENVIRONMENT,
    trust_bearing: false,
    privateKey,
  };
}

function publicEntry(k) {
  const { privateKey: _p, private_key_pkcs8: _q, ...rest } = k;
  return rest;
}

function emptyKeySet() {
  return {
    schema_version: LOCAL_KEY_SET_SCHEMA,
    environment: LOCAL_ENVIRONMENT,
    trust_bearing: false,
    warning: "LOCAL GUARD KEYS ONLY. Generated on this machine to sign intentrax guard records. Not trust-bearing, not published by Intentrax; never add them to a production key set.",
    keys: [],
  };
}

// The current signing key, rotated when it would expire within a minute (the
// sandbox key format caps validity at 24 h). Must run under the append lock.
export function currentSigningKey(guardDir, nowMs) {
  const keyPath = join(guardDir, FILES.signingKey);
  const setPath = join(guardDir, FILES.keySet);
  if (existsSync(keyPath)) {
    const doc = readJson(keyPath);
    if (doc?.schema_version !== SIGNING_KEY_SCHEMA || doc.environment !== LOCAL_ENVIRONMENT || doc.trust_bearing !== false) {
      throw new Error("guard signing key file is not a local, non-trust-bearing guard key");
    }
    const until = isoMs(doc.key?.valid_until);
    const from = isoMs(doc.key?.valid_from);
    if (from !== null && until !== null && nowMs >= from && nowMs < until - 60_000) {
      return { ...doc.key, privateKey: createPrivateKey({ key: Buffer.from(doc.key.private_key_pkcs8, "base64url"), format: "der", type: "pkcs8" }) };
    }
  }
  const key = newSigningKey(nowMs);
  const set = existsSync(setPath) ? readJson(setPath) : emptyKeySet();
  if (!Array.isArray(set.keys)) throw new Error("guard key set is malformed");
  set.keys.push(publicEntry(key));
  writeAtomic(setPath, JSON.stringify(set, null, 2) + "\n");
  writeAtomic(keyPath, JSON.stringify({
    schema_version: SIGNING_KEY_SCHEMA,
    environment: LOCAL_ENVIRONMENT,
    trust_bearing: false,
    warning: "Private key for local intentrax guard records. Not trust-bearing. Do not commit or share.",
    key: { ...publicEntry(key), private_key_pkcs8: key.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64url") },
  }, null, 2) + "\n", 0o600);
  return key;
}

// ---------------------------------------------------------------------------
// Lock

export function withLock(guardDir, fn) {
  mkdirSync(guardDir, { recursive: true });
  const lockPath = join(guardDir, FILES.lock);
  const deadline = Date.now() + LOCK_WAIT_MS;
  let fd = null;
  while (fd === null) {
    try {
      fd = openSync(lockPath, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, 0o600);
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
      try {
        // Stale when its holder is gone (a killed hook), or when it is older
        // than LOCK_STALE_MS (a holder on another machine sharing the folder).
        const holder = readFileSync(lockPath, "utf8");
        const old = Date.now() - statSync(lockPath).mtimeMs > LOCK_STALE_MS;
        if (old || (/^\d+$/.test(holder) && !processAlive(Number(holder)))) {
          if (readFileSync(lockPath, "utf8") === holder) unlinkSync(lockPath);
        }
      } catch {
        // raced with another process; retry
      }
      if (Date.now() > deadline) throw new Error("timed out waiting for the guard record lock");
      sleepMs(15 + Math.floor(Math.random() * 20));
    }
  }
  try {
    writeSync(fd, String(process.pid));
    return fn();
  } finally {
    closeSync(fd);
    try {
      unlinkSync(lockPath);
    } catch {
      // already gone
    }
  }
}

// ---------------------------------------------------------------------------
// Records

export function recordHash(body) {
  return domainDigest(RECORD_DIGEST_DOMAIN, body).slice("sha256:".length);
}

function lastLine(path) {
  if (!existsSync(path)) return null;
  const fd = openSync(path, "r");
  try {
    const size = fstatSync(fd).size;
    if (size === 0) return null;
    let chunk = 8192;
    for (;;) {
      const start = Math.max(0, size - chunk);
      const buf = Buffer.alloc(size - start);
      readSync(fd, buf, 0, buf.length, start);
      const text = buf.toString("utf8").replace(/\n+$/, "");
      const nl = text.lastIndexOf("\n");
      if (nl >= 0 || start === 0) return text.slice(nl + 1);
      chunk *= 4;
    }
  } finally {
    closeSync(fd);
  }
}

export class ChainStateError extends Error {}

// Before appending, the file's last record must be the one head.json names.
// Otherwise records were removed from the end (or the file replaced), and
// appending would rewrite head.json and erase that evidence: `guard verify`
// would go from BROKEN back to VALID. So the append is refused and the chain
// stays broken until a person starts a new one. One case is repaired: a
// crash between writing a record and writing head.json leaves head exactly
// one record behind, pointing at the new record's prev_hash.
function assertHeadMatches(guardDir, last) {
  const headPath = join(guardDir, FILES.head);
  const reset = `move ${FILES.records} and ${FILES.head} out of ${guardDir} to start a new chain (keep them as evidence)`;
  if (!existsSync(headPath)) {
    if (last) throw new ChainStateError(`${FILES.head} is missing but records exist; not appending. Run \`guard verify\`; to recover, ${reset}`);
    return;
  }
  let head;
  try {
    head = readJson(headPath);
  } catch {
    throw new ChainStateError(`${FILES.head} is unreadable; not appending. Run \`guard verify\`; to recover, ${reset}`);
  }
  if (!last) throw new ChainStateError(`${FILES.head} names record #${head.seq} but ${FILES.records} is missing or empty; not appending. To recover, ${reset}`);
  if (head.seq === last.seq && head.record_hash === last.record_hash) return;
  if (head.seq === last.seq - 1 && head.record_hash === last.prev_hash) return;
  throw new ChainStateError(`${FILES.head} names record #${head.seq} but ${FILES.records} ends at #${last.seq} (records were removed or replaced); not appending. Run \`guard verify\`; to recover, ${reset}`);
}

// appendRecord(guardDir, fields) -> the written record. `fields` carries the
// decision; this adds seq, prev_hash, time, labels, key and signature.
export function appendRecord(guardDir, fields, { now = () => Date.now() } = {}) {
  return withLock(guardDir, () => {
    const nowMs = now();
    const path = join(guardDir, FILES.records);
    const prevLine = lastLine(path);
    let seq = 1;
    let prev = GENESIS_PREV;
    let last = null;
    if (prevLine) {
      last = JSON.parse(prevLine);
      if (!Number.isSafeInteger(last.seq) || typeof last.record_hash !== "string") throw new Error("last guard record is malformed; run `guard verify`");
      seq = last.seq + 1;
      prev = last.record_hash;
    }
    assertHeadMatches(guardDir, last);
    const key = currentSigningKey(guardDir, nowMs);
    const body = {
      schema: RECORD_SCHEMA,
      seq,
      prev_hash: prev,
      recorded_at: isoZ(nowMs),
      environment: LOCAL_ENVIRONMENT,
      trust_bearing: false,
      key_id: key.key_id,
      ...fields,
    };
    const hash = recordHash(body);
    const signature = edSign(null, Buffer.from(RECORD_SIGNING_PREFIX + hash, "utf8"), key.privateKey).toString("base64url");
    const record = { ...body, record_hash: hash, signature };
    const line = JSON.stringify(record) + "\n";
    const fd = openSync(path, "a", 0o600);
    try {
      writeSync(fd, line);
    } finally {
      closeSync(fd);
    }
    const head = { schema: HEAD_SCHEMA, seq, record_hash: hash, key_id: key.key_id };
    head.signature = edSign(null, Buffer.from(HEAD_SIGNING_PREFIX + canonicalJson({ schema: head.schema, seq, record_hash: hash, key_id: key.key_id }), "utf8"), key.privateKey).toString("base64url");
    writeAtomic(join(guardDir, FILES.head), JSON.stringify(head, null, 2) + "\n");
    return record;
  });
}

// ---------------------------------------------------------------------------
// Verify (offline)

export const VERIFY_STATUS = Object.freeze({
  VALID: "LOCAL_CHAIN_VALID",
  EMPTY: "LOCAL_CHAIN_EMPTY",
  BROKEN: "LOCAL_CHAIN_BROKEN",
});

// verifyRecords(guardDir) -> { status, records, first_bad_seq?, problems[], counts, note }
export function verifyRecords(guardDir) {
  const problems = [];
  const fail = (line, message) => problems.push({ line, message });
  const path = join(guardDir, FILES.records);
  const result = (status, records, extra = {}) => ({ status, records, problems, note: NOT_TRUST_BEARING, ...extra });
  if (!existsSync(path)) {
    if (existsSync(join(guardDir, FILES.head))) {
      fail(0, "head.json exists but records.jsonl is missing (records were deleted)");
      return result(VERIFY_STATUS.BROKEN, 0);
    }
    return result(VERIFY_STATUS.EMPTY, 0);
  }
  let keys;
  try {
    keys = loadLocalKeySet(readJson(join(guardDir, FILES.keySet)));
  } catch (e) {
    fail(0, "local key set unusable: " + e.message);
    return result(VERIFY_STATUS.BROKEN, 0);
  }
  const lines = readFileSync(path, "utf8").split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  let prev = GENESIS_PREV;
  let expectSeq = 1;
  let last = null;
  const counts = { allow: 0, ask: 0, block: 0 };
  for (let i = 0; i < lines.length; i += 1) {
    const n = i + 1;
    let rec;
    try {
      rec = JSON.parse(lines[i]);
    } catch {
      fail(n, "not valid JSON");
      break;
    }
    const { record_hash: hash, signature, ...body } = rec ?? {};
    if (body.schema !== RECORD_SCHEMA) fail(n, "unknown record schema");
    if (body.environment !== LOCAL_ENVIRONMENT || body.trust_bearing !== false) fail(n, "record is not labelled environment local / trust_bearing false");
    if (body.seq !== expectSeq) fail(n, `seq is ${body.seq}, expected ${expectSeq} (a record was inserted, deleted or reordered)`);
    if (body.prev_hash !== prev) fail(n, "prev_hash does not match the previous record (the chain is broken here)");
    let computed = null;
    try {
      computed = recordHash(body);
    } catch (e) {
      fail(n, "record cannot be canonicalised: " + e.message);
    }
    if (computed !== null && computed !== hash) fail(n, "record_hash does not match the record's content (the record was edited)");
    const key = keys.get(body.key_id);
    if (!key) fail(n, `key ${body.key_id} is not in the local key set`);
    else {
      let ok = false;
      try {
        ok = typeof signature === "string" && edVerify(null, Buffer.from(RECORD_SIGNING_PREFIX + hash, "utf8"), key.publicKey, Buffer.from(signature, "base64url"));
      } catch {
        ok = false;
      }
      if (!ok) fail(n, "signature does not verify");
      const t = isoMs(body.recorded_at);
      if (t === null || t < isoMs(key.valid_from) || t >= isoMs(key.valid_until)) fail(n, "recorded_at is outside the signing key's validity window");
    }
    if (problems.length > 0) {
      return result(VERIFY_STATUS.BROKEN, i, { first_bad_seq: expectSeq, counts });
    }
    if (Object.hasOwn(counts, body.decision?.verdict)) counts[body.decision.verdict] += 1;
    prev = hash;
    expectSeq += 1;
    last = rec;
  }
  // head.json: catches a truncated tail.
  const headPath = join(guardDir, FILES.head);
  if (!existsSync(headPath)) {
    if (last) fail(lines.length, "head.json is missing");
  } else {
    try {
      const head = readJson(headPath);
      const key = keys.get(head.key_id);
      const ok = key && edVerify(null, Buffer.from(HEAD_SIGNING_PREFIX + canonicalJson({ schema: head.schema, seq: head.seq, record_hash: head.record_hash, key_id: head.key_id }), "utf8"), key.publicKey, Buffer.from(String(head.signature), "base64url"));
      if (!ok) fail(lines.length, "head.json signature does not verify");
      else if (!last || head.seq !== last.seq || head.record_hash !== last.record_hash) {
        fail(lines.length, `head.json says the last record is #${head.seq} but the file ends at #${last?.seq ?? 0} (records were removed from the end)`);
      }
    } catch (e) {
      fail(lines.length, "head.json unreadable: " + e.message);
    }
  }
  if (problems.length > 0) return result(VERIFY_STATUS.BROKEN, lines.length, { first_bad_seq: (last?.seq ?? 0) + 1, counts });
  return result(lines.length === 0 ? VERIFY_STATUS.EMPTY : VERIFY_STATUS.VALID, lines.length, { counts, last_seq: last?.seq ?? 0, last_record_hash: last?.record_hash ?? null });
}

// Read every record (no verification) for status counts.
export function readRecords(guardDir) {
  const path = join(guardDir, FILES.records);
  if (!existsSync(path)) return [];
  const out = [];
  for (const line of readFileSync(path, "utf8").split("\n")) {
    if (!line) continue;
    try {
      out.push(JSON.parse(line));
    } catch {
      out.push(null);
    }
  }
  return out;
}
