// `intentrax approve` command line. Local only: reads files, writes files,
// sends nothing. See approve/README.md.

import { closeSync, existsSync, mkdirSync, openSync, readFileSync, writeSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

import {
  ApproveError,
  DEFAULT_VALIDITY_SECONDS,
  argumentsHash,
  HARD_CAP_VALIDITY_SECONDS,
  buildApproval,
  checkApproverSet,
  directoryContext,
  generateApproverKey,
  loadApproverKey,
  parseApprovalRequest,
  renderRequest,
  signApproval,
} from "./approve.mjs";
import { PROFILE_ANY, parseJson } from "../envelope/index.mjs";

export const APPROVE_USAGE = `usage:
  intentrax approve keygen --tenant-id <id> --principal-id <opaque id> --key-id <id> [--key-version 1]
                           [--valid-from <RFC 3339>] [--valid-until <RFC 3339>]
                           --out <approver-key.json> --registration-out <registration.json>
  intentrax approve [<admission_request_hash>] --request <envelope.json> --approval-request <pending.json>
                    --key <approver-key.json> --directory <tenant-key-directory.json>
                    [--arguments <arguments.json>] [--approver-set <approver-set.json>] [--fact-map <fact-map.json>]
                    [--reject] [--reason <text>] [--valid-for <seconds>] [--yes] [--json]
                    --out <approval.json> [--disclosures-out <file>]

Signs an intentrax.approval/0.1 envelope (identity method TENANT_KEY) with a
local, human APPROVER key, after recomputing admission_request_hash and
arguments_hash and showing you the exact request. Local only: nothing is sent.
Without --yes you confirm by typing the first 8 characters of arguments_hash.
--valid-for defaults to ${DEFAULT_VALIDITY_SECONDS} s (hard cap ${HARD_CAP_VALIDITY_SECONDS} s).`;

function parseArgs(argv, spec) {
  const options = {};
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }
    const name = arg.slice(2);
    if (!Object.hasOwn(spec, name)) throw new ApproveError("USAGE", `unknown option --${name}`);
    if (spec[name] === "flag") {
      options[name] = true;
      continue;
    }
    if (i + 1 >= argv.length) throw new ApproveError("USAGE", `--${name} needs a value`);
    if (Object.hasOwn(options, name)) throw new ApproveError("USAGE", `--${name} given twice`);
    options[name] = argv[++i];
  }
  return { options, positional };
}

const readText = (path) => readFileSync(resolve(path), "utf8");

// writePrivate writes a new file with mode 0600 and refuses to overwrite.
function writeNew(path, text) {
  const full = resolve(path);
  mkdirSync(dirname(full), { recursive: true });
  const fd = openSync(full, "wx", 0o600);
  try {
    writeSync(fd, text);
  } finally {
    closeSync(fd);
  }
  return full;
}

async function confirm(io, expected) {
  if (!io.stdin.isTTY) throw new ApproveError("CONFIRMATION_REQUIRED", "not a terminal: re-run interactively, or pass --yes after reading the request");
  const rl = createInterface({ input: io.stdin, output: io.stderr });
  const answer = await new Promise((done) => rl.question(`Type the first 8 characters of arguments_hash (${expected.slice(0, 2)}…) to sign, anything else to abort: `, done));
  rl.close();
  if (answer.trim() !== expected.slice(0, 8)) throw new ApproveError("ABORTED", "not confirmed; nothing was signed");
}

export async function runApprove(argv, io = { stdout: process.stdout, stderr: process.stderr, stdin: process.stdin }) {
  if (argv[0] === "keygen") return keygen(argv.slice(1), io);
  const { options, positional } = parseArgs(argv, {
    request: "value", "approval-request": "value", key: "value", directory: "value", arguments: "value",
    "approver-set": "value", "fact-map": "value", reject: "flag", reason: "value", "valid-for": "value",
    yes: "flag", json: "flag", out: "value", "disclosures-out": "value", help: "flag",
  });
  if (options.help) {
    io.stdout.write(APPROVE_USAGE + "\n");
    return 0;
  }
  for (const required of ["request", "approval-request", "key", "directory", "out"]) {
    if (!options[required]) throw new ApproveError("USAGE", `--${required} is required\n${APPROVE_USAGE}`);
  }
  if (positional.length > 1) throw new ApproveError("USAGE", "at most one positional argument (the admission_request_hash)");
  const disclosuresOut = options["disclosures-out"] ?? options.out.replace(/(\.json)?$/, ".disclosures.json");
  for (const path of [options.out, disclosuresOut]) {
    if (existsSync(resolve(path))) throw new ApproveError("OUTPUT_EXISTS", `${path} exists; refusing to overwrite`);
  }

  // io.now exists for tests; the CLI always uses the clock.
  const now = io.now ?? Date.now();
  const key = loadApproverKey(readText(options.key));
  const requestText = readText(options.request);
  let request;
  try {
    request = parseJson(requestText, PROFILE_ANY);
  } catch (err) {
    throw new ApproveError("REQUEST_INVALID", err.message);
  }
  const approvalRequest = parseApprovalRequest(readText(options["approval-request"]));
  if (positional.length === 1 && positional[0] !== approvalRequest.admission_request_hash) {
    throw new ApproveError("ADMISSION_REQUEST_HASH_MISMATCH", "the hash on the command line differs from the approval request");
  }
  let argumentsRaw;
  if (options.arguments) {
    argumentsRaw = readText(options.arguments);
  } else if (request !== null && typeof request === "object" && Object.hasOwn(request, "arguments")) {
    // Re-read the exact text of request.arguments so duplicate names inside it
    // cannot be lost by an earlier parse: parseJson already refused them.
    argumentsRaw = JSON.stringify(request.arguments);
  } else {
    throw new ApproveError("ARGUMENTS_REQUIRED", "pass --arguments, or a request that carries arguments: you approve exact arguments, never a bare hash");
  }
  if (options.arguments && request !== null && typeof request === "object" && Object.hasOwn(request, "arguments")) {
    // Both given: they must be the same arguments.
    if (argumentsHash(argumentsRaw).hash !== argumentsHash(JSON.stringify(request.arguments)).hash) {
      throw new ApproveError("ARGUMENTS_HASH_MISMATCH", "--arguments differs from the arguments inside --request");
    }
  }
  const context = directoryContext(readText(options.directory), key.file, now);
  if (options["approver-set"]) {
    checkApproverSet(readText(options["approver-set"]), {
      keyFile: key.file,
      constraintId: approvalRequest.constraint_id,
      policyId: approvalRequest.policy.policy_id,
      expectedHash: context.approverSetHash,
    });
  }
  let factMap;
  if (options["fact-map"]) {
    try {
      factMap = parseJson(readText(options["fact-map"]), PROFILE_ANY);
    } catch (err) {
      throw new ApproveError("FACT_MAP_INVALID", err.message);
    }
  }
  const validFor = options["valid-for"] === undefined ? DEFAULT_VALIDITY_SECONDS : Number(options["valid-for"]);
  const decision = options.reject ? "REJECT" : "APPROVE";
  const built = buildApproval({ request, argumentsRaw, approvalRequest, key, context, decision, validForSeconds: validFor, reason: options.reason, now });

  io.stderr.write(renderRequest({ request, built, approvalRequest, key, decision, factMap }) + "\n\n");
  if (!options.yes) await confirm(io, built.payload.subject.arguments_hash);

  const signed = signApproval(built.payload, key);
  const outPath = writeNew(options.out, JSON.stringify(signed.envelope, null, 2) + "\n");
  const disclosuresPath = writeNew(disclosuresOut, JSON.stringify({ disclosures: built.disclosures }, null, 2) + "\n");
  const summary = {
    decision,
    approval_id: built.payload.approval_id,
    envelope_hash: signed.envelopeHash,
    admission_request_hash: built.requestHash,
    arguments_hash: built.payload.subject.arguments_hash,
    approved_at: built.payload.approved_at,
    not_after: built.payload.not_after,
    approval_path: outPath,
    disclosures_path: disclosuresPath,
    submitted: false,
  };
  if (options.json) io.stdout.write(JSON.stringify(summary, null, 2) + "\n");
  else io.stdout.write(`intentrax: ${decision === "APPROVE" ? "approval" : "rejection"} ${summary.approval_id} signed (envelope_hash ${summary.envelope_hash}), valid until ${summary.not_after}, single use.\nWritten to ${outPath} (openings in ${disclosuresPath}). Nothing was sent: attach it to the resubmitted request.\n`);
  return 0;
}

function keygen(argv, io) {
  const { options, positional } = parseArgs(argv, {
    "tenant-id": "value", "principal-id": "value", "key-id": "value", "key-version": "value",
    "valid-from": "value", "valid-until": "value", out: "value", "registration-out": "value", json: "flag",
  });
  if (positional.length > 0) throw new ApproveError("USAGE", `unexpected argument ${positional[0]}`);
  for (const required of ["out", "registration-out"]) {
    if (!options[required]) throw new ApproveError("USAGE", `--${required} is required\n${APPROVE_USAGE}`);
  }
  for (const path of [options.out, options["registration-out"]]) {
    if (existsSync(resolve(path))) throw new ApproveError("OUTPUT_EXISTS", `${path} exists; refusing to overwrite`);
  }
  const { keyFile, registration } = generateApproverKey({
    tenantId: options["tenant-id"],
    principalId: options["principal-id"],
    keyId: options["key-id"],
    keyVersion: options["key-version"] ?? "1",
    validFrom: options["valid-from"],
    validUntil: options["valid-until"],
  });
  const keyPath = writeNew(options.out, JSON.stringify(keyFile, null, 2) + "\n");
  const registrationPath = writeNew(options["registration-out"], JSON.stringify(registration, null, 2) + "\n");
  const summary = { key_id: keyFile.key_id, key_version: keyFile.key_version, principal_id: keyFile.principal_id, public_key_hex: keyFile.public_key_hex, key_path: keyPath, registration_path: registrationPath };
  if (options.json) io.stdout.write(JSON.stringify(summary, null, 2) + "\n");
  else io.stdout.write(`intentrax: APPROVER key ${keyFile.key_id}@${keyFile.key_version} for ${keyFile.principal_id} written to ${keyPath} (private, mode 0600; keep it on this machine).\nRegistration request (public, with proof of possession): ${registrationPath}. Register it in your tenant key directory before approving.\n`);
  return 0;
}

// Standalone entry until the SDK CLI dispatches `intentrax approve`:
//   node approve/cli.mjs [keygen] ...
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  runApprove(process.argv.slice(2)).then(
    (code) => { process.exitCode = code; },
    (err) => {
      process.stderr.write(`intentrax approve: ${err instanceof ApproveError ? err.message : err.stack}\n`);
      process.exitCode = 1;
    },
  );
}
