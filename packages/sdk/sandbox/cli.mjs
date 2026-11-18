#!/usr/bin/env node
// `intentrax sandbox`: the local assurance sandbox CLI.
//
//   intentrax sandbox [--scenario confirmed|contradicted] [--dir <project>] [--json]
//   intentrax sandbox --check ./my-check.mjs [--check-timeout-ms 30000] [--dir <project>] [--json]
//   intentrax sandbox verify <bundle.json> [--keys <local-key-set.json>] [--json]
//        [--issuer-keys <pinned-external-issuers.json>] [--require-external-issuer <issuer>]...
//
// Everything runs in-process with ephemeral local keys. Output files go to
// <project>/.intentrax/local/, which is gitignored. Nothing is sent anywhere.
//
// `intentrax sandbox ...` (cli/intentrax.mjs) dispatches here; from a repository
// checkout, `node sdk/typescript/sandbox/cli.mjs [args]` runs the same thing.

import { readFileSync, writeFileSync, mkdirSync, realpathSync } from "node:fs";
import { basename, join, relative, resolve, isAbsolute } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { sha256Hex, isCanonicalizable } from "./canonical.mjs";
import { runSandbox, SCENARIOS, SAMPLE_ACTION } from "./run.mjs";
import { verifyLocalBundle } from "./verifier.mjs";
import { loadLocalKeySet, LocalKeySetError } from "./keys.mjs";
import { loadPinnedIssuerKeySet, IssuerKeySetError } from "./external-decision.mjs";
import { describeCheck, runCheckWorker } from "./check-runner.mjs";
import { VERDICTS } from "./model.mjs";

export const LOCAL_DIR = join(".intentrax", "local");

export const BANNER = Object.freeze([
  "==============================================================================",
  " INTENTRAX LOCAL SANDBOX: NOT PRODUCTION ASSURANCE",
  " Signed with ephemeral keys generated on this machine",
  " (environment: local, trust_bearing: false). No production or published key",
  " was read or used, and nothing was sent over the network. Production",
  " verifiers, hosted verify and the Verification Mark reject local bundles.",
  "==============================================================================",
]);

export const EXIT_CODES = Object.freeze({
  [VERDICTS.LOCAL_NON_TRUST_BEARING]: 0,
  [VERDICTS.PENDING_FINALITY]: 10,
  [VERDICTS.INSUFFICIENT_EVIDENCE]: 11,
  [VERDICTS.CONFLICTING_EVIDENCE]: 12,
  [VERDICTS.INTEGRITY_ONLY]: 13,
  [VERDICTS.VERIFICATION_FAILED]: 14,
});
export const USAGE_EXIT_CODE = 64;
// Loading a --check module (in its worker) is bounded separately from the
// read itself, which --check-timeout-ms bounds.
const CHECK_LOAD_TIMEOUT_MS = 15000;

class UsageError extends Error {}

function exitCodeFor(verdict) {
  if (!Object.prototype.hasOwnProperty.call(EXIT_CODES, verdict)) {
    // VERIFIED_FOR_SCOPE is unreachable here by construction; refuse loudly.
    throw new Error("sandbox verifier produced a verdict above its ceiling: " + verdict);
  }
  return EXIT_CODES[verdict];
}

function parseArgs(args) {
  const opts = {
    scenario: null, check: null, checkTimeoutMs: 30000, dir: null, json: false, keys: null, help: false, positional: [],
    issuerKeys: null, requireExternalIssuer: [],
  };
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    const value = () => {
      const v = args[i + 1];
      if (v === undefined || v.startsWith("--")) throw new UsageError(a + " requires a value");
      i += 1;
      return v;
    };
    if (a === "--help" || a === "-h") opts.help = true;
    else if (a === "--json") opts.json = true;
    else if (a === "--scenario") opts.scenario = value();
    else if (a === "--check") opts.check = value();
    else if (a === "--check-timeout-ms") {
      const n = Number(value());
      if (!Number.isSafeInteger(n) || n < 1 || n > 600000) throw new UsageError("--check-timeout-ms must be an integer from 1 to 600000");
      opts.checkTimeoutMs = n;
    } else if (a === "--dir") opts.dir = value();
    else if (a === "--keys") opts.keys = value();
    else if (a === "--issuer-keys") opts.issuerKeys = value();
    else if (a === "--require-external-issuer") opts.requireExternalIssuer.push(value());
    else if (a.startsWith("--")) throw new UsageError("unknown option " + a);
    else opts.positional.push(a);
  }
  return opts;
}

// Load a developer's read-only check module.
//   export const expected = { status: "closed" };   // required: the state your action should produce
//   export const resource = "ticket:1234";          // optional label for what is checked
//   export default async function check({ resource, fields }) { return { status: ... }; }
export async function loadUserCheck(path, { cwd, timeoutMs }) {
  const abs = isAbsolute(path) ? path : resolve(cwd, path);
  let source;
  try {
    source = readFileSync(abs);
  } catch {
    throw new UsageError("--check: cannot read " + path);
  }
  // The module is loaded and run only inside a worker thread (check-runner.mjs).
  const href = pathToFileURL(abs).href;
  let mod;
  try {
    mod = await describeCheck(href, CHECK_LOAD_TIMEOUT_MS);
  } catch (err) {
    throw new UsageError("--check: cannot load " + path + ": " + (err && err.message ? err.message : err));
  }
  if (!mod.has_check) throw new UsageError("--check: module must export a default async function (or `check`) returning the observed state");
  const read = (probe, { signal } = {}) => runCheckWorker({ href, mode: "read", probe, signal });
  const expected = mod.expected;
  if (expected === null || typeof expected !== "object" || Array.isArray(expected) || Object.keys(expected).length === 0
    || !isCanonicalizable(expected)) {
    throw new UsageError("--check: module must export `expected`, a non-empty plain object of JSON values (integers only) " +
      "describing the state your action should produce");
  }
  const resource = mod.resource === null ? "user:" + basename(abs) : mod.resource;
  if (typeof resource !== "string" || resource.length === 0 || resource.length > 200 || resource.endsWith("*")) {
    throw new UsageError("--check: `resource` must be a non-empty string (max 200 chars, no trailing *)");
  }
  return {
    read,
    expected: JSON.parse(JSON.stringify(expected)),
    resource,
    checkModule: { file_name: basename(abs), sha256: sha256Hex(source) },
    timeoutMs,
  };
}

function writeJson(path, value, mode = 0o644) {
  writeFileSync(path, JSON.stringify(value, null, 2) + "\n", { mode });
}

// Everything goes under <project>/.intentrax/local/, which ignores itself.
export function writeRunArtifacts(projectDir, result) {
  const localDir = join(projectDir, LOCAL_DIR);
  const runDir = join(localDir, "runs", result.bundle.bundle_id);
  mkdirSync(runDir, { recursive: true });
  writeFileSync(join(localDir, ".gitignore"), "# Intentrax local sandbox: ephemeral keys and local-only bundles. Never commit.\n*\n");
  writeJson(join(localDir, "sandbox-signing-keys.json"), result.signingKeys, 0o600);
  const paths = {
    local_dir: localDir,
    signing_keys: join(localDir, "sandbox-signing-keys.json"),
    bundle: join(runDir, "bundle.json"),
    key_set: join(runDir, "local-key-set.json"),
    report: join(runDir, "verification-report.json"),
  };
  writeJson(paths.bundle, result.bundle);
  writeJson(paths.key_set, result.keySet);
  writeJson(paths.report, result.report);
  return paths;
}

function pad(s, n) {
  return (s + " ".repeat(n)).slice(0, Math.max(n, s.length));
}

function renderAssessments(report, out) {
  for (const a of report.assessments) {
    const prov = a.provenance ? "  [" + a.provenance + "]" : "";
    const why = a.reasons.length ? "  " + a.reasons.slice(0, 3).join(", ") : "";
    out("   " + pad(a.dimension, 22) + " " + pad(a.result, 22) + prov + why);
  }
}

function renderVerdict(report, out) {
  out("");
  out("Verdict: " + report.verdict + "   (profile " + report.assurance_profile + ")");
  if (report.verdict !== report.uncapped_verdict) {
    out("  Uncapped verdict " + report.uncapped_verdict + ", capped at " + report.verdict_ceiling +
      " because every signer is a local, non-trust-bearing key.");
  }
  const result = (dim) => report.assessments.find((a) => a.dimension === dim)?.result;
  if (report.verdict === VERDICTS.CONFLICTING_EVIDENCE && result("EFFECT_CONFIRMED") === "CONTRADICTED") {
    out("  The signed decision said ALLOW and the executor reported success, but the independent read");
    out("  disagrees with the authorised effect. A decision record alone would not have shown this.");
  }
  if (report.verdict === VERDICTS.CONFLICTING_EVIDENCE && result("EXTERNAL_AUTHORIZATION") === "CONTRADICTED") {
    out("  A genuinely signed, bound external authorization decision DENIED this action while the local");
    out("  decision said ALLOW. The external decision is evidence, not trust; the conflict is reported as such.");
  }
  out("");
  out("Limitations:");
  for (const l of report.limitations) out("  - " + l.code + ": " + l.text);
}

function rel(cwd, p) {
  const r = relative(cwd, p);
  return r && !r.startsWith("..") && !isAbsolute(r) ? r : p;
}

function usage(invokedAs) {
  return [
    "Usage:",
    "  " + invokedAs + " [--scenario confirmed|contradicted] [--dir <project>] [--json]",
    "  " + invokedAs + " --check ./my-check.mjs [--check-timeout-ms 30000] [--dir <project>] [--json]",
    "  " + invokedAs + " verify <bundle.json> [--keys <local-key-set.json>] [--json]",
    "      [--issuer-keys <pinned-external-issuers.json>] [--require-external-issuer <issuer>]...",
    "",
    "Scenarios (built-in sample action, " + SAMPLE_ACTION.description + "):",
    ...Object.entries(SCENARIOS).map(([k, v]) => "  " + pad(k, 13) + v),
    "",
    "--check runs YOUR read-only check after your action: export `expected` (the state the action",
    "should produce) and a default async function returning the observed state. The sandbox never",
    "calls your write path. A check you wrote is labelled SELF_REPORTED, not an authoritative read.",
    "",
    "verify --issuer-keys assesses third-party signed authorization decisions a bundle carries",
    "(EXTERNAL_AUTHORIZATION, THIRD_PARTY_ATTESTED) against an issuer key set YOU pinned; nothing is",
    "fetched. --require-external-issuer makes that issuer's decision required. Evidence, never trust.",
    "",
    "Exit codes: 0 LOCAL_NON_TRUST_BEARING · 10 PENDING_FINALITY · 11 INSUFFICIENT_EVIDENCE ·",
    "12 CONFLICTING_EVIDENCE · 13 INTEGRITY_ONLY · 14 VERIFICATION_FAILED · 64 usage",
  ].join("\n");
}

async function runCommand(opts, { out, cwd, now, invokedAs }) {
  if (opts.positional.length) throw new UsageError("unexpected argument " + opts.positional[0]);
  if (opts.keys) throw new UsageError("--keys applies to `verify` only");
  if (opts.issuerKeys || opts.requireExternalIssuer.length) {
    throw new UsageError("--issuer-keys and --require-external-issuer apply to `verify` only");
  }
  if (opts.check && opts.scenario) throw new UsageError("--scenario applies to the built-in sample only; it cannot be combined with --check");
  const scenario = opts.scenario ?? "confirmed";
  if (!Object.prototype.hasOwnProperty.call(SCENARIOS, scenario)) {
    throw new UsageError("unknown --scenario " + scenario + " (expected: " + Object.keys(SCENARIOS).join(", ") + ")");
  }
  const userCheck = opts.check ? await loadUserCheck(opts.check, { cwd, timeoutMs: opts.checkTimeoutMs }) : null;
  const result = await runSandbox({ scenario, userCheck, now: now ?? new Date() });
  const projectDir = opts.dir ? resolve(cwd, opts.dir) : cwd;
  const paths = writeRunArtifacts(projectDir, result);
  const report = result.report;
  const reverify = invokedAs + " verify " + rel(cwd, paths.bundle) + " --keys " + rel(cwd, paths.key_set);

  if (opts.json) {
    out(JSON.stringify({
      banner: BANNER.filter((l) => !l.startsWith("=")).map((l) => l.trim()).join(" "),
      environment: "local",
      trust_bearing: false,
      production_assurance: false,
      run_id: result.run_id,
      scenario: result.scenario,
      action: result.action,
      facts: result.facts,
      keys: result.keys,
      files: Object.fromEntries(Object.entries(paths).map(([k, v]) => [k, rel(cwd, v)])),
      reverify,
      report,
    }, null, 2));
    return exitCodeFor(report.verdict);
  }

  const f = result.facts;
  const effect = report.assessments.find((a) => a.dimension === "EFFECT_CONFIRMED");
  const observed = report.assessments.find((a) => a.dimension === "EFFECT_OBSERVED");
  BANNER.forEach((l) => out(l));
  out("");
  out("Scenario: " + result.scenario + (result.scenario === "user-check" ? "" : "  (" + SCENARIOS[result.scenario] + ")"));
  out("Action:   " + result.action.description);
  out("          SetState " + result.action.resource + " -> " + JSON.stringify(result.action.authorised_state));
  out("");
  out(" 1. Decision         " + f.decision_outcome + ", signed before execution by " + result.keys.DECISION_SERVICE);
  out(" 2. Executor report  " + f.executor_report_status + " (self-reported by " + result.keys.EXECUTOR + ")" +
    (f.synthetic_store_writes === null ? "; the sandbox did not call your system" : "; writes reaching the store: " + f.synthetic_store_writes));
  out(" 3. Independent read " + (f.read_status === "OK" ? JSON.stringify(f.observed_state) : f.read_status + (f.read_error ? " (" + f.read_error + ")" : "")));
  out("                     read by " + result.keys.EFFECT_VERIFIER + " via " +
    (f.read_kind === "USER_SUPPLIED_CHECK" ? "your check module (provenance SELF_REPORTED: you wrote the check)"
      : "the sandbox's synthetic store (provenance THIRD_PARTY_ATTESTED by the local effect-verifier key)"));
  out("                     EFFECT_CONFIRMED = " + effect.result + "   EFFECT_OBSERVED = " + observed.result);
  out(" 4. Sealed bundle    " + rel(cwd, paths.bundle));
  out(" 5. Offline verify   8 dimensions, local key set " + rel(cwd, paths.key_set));
  renderAssessments(report, out);
  renderVerdict(report, out);
  out("");
  out("Re-verify offline: " + reverify);
  out("Ephemeral private keys: " + rel(cwd, paths.signing_keys) + " (gitignored; not trust-bearing)");
  return exitCodeFor(report.verdict);
}

function verifyCommand(opts, { out, cwd }) {
  const [bundlePath, ...extra] = opts.positional;
  if (!bundlePath || extra.length) throw new UsageError("verify requires exactly one bundle path");
  if (opts.check || opts.scenario || opts.dir) {
    throw new UsageError("verify takes only <bundle.json>, --keys, --issuer-keys, --require-external-issuer and --json");
  }
  let bundle;
  try {
    bundle = JSON.parse(readFileSync(resolve(cwd, bundlePath), "utf8"));
  } catch {
    throw new UsageError("cannot read bundle JSON from " + bundlePath);
  }
  let pinned = null;
  if (opts.keys) {
    let doc;
    try {
      doc = JSON.parse(readFileSync(resolve(cwd, opts.keys), "utf8"));
    } catch {
      throw new UsageError("cannot read key set JSON from " + opts.keys);
    }
    try {
      pinned = loadLocalKeySet(doc);
    } catch (err) {
      if (err instanceof LocalKeySetError) throw new UsageError("--keys: " + err.message);
      throw err;
    }
  }
  let issuerKeys = null;
  if (opts.issuerKeys) {
    let doc;
    try {
      doc = JSON.parse(readFileSync(resolve(cwd, opts.issuerKeys), "utf8"));
    } catch {
      throw new UsageError("cannot read issuer key set JSON from " + opts.issuerKeys);
    }
    try {
      issuerKeys = loadPinnedIssuerKeySet(doc);
    } catch (err) {
      if (err instanceof IssuerKeySetError) throw new UsageError("--issuer-keys: " + err.message);
      throw err;
    }
  }
  const report = verifyLocalBundle(bundle, { pinned, issuerKeys, externalAuthorizationIssuers: opts.requireExternalIssuer });
  if (opts.json) {
    out(JSON.stringify(report, null, 2));
    return exitCodeFor(report.verdict);
  }
  BANNER.forEach((l) => out(l));
  out("");
  out("Bundle: " + bundlePath + (pinned ? "" : "   (no --keys: signer authenticity cannot be assessed)"));
  renderAssessments(report, out);
  renderVerdict(report, out);
  return exitCodeFor(report.verdict);
}

export async function sandboxMain(argv, {
  stdout = process.stdout,
  stderr = process.stderr,
  cwd = process.cwd(),
  now = null,
  invokedAs = "intentrax sandbox",
} = {}) {
  const out = (line) => stdout.write(line + "\n");
  const err = (line) => stderr.write(line + "\n");
  try {
    const isVerify = argv[0] === "verify";
    const opts = parseArgs(isVerify ? argv.slice(1) : argv);
    if (opts.help) {
      out(usage(invokedAs));
      return 0;
    }
    return isVerify ? verifyCommand(opts, { out, cwd }) : await runCommand(opts, { out, cwd, now, invokedAs });
  } catch (e) {
    if (e instanceof UsageError || (e && /--scenario|unknown scenario/.test(e.message))) {
      err("intentrax sandbox: " + e.message);
      err(usage(invokedAs));
      return USAGE_EXIT_CODE;
    }
    throw e;
  }
}

function invokedDirectly() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  const self = rel(process.cwd(), fileURLToPath(import.meta.url));
  process.exitCode = await sandboxMain(process.argv.slice(2), { invokedAs: "node " + JSON.stringify(self) });
}
