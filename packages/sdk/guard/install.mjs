// Install / uninstall `intentrax guard` in a project.
//
// install:
//   1. copies the hook runtime (guard/*.mjs plus the scan, sandbox and mcp
//      modules it imports) into .intentrax/guard/runtime/, with MANIFEST.json
//      listing each file's SHA-256. The hook then runs with plain `node` on
//      every tool call: no npx, no network, no dependency on an npx cache;
//   2. writes .intentrax/guard/.gitignore so records and keys stay local;
//   3. merges one PreToolUse hook (matcher "*") into .claude/settings.json
//      (or settings.local.json with --local). Other settings and hooks are
//      kept as they are. Running it again changes nothing;
//   4. optionally (--mcp) pins each stdio MCP server in .mcp.json and routes
//      it through `intentrax mcp proxy --on-drift block`.
// uninstall reverses 3 and 4 and removes the runtime. Records and keys are
// kept unless --purge.

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const SDK_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const GUARD_DIR_REL = ".intentrax/guard";
export const RUNTIME_DIR_REL = ".intentrax/guard/runtime";
export const HOOK_MARKER = ".intentrax/guard/runtime/guard/hook.mjs";
export const HOOK_COMMAND = `node "$CLAUDE_PROJECT_DIR/${HOOK_MARKER}"`;
export const HOOK_TIMEOUT_SECONDS = 30;
export const MANIFEST_SCHEMA = "intentrax.guard.runtime_manifest/v1";
export const MCP_ORIGINALS_REL = ".intentrax/guard/mcp-originals.json";
export const PINS_REL = ".intentrax/mcp-pins.json";

// Everything the hook imports, relative to the SDK root. The layout is kept so
// relative imports resolve unchanged inside the copy.
export const RUNTIME_FILES = Object.freeze([
  "guard/classify.mjs",
  "guard/hook.mjs",
  "guard/policy.mjs",
  "guard/records.mjs",
  "guard/shell.mjs",
  "guard/summary.mjs",
  "mcp/canonical.mjs",
  "mcp/receipt-meta.mjs",
  "sandbox/canonical.mjs",
  "sandbox/keys.mjs",
  "sandbox/time.mjs",
  "scan/classify.mjs",
  "scan/text.mjs",
]);

// Policy packs (sdk/typescript/policy-packs, `intentrax policy`) are copied
// too when this SDK ships them, so a project's .intentrax/policy.jsonc is
// evaluated by the same code that `intentrax policy check` runs. The SDK core
// (index.js) holds the C2 policy VM the packs compile to.
export const PACK_RUNTIME_ENTRY = "policy-packs/index.mjs";

export function runtimeFiles() {
  const files = [...RUNTIME_FILES];
  if (existsSync(join(SDK_ROOT, PACK_RUNTIME_ENTRY))) {
    files.push("index.js", PACK_RUNTIME_ENTRY);
    const packsDir = join(SDK_ROOT, "policy-packs", "packs");
    if (existsSync(packsDir)) {
      for (const f of readdirSync(packsDir).filter((n) => n.endsWith(".json")).sort()) files.push(`policy-packs/packs/${f}`);
    }
  }
  return files.sort();
}

export const GITIGNORE = [
  "# intentrax guard: records and keys are local to this machine (not trust-bearing).",
  "records.jsonl",
  "head.json",
  "records.lock",
  "*.tmp",
  "keys/",
  "local-key-set.json",
  "mcp-originals.json",
  "",
].join("\n");

export class InstallError extends Error {}

export function sdkVersion() {
  try {
    return JSON.parse(readFileSync(join(SDK_ROOT, "package.json"), "utf8")).version;
  } catch {
    return "unknown";
  }
}

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

export function runtimeManifest() {
  const files = {};
  for (const rel of runtimeFiles()) files[rel] = sha256(readFileSync(join(SDK_ROOT, rel)));
  return { schema: MANIFEST_SCHEMA, sdk_version: sdkVersion(), files };
}

// Compare an installed runtime with its manifest.
export function checkRuntime(projectDir) {
  const dir = join(projectDir, RUNTIME_DIR_REL);
  const manifestPath = join(dir, "MANIFEST.json");
  if (!existsSync(manifestPath)) return { installed: false, intact: false, problems: ["runtime not installed"] };
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch {
    return { installed: true, intact: false, problems: ["MANIFEST.json unreadable"] };
  }
  const problems = [];
  for (const [rel, hash] of Object.entries(manifest.files ?? {})) {
    const p = join(dir, rel);
    if (!existsSync(p)) problems.push(`${rel} missing`);
    else if (sha256(readFileSync(p)) !== hash) problems.push(`${rel} modified`);
  }
  for (const rel of RUNTIME_FILES) if (!Object.hasOwn(manifest.files ?? {}, rel)) problems.push(`${rel} not in manifest`);
  return { installed: true, intact: problems.length === 0, problems, sdk_version: manifest.sdk_version };
}

// ---------------------------------------------------------------------------
// settings.json merge (pure: text in, text out)

function detectIndent(text) {
  const m = /\n([ \t]+)"/.exec(text ?? "");
  return m ? m[1] : "  ";
}

function isGuardHook(h) {
  return h && typeof h === "object" && typeof h.command === "string" && h.command.includes(HOOK_MARKER);
}

function parseSettings(text, label) {
  if (text === null || text === undefined || text.trim() === "") return {};
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    throw new InstallError(`${label} is not valid JSON (${e.message}); not changed. Fix it or add the hook by hand.`);
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) throw new InstallError(`${label} must be a JSON object; not changed`);
  if (doc.hooks !== undefined && (typeof doc.hooks !== "object" || doc.hooks === null || Array.isArray(doc.hooks))) throw new InstallError(`${label}: "hooks" must be an object; not changed`);
  if (doc.hooks?.PreToolUse !== undefined && !Array.isArray(doc.hooks.PreToolUse)) throw new InstallError(`${label}: "hooks.PreToolUse" must be an array; not changed`);
  return doc;
}

export function guardHookEntry() {
  return { type: "command", command: HOOK_COMMAND, timeout: HOOK_TIMEOUT_SECONDS };
}

// mergeHookSettings(text) -> { text, action: "added" | "updated" | "unchanged" }
export function mergeHookSettings(text, label = ".claude/settings.json") {
  const doc = parseSettings(text, label);
  const indent = detectIndent(text);
  doc.hooks = doc.hooks ?? {};
  const groups = doc.hooks.PreToolUse ?? [];
  const hasGuard = (g) => g && typeof g === "object" && Array.isArray(g.hooks) && g.hooks.some(isGuardHook);
  const existed = groups.some(hasGuard);
  // Keep the guard hook in the first "*" group that already holds it; remove
  // it from everywhere else (older or hand-edited installs). Groups that hold
  // other hooks are never re-scoped.
  const keep = groups.find((g) => hasGuard(g) && g.matcher === "*") ?? null;
  const emptied = new Set();
  for (const g of groups) {
    if (!hasGuard(g)) continue;
    if (g === keep) {
      let kept = false;
      g.hooks = g.hooks.flatMap((h) => {
        if (!isGuardHook(h)) return [h];
        if (kept) return [];
        kept = true;
        return [guardHookEntry()];
      });
    } else {
      g.hooks = g.hooks.filter((h) => !isGuardHook(h));
      if (g.hooks.length === 0) emptied.add(g);
    }
  }
  doc.hooks.PreToolUse = groups.filter((g) => !emptied.has(g));
  if (!keep) doc.hooks.PreToolUse.push({ matcher: "*", hooks: [guardHookEntry()] });
  const out = JSON.stringify(doc, null, indent) + "\n";
  const action = !existed ? "added" : out === text ? "unchanged" : "updated";
  return { text: out, action };
}

// removeHookSettings(text) -> { text, removed }
export function removeHookSettings(text, label = ".claude/settings.json") {
  if (text === null || text === undefined) return { text, removed: 0 };
  const doc = parseSettings(text, label);
  const groups = doc.hooks?.PreToolUse;
  if (!Array.isArray(groups)) return { text, removed: 0 };
  let removed = 0;
  const emptied = new Set();
  for (const g of groups) {
    if (!g || !Array.isArray(g.hooks)) continue;
    const before = g.hooks.length;
    g.hooks = g.hooks.filter((h) => !isGuardHook(h));
    removed += before - g.hooks.length;
    if (before > 0 && g.hooks.length === 0) emptied.add(g);
  }
  if (removed === 0) return { text, removed: 0 };
  doc.hooks.PreToolUse = groups.filter((g) => !emptied.has(g));
  if (doc.hooks.PreToolUse.length === 0) delete doc.hooks.PreToolUse;
  if (Object.keys(doc.hooks).length === 0) delete doc.hooks;
  return { text: JSON.stringify(doc, null, detectIndent(text)) + "\n", removed };
}

export function settingsHasGuard(text) {
  try {
    const doc = parseSettings(text, "settings");
    return (doc.hooks?.PreToolUse ?? []).some((g) => g?.matcher === "*" && Array.isArray(g.hooks) && g.hooks.some(isGuardHook));
  } catch {
    return false;
  }
}

function readText(path) {
  return existsSync(path) ? readFileSync(path, "utf8") : null;
}

function settingsRel(local) {
  return local ? ".claude/settings.local.json" : ".claude/settings.json";
}

// ---------------------------------------------------------------------------
// MCP proxy wiring (opt-in)

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export function isProxiedEntry(entry) {
  const args = Array.isArray(entry?.args) ? entry.args : [];
  return args.some((a) => typeof a === "string" && a.startsWith("@intentrax/sdk")) && args.includes("mcp") && args.includes("proxy");
}

export function proxyEntry(name, entry, version, platform = process.platform) {
  const args = ["-y", `@intentrax/sdk@${version}`, "mcp", "proxy", "--name", name, "--pins", PINS_REL, "--on-drift", "block"];
  const out = platform === "win32" ? { command: "cmd", args: ["/c", "npx", ...args] } : { command: "npx", args };
  if (entry.env && typeof entry.env === "object") out.env = entry.env;
  return out;
}

// What the pins file holds for `name`: { state: "none" } (not pinned yet),
// { state: "unreadable" } (the file or the entry cannot be read, or it is not
// a stdio pin: never wired over) or { state: "pinned", command }.
function pinnedCommand(projectDir, name) {
  const path = join(projectDir, PINS_REL);
  if (!existsSync(path)) return { state: "none" };
  let doc;
  try {
    doc = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return { state: "unreadable" };
  }
  const servers = doc?.servers;
  if (!servers || typeof servers !== "object" || !Object.hasOwn(servers, name)) return { state: "none" };
  const server = servers[name]?.server;
  if (!server || server.transport !== "stdio" || !Array.isArray(server.command)) return { state: "unreadable" };
  return { state: "pinned", command: server.command };
}

// POSIX-shell quoting for a suggested command line.
function shellQuote(arg) {
  const s = String(arg);
  return /^[A-Za-z0-9_./:@%+=,-]+$/.test(s) ? s : "'" + s.split("'").join("'\\''") + "'";
}

function expandEnvRefs(value, env) {
  return String(value).replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g, (_, k, d) => env[k] ?? d ?? "");
}

// wireMcp -> { lines, changed }. `pinFn` defaults to mcp/commands.mjs pin().
export async function wireMcp(projectDir, { dryRun = false, version = sdkVersion(), pinFn, listToolsFn, platform = process.platform } = {}) {
  const lines = [];
  const mcpPath = join(projectDir, ".mcp.json");
  if (!existsSync(mcpPath)) return { lines: ["mcp: no .mcp.json in this project; nothing to wire"], changed: false };
  let doc;
  try {
    doc = JSON.parse(readFileSync(mcpPath, "utf8"));
  } catch (e) {
    throw new InstallError(`.mcp.json is not valid JSON (${e.message}); not changed`);
  }
  const servers = doc?.mcpServers;
  if (!servers || typeof servers !== "object") return { lines: ["mcp: .mcp.json has no mcpServers; nothing to wire"], changed: false };
  const origPath = join(projectDir, MCP_ORIGINALS_REL);
  const originals = existsSync(origPath) ? JSON.parse(readFileSync(origPath, "utf8")) : { schema: "intentrax.guard.mcp_originals/v1", servers: {} };
  let changed = false;
  if (!pinFn && !dryRun) pinFn = (await import("../mcp/commands.mjs")).pin;
  if (!listToolsFn && !dryRun) listToolsFn = (await import("../mcp/client.mjs")).listServerTools;
  for (const name of Object.keys(servers).sort()) {
    const entry = servers[name];
    if (isProxiedEntry(entry)) {
      lines.push(`mcp: ${name}: already behind intentrax mcp proxy`);
      continue;
    }
    if (!entry || typeof entry.command !== "string" || (entry.type && entry.type !== "stdio")) {
      lines.push(`mcp: ${name}: skipped (remote server; pin it with \`intentrax mcp pin --name ${name} --server <url>\` and run \`intentrax mcp check\`)`);
      continue;
    }
    if (!NAME_RE.test(name)) {
      lines.push(`mcp: ${name}: skipped (name must match ${NAME_RE.source} to be pinned)`);
      continue;
    }
    if (dryRun) {
      lines.push(`mcp: ${name}: would start it once to pin its tools, then route it through intentrax mcp proxy --on-drift block`);
      continue;
    }
    const env = { ...process.env };
    for (const [k, v] of Object.entries(entry.env ?? {})) env[k] = expandEnvRefs(v, process.env);
    const args = Array.isArray(entry.args) ? entry.args.map(String) : [];
    // The proxy launches the PINNED command. If this name is already pinned
    // with a different command, pinning again would keep the old command when
    // the tools happen to match, and the proxy would start the wrong server.
    // Refuse; re-pinning is a deliberate step for the user.
    const stored = pinnedCommand(projectDir, name);
    const argv = [entry.command, ...args];
    const repin = "intentrax mcp pin --name " + name + " --replace -- " + argv.map(shellQuote).join(" ");
    if (stored.state === "unreadable") {
      lines.push(`mcp: ${name}: not wired (${PINS_REL} cannot be read or holds no stdio pin for it; fix the file, then re-pin with \`${repin}\`)`);
      continue;
    }
    if (stored.state === "pinned" && JSON.stringify(stored.command) !== JSON.stringify(argv)) {
      lines.push(`mcp: ${name}: not wired (${PINS_REL} pins it with a different command: ${JSON.stringify(stored.command)}; review it, then re-pin with \`${repin}\`)`);
      continue;
    }
    // Start the server from the project directory to list its tools, but keep
    // that absolute path out of the pin file: it is committed, and the proxy
    // runs from the project directory anyway.
    const listTools = (spec, opts) => listToolsFn(spec.cwd ? spec : { ...spec, cwd: projectDir }, opts);
    const r = await pinFn({ name, server: { transport: "stdio", command: [entry.command, ...args] }, cwd: projectDir, env, out: PINS_REL, listTools });
    if (r.exitCode !== 0) {
      lines.push(`mcp: ${name}: not wired (${r.lines?.[0] ?? r.result})`);
      continue;
    }
    originals.servers[name] = entry;
    servers[name] = proxyEntry(name, entry, version, platform);
    changed = true;
    lines.push(`mcp: ${name}: pinned (${PINS_REL}) and routed through intentrax mcp proxy; drifted or new tools are refused`);
  }
  if (changed) {
    mkdirSync(dirname(origPath), { recursive: true });
    // The originals may hold literal credentials copied from .mcp.json:
    // owner-only permissions, and gitignored (GITIGNORE) so committing the
    // runtime never carries them.
    writeFileSync(origPath, JSON.stringify(originals, null, 2) + "\n", { mode: 0o600 });
    writeFileSync(mcpPath, JSON.stringify(doc, null, detectIndent(readFileSync(mcpPath, "utf8"))) + "\n");
  }
  return { lines, changed };
}

export function unwireMcp(projectDir, { dryRun = false } = {}) {
  const lines = [];
  const origPath = join(projectDir, MCP_ORIGINALS_REL);
  const mcpPath = join(projectDir, ".mcp.json");
  if (!existsSync(origPath) || !existsSync(mcpPath)) return { lines, changed: false };
  const originals = JSON.parse(readFileSync(origPath, "utf8"));
  const text = readFileSync(mcpPath, "utf8");
  const doc = JSON.parse(text);
  let changed = false;
  for (const [name, entry] of Object.entries(originals.servers ?? {})) {
    if (doc.mcpServers && isProxiedEntry(doc.mcpServers[name])) {
      lines.push(`mcp: ${name}: ${dryRun ? "would restore" : "restored"} the original server entry`);
      if (!dryRun) doc.mcpServers[name] = entry;
      changed = true;
    }
  }
  if (changed && !dryRun) {
    writeFileSync(mcpPath, JSON.stringify(doc, null, detectIndent(text)) + "\n");
    rmSync(origPath, { force: true });
  }
  return { lines, changed };
}

// ---------------------------------------------------------------------------
// install / uninstall

export function planInstall(projectDir, { local = false } = {}) {
  const rel = settingsRel(local);
  const settingsPath = join(projectDir, rel);
  const before = readText(settingsPath);
  const merged = mergeHookSettings(before, rel);
  return { settingsRel: rel, settingsPath, before, after: merged.text, action: merged.action };
}

export function install(projectDir, { local = false, dryRun = false } = {}) {
  if (!existsSync(projectDir)) throw new InstallError(`project directory ${projectDir} does not exist`);
  const plan = planInstall(projectDir, { local });
  const manifest = runtimeManifest();
  const lines = [];
  const runtimeDir = join(projectDir, RUNTIME_DIR_REL);
  lines.push(`${dryRun ? "would copy" : "copied"} the hook runtime (${Object.keys(manifest.files).length} files${Object.hasOwn(manifest.files, PACK_RUNTIME_ENTRY) ? ", with policy packs" : ""}, sdk ${manifest.sdk_version}) to ${RUNTIME_DIR_REL}/`);
  lines.push(`${dryRun ? "would write" : "wrote"} ${GUARD_DIR_REL}/.gitignore (records and keys stay on this machine)`);
  lines.push(`${plan.settingsRel}: ${plan.action === "added" ? (dryRun ? "would add" : "added") : plan.action === "updated" ? (dryRun ? "would update" : "updated") : "already has"} the PreToolUse hook (matcher "*")`);
  if (dryRun) return { plan, lines, manifest };

  rmSync(runtimeDir, { recursive: true, force: true });
  for (const rel of Object.keys(manifest.files)) {
    const dest = join(runtimeDir, rel);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, readFileSync(join(SDK_ROOT, rel)));
  }
  writeFileSync(join(runtimeDir, "package.json"), JSON.stringify({ private: true, type: "module", description: "intentrax guard hook runtime (copied by `intentrax guard claude-code`; do not edit)" }, null, 2) + "\n");
  writeFileSync(join(runtimeDir, "MANIFEST.json"), JSON.stringify(manifest, null, 2) + "\n");
  writeFileSync(join(projectDir, GUARD_DIR_REL, ".gitignore"), GITIGNORE);
  if (plan.action !== "unchanged") {
    mkdirSync(dirname(plan.settingsPath), { recursive: true });
    writeFileSync(plan.settingsPath, plan.after);
  }
  return { plan, lines, manifest };
}

export function uninstall(projectDir, { local = false, purge = false, dryRun = false } = {}) {
  const lines = [];
  // After this call, which settings files still load the hook? (dry run:
  // computed from the texts we would write)
  const stillLoaded = [];
  for (const rel of [settingsRel(false), settingsRel(true)]) {
    const path = join(projectDir, rel);
    const text = readText(path);
    if (text === null) continue;
    const touch = !local || rel === settingsRel(true);
    let after = text;
    if (touch) {
      const r = removeHookSettings(text, rel);
      if (r.removed > 0) {
        lines.push(`${rel}: ${dryRun ? "would remove" : "removed"} the guard hook`);
        if (!dryRun) writeFileSync(path, r.text);
        after = r.text;
      }
    }
    if (settingsHasGuard(after)) stillLoaded.push(rel);
  }
  if (stillLoaded.length > 0) {
    // The runtime, MCP wiring and records stay: a hook that points at a
    // deleted runtime would stop gating.
    lines.push(`kept ${RUNTIME_DIR_REL}/ and the MCP wiring: ${stillLoaded.join(", ")} still loads the guard (run uninstall without --local to remove everything)`);
    if (purge) lines.push("--purge ignored while a settings file still loads the guard");
    return { lines };
  }
  const mcp = unwireMcp(projectDir, { dryRun });
  lines.push(...mcp.lines);
  const runtimeDir = join(projectDir, RUNTIME_DIR_REL);
  if (existsSync(runtimeDir)) {
    lines.push(`${dryRun ? "would remove" : "removed"} ${RUNTIME_DIR_REL}/`);
    if (!dryRun) rmSync(runtimeDir, { recursive: true, force: true });
  }
  const guardDir = join(projectDir, GUARD_DIR_REL);
  if (purge && existsSync(guardDir)) {
    lines.push(`${dryRun ? "would delete" : "deleted"} ${GUARD_DIR_REL}/ (records and local keys)`);
    if (!dryRun) rmSync(guardDir, { recursive: true, force: true });
  } else if (existsSync(join(guardDir, "records.jsonl"))) {
    lines.push(`kept the local records in ${GUARD_DIR_REL}/ (delete them with --purge)`);
  }
  if (lines.length === 0) lines.push("guard is not installed here; nothing to do");
  return { lines };
}
