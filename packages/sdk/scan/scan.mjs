// `scanProject(dir, options)`: a local, static, no-account scan that lists the
// destructive or consequential actions an AI agent can reach in a project, and
// flags broad credentials, missing gates and self-reported success.
//
// It reads files only. It never imports or runs the scanned code, never makes
// a network call, and never records or prints a credential value: credentials
// are reported by variable or config name and file location only.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, posix, resolve } from "node:path";
import { extractTools, relativeImports } from "./extract.mjs";
import { classifyAction } from "./classify.mjs";
import { credentialBreadth, envReadsIn, scopedAlternative } from "./credentials.mjs";
import { parseConfig, configKind, claudeRuleMatches, claudeMatcherMatches } from "./configs.mjs";
import { assessCrossFileGate, assessGate, assessReadBack, gateKindIn, hookCommandKind } from "./gates.mjs";
import { makeLineIndex, toPosix } from "./text.mjs";

export const SCAN_NOTE = "Heuristic, static scan. It can miss actions and misclassify names.";
export const SCHEMA = "intentrax.scan.v1";
export const FINDING_TYPES = Object.freeze(["EXPOSED", "UNGATED", "SELF-REPORTED"]);

export class ScanError extends Error {
  constructor(message) {
    super(message);
    this.name = "ScanError";
  }
}

const SKIP_DIRS = new Set([
  "node_modules", "dist", "build", "out", "coverage", "vendor", "third_party", "venv", "env", "__pycache__",
  "target", "site-packages", "bower_components", "jspm_packages", "Pods",
]);
const ALLOWED_DOT_DIRS = new Set([".claude", ".cursor", ".vscode", ".gemini", ".intentrax"]);
const TEST_DIRS = new Set(["test", "tests", "__tests__", "spec", "specs", "fixtures", "__fixtures__", "__mocks__", "testdata", "test-fixtures", "e2e"]);
const SOURCE_EXT = /\.(?:m?[jt]sx?|c[jt]s|py)$/i;
const TOOL_JSON = /(?:^|\/)[^/]*(?:tool|function)[^/]*\.json$/i;
const TEST_FILE = /\.(?:test|spec)\.[^./]+$|(?:^|\/)test_[^/]*\.py$|_test\.py$/i;
const MAX_FILE_BYTES = 1_000_000;

// Keys the agent uses to talk to its model, observability or Intentrax itself.
// They do not grant the agent's tools any reach, so they are not attached.
const NON_TOOL_CREDENTIAL = /^(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_GENERATIVE_AI|GOOGLE_AI|MISTRAL|COHERE|GROQ|TOGETHER|OPENROUTER|DEEPSEEK|XAI|PERPLEXITY|FIREWORKS|REPLICATE|HUGGINGFACE|HF|AZURE_OPENAI|LANGCHAIN|LANGSMITH|LANGFUSE|HELICONE|BRAINTRUST|INTENTRAX|VOYAGE|ELEVENLABS)_/i;

function walk(root, { includeTests, maxFiles }) {
  const files = [];
  const warnings = [];
  let hooksPresent = false;
  let skippedLarge = 0;
  const stack = [""];
  while (stack.length) {
    const rel = stack.pop();
    let entries;
    try {
      entries = readdirSync(join(root, rel), { withFileTypes: true });
    } catch {
      if (rel === "") throw new ScanError(`cannot read directory ${root}`);
      warnings.push(`could not read directory ${rel}`);
      continue;
    }
    entries.sort((a, b) => (a.name < b.name ? 1 : -1));
    for (const e of entries) {
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (e.name.startsWith(".") && !ALLOWED_DOT_DIRS.has(e.name)) continue;
        if (SKIP_DIRS.has(e.name)) continue;
        if (!includeTests && TEST_DIRS.has(e.name)) continue;
        stack.push(childRel);
        continue;
      }
      if (!e.isFile()) continue;
      if (childRel.startsWith(".intentrax/hooks/")) hooksPresent = true;
      const isConfig = Boolean(configKind(childRel));
      const isSource = SOURCE_EXT.test(e.name) && (includeTests || !TEST_FILE.test(childRel));
      const isToolJson = !isConfig && TOOL_JSON.test(childRel) && !/package(-lock)?\.json$|tsconfig/.test(e.name);
      if (!isConfig && !isSource && !isToolJson) continue;
      let size = 0;
      try {
        size = statSync(join(root, childRel)).size;
      } catch {
        continue;
      }
      if (size > MAX_FILE_BYTES) {
        skippedLarge += 1;
        continue;
      }
      if (files.length >= maxFiles) {
        warnings.push(`stopped after ${maxFiles} files; the rest of the project was not scanned`);
        return { files, warnings, hooksPresent };
      }
      files.push({ rel: childRel, isConfig, isSource: isSource || isToolJson });
    }
  }
  if (skippedLarge) warnings.push(`${skippedLarge} file(s) over ${MAX_FILE_BYTES} bytes were skipped`);
  return { files, warnings, hooksPresent };
}

function loc(file, line) {
  return `${file}:${line}`;
}

function credKey(c) {
  return c.refersTo ?? c.name;
}

export function scanProject(dir = ".", options = {}) {
  const root = resolve(String(dir));
  let st;
  try {
    st = statSync(root);
  } catch {
    throw new ScanError(`no such directory: ${dir}`);
  }
  if (!st.isDirectory()) throw new ScanError(`not a directory: ${dir}`);
  const includeTests = options.includeTests === true;
  const maxFiles = Number.isSafeInteger(options.maxFiles) && options.maxFiles > 0 ? options.maxFiles : 20000;

  const { files, warnings, hooksPresent } = walk(root, { includeTests, maxFiles });
  const fileSet = new Set(files.map((f) => f.rel));
  const textCache = new Map();
  const read = (rel) => {
    if (!textCache.has(rel)) {
      let t = null;
      try {
        t = readFileSync(join(root, rel), "utf8");
      } catch {
        warnings.push(`could not read ${rel}`);
      }
      textCache.set(rel, t);
    }
    return textCache.get(rel);
  };

  // Import graph, built lazily: what a file imports, and who imports it.
  const importCache = new Map();
  const importsOf = (file, base = "") => {
    const key = `${base}\u0000${file}`;
    if (!importCache.has(key)) {
      const text = read(file);
      const isPy = /\.py$/.test(file);
      const links = text == null ? [] : relativeImports(text, isPy).flatMap((imp) => resolveImport(file, imp, fileSet, base));
      importCache.set(key, links);
    }
    return importCache.get(key);
  };
  let importerIndex = null;
  const importersOf = (file) => {
    if (!importerIndex) {
      importerIndex = new Map();
      for (const f of files.filter((x) => x.isSource)) {
        for (const link of importsOf(f.rel)) {
          if (!importerIndex.has(link.file)) importerIndex.set(link.file, []);
          importerIndex.get(link.file).push({ file: f.rel, bindings: link.bindings, namespace: link.namespace });
        }
      }
    }
    return importerIndex.get(file) ?? [];
  };
  const gateKindCache = new Map();
  const gateKindOf = (file) => {
    if (!gateKindCache.has(file)) gateKindCache.set(file, gateKindIn(read(file)));
    return gateKindCache.get(file);
  };
  // Gate evidence in other files for a tool file (one level each way).
  const crossFileLinks = (file) => {
    const imports = importsOf(file)
      .filter((l) => gateKindOf(l.file))
      .map((l) => ({ ...l, kind: gateKindOf(l.file) }));
    const importers = importersOf(file)
      .filter((imp) => gateKindOf(imp.file) && usesImport(read(imp.file), imp))
      .map((imp) => ({ file: imp.file, kind: gateKindOf(imp.file) }));
    return { imports, importers };
  };

  // 1. Agent-client configuration.
  const servers = [];
  const claudeByRoot = new Map();
  const cursorByRoot = new Map();
  for (const f of files.filter((x) => x.isConfig)) {
    const text = read(f.rel);
    if (text == null) continue;
    const parsed = parseConfig(f.rel, text);
    if (!parsed) continue;
    if (parsed.warning) {
      warnings.push(parsed.warning);
      continue;
    }
    for (const s of parsed.servers) servers.push({ ...s, configText: text });
    if (parsed.claude) {
      const prev = claudeByRoot.get(parsed.root);
      claudeByRoot.set(parsed.root, prev ? mergeClaude(prev, parsed.claude) : parsed.claude);
    }
    if (parsed.cursor) cursorByRoot.set(parsed.root, parsed.cursor);
  }

  // 2. Tool definitions in source.
  const toolsByFile = new Map();
  for (const f of files.filter((x) => x.isSource && !x.rel.startsWith(".intentrax/"))) {
    const text = read(f.rel);
    if (text == null) continue;
    const tools = extractTools(text, f.rel);
    if (tools.length) toolsByFile.set(f.rel, tools);
  }

  // 3. Link configured stdio servers to their in-repo source.
  const linkedFiles = new Map(); // file -> [server]
  for (const s of servers) {
    s.sourceFiles = [];
    if (s.disabled || s.transport !== "stdio") continue;
    const entries = [];
    for (const c of s.entries) {
      for (const cand of entryVariants(posix.join(s.root || ".", c.base || ".", c.path))) {
        if (fileSet.has(cand)) {
          entries.push(cand);
          break;
        }
      }
    }
    const seen = new Set();
    const queue = entries.map((e) => ({ file: e, depth: 0 }));
    while (queue.length) {
      const { file, depth } = queue.shift();
      if (seen.has(file)) continue;
      seen.add(file);
      const text = read(file);
      if (text == null || depth >= 3) continue;
      for (const link of importsOf(file, s.root)) queue.push({ file: link.file, depth: depth + 1 });
    }
    s.sourceFiles = [...seen];
    for (const file of seen) {
      if (!linkedFiles.has(file)) linkedFiles.set(file, []);
      linkedFiles.get(file).push(s);
    }
  }

  // 4. Actions.
  const actions = [];
  for (const [file, tools] of toolsByFile) {
    const fileText = read(file);
    const lineOf = makeLineIndex(fileText);
    const fileCreds = envReadsIn(fileText).map((r) => ({ name: r.name, refersTo: null, inline: false, file, line: lineOf(r.index), origin: "read in the same file" }));
    const linked = linkedFiles.get(file) ?? [null];
    let links = null;
    let outsideText = null;
    for (const t of tools) {
      const spanText = t.spans.map((s) => fileText.slice(s.start, s.end)).join("\n");
      const spanCreds = t.spans.flatMap((s) => envReadsIn(fileText, s.start, s.end)).map((r) => ({ name: r.name, refersTo: null, inline: false, file, line: lineOf(r.index), origin: "read in the tool handler" }));
      const classification = classifyAction({ name: t.name, description: t.description, body: spanText, annotations: t.annotations });
      let codeGate = assessGate(spanText, fileText);
      // Gates elsewhere matter only for consequential actions.
      if (!codeGate.gated && classification.consequential) {
        links = links ?? crossFileLinks(file);
        outsideText = outsideText ?? blankSpans(fileText, tools.flatMap((x) => x.spans));
        const cross = assessCrossFileGate(spanText, outsideText, links);
        codeGate = cross.gated ? cross : { ...codeGate, reasons: [...codeGate.reasons, ...cross.reasons] };
      }
      for (const server of linked) {
        actions.push({
          name: t.name,
          kind: server ? "mcp-server-tool" : `${t.framework}-tool`,
          framework: t.framework,
          file,
          line: t.line,
          server: server ? { name: server.name, configFile: server.configFile, line: server.line, client: server.client, root: server.root } : null,
          client: server?.client ?? null,
          classification: structuredClone(classification),
          annotations: t.annotations,
          credentials: dedupeCreds([...(server?.credentials ?? []).map((c) => ({ ...c, contextText: server.configText })), ...spanCreds, ...fileCreds].map((c) => ({ ...c, contextText: c.contextText ?? fileText }))),
          codeGate: structuredClone(codeGate),
          readBack: assessReadBack(spanText),
          handlerVisible: true,
          notes: [],
        });
      }
    }
  }
  // External or unresolved servers: their tools cannot be listed statically.
  for (const s of servers) {
    if (s.disabled) continue;
    const hasTools = s.sourceFiles.some((f) => toolsByFile.has(f));
    if (hasTools) continue;
    const classification = classifyAction({ name: s.name, domainTokens: s.domainTokens });
    if (classification.category === "read") {
      classification.reasons.push("its tools could not be listed statically");
    }
    actions.push({
      name: s.name,
      displayName: `MCP server "${s.name}"`,
      kind: "mcp-server",
      framework: "mcp",
      file: s.configFile,
      line: s.line,
      server: { name: s.name, configFile: s.configFile, line: s.line, client: s.client, root: s.root },
      client: s.client,
      classification,
      annotations: {},
      credentials: dedupeCreds(s.credentials.map((c) => ({ ...c, contextText: s.configText }))),
      codeGate: { gated: false, kind: null, heuristic: true, reasons: [] },
      readBack: { present: null, heuristic: true, reasons: ["handler not in this repository"], successMessage: false },
      handlerVisible: false,
      toolsUnknown: true,
      notes: [s.sourceFiles.length ? "entry file found, but no tool definitions were recognized in it" : s.transport === "http" ? "remote server; its tools are not in this repository" : "server code is not in this repository"],
    });
  }
  // Claude Code built-in Bash when the project auto-approves it.
  for (const [r, claude] of claudeByRoot) {
    const allowRule = claude.allow.find((rule) => claudeRuleMatches(rule, "Bash"));
    const bypass = claude.defaultMode === "bypassPermissions";
    if (!allowRule && !bypass) continue;
    actions.push({
      name: "Bash",
      displayName: "Bash (Claude Code shell)",
      kind: "shell-tool",
      framework: "claude-code",
      file: claude.file,
      line: 1,
      server: { name: null, root: r, client: "claude-code" },
      client: "claude-code",
      claudeToolId: "Bash",
      classification: { category: "shell", label: "runs shell commands", severity: 3, consequential: true, heuristic: true, reasons: [allowRule ? `permissions.allow contains "${allowRule}", so any command runs without a prompt` : 'defaultMode is "bypassPermissions", so any command runs without a prompt'] },
      annotations: {},
      credentials: [],
      codeGate: { gated: false, kind: null, heuristic: true, reasons: [] },
      readBack: { present: null, heuristic: true, reasons: [], successMessage: false },
      handlerVisible: false,
      notes: ["a shell reaches every credential in the agent's environment"],
    });
  }

  // 5. Client-side gates and permissions; credential breadth.
  for (const a of actions) {
    a.gate = a.codeGate;
    const r = a.server?.root ?? "";
    if (a.client === "claude-code") {
      const claude = claudeByRoot.get(r);
      const toolId = a.claudeToolId ?? (a.toolsUnknown ? `mcp__${a.server.name}__tool` : `mcp__${a.server?.name}__${a.name}`);
      if (claude) {
        if (claude.deny.some((rule) => claudeRuleMatches(rule, toolId))) {
          a.denied = true;
          a.notes.push(`denied by permissions.deny in ${claude.file}`);
        }
        const hook = claude.preToolUse.find((h) => claudeMatcherMatches(h.matcher, toolId) && h.commands.some(hookCommandKind));
        if (!a.gate.gated && hook) {
          const kind = hook.commands.map(hookCommandKind).find(Boolean);
          a.gate = { gated: true, kind: kind === "intentrax" ? "intentrax" : "approval", heuristic: true, reasons: [`Claude Code PreToolUse hook in ${hook.file} (matcher "${hook.matcher || "*"}") runs ${kind === "intentrax" ? "an Intentrax" : "an approval"} command`] };
        }
        if (!a.gate.gated && claude.ask.some((rule) => claudeRuleMatches(rule, toolId))) {
          a.gate = { gated: true, kind: "approval", heuristic: true, reasons: [`Claude Code asks before running it (permissions.ask in ${claude.file})`] };
        }
        const allow = claude.allow.find((rule) => claudeRuleMatches(rule, toolId));
        if (allow && !a.claudeToolId) a.notes.push(`auto-approved by permissions.allow "${allow}" in ${claude.file}`);
        if (claude.defaultMode === "bypassPermissions" && !a.claudeToolId) a.notes.push(`defaultMode "bypassPermissions" in ${claude.file} auto-approves every tool`);
      }
    }
    if (a.client === "cursor") {
      const cursor = cursorByRoot.get(r);
      const cmds = cursor ? (a.classification.category === "shell" ? cursor.beforeShellExecution : cursor.beforeMCPExecution) : [];
      const kind = cmds.map(hookCommandKind).find(Boolean);
      if (!a.gate.gated && kind) {
        a.gate = { gated: true, kind: kind === "intentrax" ? "intentrax" : "approval", heuristic: true, reasons: [`Cursor hook in ${cursor.file} runs ${kind === "intentrax" ? "an Intentrax" : "an approval"} command before the call`] };
      }
    }
    if (!a.gate.gated && hooksPresent) {
      a.notes.push("Intentrax hooks are scaffolded in .intentrax/hooks/, but nothing in front of this action calls one");
    }
    for (const c of a.credentials) {
      c.breadth = credentialBreadth(c.name, c.contextText) ?? (c.refersTo ? credentialBreadth(c.refersTo, c.contextText) : null);
    }
    // A server whose tools we cannot see, holding a broad credential, is
    // treated as consequential: anything that credential allows is reachable.
    if (a.toolsUnknown && !a.classification.consequential && a.credentials.some((c) => c.breadth)) {
      a.classification = {
        ...a.classification,
        category: "unknown",
        label: "tools not listed statically",
        severity: 1,
        consequential: true,
        reasons: [...a.classification.reasons, "its tools could not be listed statically and it holds a broad credential"],
      };
    }
  }

  // Same credential reaching read-only and severe tools.
  const readersByCred = new Map();
  for (const a of actions) {
    if (a.denied || a.classification.category !== "read") continue;
    for (const c of a.credentials) {
      const k = credKey(c);
      if (!readersByCred.has(k)) readersByCred.set(k, new Set());
      readersByCred.get(k).add(a.name);
    }
  }
  for (const a of actions) {
    a.sharedCredentials = [];
    if (a.classification.severity < 3) continue;
    for (const c of a.credentials) {
      const readers = readersByCred.get(credKey(c));
      if (readers && readers.size) a.sharedCredentials.push({ credential: c, readers: [...readers].sort() });
    }
  }

  // 6. Findings.
  const findings = [];
  for (const a of actions) {
    if (a.denied || !a.classification.consequential) continue;
    const display = a.displayName ?? a.name;
    const broad = a.credentials.filter((c) => c.breadth);
    const gatePhrase = a.gate.gated ? `, gated (${a.gate.kind === "intentrax" ? "Intentrax" : "approval step"})` : ", no gate";
    if (broad.length || a.sharedCredentials.length) {
      let what;
      if (broad.length) {
        const c = broad[0];
        what = `${c.breadth.label} (${credKey(c)})`;
      } else {
        const s = a.sharedCredentials[0];
        what = `${credKey(s.credential)}, which also serves read tools (${s.readers.slice(0, 3).join(", ")}${s.readers.length > 3 ? ", ..." : ""})`;
      }
      findings.push(makeFinding("EXPOSED", a, `EXPOSED ${display} reachable with ${what}${gatePhrase}`, broad, hooksPresent));
    } else if (!a.gate.gated) {
      findings.push(makeFinding("UNGATED", a, `UNGATED ${display} (${a.classification.label}) runs with no gate or approval step`, broad, hooksPresent));
    }
    if (a.handlerVisible && a.readBack.present === false && (a.classification.severity >= 2 || a.readBack.successMessage)) {
      const how = a.readBack.successMessage ? "reports success" : "returns its own result as the outcome";
      findings.push(makeFinding("SELF-REPORTED", a, `SELF-REPORTED ${display} ${how} without reading the result back`, broad, hooksPresent));
    }
  }
  const order = { EXPOSED: 0, UNGATED: 1, "SELF-REPORTED": 2 };
  findings.sort((x, y) => y.severity - x.severity || order[x.type] - order[y.type] || x.action.localeCompare(y.action) || x.location.localeCompare(y.location));
  findings.forEach((f, i) => {
    f.id = i + 1;
  });

  const consequential = actions.filter((a) => a.classification.consequential && !a.denied);
  const counts = Object.fromEntries(FINDING_TYPES.map((t) => [t, findings.filter((f) => f.type === t).length]));
  const summary = {
    filesScanned: files.length,
    actionsFound: actions.length,
    consequentialActions: consequential.length,
    gatedActions: consequential.filter((a) => a.gate.gated).length,
    mcpServers: servers.length,
    serversWithUnlistedTools: actions.filter((a) => a.toolsUnknown).length,
    findings: findings.length,
    byType: counts,
    warnings: warnings.length,
  };
  let firstLine;
  if (findings.length) firstLine = findings[0].line;
  else if (actions.length === 0) firstLine = "NO FINDINGS: no agent-reachable actions were recognized";
  else if (consequential.length === 0) firstLine = `NO FINDINGS: ${actions.length} agent-reachable action(s), none classified as consequential`;
  else firstLine = `NO FINDINGS: ${consequential.length} consequential action(s), each gated, without broad credentials, and read back where visible`;

  return {
    schema: SCHEMA,
    firstLine,
    findings,
    actions: actions.map(publicAction),
    summary,
    warnings,
    note: SCAN_NOTE,
  };
}

function makeFinding(type, a, line, broad, hooksPresent) {
  const recs = [];
  const tool = a.displayName ?? a.name;
  const inline = a.credentials.filter((c) => c.inline);
  const inlineNote = inline.length ? ` ${inline.map((c) => c.name).join(", ")} ${inline.length > 1 ? "are" : "is"} written inline in ${[...new Set(inline.map((c) => c.file))].join(", ")}: move the value to a secret store and reference it by name.` : "";

  if (type === "EXPOSED") {
    const parts = [];
    for (const c of broad) parts.push(`replace ${credKey(c)} with ${scopedAlternative(credKey(c))}`);
    for (const s of a.sharedCredentials) {
      if (broad.includes(s.credential)) continue;
      parts.push(`split ${credKey(s.credential)}: give the read tools (${s.readers.slice(0, 3).join(", ")}) a read-only credential and give ${tool} its own, narrower one (${scopedAlternative(credKey(s.credential))})`);
    }
    recs.push({ kind: "least-privilege", text: `Narrow the credential first: ${parts.join("; ")}.${inlineNote}` });
    if (!a.gate.gated) recs.push({ kind: "intentrax", text: gateRec(a, tool, hooksPresent) });
  } else if (type === "UNGATED") {
    let text;
    if (a.classification.category === "shell") {
      text = `Run the agent's shell without production credentials in its environment (a container or sandbox), and allowlist the commands it needs instead of auto-approving all of them.`;
    } else {
      const c = a.credentials[0];
      text = `Give ${tool} only ${c ? scopedAlternative(credKey(c)) : "a credential limited to what it does"}, and remove it from the agent's tools if the agent does not need it.`;
    }
    recs.push({ kind: "least-privilege", text: text + inlineNote });
    recs.push({ kind: "intentrax", text: gateRec(a, tool, hooksPresent) });
  } else {
    recs.push({ kind: "least-privilege", text: `Read the result back with a separate read-only credential, not the one that performed ${tool}, and report success only when the read-back matches.` });
    recs.push({ kind: "intentrax", text: "Try the read-back locally: npx @intentrax/sdk sandbox --check ./check.mjs reads the outcome and flags a contradiction (a local, non-trust-bearing trial, not evidence)." });
  }
  return {
    type,
    line,
    action: a.name,
    severity: a.classification.severity,
    category: a.classification.category,
    location: loc(a.file, a.line),
    server: a.server?.name ? { name: a.server.name, config: loc(a.server.configFile, a.server.line) } : null,
    classification: a.classification,
    credentials: a.credentials.map(publicCred),
    gate: a.gate,
    readBack: a.readBack,
    notes: a.notes,
    recommendations: recs,
    heuristic: true,
  };
}

function gateRec(a, tool, hooksPresent) {
  const adapter = adapterFor(a);
  const scaffold = hooksPresent ? "call the scaffolded .intentrax/hooks/ entrypoint" : `run npx @intentrax/sdk init ${adapter} and call the generated hook`;
  return `Then gate it: ${scaffold} before ${tool} runs, at the tool dispatcher, so a denied or failed admission stops the call (fail closed).`;
}

function adapterFor(a) {
  if (a.client === "claude-code") return "claude-code";
  if (a.client === "cursor" && a.classification.category === "shell") return "cursor";
  if (a.framework === "mcp" || a.server) return "mcp";
  if (["langchain", "langgraph", "vercel-ai-sdk"].includes(a.framework)) return a.framework;
  return "custom-agent";
}

function publicCred(c) {
  const out = { name: c.name, location: loc(c.file, c.line), origin: c.origin };
  if (c.refersTo) out.refersTo = c.refersTo;
  if (c.inline) out.inline = true;
  if (c.breadth) out.breadth = c.breadth;
  return out;
}

function publicAction(a) {
  return {
    name: a.name,
    displayName: a.displayName ?? a.name,
    kind: a.kind,
    framework: a.framework,
    location: loc(a.file, a.line),
    server: a.server?.name ? { name: a.server.name, config: loc(a.server.configFile, a.server.line), client: a.server.client } : null,
    classification: a.classification,
    credentials: a.credentials.map(publicCred),
    gate: a.gate,
    readBack: a.readBack,
    denied: a.denied === true,
    toolsUnknown: a.toolsUnknown === true,
    notes: a.notes,
  };
}

function dedupeCreds(creds) {
  const out = [];
  const seen = new Set();
  for (const c of creds) {
    const k = credKey(c);
    if (NON_TOOL_CREDENTIAL.test(k)) continue;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(c);
  }
  return out;
}

function mergeClaude(a, b) {
  return {
    file: a.file,
    allow: [...a.allow, ...b.allow],
    ask: [...a.ask, ...b.ask],
    deny: [...a.deny, ...b.deny],
    defaultMode: b.defaultMode ?? a.defaultMode,
    enableAllProjectMcpServers: a.enableAllProjectMcpServers || b.enableAllProjectMcpServers,
    preToolUse: [...a.preToolUse, ...b.preToolUse],
  };
}

// The file with every tool span replaced by spaces (offsets kept).
function blankSpans(text, spans) {
  let out = text;
  for (const sp of spans) out = out.slice(0, sp.start) + " ".repeat(Math.max(0, sp.end - sp.start)) + out.slice(sp.end);
  return out;
}

// The importer refers to what it imported somewhere besides the import itself.
function usesImport(text, imp) {
  if (!text) return false;
  const names = [...(imp.bindings ?? []), ...(imp.namespace ? [imp.namespace] : [])];
  return names.some((n) => (text.match(new RegExp(`(?<![\\w$.])${n.replace(/\$/g, "\\$")}(?![\\w$])`, "g")) ?? []).length >= 2);
}

function norm(p) {
  const n = posix.normalize(toPosix(p)).replace(/^\.\//, "");
  return n === "." ? "" : n;
}

// node dist/index.js usually comes from src/index.ts.
function entryVariants(p) {
  const base = norm(p);
  const out = [base];
  const noExt = base.replace(/\.(?:m?[jt]sx?|c[jt]s)$/, "");
  for (const ext of [".ts", ".mts", ".tsx", ".js", ".mjs"]) out.push(noExt + ext);
  const src = base.replace(/(^|\/)(?:dist|build|out|lib)\//, "$1src/");
  if (src !== base) {
    const srcNoExt = src.replace(/\.(?:m?[jt]sx?|c[jt]s)$/, "");
    for (const ext of [".ts", ".mts", ".tsx", ".js", ".mjs"]) out.push(srcNoExt + ext);
  }
  return out;
}

function importVariants(fromFile, mod, isPy, serverRoot) {
  const dir = posix.dirname(fromFile);
  if (!isPy) {
    const target = norm(posix.join(dir, mod));
    const noExt = target.replace(/\.(?:m?[jt]sx?|c[jt]s)$/, "");
    const out = [target];
    for (const ext of [".ts", ".mts", ".tsx", ".js", ".mjs", ".cjs", ".jsx"]) out.push(noExt + ext);
    for (const ext of [".ts", ".js", ".mjs"]) out.push(`${target}/index${ext}`);
    return out;
  }
  const base = pyModuleBase(fromFile, mod, serverRoot);
  return base == null ? [] : [`${base}.py`, `${base}/__init__.py`];
}

// Python module path without extension. A relative module resolves against
// the importing file; an absolute one against the server root and, failing
// that, the importing file's directory (scripts run from their own folder).
function pyModuleBase(fromFile, mod, root) {
  const dir = posix.dirname(fromFile);
  if (mod.startsWith(".")) {
    const dots = mod.match(/^\.+/)[0].length;
    let d = dir;
    for (let i = 1; i < dots; i += 1) d = posix.dirname(d);
    return norm(posix.join(d, mod.slice(dots).replace(/\./g, "/")));
  }
  return norm(posix.join(root || ".", mod.replace(/\./g, "/")));
}

// Files an import resolves to, each with the local names that refer to it.
// Python `from . import queries` resolves the submodule `queries.py` too, with
// `queries` acting as a namespace for it.
function resolveImport(fromFile, imp, fileSet, root) {
  const isPy = /\.py$/.test(fromFile);
  const out = [];
  const pick = (cands, link) => {
    const hit = cands.find((c) => fileSet.has(c) && c !== fromFile);
    if (hit) out.push({ file: hit, ...link });
  };
  if (!isPy) {
    pick(importVariants(fromFile, imp.module, false, root), { bindings: imp.bindings ?? [], namespace: imp.namespace ?? null });
    return out;
  }
  const roots = [...new Set([root || "", posix.dirname(fromFile)])];
  for (const r of imp.module.startsWith(".") ? [root || ""] : roots) {
    const base = pyModuleBase(fromFile, imp.module, r);
    if (base == null) continue;
    const before = out.length;
    pick([`${base}.py`, `${base}/__init__.py`], { bindings: imp.bindings ?? [], namespace: imp.namespace ?? null });
    (imp.bindings ?? []).forEach((local, i) => {
      const name = imp.submodules?.[i];
      if (name) pick([`${base ? `${base}/` : ""}${name}.py`, `${base ? `${base}/` : ""}${name}/__init__.py`], { bindings: [], namespace: local });
    });
    if (out.length > before) break;
  }
  return out;
}
