// Agent-client configuration: MCP server configs (Claude Code .mcp.json and
// .claude/settings*.json, Cursor .cursor/mcp.json, VS Code .vscode/mcp.json and
// settings.json, Claude Desktop, Gemini CLI, generic mcp.json), Claude Code
// permissions and PreToolUse hooks, and Cursor hooks.
//
// Credential VALUES in these files are never kept: an env entry becomes
// { name, refersTo?, inline } and nothing else.

import { posix } from "node:path";
import { parseJsonc, makeLineIndex, tokenize } from "./text.mjs";
import { isCredentialName, referencedVars } from "./credentials.mjs";

const CONFIG_KINDS = [
  { re: /(^|\/)\.mcp\.json$/, client: "claude-code", up: 0 },
  { re: /(^|\/)\.claude\/settings(\.local)?\.json$/, client: "claude-code", up: 1, claudeSettings: true },
  { re: /(^|\/)\.cursor\/mcp\.json$/, client: "cursor", up: 1 },
  { re: /(^|\/)\.cursor\/hooks\.json$/, client: "cursor", up: 1, cursorHooks: true },
  { re: /(^|\/)\.vscode\/mcp\.json$/, client: "vscode", up: 1 },
  { re: /(^|\/)\.vscode\/settings\.json$/, client: "vscode", up: 1 },
  { re: /(^|\/)\.gemini\/settings\.json$/, client: "gemini-cli", up: 1 },
  { re: /(^|\/)claude_desktop_config\.json$/, client: "claude-desktop", up: 0 },
  { re: /(^|\/)mcp\.json$/, client: "mcp-client", up: 0 },
];

export function configKind(relPath) {
  return CONFIG_KINDS.find((k) => k.re.test(relPath)) ?? null;
}

function rootOf(relPath, up) {
  let dir = posix.dirname(relPath);
  for (let i = 0; i < up; i += 1) dir = posix.dirname(dir);
  return dir === "." ? "" : dir;
}

function serversOf(json) {
  if (!json || typeof json !== "object") return null;
  if (json.mcpServers && typeof json.mcpServers === "object") return json.mcpServers;
  if (json.servers && typeof json.servers === "object") return json.servers;
  if (json.mcp && typeof json.mcp === "object" && json.mcp.servers && typeof json.mcp.servers === "object") return json.mcp.servers;
  if (json["mcp.servers"] && typeof json["mcp.servers"] === "object") return json["mcp.servers"];
  return null;
}

const SECRET_FLAG = /^--?([A-Za-z0-9_-]*(?:token|key|secret|password|passwd|pat|auth|credential)[A-Za-z0-9_-]*)(?:=(.*))?$/i;

// Credentials a server receives: env entries, auth headers, URL query
// parameters, secret-looking CLI flags and docker `-e NAME`.
function serverCredentials(server, file, line, serverName) {
  const creds = [];
  const add = (c) => creds.push({ file, line, ...c });
  const env = server.env && typeof server.env === "object" ? server.env : {};
  for (const [k, v] of Object.entries(env)) {
    const refs = referencedVars(v);
    if (!isCredentialName(k) && !refs.some(isCredentialName)) continue;
    add({
      name: k,
      refersTo: refs.find((r) => r !== k) ?? null,
      inline: refs.length === 0 && typeof v === "string" && v.length > 0,
      origin: `${serverName} env.${k}`,
    });
  }
  const headers = server.headers && typeof server.headers === "object" ? server.headers : {};
  for (const [h, v] of Object.entries(headers)) {
    if (!/authori[sz]ation|token|key|secret|cookie|auth/i.test(h)) continue;
    const refs = referencedVars(v);
    if (refs.length) for (const r of refs) add({ name: r, refersTo: null, inline: false, origin: `${serverName} headers.${h}` });
    else add({ name: `header ${h}`, refersTo: null, inline: true, origin: `${serverName} headers.${h}` });
  }
  if (typeof server.url === "string" || typeof server.serverUrl === "string") {
    const raw = server.url ?? server.serverUrl;
    for (const r of referencedVars(raw)) if (isCredentialName(r)) add({ name: r, refersTo: null, inline: false, origin: `${serverName} url` });
    try {
      const u = new URL(raw.replace(/\$\{[^}]*\}/g, "x"));
      for (const p of u.searchParams.keys()) {
        if (/token|key|secret|auth|password|sig/i.test(p)) add({ name: `url query parameter "${p}"`, refersTo: null, inline: true, origin: `${serverName} url` });
      }
    } catch {
      // not a URL we can parse; nothing to record
    }
  }
  const args = Array.isArray(server.args) ? server.args.map(String) : [];
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if ((a === "-e" || a === "--env") && args[i + 1]) {
      const [n, ...rest] = args[i + 1].split("=");
      if (isCredentialName(n)) add({ name: n, refersTo: null, inline: rest.length > 0 && referencedVars(rest.join("=")).length === 0, origin: `${serverName} args (${a} ${n})` });
      i += 1;
      continue;
    }
    const f = SECRET_FLAG.exec(a);
    if (f) {
      const value = f[2] ?? args[i + 1];
      const refs = referencedVars(value);
      if (refs.length) for (const r of refs) add({ name: r, refersTo: null, inline: false, origin: `${serverName} args (--${f[1]})` });
      else add({ name: `flag --${f[1]}`, refersTo: null, inline: value !== undefined, origin: `${serverName} args (--${f[1]})` });
      if (f[2] === undefined) i += 1;
    }
  }
  return creds;
}

// Tokens used for domain heuristics (server name, command, package names,
// URL host). Values after secret flags and env assignments are excluded.
function domainTokensOf(name, server) {
  const parts = [name, server.command ?? ""];
  const args = Array.isArray(server.args) ? server.args.map(String) : [];
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (SECRET_FLAG.test(a)) {
      if (!a.includes("=")) i += 1;
      continue;
    }
    if (a === "-e" || a === "--env") {
      i += 1;
      continue;
    }
    if (a.includes("=") || /^https?:/i.test(a)) continue;
    parts.push(a);
  }
  const raw = server.url ?? server.serverUrl;
  if (typeof raw === "string") {
    try {
      parts.push(new URL(raw.replace(/\$\{[^}]*\}/g, "x")).hostname);
    } catch {
      // ignore
    }
  }
  return [...new Set(parts.flatMap((p) => tokenize(p)))];
}

// Candidate entry files for a stdio server, relative to the config root.
function entryCandidates(server) {
  const out = [];
  const tokens = [server.command, ...(Array.isArray(server.args) ? server.args : [])].filter((t) => typeof t === "string");
  let base = typeof server.cwd === "string" ? server.cwd : "";
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if ((t === "--directory" || t === "--cwd" || t === "--prefix" || t === "-C") && tokens[i + 1]) {
      base = tokens[i + 1];
      i += 1;
      continue;
    }
    if (t === "-m" && tokens[i + 1]) {
      const mod = tokens[i + 1].replace(/\./g, "/");
      out.push({ base, path: `${mod}.py` }, { base, path: `${mod}/__main__.py` }, { base, path: `${mod}/server.py` }, { base, path: `${mod}/__init__.py` });
      i += 1;
      continue;
    }
    if (/\.(?:m?[jt]sx?|c[jt]s|py)$/i.test(t)) out.push({ base, path: t });
  }
  return out.map((c) => ({ base: clean(c.base), path: clean(c.path) }));
}

function clean(p) {
  return String(p ?? "")
    .replace(/\$\{(?:workspaceFolder|workspaceRoot|PWD|CLAUDE_PROJECT_DIR|pwd)\}\/?/g, "")
    .replace(/\$(?:PWD|CLAUDE_PROJECT_DIR)\/?/g, "")
    .split("\\")
    .join("/");
}

function lineOfKey(text, key) {
  const lineOf = makeLineIndex(text);
  const i = text.indexOf(JSON.stringify(key));
  return i >= 0 ? lineOf(i) : 1;
}

// Parses one config file. Returns { servers, claude, cursor, warning }.
export function parseConfig(relPath, text) {
  const kind = configKind(relPath);
  if (!kind) return null;
  let json;
  try {
    json = parseJsonc(text);
  } catch {
    return { warning: `could not parse ${relPath} as JSON; MCP servers or hooks in it were not scanned` };
  }
  const root = rootOf(relPath, kind.up);
  const result = { root, servers: [], claude: null, cursor: null };

  const servers = serversOf(json);
  if (servers) {
    for (const [name, server] of Object.entries(servers)) {
      if (!server || typeof server !== "object") continue;
      const line = lineOfKey(text, name);
      result.servers.push({
        name,
        client: kind.client,
        configFile: relPath,
        line,
        root,
        disabled: server.disabled === true || server.enabled === false,
        transport: typeof (server.url ?? server.serverUrl) === "string" ? "http" : "stdio",
        credentials: serverCredentials(server, relPath, line, name),
        domainTokens: domainTokensOf(name, server),
        entries: entryCandidates(server),
      });
    }
  }

  if (kind.claudeSettings) {
    const perms = json.permissions && typeof json.permissions === "object" ? json.permissions : {};
    const list = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "string") : []);
    const pre = [];
    const hooks = json.hooks && typeof json.hooks === "object" ? json.hooks : {};
    for (const entry of Array.isArray(hooks.PreToolUse) ? hooks.PreToolUse : []) {
      const commands = (Array.isArray(entry?.hooks) ? entry.hooks : []).map((h) => String(h?.command ?? "")).filter(Boolean);
      pre.push({ matcher: typeof entry?.matcher === "string" ? entry.matcher : "", commands, file: relPath, line: lineOfKey(text, "PreToolUse") });
    }
    result.claude = {
      file: relPath,
      allow: list(perms.allow),
      ask: list(perms.ask),
      deny: list(perms.deny),
      defaultMode: typeof perms.defaultMode === "string" ? perms.defaultMode : null,
      enableAllProjectMcpServers: json.enableAllProjectMcpServers === true,
      preToolUse: pre,
    };
  }

  if (kind.cursorHooks) {
    const hooks = json.hooks && typeof json.hooks === "object" ? json.hooks : {};
    const pick = (k) => (Array.isArray(hooks[k]) ? hooks[k] : []).map((h) => String(h?.command ?? "")).filter(Boolean);
    result.cursor = {
      file: relPath,
      line: lineOfKey(text, "hooks"),
      beforeMCPExecution: pick("beforeMCPExecution"),
      beforeShellExecution: pick("beforeShellExecution"),
    };
  }
  return result;
}

// Claude Code permission rule match for a tool id such as
// "mcp__infra__delete_volume" or "Bash".
export function claudeRuleMatches(rule, toolId) {
  const r = rule.trim();
  if (r === toolId) return true;
  if (toolId.startsWith("mcp__")) {
    const [, server] = toolId.split("__");
    if (r === `mcp__${server}` || r === `mcp__${server}__*` || r === "mcp__*") return true;
  }
  if (toolId === "Bash") {
    // "Bash", "Bash(*)" and "Bash(:*)" allow every command; narrower rules
    // ("Bash(npm test)") cover only some.
    return r === "Bash" || r === "Bash(*)" || r === "Bash(:*)";
  }
  return false;
}

// PreToolUse matcher semantics: empty or "*" matches all; otherwise the
// matcher is matched as a regular expression against the whole tool name.
export function claudeMatcherMatches(matcher, toolId) {
  if (!matcher || matcher === "*") return true;
  if (matcher === toolId) return true;
  try {
    return new RegExp(`^(?:${matcher})$`).test(toolId);
  } catch {
    return false;
  }
}
