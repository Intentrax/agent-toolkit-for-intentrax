// Static extraction of tool definitions from source files: MCP servers
// (TypeScript/JavaScript and Python), OpenAI and Anthropic tool/function
// definitions, LangChain/LangGraph tools, Vercel AI SDK tools and Mastra
// tools. Pattern-based (the anchors follow
// skills/intentrax-integrate-agent-actions/references/discovery-patterns.md):
// it reads text, never imports or runs it.

import { makeLineIndex, readString, matchBracket, depthAt, findKeyString } from "./text.mjs";

const MAX_SPAN_LINES = 120;

function frameworkOf(text, isPython, hint) {
  if (/@modelcontextprotocol\/sdk|from\s+mcp\b|import\s+mcp\b|from\s+fastmcp\b|import\s+fastmcp\b|FastMCP\s*\(|McpServer\s*\(/.test(text)) {
    if (hint === "mcp" || hint === "object") return "mcp";
  }
  if (/@langchain\/langgraph|from\s+langgraph\b|import\s+langgraph\b/.test(text)) return "langgraph";
  if (/@langchain\/|from\s+langchain|import\s+langchain/.test(text)) return "langchain";
  if (/from\s+["']ai["']|require\(\s*["']ai["']\s*\)|@ai-sdk\//.test(text)) return "vercel-ai-sdk";
  if (/@mastra\//.test(text)) return "mastra";
  if (/from\s+agents\b|@openai\/agents/.test(text)) return "openai-agents";
  if (/\bopenai\b/i.test(text)) return "openai";
  if (/\banthropic\b/i.test(text)) return "anthropic";
  return isPython ? "python" : "javascript";
}

function annotationsIn(text) {
  const out = {};
  const d = /["']?destructiveHint["']?\s*[:=]\s*(true|false|True|False)\b/.exec(text);
  if (d) out.destructiveHint = d[1].toLowerCase() === "true";
  const r = /["']?readOnlyHint["']?\s*[:=]\s*(true|false|True|False)\b/.exec(text);
  if (r) out.readOnlyHint = r[1].toLowerCase() === "true";
  return out;
}

function prevIdentifier(text, index) {
  const before = text.slice(Math.max(0, index - 200), index);
  const key = /(?:^|[\s,{])(?:["']([^"'\n]+)["']|([A-Za-z_$][\w$]*))\s*:\s*$/.exec(before);
  if (key) return key[1] ?? key[2];
  const decl = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*$/.exec(before);
  if (decl) return decl[1];
  return null;
}

// Each extractor pushes { name, kind, framework, index, description, annotations, callText }.
function extractJs(text, push) {
  let m;

  // MCP TypeScript SDK: server.tool("name", "description"?, ...)
  const dotTool = /\.tool\s*\(/g;
  while ((m = dotTool.exec(text))) {
    const open = m.index + m[0].length - 1;
    const name = readString(text, open + 1);
    if (!name || name.start !== skipWs(text, open + 1)) continue;
    const after = skipWs(text, name.end);
    let description = "";
    if (text[after] === ",") {
      const d = readString(text, after + 1);
      if (d && d.start === skipWs(text, after + 1)) description = d.value;
    }
    const close = matchBracket(text, open);
    const callText = text.slice(m.index, close > 0 ? close : m.index + 1500);
    push({ name: name.value, framework: "mcp", index: m.index, description, annotations: annotationsIn(callText) });
  }

  // MCP TypeScript SDK: server.registerTool("name", { description, annotations }, handler)
  const register = /\.registerTool\s*\(/g;
  while ((m = register.exec(text))) {
    const open = m.index + m[0].length - 1;
    const name = readString(text, open + 1);
    if (!name) continue;
    const close = matchBracket(text, open);
    const end = close > 0 ? close : m.index + 2000;
    const desc = findKeyString(text, "description", name.end, end);
    push({ name: name.value, framework: "mcp", index: m.index, description: desc?.value ?? "", annotations: annotationsIn(text.slice(m.index, end)) });
  }

  // Bare tool(...): Vercel AI SDK tool({ ... }) or LangChain tool(fn, { name, ... })
  const bareTool = /(?<![.\w$])(tool|dynamicTool|createTool)\s*\(/g;
  while ((m = bareTool.exec(text))) {
    const open = m.index + m[0].length - 1;
    const first = skipWs(text, open + 1);
    const close = matchBracket(text, open);
    const end = close > 0 ? close : m.index + 2000;
    if (text[first] === "{") {
      const objClose = matchBracket(text, first);
      const objEnd = objClose > 0 ? objClose : end;
      const id = findKeyString(text, "id", first, objEnd, { open: first, depth: 1 }) ?? findKeyString(text, "name", first, objEnd, { open: first, depth: 1 });
      const name = id?.value ?? prevIdentifier(text, m.index);
      if (!name) continue;
      const desc = findKeyString(text, "description", first, objEnd, { open: first, depth: 1 });
      const fw = m[1] === "createTool" ? "mastra" : frameworkOf(text, false, "vercel");
      push({ name, framework: fw, index: m.index, description: desc?.value ?? "", annotations: annotationsIn(text.slice(first, objEnd)) });
    } else {
      const nameKey = findKeyString(text, "name", first, end);
      if (!nameKey) continue;
      const desc = findKeyString(text, "description", first, end);
      push({ name: nameKey.value, framework: frameworkOf(text, false, "langchain"), index: m.index, description: desc?.value ?? "", annotations: {} });
    }
  }

  // LangChain JS: new DynamicStructuredTool({ name, description, func })
  const dyn = /new\s+(?:DynamicStructuredTool|DynamicTool)\s*\(\s*\{/g;
  while ((m = dyn.exec(text))) {
    const objOpen = m.index + m[0].length - 1;
    const objClose = matchBracket(text, objOpen);
    const end = objClose > 0 ? objClose : m.index + 2000;
    const name = findKeyString(text, "name", objOpen, end, { open: objOpen, depth: 1 });
    if (!name) continue;
    const desc = findKeyString(text, "description", objOpen, end, { open: objOpen, depth: 1 });
    push({ name: name.value, framework: frameworkOf(text, false, "langchain"), index: m.index, description: desc?.value ?? "", annotations: {} });
  }

  // LangChain JS: class X extends StructuredTool { name = "x"; description = "..." }
  const cls = /class\s+([A-Za-z_$][\w$]*)\s+extends\s+(?:StructuredTool|Tool|DynamicTool)\b[^{]*\{/g;
  while ((m = cls.exec(text))) {
    const open = m.index + m[0].length - 1;
    const close = matchBracket(text, open);
    const end = close > 0 ? close : m.index + 3000;
    const name = findKeyString(text, "name", open, end, { open, depth: 1 });
    const desc = findKeyString(text, "description", open, end, { open, depth: 1 });
    push({ name: name?.value ?? m[1], framework: frameworkOf(text, false, "langchain"), index: m.index, description: desc?.value ?? "", annotations: {} });
  }
}

function extractPython(text, push) {
  let m;

  // @mcp.tool(), @server.tool(name=...), @tool, @tool("name"), @function_tool
  const deco = /^[ \t]*@((?:[A-Za-z_]\w*\.)*)(tool|function_tool)\b/gm;
  while ((m = deco.exec(text))) {
    let i = m.index + m[0].length;
    let decoArgs = "";
    const p = skipWs(text, i, true);
    if (text[p] === "(") {
      const close = matchBracket(text, p, { python: true });
      if (close < 0) continue;
      decoArgs = text.slice(p, close + 1);
      i = close + 1;
    }
    const nl = text.indexOf("\n", i);
    if (nl < 0) continue;
    const def = /^(?:\s*\n)*(?:[ \t]*@[^\n]*\n)*[ \t]*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/.exec(text.slice(nl));
    if (!def) continue;
    const defParen = nl + def.index + def[0].length - 1;
    let name = def[1];
    const named = /\bname\s*=\s*/.exec(decoArgs);
    if (named) {
      const s = readString(decoArgs, named.index + named[0].length);
      if (s) name = s.value;
    } else {
      const s = readString(decoArgs, 1);
      if (s && s.start === skipWs(decoArgs, 1)) name = s.value;
    }
    let description = "";
    const descArg = /\bdescription\s*=\s*/.exec(decoArgs);
    if (descArg) description = readString(decoArgs, descArg.index + descArg[0].length)?.value ?? "";
    if (!description) {
      const parenClose = matchBracket(text, defParen, { python: true });
      if (parenClose > 0) {
        const doc = /^\s*(?:->[^:\n]*)?:\s*\n\s*([rRuU]?(?:"""|'''))/.exec(text.slice(parenClose + 1));
        if (doc) description = readString(text, parenClose + 1 + doc.index + doc[0].length - doc[1].length)?.value ?? "";
      }
    }
    const prefix = m[1].replace(/\.$/, "");
    const hint = prefix ? "mcp" : "decorator";
    let framework = frameworkOf(text, true, hint);
    if (m[2] === "function_tool") framework = "openai-agents";
    push({ name, framework, index: m.index, description, annotations: annotationsIn(decoArgs) });
  }

  // Tool(name=..., ...), types.Tool(...), StructuredTool.from_function(...), FunctionTool(...)
  const ctor = /\b(?:types\.)?(?:Tool|StructuredTool\.from_function|Tool\.from_function|FunctionTool(?:\.from_defaults)?)\s*\(/g;
  while ((m = ctor.exec(text))) {
    const open = m.index + m[0].length - 1;
    const close = matchBracket(text, open, { python: true });
    if (close < 0) continue;
    const name = findKeyString(text, "name", open, close, { open, depth: 1 });
    if (!name) continue;
    const desc = findKeyString(text, "description", open, close, { open, depth: 1 });
    const call = text.slice(open, close);
    const framework = /\binputSchema\s*=/.test(call) ? "mcp" : frameworkOf(text, true, "ctor");
    push({ name: name.value, framework, index: m.index, description: desc?.value ?? "", annotations: annotationsIn(call) });
  }

  // class X(BaseTool): name: str = "x"
  const cls = /^class\s+([A-Za-z_]\w*)\s*\([^)]*\b(?:BaseTool|StructuredTool)\b[^)]*\)\s*:/gm;
  while ((m = cls.exec(text))) {
    const end = Math.min(text.length, m.index + 3000);
    const name = /\bname\s*(?::\s*[\w\[\]]+\s*)?=\s*/.exec(text.slice(m.index, end));
    const nameValue = name ? readString(text, m.index + name.index + name[0].length)?.value : null;
    const desc = /\bdescription\s*(?::\s*[\w\[\]]+\s*)?=\s*/.exec(text.slice(m.index, end));
    const descValue = desc ? readString(text, m.index + desc.index + desc[0].length)?.value : "";
    push({ name: nameValue ?? m[1], framework: frameworkOf(text, true, "class"), index: m.index, description: descValue ?? "", annotations: {} });
  }
}

// Object-literal and dict definitions shared by JS, Python and JSON:
// { name, description, inputSchema }        (MCP list_tools)
// { name, description, input_schema }       (Anthropic tool use)
// { type: "function", function: { name, description, parameters } }  (OpenAI)
function extractObjectDefinitions(text, push, isPython) {
  const re = /["']?\bname["']?\s*:\s*(?=[rRuU]?["'`])/g;
  let m;
  while ((m = re.exec(text))) {
    const name = readString(text, m.index + m[0].length);
    if (!name) continue;
    const open = enclosingOpenBrace(text, m.index);
    if (open < 0) continue;
    const close = matchBracket(text, open, { python: isPython });
    if (close < 0) continue;
    if (depthAt(text, open, m.index) !== 1) continue;
    const obj = text.slice(open, close + 1);
    const schemaKey = /["']?\b(inputSchema|input_schema|parameters|args_schema)["']?\s*:/.exec(obj);
    if (!schemaKey) continue;
    const desc = findKeyString(text, "description", open, close, { open, depth: 1 });
    let framework;
    if (schemaKey[1] === "inputSchema") framework = "mcp";
    else if (schemaKey[1] === "input_schema") framework = "anthropic";
    else if (schemaKey[1] === "args_schema") framework = frameworkOf(text, isPython, "object");
    else framework = "openai";
    push({ name: name.value, framework, index: m.index, description: desc?.value ?? "", annotations: annotationsIn(obj) });
  }
}

function enclosingOpenBrace(text, index) {
  let depth = 0;
  for (let i = index - 1; i >= Math.max(0, index - 600); i -= 1) {
    const c = text[i];
    if (c === "}") depth += 1;
    else if (c === "{") {
      if (depth === 0) return i;
      depth -= 1;
    }
  }
  return -1;
}

function skipWs(text, i, sameLine = false) {
  let j = i;
  while (j < text.length && (sameLine ? /[ \t]/ : /\s/).test(text[j])) j += 1;
  return j;
}

// Handler spans for low-level dispatchers: `case "name":` (JS) and
// `if name == "name":` / `elif name == "name":` (Python).
function dispatcherSpan(text, toolName) {
  const esc = toolName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`case\\s+["'\`]${esc}["'\`]\\s*:|(?:if|elif)\\s+[\\w.\\[\\]"']+\\s*==\\s*["']${esc}["']\\s*:`);
  const m = re.exec(text);
  if (!m) return null;
  const rest = text.slice(m.index + m[0].length);
  const next = /\n\s*(?:case\s+["'`]|default\s*:|elif\s|else\s*:)/.exec(rest);
  const lines = rest.split("\n").slice(0, 80).join("\n");
  const end = m.index + m[0].length + Math.min(next ? next.index : rest.length, lines.length);
  return { start: m.index, end };
}

// Returns tool definitions found in one file, each with a body span (the text
// from the definition to the next definition, capped) used for side-effect,
// gate and read-back heuristics.
export function extractTools(text, relPath) {
  const isPython = /\.py$/i.test(relPath);
  const isJson = /\.json$/i.test(relPath);
  const found = [];
  const seen = new Set();
  const push = (t) => {
    if (!t.name || typeof t.name !== "string" || t.name.length > 120 || /\s{2,}|\n/.test(t.name)) return;
    const key = t.name;
    if (seen.has(key)) return;
    seen.add(key);
    found.push(t);
  };
  if (isJson) extractObjectDefinitions(text, push, false);
  else if (isPython) {
    extractPython(text, push);
    extractObjectDefinitions(text, push, true);
  } else {
    extractJs(text, push);
    extractObjectDefinitions(text, push, false);
  }
  found.sort((a, b) => a.index - b.index);
  const lineOf = makeLineIndex(text);
  // Dispatcher handlers (`case "x":`) belong to their own tool, so a
  // definition span stops where any of them starts.
  const dispatchers = found.map((t) => dispatcherSpan(text, t.name)).filter(Boolean);
  return found.map((t, i) => {
    const nextIndex = i + 1 < found.length ? found[i + 1].index : text.length;
    let end = nextIndex;
    for (const d of dispatchers) if (d.start > t.index && d.start < end) end = d.start;
    const startLine = lineOf(t.index);
    if (lineOf(end) - startLine > MAX_SPAN_LINES) {
      let n = 0;
      let j = t.index;
      while (j < end && n < MAX_SPAN_LINES) {
        j = text.indexOf("\n", j + 1);
        if (j < 0) {
          j = end;
          break;
        }
        n += 1;
      }
      end = j;
    }
    const spans = [{ start: t.index, end }];
    const dispatch = dispatcherSpan(text, t.name);
    if (dispatch && (dispatch.start < t.index || dispatch.start >= end)) spans.push(dispatch);
    return { ...t, line: startLine, spans };
  });
}

// Relative imports followed from an MCP server entry file.
export function relativeImports(text, isPython) {
  const out = [];
  let m;
  if (isPython) {
    const re = /^\s*from\s+(\.+[\w.]*|[A-Za-z_][\w.]*)\s+import\s+([^\n]+)/gm;
    while ((m = re.exec(text))) out.push({ module: m[1], names: m[2] });
  } else {
    const re = /(?:import|export)\s[^'"`;]*?from\s*["'](\.{1,2}\/[^"']+)["']|import\s*\(\s*["'](\.{1,2}\/[^"']+)["']\s*\)|require\(\s*["'](\.{1,2}\/[^"']+)["']\s*\)|import\s+["'](\.{1,2}\/[^"']+)["']/g;
    while ((m = re.exec(text))) out.push({ module: m[1] ?? m[2] ?? m[3] ?? m[4] });
  }
  return out;
}
