// `intentrax policy init --from-scan`: run `intentrax scan`, pick the packs
// whose scan rule ids match what it found, and write a draft policy file with
// a comment on every choice. The output is deterministic (no timestamps), so
// running it twice on the same project gives the same file.

import { scanProject } from "../scan/scan.mjs";
import { listPacks, getPack, POLICY_FILE_SCHEMA_VERSION, ENVIRONMENTS, tokens } from "./index.mjs";

const MAX_REASONS = 3;

// Comments carry names and locations from the scanned project: keep them on
// one printable line.
function clean(text, max = 80) {
  const s = String(text ?? "").replace(/[^\x20-\x7e]/g, "?").replace(/\*\//g, "*?");
  return s.length > max ? `${s.slice(0, max - 3)}...` : s;
}

function actionTokens(a) {
  return new Set([...tokens(a.name), ...tokens(a.displayName), ...tokens(a.server?.name)]);
}

// Which packs the scan result selects, each with the actions and findings
// that selected it.
export function selectPacks(scan) {
  const actions = (scan.actions ?? []).filter((a) => !a.denied);
  const findingTypes = new Map();
  for (const f of scan.findings ?? []) {
    const key = `${f.action}\u0000${f.location}`;
    if (!findingTypes.has(key)) findingTypes.set(key, new Set());
    findingTypes.get(key).add(f.type);
  }
  const typesOf = (a) => [...(findingTypes.get(`${a.name}\u0000${a.location}`) ?? [])].sort();
  const exposedAny = (scan.findings ?? []).filter((f) => f.type === "EXPOSED");

  const selections = [];
  for (const summary of listPacks()) {
    const pack = getPack(summary.pack_id);
    const ids = new Set(pack.scan.rule_ids);
    const nameTokens = pack.scan.name_tokens ? new Set(pack.scan.name_tokens) : null;
    const hits = [];
    for (const a of actions) {
      const category = a.classification?.category;
      const toks = actionTokens(a);
      const named = nameTokens ? [...toks].some((t) => nameTokens.has(t)) : true;
      let why = null;
      // A shell can run anything, so a pack that lists the shell category is
      // selected by any shell tool, whatever its name.
      if (category === "shell" && ids.has("scan.category.shell")) why = "a shell tool can run these commands";
      else if (ids.has(`scan.category.${category}`) && named) why = `classified as ${a.classification.label}`;
      else if (ids.has("scan.any") && nameTokens && named) why = "its name matches this pack";
      else if (ids.has("scan.kind.mcp-server") && a.server) why = "it is an MCP tool or server";
      if (why) hits.push({ action: a, why, types: typesOf(a) });
    }
    const exposed = ids.has("scan.finding.EXPOSED") ? exposedAny : [];
    if (hits.length || exposed.length) selections.push({ pack, summary, hits, exposed });
  }
  return selections;
}

function decisionLine(pack) {
  return Object.entries(pack.actions).map(([action, spec]) => `${action} ${spec.decisions.join("/")}`).join("; ");
}

function reasonLines(sel) {
  const lines = [];
  for (const h of sel.hits.slice(0, MAX_REASONS)) {
    const a = h.action;
    const label = a.displayName ?? a.name;
    const server = a.server?.name && a.kind !== "mcp-server" ? ` on MCP server "${clean(a.server.name, 40)}"` : "";
    const types = h.types.length ? ` [${h.types.join(", ")}]` : "";
    lines.push(`${clean(label, 60)}${server} at ${clean(a.location, 80)}: ${h.why}${types}`);
  }
  if (sel.hits.length > MAX_REASONS) lines.push(`and ${sel.hits.length - MAX_REASONS} more action(s)`);
  if (!sel.hits.length && sel.exposed.length) {
    const f = sel.exposed[0];
    lines.push(`EXPOSED finding on ${clean(f.action, 60)} at ${clean(f.location, 80)}: a broad credential is reachable`);
  }
  return lines;
}

function wrap(text, width = 92, prefix = "  //   ") {
  const words = text.split(/\s+/);
  const out = [];
  let line = "";
  for (const w of words) {
    if (line && (line.length + 1 + w.length) > width - prefix.length) {
      out.push(prefix + line);
      line = w;
    } else {
      line = line ? `${line} ${w}` : w;
    }
  }
  if (line) out.push(prefix + line);
  return out;
}

// The draft policy file text (JSON with comments).
export function renderPolicyFile(scan, selections, { environment = "PROD" } = {}) {
  if (!ENVIRONMENTS.includes(environment)) throw new Error("environment must be PROD, STAGING or DEV");
  const s = scan.summary ?? {};
  const out = [];
  out.push("// Intentrax policy file: a DRAFT written by `intentrax policy init --from-scan`.");
  out.push(`// Scan: ${s.actionsFound ?? 0} agent-reachable action(s), ${s.consequentialActions ?? 0} consequential, ${s.findings ?? 0} finding(s).`);
  out.push("// The scan is heuristic and static: it can miss actions and misclassify names. Review every");
  out.push("// pack below before you rely on it, and remove the ones you do not want.");
  out.push("//");
  out.push("// Decisions: allow (no objection: the agent's own permission rules still decide), ask (a person");
  out.push("// approves first), block (refused).");
  out.push("// Each pack is pinned by pack_hash: if a pack changes, loading this file fails until you");
  out.push("// review the new pack (intentrax policy show <pack>) and update the hash.");
  out.push("// Facts (amounts, branches, recipient domains) are read from the agent's tool input on this");
  out.push("// machine: the decision can be re-checked from the policy hash, the facts are self-reported.");
  out.push("// Check it: intentrax policy validate <this file>. Try a call: intentrax policy check.");
  out.push("{");
  out.push(`  "schema_version": "${POLICY_FILE_SCHEMA_VERSION}",`);
  out.push("  // environment: the eeo.request.environment fact for every call (PROD, STAGING or DEV).");
  out.push("  // PROD is the cautious default. Set DEV only where the agent cannot reach production.");
  out.push(`  "environment": "${environment}",`);
  if (!selections.length) {
    out.push("  // The scan found no action that any pack covers. Add packs by hand: intentrax policy list.");
    out.push('  "packs": []');
  } else {
    out.push('  "packs": [');
    selections.forEach((sel, i) => {
      const { pack, summary } = sel;
      if (i > 0) out.push("");
      out.push(`    // ${pack.pack_id} ${pack.pack_version}: ${pack.title}.`);
      out.push(...wrap(pack.summary, 96, "    //   "));
      out.push("    //   Selected because the scan found:");
      for (const line of reasonLines(sel)) out.push(`    //   - ${line}`);
      out.push(...wrap(`Decisions: ${decisionLine(pack)}.`, 96, "    //   "));
      const paramNames = Object.keys(pack.params);
      for (const name of paramNames) out.push(...wrap(`param ${name}: ${pack.params[name].description}`, 96, "    //   "));
      const params = paramNames.length ? `{ ${paramNames.map((n) => `${JSON.stringify(n)}: ${JSON.stringify(pack.params[n].default)}`).join(", ")} }` : "{}";
      const comma = i < selections.length - 1 ? "," : "";
      out.push(`    { "pack": ${JSON.stringify(pack.pack_id)}, "pack_hash": "${summary.pack_hash}", "params": ${params} }${comma}`);
    });
    out.push("  ]");
  }
  const chosen = new Set(selections.map((x) => x.pack.pack_id));
  const rest = listPacks().filter((p) => !chosen.has(p.pack_id)).map((p) => p.pack_id);
  if (rest.length) {
    out.push("  // Not selected (nothing in the scan matched them):");
    out.push(...wrap(rest.join(", "), 96, "  //   "));
  }
  out.push("}");
  return out.join("\n") + "\n";
}

export function initFromScan(dir, { environment = "PROD", includeTests = false, maxFiles } = {}) {
  const scan = scanProject(dir, { includeTests, maxFiles });
  const selections = selectPacks(scan);
  return { scan, selections, text: renderPolicyFile(scan, selections, { environment }) };
}
