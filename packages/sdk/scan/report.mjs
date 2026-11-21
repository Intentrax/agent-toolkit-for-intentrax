// Text and JSON rendering for `intentrax scan`. The first line of the text
// report is the catch. Only names, locations and matched verbs are printed:
// never credential values, URLs, descriptions or source snippets.

export const EXIT_CODES = Object.freeze({ NO_FINDINGS: 0, FINDINGS: 20, SCAN_ERROR: 2 });

export function exitCodeFor(result) {
  return result.findings.length ? EXIT_CODES.FINDINGS : EXIT_CODES.NO_FINDINGS;
}

function credLine(c) {
  const parts = [`${c.name}${c.refersTo ? ` (from ${c.refersTo})` : ""} at ${c.location}`];
  if (c.inline) parts.push("value written inline in the file (not shown)");
  if (c.breadth) parts.push(`${c.breadth.label}: ${c.breadth.reason}`);
  return parts.join("; ");
}

export function formatText(result) {
  const out = [];
  if (result.findings.length) {
    for (const f of result.findings) out.push(f.line);
  } else {
    out.push(result.firstLine);
  }
  out.push("");

  if (result.findings.length) {
    out.push("Details (every classification below is heuristic):");
    for (const f of result.findings) {
      out.push("");
      out.push(`[${f.id}] ${f.line}`);
      out.push(`    where: ${f.location}${f.server ? ` (MCP server "${f.server.name}", configured at ${f.server.config})` : ""}`);
      out.push(`    classified (heuristic): ${f.classification.label}. ${f.classification.reasons.join("; ")}`);
      for (const c of f.credentials) out.push(`    credential (heuristic): ${credLine(c)}`);
      out.push(`    gate (heuristic): ${f.gate.gated ? f.gate.reasons.join("; ") : ["none found", ...f.gate.reasons].join("; ")}`);
      if (f.readBack.present !== null) out.push(`    read-back (heuristic): ${f.readBack.present ? f.readBack.reasons.join("; ") : "none found"}`);
      for (const n of f.notes) out.push(`    note: ${n}`);
      f.recommendations.forEach((r, i) => {
        out.push(`    ${i + 1}. ${r.kind === "least-privilege" ? "Least privilege" : "Intentrax"}: ${r.text}`);
      });
    }
    out.push("");
  }

  for (const w of result.warnings) out.push(`warning: ${w}`);
  const s = result.summary;
  out.push(
    `Summary: ${s.filesScanned} file(s) scanned; ${s.actionsFound} agent-reachable action(s), ${s.consequentialActions} consequential, ${s.gatedActions} gated; ` +
      `${s.mcpServers} MCP server(s) configured${s.serversWithUnlistedTools ? `, ${s.serversWithUnlistedTools} with tools not listed statically` : ""}; ` +
      `${s.findings} finding(s) (${s.byType.EXPOSED} EXPOSED, ${s.byType.UNGATED} UNGATED, ${s.byType["SELF-REPORTED"]} SELF-REPORTED).`,
  );
  out.push(result.note);
  return out.join("\n") + "\n";
}

export function formatJson(result) {
  return JSON.stringify(result, null, 2) + "\n";
}
