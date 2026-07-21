# Agent Toolkit for Intentrax

**Execution assurance for AI coding agents.** When an autonomous agent takes a
consequential action — a payment, a production change, a clinical or regulated
step — [Intentrax](https://www.intentrax.com) produces a cryptographic,
third-party-verifiable proof of *what the agent intended, what was decided, and
that the execution matched*. Portable across trust boundaries; not an in-cloud
attribution flag, not a log line the operator could have written after the fact.

This toolkit gives coding agents (Claude Code, Cursor, VS Code, Windsurf, Kiro,
Codex, Gemini CLI, Qwen Code, Zed, and any MCP-compatible host) the tools and
knowledge to build and verify Intentrax-instrumented applications.

## What's in the toolkit

| Piece | Package / repo | What it does |
| --- | --- | --- |
| **MCP server** | [`@intentrax/mcp-server`](https://www.npmjs.com/package/@intentrax/mcp-server) | Two read-only tools your agent can call: verify a public proof, read a tenant-scoped proof. Never executes, admits, signs, or writes. |
| **SDK** | [`@intentrax/sdk`](https://www.npmjs.com/package/@intentrax/sdk) | Instrument admission → execution → verification in your app, with the idempotency linkage handled for you. |
| **Skill & plugin** | [`Intentrax/intentrax-skills`](https://github.com/Intentrax/intentrax-skills) | Teaches an agent *when* execution assurance is worth adding and *how* to wire it. Doubles as a Claude Code plugin marketplace. |

## Quickstart

### Claude Code (one command)

```
/plugin marketplace add Intentrax/intentrax-skills
/plugin install intentrax-execution-assurance@intentrax
```

This installs the skill **and** the read-only MCP server together.

### Any other host

Add the read-only MCP server. The command is `npx -y @intentrax/mcp-server`
everywhere — only the config file differs. Most hosts take this block:

```json
{
  "mcpServers": {
    "intentrax-readonly": {
      "command": "npx",
      "args": ["-y", "@intentrax/mcp-server"],
      "env": {
        "INTENTRAX_MCP_API_KEY": "${INTENTRAX_MCP_API_KEY}",
        "INTENTRAX_MCP_TENANT_ID": "${INTENTRAX_MCP_TENANT_ID}"
      }
    }
  }
}
```

| Host | Config file |
| --- | --- |
| Claude Desktop | mac `~/Library/Application Support/Claude/claude_desktop_config.json` · Win `%APPDATA%\Claude\claude_desktop_config.json` |
| Cursor | `.cursor/mcp.json` |
| Kiro | `.kiro/settings/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Gemini CLI | `~/.gemini/settings.json` |
| Qwen Code | `~/.qwen/settings.json` |

**VS Code** (`servers`+`inputs`), **Zed** (`context_servers`), **Codex** (TOML),
and **AgentScope** (Python) use their own format — full per-host blocks are in the
[`@intentrax/mcp-server` README](https://www.npmjs.com/package/@intentrax/mcp-server).

The public verification tool needs no credentials. For the tenant-scoped tool,
set `INTENTRAX_MCP_API_KEY` and `INTENTRAX_MCP_TENANT_ID` in your environment —
**never commit a key.**

## When execution assurance is worth adding

Add it when **two or more** hold:

- The action moves money, changes a medical/clinical record, alters production
  infrastructure, or makes a regulated decision.
- An autonomous agent or LLM — not a human clicking a button — initiates it.
- Someone who does **not** trust your logs (an auditor, regulator, insurer,
  counterparty, or the affected user) may later need to verify what happened.
- The action is hard to reverse, or a dispute about "did the agent do X" is
  plausible.

Skip it for reads, search, drafting, UI state, or trivially reversible actions.
The full decision guide and instrumentation recipe is in the
[execution-assurance skill](https://github.com/Intentrax/intentrax-skills).

## Honesty boundary

The engine is the sole producer of proofs, signatures, and receipts. These tools
submit and verify — they never re-derive or sign proof material. Only a backend
`VALID` verdict is a pass; never present an unverified action as verified.

## Links

- SDK — https://www.npmjs.com/package/@intentrax/sdk
- MCP server — https://www.npmjs.com/package/@intentrax/mcp-server
- Skill & plugin — https://github.com/Intentrax/intentrax-skills
- Public verifier — https://verify.intentrax.com
- Developer docs — https://www.intentrax.com/developers

## License

Apache-2.0.
