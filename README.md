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

The command is the same everywhere — `npx -y @intentrax/mcp-server`. Only the
config file and its format differ per host. Pick your host below.

**Credentials, honestly:** the **public verify tool is keyless** — it works with
no environment variables at all. `INTENTRAX_MCP_API_KEY` and
`INTENTRAX_MCP_TENANT_ID` are needed **only** for the tenant proof-read tool,
which additionally requires an issued tenant and an enabled production API
runtime. If you only need public verification, omit the `env` block entirely.
**Never commit a key** — reference it from your environment, as shown below.

Most hosts use this **standard MCP block** (referenced as "the standard block"
in the per-host sections that follow):

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

### Claude Code (one command)

```
/plugin marketplace add Intentrax/intentrax-skills
/plugin install intentrax-execution-assurance@intentrax
```

This installs the skill **and** the read-only MCP server together. Prefer a
project-scoped config instead? Drop the standard block into `.mcp.json` at your
repo root.

### Claude Desktop

Add the standard block to your `claude_desktop_config.json`:

- macOS — `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows — `%APPDATA%\Claude\claude_desktop_config.json`

### Cursor

Add the standard block to `.cursor/mcp.json`.

### Kiro

Add the standard block to `.kiro/settings/mcp.json`.

### Windsurf

Add the standard block to `~/.codeium/windsurf/mcp_config.json`.

### Gemini CLI

Add the standard block to `~/.gemini/settings.json`.

### Qwen Code

Add the standard block to `~/.qwen/settings.json`.

### Codex

`~/.codex/config.toml` uses TOML, and lists env variable **names** under
`env_vars` (it forwards them from your environment):

```toml
[mcp_servers.intentrax-readonly]
command = "npx"
args = ["-y", "@intentrax/mcp-server"]
env_vars = ["INTENTRAX_MCP_API_KEY", "INTENTRAX_MCP_TENANT_ID"]
```

### VS Code (Copilot)

`.vscode/mcp.json` uses a `servers` key and an `inputs` array that prompts you
for the values (so no secret is written to disk):

```json
{
  "inputs": [
    {
      "id": "intentrax-mcp-key",
      "type": "promptString",
      "description": "Intentrax MCP API key",
      "password": true
    },
    {
      "id": "intentrax-mcp-tenant",
      "type": "promptString",
      "description": "Intentrax MCP tenant ID"
    }
  ],
  "servers": {
    "intentrax-readonly": {
      "command": "npx",
      "args": ["-y", "@intentrax/mcp-server"],
      "env": {
        "INTENTRAX_MCP_API_KEY": "${input:intentrax-mcp-key}",
        "INTENTRAX_MCP_TENANT_ID": "${input:intentrax-mcp-tenant}"
      }
    }
  }
}
```

### Zed

`settings.json` uses a `context_servers` top-level key; the command and args are
the same:

```json
{
  "context_servers": {
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

### AgentScope

AgentScope is a Python framework; it's supported via the same
[`@intentrax/mcp-server`](https://www.npmjs.com/package/@intentrax/mcp-server)
package — register it as an MCP server through AgentScope's toolkit. No JSON
config file of its own.

### Any other MCP host

Use the standard block in whatever config file your host reads. If your host
isn't listed here, the
[`@intentrax/mcp-server` README](https://www.npmjs.com/package/@intentrax/mcp-server)
has the current per-host details.

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
