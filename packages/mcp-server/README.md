# @intentrax/mcp-server

A read-only [Model Context Protocol](https://modelcontextprotocol.io) server that
lets coding agents (Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Kiro,
Codex, Gemini CLI, Qwen Code, Zed, and any MCP-compatible host) verify Intentrax
proofs. It exposes exactly two tools and **never** executes,
admits, signs, writes, or claims proof authority:

- `intentrax_verify_public_proof` — keyless `GET https://verify.intentrax.com/api/public/verify/proof/{proof_id}`
- `intentrax_read_tenant_proof` — tenant-scoped `GET https://api.intentrax.com/v1/proofs/{proof_id}`

Requires **Node.js 20+**. Ships as a single compiled JavaScript bundle, so
`npx @intentrax/mcp-server` works out of the box (no TypeScript loader needed).

## Use it with a coding agent

The command is the same everywhere — `npx -y @intentrax/mcp-server`. Only the
config file and (for Codex) the format differ. **Never put a key in a committed
config file:** the public verification tool needs no credentials, and the
tenant-scoped tool reads `INTENTRAX_MCP_API_KEY` and `INTENTRAX_MCP_TENANT_ID`
from your host environment (via `${VAR}` references, or Codex's `env_vars`
passthrough). Without them, the tenant tool fails closed and the public tool
still works.

### Hosts that use the standard `mcpServers` JSON

Most hosts take the identical block below — only the file location differs. Add:

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
| Claude Code | project `.mcp.json` (or install the plugin — see below) |
| Claude Desktop | macOS `~/Library/Application Support/Claude/claude_desktop_config.json` · Windows `%APPDATA%\Claude\claude_desktop_config.json` |
| Cursor | `.cursor/mcp.json` or `~/.cursor/mcp.json` |
| Kiro | `.kiro/settings/mcp.json` or `~/.kiro/settings/mcp.json` (add `"disabled": false`) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Gemini CLI | `~/.gemini/settings.json` or project `.gemini/settings.json` |
| Qwen Code | `~/.qwen/settings.json` or project `.qwen/settings.json` |

Claude Code users can instead install the plugins: `intentrax-mcp` bundles this
server, and `intentrax-execution-assurance` adds the skills.

```
/plugin marketplace add Intentrax/intentrax-skills
/plugin install intentrax-mcp@intentrax
/plugin install intentrax-execution-assurance@intentrax
```

### VS Code (GitHub Copilot)

`.vscode/mcp.json` (workspace) or user settings. VS Code uses the root key
`servers` (not `mcpServers`) and an `inputs` array so the key is prompted, never
committed:

```json
{
  "inputs": [
    { "id": "intentrax-api-key", "type": "promptString", "description": "Intentrax MCP API key", "password": true },
    { "id": "intentrax-tenant-id", "type": "promptString", "description": "Intentrax tenant ID" }
  ],
  "servers": {
    "intentrax-readonly": {
      "command": "npx",
      "args": ["-y", "@intentrax/mcp-server"],
      "env": {
        "INTENTRAX_MCP_API_KEY": "${input:intentrax-api-key}",
        "INTENTRAX_MCP_TENANT_ID": "${input:intentrax-tenant-id}"
      }
    }
  }
}
```

### Zed

`~/.config/zed/settings.json`. Zed uses the key `context_servers`:

```json
{
  "context_servers": {
    "intentrax-readonly": {
      "source": "custom",
      "command": "npx",
      "args": ["-y", "@intentrax/mcp-server"],
      "env": {
        "INTENTRAX_MCP_API_KEY": "your-key",
        "INTENTRAX_MCP_TENANT_ID": "your-tenant"
      }
    }
  }
}
```

### Codex

`~/.codex/config.toml` (or a trusted project `.codex/config.toml`). TOML format;
`env_vars` passes the key/tenant through from your environment without
hardcoding them:

```toml
[mcp_servers.intentrax-readonly]
command = "npx"
args = ["-y", "@intentrax/mcp-server"]
env_vars = ["INTENTRAX_MCP_API_KEY", "INTENTRAX_MCP_TENANT_ID"]
```

### AgentScope (Python framework)

AgentScope isn't a config-file host — you register the server in code. Set the
env vars in the process environment, then:

```python
from agentscope.service import ServiceToolkit

toolkit = ServiceToolkit()
toolkit.add_mcp_servers({
    "mcpServers": {
        "intentrax-readonly": {
            "command": "npx",
            "args": ["-y", "@intentrax/mcp-server"],
        }
    }
})
```

See the [AgentScope MCP docs](https://doc.agentscope.io) if the API differs in
your version.

### Any other MCP-compatible host

Hosts not listed accept either the standard `mcpServers` JSON above or a direct
stdio spawn:

```bash
npx -y @intentrax/mcp-server
```

Optional for all: `INTENTRAX_MCP_TIMEOUT_MS` (1000–15000, default 10000). Only the
exact production origins `https://verify.intentrax.com` and
`https://api.intentrax.com` are accepted; other origins fail closed.

## Run it directly

```bash
npx -y @intentrax/mcp-server
```

The transport is JSON-RPC over stdin/stdout, one message per line. Keep stdout
exclusively for MCP protocol messages.

## What this is for

Intentrax produces third-party-verifiable proofs of what an autonomous agent
did. This server is the read/verify side of that: while you build an
Intentrax-instrumented app, your agent can confirm a proof is genuine without
writing any HTTP. For *when and how* to instrument admission → execution →
verification, see the [execution-assurance skill](https://github.com/Intentrax/intentrax-skills).

## License

Apache-2.0. The canonical server implementation lives in the Intentrax platform;
this package is the standalone, publishable distribution of it.
