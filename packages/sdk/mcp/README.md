# `@intentrax/sdk/mcp`: "A tool you approved changed" (R1b)

Pins the tool definitions of a third-party MCP server and catches changes made after you approved them: rug pulls, rewritten descriptions, widened schemas, and annotations flipped to look safer. It also blocks those changes in a proxy.

Everything runs **offline and in private**. It needs no Intentrax account or token. Tool descriptions never leave your machine.

> Covers tool definitions only. It does not show that the server's code or behaviour is unchanged.

**Status:** shipped in `@intentrax/sdk` 1.8.0 as `intentrax mcp pin|check|proxy` and the
`@intentrax/sdk/mcp` subpath export (with types). Run `npx @intentrax/sdk mcp --help`.

## Commands

```
intentrax mcp pin   --server <cmd|url> [--name <name>] [--out .intentrax/mcp-pins.json]
intentrax mcp pin   --name <name> --accept <tool,...>     # re-pin named tools on purpose
intentrax mcp pin   --name <name> --replace                # re-pin everything
intentrax mcp check [--pins .intentrax/mcp-pins.json] [--name <name>] [--json]
intentrax mcp proxy [--pins ...] [--name <name>] [--on-drift block|warn]
```

Server options:
- `--server <cmd|url>` takes a command line or an MCP URL; `-- <command> [args...]` gives a stdio server as argv instead.
- `--header "Name: value"` (HTTP) and `--env KEY=value` (stdio) are repeatable. Put credentials in `${ENV_VAR}` placeholders, for example `--header 'Authorization: Bearer ${GITHUB_TOKEN}'` (single quotes, so a POSIX shell does not expand it; Intentrax expands it when connecting).
- `--registry-name` records the MCP Registry name with the pin; `--timeout-ms` sets the per-request timeout (default 15000).

In a host's MCP config, run the proxy in place of the server:

```json
{ "command": "npx", "args": ["-y", "@intentrax/sdk", "mcp", "proxy", "--name", "github"] }
```

### `check` exit codes

| Exit | Result | Meaning |
| --- | --- | --- |
| 0 | `MATCH` | Every pinned server's tools match its pin. |
| 10 | `CHANGED` | Drift. The first line starts with `CHANGED` and lists, for each tool, the change categories and any annotation weakening (e.g. `readOnlyHint became true`). |
| 2 | `UNCHECKED` | The check failed closed. The tools couldn't be listed (timeout, exit, HTTP error, a failing or looping page), or the pin file is missing, invalid or hand-edited. |
| 1 | `USAGE` | Bad arguments. |

**Several servers:**
- When drift and an unreachable server occur together, the exit code is 10.
- Both cases are non-zero.

**Every report:**
- includes the cloaking note;
- ends with the fixed limitation line.

### `pin`

- **A first pin follows every `nextCursor`.** A partial list is an error and writes nothing.
- **Re-running `pin` on a changed server:**
  - refuses to overwrite and exits 10;
  - `--accept` re-pins only the tools you name: changed, new or removed;
  - every other tool keeps its pinned definition.
- **Credentials are never stored.** Literal values in sensitive headers, env entries, URL query parameters or URL user-info are refused. Use `${ENV_VAR}` placeholders. They are expanded only when connecting and never logged.

### `proxy`

A stdio proxy that sits between the host and the server. The server can be a stdio command or Streamable HTTP. The proxy:

- **Re-checks on connect and on `notifications/tools/list_changed`.** It runs on the host's own session.
- **Compares every `tools/list` response the host receives, tool by tool.** This is what defeats cloaking. `check` cannot do it, because it only sees what its own client is sent.
- **With `--on-drift block` (the default):**
  - changed and new tools are removed from `tools/list`;
  - `tools/call` to them is refused with JSON-RPC error `-32090`, which explains how to re-pin;
  - calls wait while a re-check runs;
  - if the tools cannot be listed, calls are refused.
- **With `--on-drift warn`:** it forwards everything and only logs.
- **Logs go to stderr only.** The protocol stream stays pure JSON-RPC.

## Pin file: `.intentrax/mcp-pins.json` (`intentrax.mcp.pin/0.1`, unsigned)

```json
{
  "schema": "intentrax.mcp.pin/0.1",
  "note": "Unsigned v0.1 pin file: ...",
  "servers": {
    "github": {
      "profile": "intentrax.mcp.tool_manifest/0.1",
      "server": { "registry_name": "com.example/github", "transport": "streamable-http",
                  "url": "https://…", "headers": { "Authorization": "Bearer ${GITHUB_TOKEN}" },
                  "server_info": { "name": "…", "version": "…" } },
      "protocol_version": "2026-07-28",
      "manifest_digest": "sha256:…",
      "tools": [{ "name": "…", "digest": "sha256:…", "definition": { "name": "…", "…": "…" } }],
      "pinned_at": "2026-11-19T12:00:00Z",
      "pinned_by": "local"
    }
  }
}
```

**How it relates to assessment §5.A:**
- The fields are the §5.A fields.
- Each tool also keeps its normalized definition, so `check` can say *which* fields changed.
- On load, every definition is re-hashed. A hand-edited entry is reported as inconsistent (exit 2), never trusted.
- The digests are the prototype's rules, unchanged:
  - `INTENTRAX_MCP_TOOL_DEFINITION_V0_1`;
  - `INTENTRAX_MCP_TOOL_MANIFEST_V0_1`;
  - RFC 8785 canonical JSON;
  - `_meta` is excluded.

## Protocol support

**2026-07-28 (stateless):**
- `server/discover` first, with `_meta` on every request.
- Over HTTP, the `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` headers are set.

**Fallback to legacy `initialize`:** for 2025-11-25, 2025-06-18 and 2025-03-26.
- The fallback is used if discover is refused, times out, or the process dies on it. In that last case, the process is restarted once.
- 2024-11-05 is not accepted (fail closed).

**Streamable HTTP:**
- JSON and SSE responses;
- `Mcp-Session-Id`;
- a GET notification stream (the proxy uses it for `list_changed`).

**Not covered:**
- 2026-07-28 `subscriptions/listen` is forwarded by the proxy but not opened by it.
- Batches are refused by the proxy.

## Modules

| File | Purpose |
| --- | --- |
| `canonical.mjs`, `tool-manifest.mjs`, `receipt-meta.mjs` | Ported from `examples/mcp-trust-receipts/src/`, with the same behaviour and profile strings. |
| `client.mjs` | Minimal MCP client: stdio and Streamable HTTP transports, discover/initialize, `tools/list` pagination, timeouts. |
| `commands.mjs` | `pin`, `check`: pure functions returning `{ exitCode, result, lines, report }`. |
| `proxy.mjs` | `startProxy` / `runProxy`. |
| `index.mjs` | Barrel for the future `@intentrax/sdk/mcp` export. |

## Tests

```bash
cd sdk/typescript/mcp && node --test test/*.test.mjs
```
