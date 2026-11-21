# `intentrax scan`: what could your agent break? (preview, R1c)

> **Heuristic, static scan. It can miss actions and misclassify names.**

`intentrax scan` lists the destructive or consequential actions an AI agent can
reach in a project. It flags three things:

- broad credentials behind those actions;
- actions with no gate in front of them;
- actions whose success is self-reported, with no read-back.

It is local, static and needs no account:

- it reads files only: it never imports or runs the project's code;
- it makes no network call;
- it never prints a credential value. A credential is reported by its variable
  or config name and its file location only. Literal values in config files are
  noted as "written inline (not shown)".

The first line of the output is the catch:

```text
EXPOSED delete_volume reachable with an account-wide token (RAILWAY_ACCOUNT_TOKEN), no gate
UNGATED MCP server "billing-remote" (moves money) runs with no gate or approval step
SELF-REPORTED delete_volume reports success without reading the result back
```

Plan: `docs/architecture/INTENTRAX_INCIDENT_LED_MILESTONES.md` (R1c). Why
prevention comes first: `docs/gtm/pain-point-research-2026-11.md`. In the
incident behind R1c, an agent deleted a production volume and its backups with
an account-wide token. Commenters' first fix was least privilege, so every
finding recommends narrowing the credential **before** any Intentrax step.

## Run it

With `@intentrax/sdk` 1.8.0 or later:

```bash
npx @intentrax/sdk scan [dir] [--json] [--include-tests] [--max-files N]
```

From a checkout of this repository, `node sdk/typescript/scan/cli.mjs` takes the
same arguments.

| Exit | Meaning |
| --- | --- |
| 0 | no findings |
| 20 | findings |
| 2 | scan error: the directory is missing or unreadable, or the usage is bad |

`--json` prints `{ schema: "intentrax.scan.v1", firstLine, findings, actions, summary, warnings, note }`.

From code:

```js
import { scanProject } from "./scan/scan.mjs";
const { findings, summary, firstLine } = scanProject("path/to/project");
```

## Finding types

Each finding is one line. Its details carry the classification and its reasons,
the credentials (names and locations), the gate and read-back evidence, and
two ordered recommendations: least privilege first, then Intentrax.

| Line | When | Recommendations |
| --- | --- | --- |
| `EXPOSED` | A consequential action is reachable with a credential whose name suggests broad reach: account-wide, organization-wide, admin, root, owner, master, service-role, full-access, a global API key, a personal access token, a standard Stripe secret key, long-lived cloud keys, kubeconfig. Also flagged: the **same** credential reaching both read-only tools and a severe tool (destructive, money, shell, SQL, infrastructure). | 1. Replace the credential with the platform's scoped mechanism: "a token limited to …", a fine-grained PAT, a Stripe restricted key, a narrow IAM role. Or split it into a read-only credential and a narrow one for the severe tool. 2. If no gate is present, add an Intentrax gate. |
| `UNGATED` | A consequential action with no gate or approval step in front of it, and no broad credential. (EXPOSED already says "no gate".) | 1. Give the tool a credential limited to what it does, or remove the tool. For a shell: no production credentials in its environment, and an allowlist instead of auto-approve. 2. `npx @intentrax/sdk init <adapter>`, then call the hook before the tool runs (fail closed). |
| `SELF-REPORTED` | A consequential action whose handler is in the repository, with no read of the affected state after it. Flagged when the action has severity ≥ 2 (deploys, messages, access changes and the severe kinds), or when it returns a success message. | 1. Read back with a separate read-only credential. 2. Try `npx @intentrax/sdk sandbox --check` (a local, non-trust-bearing trial, not evidence). |

Findings are ordered by severity, then type. Severity 3 covers destructive
actions, money movement, shell, arbitrary SQL and infrastructure.

## What it discovers

The discovery anchors come from
`skills/intentrax-integrate-agent-actions/references/discovery-patterns.md`.
The adapter names come from `npx @intentrax/sdk init`.

- **MCP server configs.** It reads these files:
  - `.mcp.json`;
  - `.claude/settings.json` and `.claude/settings.local.json`;
  - `.cursor/mcp.json`;
  - `.vscode/mcp.json` and `.vscode/settings.json`;
  - `.gemini/settings.json`;
  - `claude_desktop_config.json`;
  - `mcp.json`.

  JSON with comments is accepted. Credentials come from:
  - `env` entries;
  - auth headers;
  - URL query parameters;
  - secret-looking CLI flags;
  - docker `-e NAME`.

  An stdio server whose entry file is in the repository is linked to its
  source. The scan follows `node path`, `tsx path`, `python -m pkg.mod` and
  `uv --directory d run file.py`, maps `dist/` to `src/`, and follows relative
  imports 3 levels deep. That server's tools then carry its config's
  credentials.

  A server whose code is not in the repository (an npm package, a docker image,
  or a remote URL) becomes a single action. It is classified by the words in
  its name and launch command (postgres, stripe, github, aws, shell, …).
- **Tool definitions in source:**
  - MCP TypeScript `server.tool()` and `registerTool()`;
  - low-level `ListTools` arrays with `case "name":` handlers;
  - Python FastMCP `@mcp.tool()`, `Tool(...)` and `if name == "x":` dispatchers;
  - Anthropic `input_schema` and OpenAI `parameters` tool definitions, both chat
    and Responses shapes;
  - OpenAI Agents SDK `@function_tool`;
  - LangChain and LangGraph: `tool()`, `DynamicStructuredTool`, `StructuredTool`
    and `BaseTool` subclasses, `@tool`;
  - Vercel AI SDK `tool({ ... })`;
  - Mastra `createTool`;
  - `*tool*.json` and `*function*.json` definition files.
- **Shell tools:**
  - tools named for shells or commands;
  - handlers that spawn processes;
  - Claude Code's built-in `Bash` when the project auto-approves it
    (`permissions.allow: ["Bash(*)"]` or `defaultMode: "bypassPermissions"`).

## Classification (heuristic)

Every classification has `heuristic: true` and the reasons behind it.

- **Name verbs.** For example `delete_volume`, `volumeDelete`, `issue_refund`,
  `run_sql` and `execute_command`.
  - A read verb in the name (`get_refund`, `list_transfers`,
    `list_deleted_items`) keeps the tool read-only, unless the name also has a
    plain destructive verb.
  - Words that are nouns in one name and verbs in another (`blog_post` vs
    `post_tweet`) count only as the first word of the name.
- **Descriptions** are used when the name has no verb. Negated verbs ("does not
  delete") are skipped.
- **Handler side effects** can raise a classification but never lower it. They
  include SQL `DELETE`/`DROP`, HTTP `DELETE`, payment API calls, process
  execution, message sending and file deletion. A generic `.delete(` (often a
  `Map` or a cache) does not overrule a read name.
- **MCP annotations are untrusted.** `destructiveHint: true` raises concern.
  `destructiveHint: false` and `readOnlyHint: true` never lower it, and the
  reasons say they were ignored.

## Gate and read-back (heuristic)

A tool counts as gated when one of these sits in front of it:

- an Intentrax admission or execute call in its handler, or in the same file
  (assumed to be a shared dispatcher). This means `admitAgentGatewayHttp`,
  `executeIntentHttp` or a generated hook entrypoint such as
  `beforeMCPToolCall` or `withIntentraxLangChainCallback`. A call placed
  **after** the side effect does not count;
- an approval step: `needsApproval`, LangGraph `interrupt`/`interrupt_before`,
  LangChain human-approval handlers, MCP elicitation, or OpenAI Agents
  `needs_approval`;
- a Claude Code `PreToolUse` hook whose matcher covers the tool and whose
  command runs Intentrax or an approval step;
- a Claude Code `permissions.ask` rule;
- a Cursor `beforeMCPExecution` or `beforeShellExecution` hook.

A tool matched by `permissions.deny` is listed but not reported.

A read-back is a read of the affected state after the side effect, or a call
to a confirmation step (`confirmThenReport`, `readBack`, AWS waiters,
`verifyDeleted…`).

## Known limits

- **Names are not behaviour.** A tool named `sync` may delete. A tool named
  `delete_draft` may be harmless.
- **Credential breadth is inferred from names only.** The scan cannot see a
  token's real scopes.
- **What it cannot see:** a server whose code is outside the repository, tools
  registered dynamically, and dispatchers in another file.
- **No cross-file guarantee.** A gate in a different file from the tool is not
  linked, so the tool may be reported as UNGATED.
- **Config the scan never reads:**
  - client settings outside the project, such as user-level Claude or Cursor
    config;
  - `--dangerously-skip-permissions`;
  - `.env` files.
- **Skipped by default:** test and fixture directories, generated code
  (`dist`, `build`) and vendored code. Use `--include-tests` to scan test and
  fixture directories.

## Tests

```bash
node --test sdk/typescript/scan/test/*.test.mjs
```

The fixture projects live in `test/fixtures/`:

| Fixture | Shows |
| --- | --- |
| `exposed-mcp` | An MCP config with a destructive tool and an account-wide token, inline fake secrets, and a remote server. |
| `gated` | An Intentrax dispatcher gate and a Claude Code PreToolUse hook. |
| `readback` | A Vercel AI SDK tool and a LangChain Python tool, each with a read-back. |
| `clean` | Read-only tools. |
| `shared-credential` | One token serving read and destructive tools. |
| `shell` | An auto-approved Bash tool and a denied server. |

The tests also check that no fixture secret value or server URL ever appears
in text or JSON output.

## Status

Shipped in `@intentrax/sdk` 1.8.0: `cli/intentrax.mjs` dispatches `scan` to
`scanMain`, and `package.json` `files` packs `scan/*.mjs` and
`scan/README.md` (never `scan/test`). Exit codes stay 0, 20 and 2.
