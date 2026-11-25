# `intentrax guard`: a local gate for Claude Code (preview)

> **Local and not trust-bearing.** The guard's records are signed with a key
> generated on your machine. Anyone who can write the project directory can
> rewrite and re-sign them. They show what the guard decided on this machine.
> They are not proof to anyone else.

One command installs a Claude Code `PreToolUse` hook. The hook sorts every tool
call into one of three verdicts:

| Verdict | What Claude Code does | Examples (built-in rules) |
| --- | --- | --- |
| **block** | denies the call; Claude sees the reason | `git push --force`, `rm -rf /` or `~` or `.`, `DROP TABLE`, `TRUNCATE`, `DELETE` without `WHERE`, SQL writes to a database that looks like production, `terraform destroy`, `kubectl delete ns`, `mkfs`, `dd of=/dev/…`, fork bombs, changes to the guard's own files (`.intentrax/guard/`: runtime, record, keys, guard rules), the pack policy (`.intentrax/policy.jsonc`) or the MCP pins (`.intentrax/mcp-pins.json`) |
| **ask** | asks you first | `git push`, `git reset --hard`, recursive deletes, deploys and publishes (`npm publish`, `vercel --prod`, `kubectl apply`, `gh pr merge`), SQL writes, `curl … \| sh`, payment and messaging API calls, reading or writing `.env` and key files, changes to `.claude/settings*.json` or `.mcp.json` (you see the diff), writes outside the project, MCP tools that delete, move money, run shell or SQL, deploy, send messages or change access |
| **allow** | nothing extra: Claude Code's own permission rules and modes still apply | everything else |

The guard never auto-approves. "allow" means the hook emits no decision, so
your existing allow and deny rules, and your permission mode, behave as before.

It needs no account and makes no network call. Every decision, including
allows, is appended to a local hash-chained record that `guard verify`
re-checks offline.

## Run it

```bash
npx @intentrax/sdk guard claude-code        # install in the current project
npx @intentrax/sdk guard status             # hook, policy, counts, chain
npx @intentrax/sdk guard verify             # re-check the record chain offline
npx @intentrax/sdk guard explain --command 'git push -f'   # classify without running or recording
npx @intentrax/sdk guard uninstall          # remove the hook (records kept unless --purge)
```

`npx @intentrax/sdk guard` ships in `@intentrax/sdk` 1.11.0. From a checkout
of this repository, `node sdk/typescript/guard/cli.mjs` takes the same
arguments.

`guard claude-code` options:

| Option | Effect |
| --- | --- |
| `--dry-run` | print what would change, including the merged settings file; write nothing |
| `--local` | use `.claude/settings.local.json` (just you) instead of `.claude/settings.json` (shared with the repo) |
| `--mcp` | also pin each stdio MCP server in `.mcp.json` and route it through `intentrax mcp proxy --on-drift block` (see below) |
| `--dir <dir>` | the project directory (default: the current directory) |
| `--json` | machine-readable report |

The install ends with a self-test. It sends the hook a `git push --force`
call, which is never run, and expects `deny`. That writes the first local
record, and the install then verifies the chain. Restart Claude Code (or open
`/hooks`) to load the hook.

## What it changes

- `.claude/settings.json` gets one entry under `hooks.PreToolUse` (matcher
  `"*"`). Every other setting and hook stays as it was. Running the install
  again changes nothing. A settings file that is not valid JSON is refused, not
  rewritten.
- `.intentrax/guard/runtime/` holds a copy of the hook and the modules it
  imports (classification is shared with `intentrax scan`). `MANIFEST.json`
  lists each file's SHA-256. The hook runs as
  `node "$CLAUDE_PROJECT_DIR/.intentrax/guard/runtime/guard/hook.mjs"`: no
  npx and no network on each tool call. Commit the runtime with the settings
  file so the hook works for everyone who clones the repository.
- `.intentrax/guard/.gitignore` keeps the records and keys out of git.

## Failing closed

- If the hook cannot read its input or classify a call, it exits 2. Claude
  Code treats exit 2 as a block.
- Modules load inside a `try`, so a missing or edited runtime file also exits
  2. Any other crash would let the call through, so the hook avoids one.
- If the record cannot be written, a block or ask still applies. An allow goes
  through with a warning on stderr.
- The guard blocks the agent from changing its own files (runtime, record,
  keys, guard rules), the pack policy and the MCP pins, and from running
  `guard uninstall`; run those yourself. A change to `.claude/settings*.json`,
  which loads the hook, or to `.mcp.json`, which routes servers through the
  proxy, asks you first. Paths are compared after `.` and `..` are resolved
  and symlinks are followed.

Limits: the hook needs `node` on the `PATH` Claude Code uses. On Windows,
Claude Code runs hooks through Git Bash. Classification reads command text.
A command built at run time (base64, variables, a script file) can get past it.
Treat it as a floor against accidents, not a sandbox against a determined
adversary.

## The local record

`.intentrax/guard/records.jsonl` holds one record per decision:

```json
{"schema":"intentrax.guard.local_record/v0.1","seq":2,"prev_hash":"…","recorded_at":"…",
 "environment":"local","trust_bearing":false,"key_id":"local-guard-…",
 "source":"claude-code.PreToolUse","session_id":"…","tool_use_id":"…","tool_name":"Bash",
 "arguments_hash":"…","arguments_hash_rule":"spec-01-4:INTENTRAX_MCP_TOOL_ARGUMENTS_V0_1",
 "summary":"git push --force origin main",
 "decision":{"verdict":"block","category":"deploy","rule":"git-force-push","reason":"…",
             "builtin_verdict":"block","policy_name":"…","policy_source":"built-in","policy_hash":"…"},
 "hook_output":"deny","record_hash":"…","signature":"…"}
```

- `record_hash` = SHA-256 over `INTENTRAX_GUARD_LOCAL_RECORD_V0_1` followed by
  the canonical JSON (RFC 8785) of every other field. `prev_hash` chains each
  record to the one before it.
- `signature` is Ed25519 over `intentrax.guard.local_record.sig.v0.1\n` + `record_hash`.
  The key comes from `local-key-set.json` (the sandbox's local key-set format:
  `environment: "local"`, `trust_bearing: false`). It rotates every 24 hours.
- `head.json` holds the last `seq` and `record_hash`, signed. It catches
  records removed from the end.
- `arguments_hash` follows the published rule in
  `docs/architecture/specs/01-admission-request-v1.1.md` §4. It is computed over
  the tool's input, so for an MCP tool it equals the `mcp` module's
  `arguments_digest`.
- `summary` is at most 160 characters, with likely credentials replaced by
  `[redacted]`. File tools keep only the path, MCP tools only the tool name. The
  full input is never stored.

`guard verify` exits 0 for `LOCAL_CHAIN_VALID` (or `LOCAL_CHAIN_EMPTY`). It
exits 2 for `LOCAL_CHAIN_BROKEN` and names the first bad line. It catches an
edited, inserted, deleted or reordered record, a removed tail, a bad signature
and a key set relabelled as trust-bearing. It cannot catch someone on this
machine who rewrites the whole chain with the local key. That is what "not
trust-bearing" means.

If the end of the file no longer matches `head.json`, for example after
records were removed, the hook stops appending. Appending would overwrite
`head.json` and hide the gap. The block or ask decision still applies, and
stderr and `guard status` say why. To start a new chain, move
`records.jsonl` and `head.json` aside and keep them as evidence.

## Policy

The built-in rules always apply. Two optional project sources are applied on
top of them:

1. **Policy packs**: `.intentrax/policy.jsonc`. `intentrax policy init
   --from-scan` writes it, and it pins each pack by `pack_hash`. The hook
   evaluates it with the SDK's policy-packs module, which is copied into the
   hook runtime. Each pack decision comes from a C2 policy. The record keeps
   `pack_id`, `pack_hash`, `source_policy_hash`, `compiled_policy_hash`,
   `execution_event_hash` and `evaluation_hash`. The decision can then be
   re-checked from the event and the policy hash. The facts are derived
   locally from the agent's input (`facts_source: LOCAL_GUARD_DERIVED`), so
   that derivation is self-reported. A pack that decides `none` has no
   opinion. Custom pack files the policy references (`packs[].path`) are
   protected like the policy itself. Sometimes the file cannot be loaded, for
   example after a `pack_hash` mismatch from an edited pack, or because this
   runtime has no pack module. The guard does not then fall back quietly to
   its built-in rules. Built-in blocks stay, every other shell, write and MCP
   call asks (rule `pack-policy-unavailable`), and `guard status` shows why.
   Reads are unaffected. See the policy-packs README for the format.
2. **Guard rules**: `.intentrax/guard/policy.json`, hand-written rules in the
   schema below.

```json
{
  "schema": "intentrax.guard.policy/v1",
  "name": "team",
  "categories": { "deploy": "allow", "communication": "block" },
  "rules": [
    { "id": "pushes-ok", "verdict": "allow", "tools": ["Bash"], "command_regex": "^git push origin feature/" },
    { "id": "no-prod-psql", "verdict": "block", "tools": ["Bash"], "command_regex": "psql .*prod", "reason": "use the migration pipeline" },
    { "id": "configs", "verdict": "ask", "tools": ["Edit", "Write"], "path_glob": ["config/**"] },
    { "id": "big-refunds", "verdict": "block", "tools": ["mcp__stripe__*"], "input_regex": { "amount": "^[0-9]{5,}$" } }
  ]
}
```

- `categories` sets the verdict for MCP tools by scan category (`destructive`,
  `financial`, `shell`, `database`, `infrastructure`, `deploy`,
  `communication`, `access`, `browser`, `write`, `unknown`, `read`,
  `unclassified`).
- A rule matches when every matcher it has matches:
  - `tools` takes exact names or `*` globs;
  - `command_regex` is tested against the command line and each simple command
    in it;
  - `path_glob` takes project-relative globs;
  - `input_regex` maps top-level input fields to regexes.
- Across the built-in rules, packs and guard rules, the strictest verdict
  wins. An `allow` from a rule or a pack may lower a built-in **ask**.
  Nothing lowers a built-in **block**.
- An allow covers only what it matches. On a shell line with several commands,
  every command that asks needs its own allow rule: `git push origin
  feature/x && rm -rf data` still asks. A pack judges the whole call, so its
  allow counts only for a single command. Lines with `$(…)`, backticks or a
  shell body (`bash -c`, `eval`, `xargs`) are never relaxed. A pack `allow` means no objection: like
  every allow, it emits no decision, so Claude Code's own rules still apply.
- A policy file is data only, never code. A malformed file is ignored. The
  built-in policy then applies, and `guard status` shows the warning.

## MCP servers (`--mcp`)

The hook already classifies MCP tool calls by name. `--mcp` adds tool pinning
for each stdio server in `.mcp.json`:

1. It starts the server once to list its tools.
2. It pins them in `.intentrax/mcp-pins.json` (`intentrax mcp pin`).
3. It replaces the server entry with
   `npx -y @intentrax/sdk@<version> mcp proxy --name <name> --on-drift block`.
   The server's `env` stays as it was.

The proxy hides changed and new tools and refuses calls to them. The original
entries are saved in `.intentrax/guard/mcp-originals.json`, and `guard
uninstall` restores them. That file can hold credentials copied from
`.mcp.json`, so it is written owner-only and gitignored. It stays on the
machine that ran the install, and on another machine you restore those entries
by hand. Each server is started from the project directory to list its tools;
the pin file stores no absolute path. If a server name is already pinned with a
different command, `--mcp` leaves that server alone and says how to re-pin
it on purpose (`intentrax mcp pin --name <name> --replace -- <command>`).
Otherwise the proxy would start the old command. Remote (HTTP) servers are skipped; pin those with
`intentrax mcp pin --server <url>`. Pinning covers tool definitions only. It
does not show that a server's code or behaviour is unchanged.

## Status and the next step

`guard status` shows whether the hook is installed, whether the runtime is
intact, which policy applies, counts by verdict and rule, and the chain status.
It ends with this line:

> These records are local and not trust-bearing: anyone with access to this
> machine can rewrite them. To have gated calls admitted and recorded by the
> hosted Intentrax engine instead, request a key:
> https://www.intentrax.com/request-architectural-review

## Exit codes

| Exit | Meaning |
| --- | --- |
| 0 | ok (install and self-test passed; chain valid or empty) |
| 2 | chain broken, install refused, or self-test failed |
| 1 | usage |

The hook itself exits 0 (with or without a decision on stdout) or 2 (failed
closed).
