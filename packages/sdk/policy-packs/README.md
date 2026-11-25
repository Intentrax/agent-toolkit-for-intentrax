# Open policy packs: scan → pack → guard (preview)

> **Pattern matching on what the agent asks to do, decided by a policy you can
> re-check.** A pack can miss a dangerous call that is phrased in a way it does
> not recognise, and it can ask about a harmless one.

A policy pack turns one kind of risky agent action into a decision: **allow**
(no objection), **ask** (a person approves first) or **block** (refused).
`intentrax guard` (a later SDK release) never auto-approves. A pack's allow means only that the pack
has no objection, and the agent's own permission rules (for example Claude
Code's) still decide.
Each pack maps to one `intentrax scan` category, so the path is:

1. `intentrax scan` lists what your agent can reach.
2. `intentrax policy init --from-scan` writes a draft policy file that selects
   the matching packs, with a comment on every choice.
3. `intentrax guard` (a local Claude Code hook; not in this SDK release yet, it
   ships in a later one) loads that file
   and applies the decision before each tool call.

Everything here is local and static. Nothing is run or sent, and no account is
needed. Zero runtime dependencies.

## The packs

| Pack | Scan category | Decisions |
| --- | --- | --- |
| `intentrax.shell-destructive` | shell | block `rm -rf /`, `~`, drive roots, `mkfs`, `dd of=/dev/…`; ask any other recursive delete (`rm -r`, `find -delete`, `git clean -f`) |
| `intentrax.secrets-exfiltration` | shell (and `EXPOSED` findings) | block secret files (`.env`, SSH keys, cloud credentials) or an environment dump sent over the network; ask before reading a secret file or sending a `$…TOKEN` variable |
| `intentrax.git-force-push` | deploy | block force push to, or deletion of, `main`, `master`, `trunk`, `production` or `release`; ask any other force push or remote branch deletion |
| `intentrax.release-publish` | deploy | ask before `npm publish`, `docker push`, `gh pr merge`, `vercel --prod`, pushing tags, and merge/deploy/publish/release tools |
| `intentrax.infrastructure-changes` | infrastructure | teardown (`terraform destroy`, `kubectl delete`, `aws … delete-*`, volume delete tools): block, or ask in DEV; changes (`terraform apply`, `kubectl apply`, `helm upgrade`): ask, or allow in DEV |
| `intentrax.database-writes` | database | destructive SQL (`DROP`, `TRUNCATE`, `DELETE` without `WHERE`, resets): block, or allow in DEV; other writes: ask, or allow in DEV and STAGING. Reads are not matched |
| `intentrax.refunds-threshold` | financial | refunds: allow up to `approval_above_minor` (default 5000), ask above it, block above `deny_above_minor` (default 50000); ask when the amount is not in the call |
| `intentrax.payment-transfers` | financial | ask before every payment, transfer, payout, charge or wire; block above `deny_above_minor` (default 100000) |
| `intentrax.email-outside-domain` | communication | allow email where every recipient is at `internal_domain`; ask otherwise |
| `intentrax.chat-messages` | communication | ask before posting to Slack, Discord, Teams, Telegram, WhatsApp or SMS, or calling a chat webhook |
| `intentrax.mcp-tool-drift` | unknown (MCP servers) | block an MCP tool whose definition changed since `intentrax mcp pin`, or that appeared after pinning |
| `intentrax.access-changes` | access | block admin or owner grants and making things public; ask any other access change (invites, roles, sharing, IAM, `chmod 777`) |
| `intentrax.phi-tools` | write (by tool name) | ask before every call to a tool whose name suggests patient health data. Not a compliance control; it makes no regulatory claim |
| `intentrax.browser-actions` | browser | ask before clicks, typing, form fills, uploads or page code in a browser tool; navigation and screenshots are not matched |
| `intentrax.destructive-tools` | destructive | tools that delete volumes, backups, databases, projects, accounts, buckets or clusters: block, or ask in DEV; ask any other delete tool |

`intentrax policy show <pack>` prints each pack's actions, params, approval
constraint and **limits**. Read the limits before you rely on a pack.

## Commands

Shipped in `@intentrax/sdk` 1.10.0 as `intentrax policy` (`npx @intentrax/sdk
policy …`). From a checkout of this repository, `node
sdk/typescript/policy-packs/cli.mjs` takes the same arguments.

```bash
intentrax policy list [--json]
intentrax policy show <pack> [--json]
intentrax policy hash <pack | pack.json> [--json]
intentrax policy validate [policy.jsonc | pack.json] [--json]
intentrax policy init --from-scan [dir] [--out <file>] [--environment PROD|STAGING|DEV] [--force] [--include-tests] [--json]
intentrax policy check --tool <name> [--input <json>] [--policy <file> | --pack <pack>...] [--environment E] [--pin-status S] [--json]
```

| Exit | Meaning |
| --- | --- |
| 0 | success (`validate`: valid) |
| 1 | invalid (`validate`, or `hash` of an invalid pack file) |
| 2 | usage or I/O error, including refusing to overwrite a policy file without `--force` |

```text
$ intentrax policy check --pack git-force-push --tool Bash --input '{"command":"git push -f origin main"}'
BLOCK intentrax.git-force-push matched git.force_push (resource=main): blocked by rule rule.deny-force-push-main. …
```

## How a decision is made

1. **Match.** Each pack has ordered matchers. A matcher looks at the tool name
   (exact names, a regex, or words in the name) and at fields of the tool input
   (a regex on `/command`, `/sql`, `/file_path`, …). The first matcher that fits
   gives an **action class**, such as `git.force_push`.
2. **Derive facts.** The matcher reads the facts of
   [spec 03](../../../docs/architecture/specs/03-enforce-mode-and-policy-facts.md)
   §4.1 from the tool input: `amount_minor` (an integer in minor units),
   `resource` (a branch, a charge id, or the recipients' shared email domain)
   and `currency`. `environment` always comes from the policy file, never from
   the agent.
3. **Evaluate.** The event
   `{"eeo": {"execution_domain": {"lane": "ADMISSION", "mutation_performed": false}, "request": {"tool": "<action class>", …facts}}}`
   is evaluated by the pack's policy with the SDK's port of the Go policy
   engine (C2.1 → C2.4, the same code `verify-proof` uses to re-check a policy
   decision). The policy is C2 DSL with `default_effect: DENY`. It uses only
   the compiled operators (no `IN`, `NOT_IN`, `EXISTS` or `CONDITIONAL`) and
   only the spec 03 tenant fields.
4. **Decide.** `COMPLIANT` with no constraint → allow. `COMPLIANT` with the
   pack's `REQUIRE_APPROVAL` constraint (spec 02) → ask. `NON_COMPLIANT`,
   `ERROR`, a fact of the wrong type, or any other constraint → block (fail
   closed). With several packs, the strictest decision wins.

**What can be re-checked and what cannot.** The decision can be recomputed
from the event and `source_policy_hash`: the evaluation result carries
`execution_event_hash` and `evaluation_hash`, and the tests recompute them with
`reevaluatePolicy`. The facts are not checked by anyone: they are derived
locally from what the agent sent (`facts_source: LOCAL_GUARD_DERIVED`).
`eeo.request.tool` holds the pack's action class, not the vendor tool name.

## Pack hashes

Every pack has a content hash:

```
pack_hash = SHA-256( UTF-8("INTENTRAX_POLICY_PACK_V0_1") || JCS(pack) )
```

The hash uses RFC 8785 canonical JSON of the whole pack document. A pack holds
only strings, booleans, safe integers, arrays and objects, so the hash does
not depend on key order, whitespace or line endings. A policy file pins each
pack by `pack_hash`, and a pack that changed under the pin fails to load until
someone reviews it. A guard result, and a proof built from it, can therefore
say exactly which pack ran.

Params (refund thresholds, the internal email domain) do not change
`pack_hash`. They change the instantiated policy and its `source_policy_hash`,
which the result also carries. `test/pack-hashes.json` pins every built-in
pack. Changing a pack without bumping `pack_version` fails the tests.

## Formats

### Pack (`intentrax.policy_pack/0.1`)

| Member | Meaning |
| --- | --- |
| `pack_id`, `pack_version` | `intentrax.<name>` for built-in packs; semver |
| `title`, `summary`, `limits` | text; `limits` lists what the pack cannot see |
| `scan` | `category` (one `intentrax scan` category), `rule_ids` (`scan.category.<c>`, `scan.finding.EXPOSED`, `scan.kind.mcp-server`, `scan.any`) and optional `name_tokens` that `init --from-scan` matches against action names |
| `params`, `param_rules` | named `INTEGER` or `STRING` values with defaults and ranges, used in the policy as `{"param": "<name>"}`; `less_than` orders two params |
| `matchers` | ordered; each has `tool` (`equals`, `regex`, `token_groups`, `tokens_none`), optional `input` (`pointer` + `regex` or `equals`), optional `context` (`mcp_pin_status`), an `action` class and `facts` (`pointers` + type, regex `capture`, or `email_domain`; `required` facts make the matcher skip when absent) |
| `actions` | every action class with the decisions it can get (`allow`, `ask`, `block`) and why |
| `policy` | the C2 DSL tenant policy (`policy_id` = `pack_id`, `policy_version` = `pack_version`) |
| `approval` | the spec 02 constraint: `constraint_id`, `type: REQUIRE_APPROVAL`, `approver_hint` |
| `examples` | tool calls with the expected decision, at least one matching and one not (`expect: none`); the tests run every one |

Tokens in tool names are maximal runs of ASCII letters and digits, split where
a lower-case letter or digit is followed by an upper-case letter, lower-cased
(`mcp__stripe__createRefund` → `mcp`, `stripe`, `create`, `refund`). This is
the same rule as the C2.1 forbidden-literal check.

### Policy file (`intentrax.policy_file/0.1`)

JSON with `//` and `/* */` comments. The default path is
`.intentrax/policy.jsonc`.

```jsonc
{
  "schema_version": "intentrax.policy_file/0.1",
  "environment": "PROD",            // PROD, STAGING or DEV; left out = absent fact
  "packs": [
    { "pack": "intentrax.refunds-threshold", "pack_hash": "<64 hex>", "params": { "approval_above_minor": 5000, "deny_above_minor": 50000 } },
    { "path": "./my-pack.json", "pack_hash": "<64 hex>" }
  ]
}
```

### Guard interface

```js
import { loadPolicyFile, evaluateToolCall } from "./policy-packs/index.mjs";
const policy = loadPolicyFile(".intentrax/policy.jsonc"); // throws PolicyPackError: fail closed
const { decision, reason, results } = evaluateToolCall(policy, {
  tool_name: "Bash",                   // Claude Code PreToolUse tool_name
  tool_input: { command: "rm -rf /" }, // PreToolUse tool_input
  context: { mcp_pin_status: "CHANGED" }, // optional: what intentrax mcp check says for this tool
});
// decision: allow | ask | block | none (no pack matched)
// results[]: pack_id, pack_version, pack_hash, source_policy_hash, compiled_policy_hash,
//            matcher_id, action, facts, event, evaluation {decision, rule_id, constraints,
//            execution_event_hash, evaluation_hash, error_code}, decision, reason
```

If `.intentrax/policy.jsonc` exists but does not load (a changed pack, a bad
param, a missing pack file), `intentrax guard` (a later SDK release) does not
quietly drop the packs.
It keeps its built-in blocks and asks before every other shell, write or MCP
call until the file is fixed; reads are unaffected. It also blocks the agent
from writing the policy file, the MCP pins and any custom pack file the policy
names.

### Validation

The validator is `validatePack`. It refuses:

- a policy that is not clean C2 DSL;
- a regex outside the RE2-compatible subset (no lookaround, backreferences or
  named groups);
- an action with no matcher or no rule;
- a constraint other than the pack's `REQUIRE_APPROVAL`.

It also probes every matcher with only the facts that matcher always supplies,
in every environment. The probe refuses a pack whose policy would error or fall
through to the default deny, or that decides something the pack does not
declare.

A custom pack is a JSON file with its own `pack_id` (the `intentrax.` prefix is
reserved). It is referenced from a policy file as
`{ "path": "./my-pack.json", "pack_hash": "…" }`.

## Tests

```bash
node --test sdk/typescript/policy-packs/test/*.test.mjs
```

The suite covers:

- every example in every pack, positive and negative;
- every declared decision reached by some example;
- validator-clean policies, and refusal of `IN`/`NOT_IN`/`EXISTS`/`CONDITIONAL`
  and forbidden literal tokens;
- deterministic, key-order-independent, pinned hashes;
- re-checking each decision with `reevaluatePolicy`;
- `init --from-scan` on the scan's fixture projects, with no fixture secret or
  server URL in the draft;
- the CLI.
