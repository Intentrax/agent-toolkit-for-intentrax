# One-Command Adapter Init

The TypeScript SDK package exposes a small `intentrax` CLI for local adapter
onboarding.

```bash
npx @intentrax/sdk init claude-code --dry-run
npx @intentrax/sdk init cursor
npx @intentrax/sdk init mcp --output-dir .
npx @intentrax/sdk init langchain
npx @intentrax/sdk init langgraph
npx @intentrax/sdk init vercel-ai-sdk
npx @intentrax/sdk init cursor --force
npx @intentrax/sdk check-init --output-dir .
```

The six commands above are the MVP-native one-command adapters. Expanded
scaffold aliases are also available for `custom-agent`, `crewai`, `autogen`,
`openclaw`, `n8n`, and `deepflow`; they emit the same no-secret files and pass
the same offline `check-init` verifier, but remain scaffold aliases rather than
MVP-native hooks.

On Windows PowerShell shells that block npm/npx `.ps1` shims, use `npx.cmd`
with the same arguments.

Without `--dry-run`, the command writes:

- `.intentrax/agent-adapter.json`
- `.intentrax/sample-admission-request.json`
- `.intentrax/action-receipt.json`
- `.intentrax/submit_sample.curl`
- `.intentrax/hooks/<adapter-native-hook>.mjs`
- `.intentrax/wiring/<adapter-host-wiring>.md`

The files contain adapter metadata and a deterministic sample admission
envelope plus a no-secret native hook or wrapper starter and a concrete host
wiring guide. The local action receipt is a non-authoritative developer summary
that binds the sample, hook starter, host wiring guide, submit command, and
future AEVN/AEP evidence path by hash. The sample is contract-admissible for
the locked private-alpha Agent Gateway bundle and the selected adapter surface.
It does not contain API keys, tenant secrets, signing keys, or private key
material.

`intentrax init` is safe to rerun when the generated files are unchanged. If an
existing `.intentrax` file has local edits, the CLI refuses to overwrite it and
exits before writing anything. Use `--force` only after reviewing local changes
that should be replaced by freshly generated scaffolding.

The hook starter sanitizes auth-like fields before building event hashes and
fails closed when runtime admission is denied or unavailable. It is still a
bridge into the Intentrax runtime only: tool execution, payload mutation,
policy re-evaluation, and proof generation remain outside the adapter.

After initialization, verify the generated adapter offline:

```bash
npx @intentrax/sdk check-init --output-dir . --json
```

`check-init` requires no `INTENTRAX_API_KEY` and does not submit to the runtime.
It verifies the expected `.intentrax` files, recomputes the action receipt,
hook source, and host wiring guide hash bindings, validates the Agent Gateway
sample fixture, and imports the generated hook in no-submit mode with a
secret-bearing fixture to prove the starter does not leak secrets or require
network access.

The CLI output also writes `.intentrax/submit_sample.curl`, a no-secret command
file that uses the generated sample unchanged:

```bash
curl -sS "http://127.0.0.1:8080/v1/agent/admissions" -H "content-type: application/json" -H "X-Intentrax-Tenant-ID: tenant-local-dev" -H "X-Intentrax-Api-Key: $INTENTRAX_API_KEY" -H "X-Intentrax-Idempotency-Key: <sample idempotency_key_hash>" --data-binary "@.intentrax/sample-admission-request.json"
```

MVP adapter sample shapes:

| Adapter | Surface | Adapter ID | Action |
| --- | --- | --- | --- |
| `claude-code` | `MCP_TOOL_CALL` | `GENERIC_MCP_PROOF_ADAPTER` | `GET_PROOF` |
| `cursor` | `MCP_TOOL_CALL` | `GENERIC_MCP_PROOF_ADAPTER` | `GET_PROOF` |
| `mcp` | `MCP_TOOL_CALL` | `GENERIC_MCP_PROOF_ADAPTER` | `GET_PROOF` |
| `langchain` | `SDK_AGENT_CALL` | `SDK_AGENT_PROOF_ADAPTER` | `SUBMIT_INTENT` |
| `langgraph` | `SDK_AGENT_CALL` | `SDK_AGENT_PROOF_ADAPTER` | `SUBMIT_INTENT` |
| `vercel-ai-sdk` | `SDK_AGENT_CALL` | `SDK_AGENT_PROOF_ADAPTER` | `SUBMIT_INTENT` |

Expanded scaffold sample shapes:

| Adapter | Surface | Adapter ID | Action |
| --- | --- | --- | --- |
| `custom-agent` | `DIRECT_TOOL_CALL` | `DIRECT_TOOL_PROOF_ADAPTER` | `GET_PROOF` |
| `crewai` | `SDK_AGENT_CALL` | `SDK_AGENT_PROOF_ADAPTER` | `SUBMIT_INTENT` |
| `autogen` | `A2A_DELEGATION` | `GENERIC_A2A_PROOF_ADAPTER` | `HAND_OFF_PROOF` |
| `openclaw` | `SDK_AGENT_CALL` | `SDK_AGENT_PROOF_ADAPTER` | `SUBMIT_INTENT` |
| `n8n` | `DIRECT_TOOL_CALL` | `DIRECT_TOOL_PROOF_ADAPTER` | `GET_PROOF` |
| `deepflow` | `SDK_AGENT_CALL` | `SDK_AGENT_PROOF_ADAPTER` | `SUBMIT_INTENT` |
