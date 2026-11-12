# Claude Code Adapter Quickstart

Use the packaged CLI quickstart when you want a contract-admissible Claude Code hook in under a minute:

~~~bash
npx @intentrax/sdk init claude-code --output-dir .
~~~

The command writes `.intentrax/agent-adapter.json`,
`.intentrax/sample-admission-request.json`, `.intentrax/action-receipt.json`,
and
`.intentrax/hooks/claude-code-pre-tool-use.mjs`, plus
`.intentrax/wiring/claude-code-host-wiring.md`. Open the wiring guide to import
`beforeClaudeCodeToolUse` from the host pre-tool-use hook. Submit the sample
only after setting the runtime credential in your shell:

~~~bash
export INTENTRAX_API_KEY="..."
curl -sS "http://127.0.0.1:8080/v1/agent/admissions" \
  -H "content-type: application/json" \
  -H "X-Intentrax-Tenant-ID: tenant-local-dev" \
  -H "X-Intentrax-Api-Key: $INTENTRAX_API_KEY" \
  -H "X-Intentrax-Idempotency-Key: <sample idempotency_key_hash>" \
  --data-binary @.intentrax/sample-admission-request.json
~~~

The generated request maps Claude Code tool hooks onto `MCP_TOOL_CALL` with the `GENERIC_MCP_PROOF_ADAPTER`. Tool execution, payload mutation, policy re-evaluation, and proof generation stay outside the adapter boundary.
