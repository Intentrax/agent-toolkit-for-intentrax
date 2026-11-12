# Generic MCP Adapter Quickstart

Use the packaged CLI quickstart when you want a contract-admissible generic MCP tool-call admission path in under a minute:

~~~bash
npx @intentrax/sdk init mcp --output-dir .
~~~

The command writes `.intentrax/agent-adapter.json`,
`.intentrax/sample-admission-request.json`, `.intentrax/action-receipt.json`,
and
`.intentrax/hooks/mcp-tool-call-admission.mjs`, plus
`.intentrax/wiring/mcp-host-wiring.md`. Open the wiring guide to import
`beforeMCPToolCall` before forwarding `tools/call` to the upstream handler.
Submit the sample only after setting the runtime credential in your shell:

~~~bash
export INTENTRAX_API_KEY="..."
curl -sS "http://127.0.0.1:8080/v1/agent/admissions" \
  -H "content-type: application/json" \
  -H "X-Intentrax-Tenant-ID: tenant-local-dev" \
  -H "X-Intentrax-Api-Key: $INTENTRAX_API_KEY" \
  -H "X-Intentrax-Idempotency-Key: <sample idempotency_key_hash>" \
  --data-binary @.intentrax/sample-admission-request.json
~~~

The generated request maps MCP `tools/call` evidence onto `MCP_TOOL_CALL` with the `GENERIC_MCP_PROOF_ADAPTER`. MCP protocol truth remains upstream; AEVN/AEP evidence remains authoritative inside Intentrax.
