# Cursor Adapter Quickstart

Use the packaged CLI quickstart when you want a contract-admissible Cursor shell or tool hook in under a minute:

~~~bash
npx @intentrax/sdk init cursor --output-dir .
~~~

The command writes `.intentrax/agent-adapter.json`,
`.intentrax/sample-admission-request.json`, `.intentrax/action-receipt.json`,
and
`.intentrax/hooks/cursor-before-shell-execution.mjs`, plus
`.intentrax/wiring/cursor-host-wiring.md`. Open the wiring guide to import
`beforeCursorShellExecution` from the host shell-execution hook. Submit the
sample only after setting the runtime credential in your shell:

~~~bash
export INTENTRAX_API_KEY="..."
curl -sS "http://127.0.0.1:8080/v1/agent/admissions" \
  -H "content-type: application/json" \
  -H "X-Intentrax-Tenant-ID: tenant-local-dev" \
  -H "X-Intentrax-Api-Key: $INTENTRAX_API_KEY" \
  -H "X-Intentrax-Idempotency-Key: <sample idempotency_key_hash>" \
  --data-binary @.intentrax/sample-admission-request.json
~~~

The generated request maps Cursor execution hooks onto `MCP_TOOL_CALL` with the `GENERIC_MCP_PROOF_ADAPTER`. Intentrax receives proof references and hashes only; the adapter does not execute tools or mutate prompts.
