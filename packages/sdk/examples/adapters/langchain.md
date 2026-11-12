# LangChain Adapter Quickstart

Use the packaged CLI quickstart when you want a contract-admissible LangChain callback or tool wrapper in under a minute:

~~~bash
npx @intentrax/sdk init langchain --output-dir .
~~~

The command writes `.intentrax/agent-adapter.json`,
`.intentrax/sample-admission-request.json`, `.intentrax/action-receipt.json`,
and
`.intentrax/hooks/langchain-callback-wrapper.mjs`, plus
`.intentrax/wiring/langchain-host-wiring.md`. Open the wiring guide to import
`withIntentraxLangChainCallback` from the callback or tool wrapper boundary.
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

The generated request maps LangChain callbacks onto `SDK_AGENT_CALL` with the `SDK_AGENT_PROOF_ADAPTER`. The adapter submits hash-bound evidence references and does not re-run policy or generate proof.
