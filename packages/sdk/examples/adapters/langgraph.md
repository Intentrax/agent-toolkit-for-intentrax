# LangGraph Adapter Quickstart

Use the packaged CLI quickstart when you want a contract-admissible LangGraph node middleware path in under a minute:

~~~bash
npx @intentrax/sdk init langgraph --output-dir .
~~~

The command writes `.intentrax/agent-adapter.json`,
`.intentrax/sample-admission-request.json`, `.intentrax/action-receipt.json`,
and
`.intentrax/hooks/langgraph-node-middleware.mjs`, plus
`.intentrax/wiring/langgraph-host-wiring.md`. Open the wiring guide to import
`withIntentraxLangGraphNode` from node middleware before checkpointed state
commits. Submit the sample only after setting the runtime credential in your
shell:

~~~bash
export INTENTRAX_API_KEY="..."
curl -sS "http://127.0.0.1:8080/v1/agent/admissions" \
  -H "content-type: application/json" \
  -H "X-Intentrax-Tenant-ID: tenant-local-dev" \
  -H "X-Intentrax-Api-Key: $INTENTRAX_API_KEY" \
  -H "X-Intentrax-Idempotency-Key: <sample idempotency_key_hash>" \
  --data-binary @.intentrax/sample-admission-request.json
~~~

The generated request maps LangGraph middleware onto `SDK_AGENT_CALL` with the `SDK_AGENT_PROOF_ADAPTER`. Graph execution stays in the application; Intentrax receives normalized admission evidence.
