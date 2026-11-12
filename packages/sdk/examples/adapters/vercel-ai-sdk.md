# Vercel AI SDK Adapter Quickstart

Use the packaged CLI quickstart when you want a contract-admissible Vercel AI SDK route wrapper in under a minute:

~~~bash
npx @intentrax/sdk init vercel-ai-sdk --output-dir .
~~~

The command writes `.intentrax/agent-adapter.json`,
`.intentrax/sample-admission-request.json`, `.intentrax/action-receipt.json`,
and
`.intentrax/hooks/vercel-ai-sdk-route-wrapper.mjs`, plus
`.intentrax/wiring/vercel-ai-sdk-host-wiring.md`. Open the wiring guide to
import `withIntentraxVercelAIRoute` inside the route handler before side effects
proceed. Submit the sample only after setting the runtime credential in your
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

The generated request maps TypeScript route wrapper evidence onto `SDK_AGENT_CALL` with the `SDK_AGENT_PROOF_ADAPTER`. The SDK wrapper preserves AEVN/AEP authority and never stores private key material.
