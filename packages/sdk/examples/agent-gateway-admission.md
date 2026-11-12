# TypeScript Agent Gateway Admission Example

This generated example is downstream from the locked runtime Agent Gateway fixture.

- SDK/client reference: sdk/typescript/http.js
- Shared spec: sdk/shared-specs/agent-gateway-admission-examples.v1.json
- Endpoint: POST /v1/agent/admissions
- Required API scope: agent.gateway.admit

The SDK lane should submit the normalized admission request body exactly as shown after deriving it from the MCP or A2A protocol envelope. The SDK must not execute tools, deliver A2A messages, re-evaluate policy, generate proofs, mutate proof artifacts, or handle private key material in this path.

## MCP Admission Request Body

~~~json
{
  "schema_version": "intentrax.runtime.agent_admission_request/1.0",
  "tenant_id": "tenant-alpha",
  "surface_id": "MCP_TOOL_CALL",
  "action": "GET_PROOF",
  "adapter_id": "GENERIC_MCP_PROOF_ADAPTER",
  "evidence_refs": [
    "sha256:46f136e995bf1921533652a0721e8ea47816d250aee0da951258bec5645754af",
    "sha256:4c6a9a6ce776170fa968682c51efafdd39301390f94176b2029e22594917ee1f",
    "sha256:8a6d71f9e60ab0ef32de1eb63d049adb3820104c30489a5c42e7acaeeb222ce1",
    "sha256:8c63d17014da7fd015b77c10fb702bcf005f0ed1dee1516991747e230c3dbfc0",
    "sha256:b4c6a6ab375273436e38f7b5fb58b1c270a453297a184c019c4cabab3007e698",
    "sha256:b9d82729f18f8720ee4d8575192966b9aec2320b25a8e79c6e2862c005053787"
  ],
  "proof_refs": [
    "sha256:46f136e995bf1921533652a0721e8ea47816d250aee0da951258bec5645754af",
    "sha256:4c6a9a6ce776170fa968682c51efafdd39301390f94176b2029e22594917ee1f",
    "sha256:8a6d71f9e60ab0ef32de1eb63d049adb3820104c30489a5c42e7acaeeb222ce1",
    "sha256:8c63d17014da7fd015b77c10fb702bcf005f0ed1dee1516991747e230c3dbfc0",
    "sha256:b4c6a6ab375273436e38f7b5fb58b1c270a453297a184c019c4cabab3007e698",
    "sha256:b9d82729f18f8720ee4d8575192966b9aec2320b25a8e79c6e2862c005053787"
  ],
  "request_payload_hash": "6ae40172c3a90cd17e4e20800103a0255ec4e0c1ea34dab4cd3623c337284b6b",
  "protocol_payload_ref": "sha256:6ae40172c3a90cd17e4e20800103a0255ec4e0c1ea34dab4cd3623c337284b6b",
  "idempotency_key_hash": "78f5d628566a249e99a7468f670dcfa0fb175464a4540626294460179801e808"
}
~~~

## A2A Admission Request Body

~~~json
{
  "schema_version": "intentrax.runtime.agent_admission_request/1.0",
  "tenant_id": "tenant-alpha",
  "surface_id": "A2A_DELEGATION",
  "action": "HAND_OFF_PROOF",
  "adapter_id": "GENERIC_A2A_PROOF_ADAPTER",
  "evidence_refs": [
    "sha256:46f136e995bf1921533652a0721e8ea47816d250aee0da951258bec5645754af",
    "sha256:4c6a9a6ce776170fa968682c51efafdd39301390f94176b2029e22594917ee1f",
    "sha256:8a6d71f9e60ab0ef32de1eb63d049adb3820104c30489a5c42e7acaeeb222ce1",
    "sha256:8c63d17014da7fd015b77c10fb702bcf005f0ed1dee1516991747e230c3dbfc0",
    "sha256:b4c6a6ab375273436e38f7b5fb58b1c270a453297a184c019c4cabab3007e698",
    "sha256:b9d82729f18f8720ee4d8575192966b9aec2320b25a8e79c6e2862c005053787"
  ],
  "proof_refs": [
    "sha256:46f136e995bf1921533652a0721e8ea47816d250aee0da951258bec5645754af",
    "sha256:4c6a9a6ce776170fa968682c51efafdd39301390f94176b2029e22594917ee1f",
    "sha256:8a6d71f9e60ab0ef32de1eb63d049adb3820104c30489a5c42e7acaeeb222ce1",
    "sha256:8c63d17014da7fd015b77c10fb702bcf005f0ed1dee1516991747e230c3dbfc0",
    "sha256:b4c6a6ab375273436e38f7b5fb58b1c270a453297a184c019c4cabab3007e698",
    "sha256:b9d82729f18f8720ee4d8575192966b9aec2320b25a8e79c6e2862c005053787"
  ],
  "request_payload_hash": "60ca15bd3edbdf8086638d66ab7fa735c51c63bcd044b29f620038fcc0df6add",
  "protocol_payload_ref": "sha256:60ca15bd3edbdf8086638d66ab7fa735c51c63bcd044b29f620038fcc0df6add",
  "idempotency_key_hash": "ca33f77093da4a962f26fe1f0f41f5b478a8fc30772d358e46a1412de8d9701f"
}
~~~
