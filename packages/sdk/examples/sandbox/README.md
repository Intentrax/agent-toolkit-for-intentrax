# Sandbox proof samples

Real proof exports for trying `intentrax verify-proof` offline, with no account,
key, or network access.

They are produced by the Intentrax engine's own proof pipeline
(`engine/cmd/sandbox-sample-proof-gen`): AEP construction, signature payload,
ed25519 signing, and registry records, the same code paths as real proofs.
Two things differ:

- the signing keys are **sandbox keys**, published in `trust/sandbox-key-set.json`
  with `trust_bearing: false`. Their signing halves were never stored, so nobody,
  including Intentrax, can sign new proofs with them;
- the proof describes a `DEV`-environment sandbox tenant (`tenant-sandbox-sample`).

A sandbox proof shows **how verification works**. It is not production assurance,
and the verifier says so.

| File | What it is | Expected result |
|---|---|---|
| `sandbox-proof-export.json` | A valid sandbox proof | `SANDBOX_NON_TRUST_BEARING`, exit 0 |
| `tampered-aep-swap.json` | The AEP was rewritten after signing (it now claims `policy.unrestricted`), and every unsigned copy and outer hash was recomputed to match | Fails closed, exit 2: the signed payload no longer carries the record's AEP |
| `tampered-signature.json` | One signature byte flipped; outer hashes recomputed | Fails closed, exit 2: ed25519 verification fails |
| `tampered-roster.json` | Starts from the flipped signature, removes that signer from `key_references` and lowers the quorum to 1; outer hashes recomputed | Fails closed, exit 2: the signer roster, key bindings and signature bundle no longer agree |
| `unpinned-signer.json` | A fully valid proof signed by keys that were never published | `UNPINNED_SIGNER`, exit 3: the signatures are genuine, but who signed is unproven |

```bash
npx @intentrax/sdk verify-proof node_modules/@intentrax/sdk/examples/sandbox/sandbox-proof-export.json
npx @intentrax/sdk verify-proof node_modules/@intentrax/sdk/examples/sandbox/tampered-aep-swap.json
npx @intentrax/sdk verify-proof node_modules/@intentrax/sdk/examples/sandbox/tampered-signature.json
npx @intentrax/sdk verify-proof node_modules/@intentrax/sdk/examples/sandbox/tampered-roster.json
npx @intentrax/sdk verify-proof node_modules/@intentrax/sdk/examples/sandbox/unpinned-signer.json
```

What a passing verification shows: the record has not been altered since it was
signed, the signatures are genuine ed25519 signatures over the signed payload,
the signed payload carries this record's own AEP, and the signers are the
published keys. It does **not** show that the described action was carried out
or had its intended effect.

To verify production proofs, pass the key set Intentrax publishes for production
signers: `--trusted-keys <file>`.
