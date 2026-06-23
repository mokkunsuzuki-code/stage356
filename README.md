# Stage356: Runtime Verification & Fail-Closed Execution Gate

Stage356 extends Stage355 by turning key-status verification into a runtime fail-closed gate.

Stage355 checks whether the key status records are safe.

Stage356 checks whether the runtime is allowed to proceed based on the Stage355 result.

---

## What Stage356 Adds

Stage356 adds:

- Stage355 result loading
- Stage355 status loading
- Stage355 entry_hash binding
- Runtime fail-closed decision
- Local / GitHub Actions runtime context detection
- Runtime decision output: allow / warn / block
- Runtime receipt generation
- Fail-closed safety rules

---

## Main Purpose

Stage356 answers this question:

```text
Should the system be allowed to run based on the latest key-status verification result?

In simple terms:

Stage354 creates the key ledger.
Stage355 checks the key status.
Stage356 blocks execution if the key-status verification is unsafe.
Inputs

Stage356 reads:

docs/keys/stage355_revocation_enforcement_result.json
docs/keys/stage355_key_status_verification.json
Outputs

Stage356 generates:

docs/runtime/stage356_runtime_fail_closed_gate.json
docs/runtime/stage356_runtime_execution_receipt.json
docs/runtime/stage356_runtime_summary.txt
Runtime Decisions

Stage356 can return:

allow
warn
block
allow

The runtime is allowed when:

Stage355 result exists
Stage355 decision is accept_verification_ready
Stage355 violations are empty
Stage355 entry_hash is present
Stage355 safety boundaries pass
Runtime context is acceptable
warn

The runtime may warn when:

Running locally outside GitHub Actions
Public metadata is valid
No violations are present
block

The runtime is blocked when:

Stage355 result is missing
Stage355 status is missing
Stage355 decision is not acceptable
Stage355 violations exist
Stage355 entry_hash is missing
Stage355 hash binding fails
Private key boundary fails
PQC intent_only is treated as active
Safety Boundary

Stage356 does not:

publish private keys
publish raw secrets
perform real production key rotation
claim real Rekor inclusion
claim real PQC signature verification
execute dangerous code

Stage356 is a runtime gate over public verification metadata.

Relationship to Stage355

Stage355:

Verifies key status and revocation safety.

Stage356:

Uses the Stage355 result to decide whether runtime execution should continue.
License

MIT License
