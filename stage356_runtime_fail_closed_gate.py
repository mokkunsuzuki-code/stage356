import json
import hashlib
import os
from pathlib import Path
from datetime import datetime, timezone

KEYS = Path("docs/keys")
RUNTIME = Path("docs/runtime")
RUNTIME.mkdir(parents=True, exist_ok=True)

stage355_result_path = KEYS / "stage355_revocation_enforcement_result.json"
stage355_status_path = KEYS / "stage355_key_status_verification.json"

runtime_gate_path = RUNTIME / "stage356_runtime_fail_closed_gate.json"
runtime_receipt_path = RUNTIME / "stage356_runtime_execution_receipt.json"
runtime_summary_path = RUNTIME / "stage356_runtime_summary.txt"

created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def sha256_obj(obj):
    data = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def load_json(path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))

stage355_result = load_json(stage355_result_path)
stage355_status = load_json(stage355_status_path)

is_github_actions = os.getenv("GITHUB_ACTIONS") == "true"
github_run_id = os.getenv("GITHUB_RUN_ID")
github_sha = os.getenv("GITHUB_SHA")
github_repository = os.getenv("GITHUB_REPOSITORY")
github_workflow = os.getenv("GITHUB_WORKFLOW")

runtime_context = {
    "is_github_actions": is_github_actions,
    "github_actions_env": os.getenv("GITHUB_ACTIONS"),
    "github_run_id": github_run_id,
    "github_sha": github_sha,
    "github_repository": github_repository,
    "github_workflow": github_workflow,
    "local_execution": not is_github_actions
}

checks = {
    "stage355_result_exists": stage355_result is not None,
    "stage355_status_exists": stage355_status is not None,
    "stage355_decision_accept": False,
    "stage355_violations_empty": False,
    "stage355_result_sha256_present": False,
    "stage355_entry_hash_present": False,
    "stage355_entry_hash_matches_status_previous_binding": False,
    "stage355_no_private_keys": False,
    "stage355_no_real_pqc_signature_claim": False,
    "stage355_pqc_intent_not_active": False,
    "runtime_context_detected": True,
    "ci_context_valid_if_required": True,
}

reasons = []
violations = []

stage355_entry_hash = None
stage355_result_sha256 = None

if stage355_result:
    stage355_entry_hash = stage355_result.get("entry_hash")
    stage355_result_sha256 = stage355_result.get("result_sha256")

    checks["stage355_decision_accept"] = stage355_result.get("decision") == "accept_verification_ready"
    checks["stage355_violations_empty"] = stage355_result.get("violations") == []
    checks["stage355_result_sha256_present"] = isinstance(stage355_result_sha256, str) and len(stage355_result_sha256) == 64
    checks["stage355_entry_hash_present"] = isinstance(stage355_entry_hash, str) and len(stage355_entry_hash) == 64

    if not checks["stage355_decision_accept"]:
        violations.append("stage355_decision_not_accept_verification_ready")
    if not checks["stage355_violations_empty"]:
        violations.append("stage355_has_violations")

if stage355_status:
    status_previous_hash = stage355_status.get("previous_hash")
    status_entry_hash = stage355_status.get("entry_hash")

    # Stage355 result.entry_hash should match Stage355 status.entry_hash.
    checks["stage355_entry_hash_matches_status_previous_binding"] = (
        stage355_entry_hash is not None and stage355_entry_hash == status_entry_hash
    )

    safety = stage355_status.get("safety_boundary", {})
    checks["stage355_no_private_keys"] = safety.get("no_private_keys") is True
    checks["stage355_no_real_pqc_signature_claim"] = safety.get("no_real_pqc_signature_claim") is True
    checks["stage355_pqc_intent_not_active"] = safety.get("pqc_ml_dsa_active_signature_not_claimed") is True

    if not checks["stage355_no_private_keys"]:
        violations.append("stage355_private_key_safety_boundary_failed")
    if not checks["stage355_no_real_pqc_signature_claim"]:
        violations.append("stage355_real_pqc_signature_claim_detected")
    if not checks["stage355_pqc_intent_not_active"]:
        violations.append("stage355_pqc_intent_active_claim_detected")
else:
    checks["stage355_entry_hash_matches_status_previous_binding"] = False

# In this public stage, local execution is allowed only as a warning context.
# In CI, GITHUB_ACTIONS must be true. Future stages may enforce CI-only mode.
if is_github_actions:
    checks["ci_context_valid_if_required"] = True
else:
    checks["ci_context_valid_if_required"] = True
    reasons.append("local_context_detected_warn_only")

previous_hash = stage355_entry_hash or "MISSING_STAGE355_ENTRY_HASH"

gate_payload_without_hash = {
    "stage": 356,
    "engine": "Runtime Verification & Fail-Closed Execution Gate",
    "source_stage": 355,
    "created_at": created_at,
    "previous_hash": previous_hash,
    "stage355_binding": {
        "stage355_result_path": str(stage355_result_path),
        "stage355_status_path": str(stage355_status_path),
        "stage355_entry_hash": stage355_entry_hash,
        "stage355_result_sha256": stage355_result_sha256
    },
    "runtime_context": runtime_context,
    "checks": checks,
    "violations": violations,
    "fail_closed_policy": {
        "block_if_stage355_missing": True,
        "block_if_stage355_decision_not_accept": True,
        "block_if_stage355_violations_present": True,
        "block_if_stage355_entry_hash_missing": True,
        "block_if_stage355_status_mismatch": True,
        "block_if_private_key_boundary_failed": True,
        "block_if_pqc_intent_claimed_active": True
    },
    "safety_boundary": {
        "no_private_keys": True,
        "no_raw_secrets": True,
        "no_real_key_rotation_claim": True,
        "no_real_rekor_claim": True,
        "no_real_pqc_signature_claim": True,
        "runtime_gate_only": True
    }
}

entry_hash = sha256_obj(gate_payload_without_hash)

# Runtime decision
if not checks["stage355_result_exists"]:
    runtime_decision = "block"
    reasons.append("stage355_result_missing")
elif not checks["stage355_status_exists"]:
    runtime_decision = "block"
    reasons.append("stage355_status_missing")
elif not checks["stage355_decision_accept"]:
    runtime_decision = "block"
    reasons.append("stage355_decision_not_accept")
elif not checks["stage355_violations_empty"]:
    runtime_decision = "block"
    reasons.append("stage355_violations_present")
elif not checks["stage355_entry_hash_present"]:
    runtime_decision = "block"
    reasons.append("stage355_entry_hash_missing")
elif not checks["stage355_entry_hash_matches_status_previous_binding"]:
    runtime_decision = "block"
    reasons.append("stage355_entry_hash_mismatch")
elif not checks["stage355_no_private_keys"]:
    runtime_decision = "block"
    reasons.append("private_key_boundary_failed")
elif not checks["stage355_pqc_intent_not_active"]:
    runtime_decision = "block"
    reasons.append("pqc_intent_active_claim_detected")
elif not is_github_actions:
    runtime_decision = "warn"
    reasons.append("runtime_allowed_with_local_warning")
else:
    runtime_decision = "allow"
    reasons.append("runtime_allowed_in_ci_context")

gate_payload = dict(gate_payload_without_hash)
gate_payload["entry_hash"] = entry_hash
gate_payload["runtime_decision"] = runtime_decision
gate_payload["reasons"] = reasons

receipt_without_hash = {
    "stage": 356,
    "engine": "Runtime Verification & Fail-Closed Execution Gate",
    "source_stage": 355,
    "created_at": created_at,
    "runtime_decision": runtime_decision,
    "previous_hash": previous_hash,
    "entry_hash": entry_hash,
    "checks": checks,
    "violations": violations,
    "reasons": reasons
}

receipt = dict(receipt_without_hash)
receipt["receipt_sha256"] = sha256_obj(receipt_without_hash)

runtime_gate_path.write_text(json.dumps(gate_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
runtime_receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

summary = f"""Stage356 Runtime Verification & Fail-Closed Execution Gate

Runtime decision:
{runtime_decision}

What Stage356 adds:
- Reads Stage355 revocation enforcement result
- Reads Stage355 key status verification result
- Binds Stage355 entry_hash as Stage356 previous_hash
- Blocks runtime if Stage355 decision is not accept_verification_ready
- Blocks runtime if Stage355 violations exist
- Blocks runtime if Stage355 hash binding fails
- Blocks runtime if private key safety boundary fails
- Blocks runtime if PQC intent_only is treated as active
- Detects GitHub Actions runtime context

Stage355 previous hash:
{previous_hash}

Stage356 entry hash:
{entry_hash}

Runtime context:
- GitHub Actions: {is_github_actions}
- Local execution: {not is_github_actions}

Generated files:
- {runtime_gate_path}
- {runtime_receipt_path}
- {runtime_summary_path}

Safety boundary:
- No private keys
- No raw secrets
- No real key rotation claim
- No real Rekor claim
- No real PQC signature claim
- Runtime gate only
"""

runtime_summary_path.write_text(summary, encoding="utf-8")
print(summary)

# Optional real fail-closed behavior for CI:
# If running in GitHub Actions and decision is block, exit 1.
if is_github_actions and runtime_decision == "block":
    raise SystemExit(1)
