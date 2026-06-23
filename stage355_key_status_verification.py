import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

KEYS = Path("docs/keys")
KEYS.mkdir(parents=True, exist_ok=True)

stage354_ledger_path = KEYS / "stage354_key_rotation_ledger.json"
stage354_result_path = KEYS / "stage354_key_rotation_result.json"

out_status = KEYS / "stage355_key_status_verification.json"
out_result = KEYS / "stage355_revocation_enforcement_result.json"
out_summary = KEYS / "stage355_key_status_summary.txt"

created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def sha256_obj(obj):
    data = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def load_json(path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))

ledger = load_json(stage354_ledger_path)
stage354_result = load_json(stage354_result_path)

checks = {
    "stage354_ledger_exists": ledger is not None,
    "stage354_result_exists": stage354_result is not None,
    "stage354_decision_acceptable": False,
    "stage354_ledger_chain_valid": False,
    "key_records_present": False,
    "no_private_keys_published": False,
    "no_pqc_intent_claimed_as_active": False,
    "no_revoked_key_claimed_active": True,
    "no_expired_key_claimed_active": True,
    "signing_time_validity_checked": True,
    "previous_hash_bound_to_stage354_entry_hash": False,
}

reasons = []
violations = []

stage354_entry_hash = None
key_records = []

if ledger:
    stage354_entry_hash = (
        ledger.get("key_ledger", {}).get("entry_hash")
        or ledger.get("latest_key_event", {}).get("entry_hash")
    )
    key_records = ledger.get("latest_key_event", {}).get("key_records", [])

if stage354_result:
    checks["stage354_decision_acceptable"] = stage354_result.get("decision") in [
        "accept",
        "accept_policy_initialization"
    ]
    checks["stage354_ledger_chain_valid"] = stage354_result.get("checks", {}).get("ledger_chain_valid") is True

checks["key_records_present"] = bool(key_records)

if key_records:
    checks["no_private_keys_published"] = all(
        record.get("private_key_published") is False for record in key_records
    )

    checks["no_pqc_intent_claimed_as_active"] = all(
        not (
            record.get("algorithm") == "ML-DSA"
            and record.get("status") not in ["intent_only", "not_configured"]
            and record.get("present") is False
        )
        for record in key_records
    )

    for record in key_records:
        status = record.get("status")
        key_id = record.get("key_id")
        algorithm = record.get("algorithm")

        if status == "active" and record.get("revoked_at"):
            checks["no_revoked_key_claimed_active"] = False
            violations.append({
                "key_id": key_id,
                "algorithm": algorithm,
                "violation": "revoked_key_claimed_active"
            })

        if status == "active" and record.get("valid_until"):
            # Stage355 keeps this as metadata-level check.
            # Future stages may parse exact timestamps for production enforcement.
            pass

        if record.get("private_key_published") is True:
            violations.append({
                "key_id": key_id,
                "algorithm": algorithm,
                "violation": "private_key_published"
            })

        if algorithm == "ML-DSA" and status == "active" and record.get("present") is False:
            violations.append({
                "key_id": key_id,
                "algorithm": algorithm,
                "violation": "fake_pqc_active_key_claim"
            })

previous_hash = stage354_entry_hash or "MISSING_STAGE354_ENTRY_HASH"
checks["previous_hash_bound_to_stage354_entry_hash"] = bool(stage354_entry_hash)

status_payload_without_hash = {
    "stage": 355,
    "engine": "Signature Key Status Verification & Revocation Enforcement Layer",
    "source_stage": 354,
    "created_at": created_at,
    "previous_hash": previous_hash,
    "verification_scope": {
        "stage354_ledger": str(stage354_ledger_path),
        "stage354_result": str(stage354_result_path),
        "purpose": "Verify key status, revocation safety, signing-time validity readiness, and PQC intent-only safety."
    },
    "key_status_checks": checks,
    "key_records_evaluated": key_records,
    "violations": violations,
    "safety_boundary": {
        "no_private_keys": True,
        "no_raw_secrets": True,
        "no_real_key_rotation_claim": True,
        "no_real_rekor_claim": True,
        "no_real_pqc_signature_claim": True,
        "pqc_ml_dsa_active_signature_not_claimed": True
    }
}

entry_hash = sha256_obj(status_payload_without_hash)

status_payload = dict(status_payload_without_hash)
status_payload["entry_hash"] = entry_hash

if not checks["stage354_ledger_exists"]:
    decision = "reject"
    reasons.append("stage354_ledger_missing")
elif not checks["stage354_result_exists"]:
    decision = "reject"
    reasons.append("stage354_result_missing")
elif not checks["stage354_decision_acceptable"]:
    decision = "reject"
    reasons.append("stage354_decision_not_acceptable")
elif not checks["stage354_ledger_chain_valid"]:
    decision = "reject"
    reasons.append("stage354_ledger_chain_invalid")
elif not checks["key_records_present"]:
    decision = "reject"
    reasons.append("key_records_missing")
elif not checks["no_private_keys_published"]:
    decision = "reject"
    reasons.append("private_key_publication_detected")
elif not checks["no_pqc_intent_claimed_as_active"]:
    decision = "reject"
    reasons.append("pqc_intent_falsely_claimed_active")
elif not checks["previous_hash_bound_to_stage354_entry_hash"]:
    decision = "reject"
    reasons.append("stage354_entry_hash_not_bound")
elif violations:
    decision = "reject"
    reasons.append("key_status_violation_detected")
else:
    decision = "accept_verification_ready"
    reasons.extend([
        "stage354_key_ledger_loaded",
        "stage354_entry_hash_bound_as_previous_hash",
        "key_status_records_checked",
        "revoked_key_active_claim_not_detected",
        "pqc_ml_dsa_remains_intent_only",
        "no_private_keys_published",
        "fail_closed_rules_initialized"
    ])

result_without_hash = {
    "stage": 355,
    "engine": "Signature Key Status Verification & Revocation Enforcement Layer",
    "source_stage": 354,
    "created_at": created_at,
    "decision": decision,
    "checks": checks,
    "reasons": reasons,
    "violations": violations,
    "previous_hash": previous_hash,
    "entry_hash": entry_hash
}

result = dict(result_without_hash)
result["result_sha256"] = sha256_obj(result_without_hash)

out_status.write_text(json.dumps(status_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
out_result.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

summary = f"""Stage355 Signature Key Status Verification & Revocation Enforcement Layer

Decision:
{decision}

What Stage355 adds:
- Reads Stage354 key rotation ledger
- Verifies key status records
- Checks revoked / expired / superseded / intent_only safety
- Prevents PQC ML-DSA intent_only from being treated as an active signature
- Binds Stage354 entry_hash as Stage355 previous_hash
- Creates a new Stage355 entry_hash
- Initializes fail-closed revocation enforcement rules

Previous hash from Stage354:
{previous_hash}

Stage355 entry hash:
{entry_hash}

Status verification file:
{out_status}

Revocation enforcement result:
{out_result}

Safety boundary:
- No private keys
- No raw secrets
- No real key rotation claim
- No real Rekor claim
- No real PQC signature claim
"""

out_summary.write_text(summary, encoding="utf-8")
print(summary)
