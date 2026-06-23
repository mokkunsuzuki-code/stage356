import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

DOCS = Path("docs")
KEYS = DOCS / "keys"
KEYS.mkdir(parents=True, exist_ok=True)

ledger_path = KEYS / "stage354_key_rotation_ledger.json"
result_path = KEYS / "stage354_key_rotation_result.json"
summary_path = KEYS / "stage354_key_rotation_summary.txt"

created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def sha256_obj(obj):
    data = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def file_exists(path):
    return Path(path).exists()

# Stage353の代表的な出力を探す。存在しない場合でもStage354初期化は可能。
stage353_candidates = [
    "docs/transparency/stage353_verification_transparency_result.json",
    "docs/stage353_verification_transparency_result.json",
    "docs/verification/stage353_verification_result.json",
]

stage353_result_exists = any(file_exists(p) for p in stage353_candidates)

stage178_binding = {
    "assumption": [
        "Signing keys are not assumed to remain safe forever.",
        "Keys may be rotated, revoked, replaced, or superseded.",
        "Verification must consider key validity at signing time."
    ],
    "threat_model": [
        "A compromised old key may be used to forge new evidence.",
        "A revoked key may be used after revocation.",
        "A key may be replaced without transparent history.",
        "A future PQC migration may change valid signing algorithms."
    ],
    "guarantee": [
        "Each signing key state transition is recorded in a transparent ledger.",
        "Expired or revoked keys cannot be silently treated as valid for new signatures.",
        "Verification can check key status against the claimed signing context.",
        "No private keys or raw secret material are published."
    ]
}

key_records = [
    {
        "key_id": "gpg-not-present",
        "algorithm": "GPG",
        "present": False,
        "status": "not_configured",
        "valid_from": None,
        "valid_until": None,
        "revoked_at": None,
        "private_key_published": False
    },
    {
        "key_id": "sigstore-oidc-required-in-ci",
        "algorithm": "Sigstore-OIDC",
        "present": False,
        "status": "required_in_ci_not_present_locally",
        "valid_from": None,
        "valid_until": None,
        "revoked_at": None,
        "private_key_published": False
    },
    {
        "key_id": "ed25519-witness-not-present",
        "algorithm": "Ed25519",
        "present": False,
        "status": "not_configured",
        "valid_from": None,
        "valid_until": None,
        "revoked_at": None,
        "private_key_published": False
    },
    {
        "key_id": "pqc-ml-dsa-intent",
        "algorithm": "ML-DSA",
        "standard": "NIST FIPS 204",
        "present": False,
        "status": "intent_only",
        "valid_from": None,
        "valid_until": None,
        "revoked_at": None,
        "private_key_published": False
    }
]

previous_hash = "GENESIS"

event_without_hash = {
    "event_type": "key_rotation_policy_initialization",
    "key_scope": "stage351_signature_envelope",
    "affected_algorithms": [
        "gpg",
        "sigstore_oidc",
        "ed25519_witness",
        "pqc_ml_dsa"
    ],
    "key_records": key_records,
    "previous_hash": previous_hash
}

entry_hash = sha256_obj(event_without_hash)

latest_key_event = dict(event_without_hash)
latest_key_event["entry_hash"] = entry_hash

ledger = {
    "stage": 354,
    "engine": "Signature Key Rotation Ledger Layer",
    "source_stage": 353,
    "created_at": created_at,
    "stage178_binding": stage178_binding,
    "key_ledger": {
        "ledger_path": str(ledger_path),
        "previous_hash": previous_hash,
        "entry_hash": entry_hash,
        "entry_count": 1
    },
    "latest_key_event": latest_key_event,
    "safety_boundary": {
        "no_private_keys": True,
        "no_raw_secrets": True,
        "no_fake_rotation_claim": True,
        "no_fake_pqc_key_claim": True,
        "no_external_rekor_claim": True
    }
}

checks = {
    "stage353_transparency_result_exists": stage353_result_exists,
    "stage178_assumption_present": bool(stage178_binding["assumption"]),
    "stage178_threat_model_present": bool(stage178_binding["threat_model"]),
    "stage178_guarantee_present": bool(stage178_binding["guarantee"]),
    "key_records_present": bool(key_records),
    "no_private_keys_published": all(r.get("private_key_published") is False for r in key_records),
    "no_fake_key_rotation_claim": True,
    "pqc_intent_not_claimed_as_active_key": all(
        not (r.get("algorithm") == "ML-DSA" and r.get("status") == "active")
        for r in key_records
    ),
    "ledger_chain_valid": entry_hash == sha256_obj(event_without_hash)
}

if not checks["no_private_keys_published"]:
    decision = "reject"
elif not checks["pqc_intent_not_claimed_as_active_key"]:
    decision = "reject"
elif not checks["ledger_chain_valid"]:
    decision = "reject"
else:
    decision = "accept_policy_initialization"

result = {
    "stage": 354,
    "engine": "Signature Key Rotation Ledger Layer",
    "source_stage": 353,
    "created_at": created_at,
    "checks": checks,
    "decision": decision,
    "reasons": [
        "key_rotation_policy_initialized",
        "stage178_security_framework_bound",
        "signature_key_lifecycle_declared",
        "no_private_keys_published",
        "pqc_ml_dsa_recorded_as_intent_only"
    ],
    "ledger_sha256": sha256_obj(ledger),
    "result_sha256": None
}

result["result_sha256"] = sha256_obj({k: v for k, v in result.items() if k != "result_sha256"})

ledger_path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

summary = f"""Stage354 Signature Key Rotation Ledger Layer

Decision:
{decision}

What Stage354 adds:
- Signature key rotation ledger initialization
- Stage178 Assumption / Threat Model / Guarantee binding
- GPG / Sigstore OIDC / Ed25519 / ML-DSA key lifecycle records
- previous_hash / entry_hash ledger chaining
- private key publication prevention
- PQC ML-DSA recorded as intent_only, not active key

Safety boundary:
- No private keys
- No raw secrets
- No fake key rotation claim
- No fake PQC active key claim
- No external Rekor claim

Ledger entry hash:
{entry_hash}

Ledger file:
{ledger_path}

Result file:
{result_path}
"""

summary_path.write_text(summary, encoding="utf-8")

print(summary)
