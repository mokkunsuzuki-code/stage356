#!/usr/bin/env python3
import json
import os
import hashlib
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]

STAGE351_PATH = ROOT / "docs/signatures/stage351_signature_manifest.json"
STAGE350_PATH = ROOT / "docs/enforcement/enforcement_session.json"
OUTPUT_PATH = ROOT / "docs/signatures/stage352_signature_manifest_verification.json"

def canonical_json(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def sha256_obj(obj) -> str:
    return hashlib.sha256(canonical_json(obj)).hexdigest()

def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def is_ci():
    return os.getenv("CI", "").lower() == "true" or os.getenv("GITHUB_ACTIONS", "").lower() == "true"

def main():
    stage351_exists = STAGE351_PATH.exists()
    stage350_exists = STAGE350_PATH.exists()

    stage351 = json.loads(STAGE351_PATH.read_text(encoding="utf-8")) if stage351_exists else {}
    stage350 = json.loads(STAGE350_PATH.read_text(encoding="utf-8")) if stage350_exists else {}

    required_fields = [
        "stage",
        "engine",
        "source_stage",
        "target",
        "context_binding",
        "signature_envelope",
        "hybrid_binding",
        "safety_boundary"
    ]

    required_fields_present = all(k in stage351 for k in required_fields)

    stage350_session_hash_match = (
        stage351.get("target", {}).get("session_sha256")
        == stage350.get("session_sha256")
    )

    canonical_payload = {
        "target": stage351.get("target"),
        "context_binding": stage351.get("context_binding"),
        "signature_envelope": stage351.get("signature_envelope")
    }

    recomputed_canonical_payload_sha256 = sha256_obj(canonical_payload)
    recorded_canonical_payload_sha256 = stage351.get("hybrid_binding", {}).get("canonical_payload_sha256")

    canonical_payload_hash_match = (
        recomputed_canonical_payload_sha256 == recorded_canonical_payload_sha256
    )

    recorded_signature_manifest_sha256 = stage351.get("hybrid_binding", {}).get("signature_manifest_sha256")

    stage351_without_signature_manifest_sha256 = json.loads(json.dumps(stage351))
    if "hybrid_binding" in stage351_without_signature_manifest_sha256:
        stage351_without_signature_manifest_sha256["hybrid_binding"].pop("signature_manifest_sha256", None)

    recomputed_signature_manifest_sha256 = sha256_obj(stage351_without_signature_manifest_sha256)

    signature_manifest_hash_match = (
        recomputed_signature_manifest_sha256 == recorded_signature_manifest_sha256
    )

    context = stage351.get("context_binding", {})
    github_actions = context.get("github_actions", {})
    local_execution = context.get("local_execution", {})
    envelope = stage351.get("signature_envelope", {})

    ci_in_manifest = context.get("ci_environment")
    ci_now = is_ci()

    sigstore = envelope.get("sigstore_oidc", {})
    pqc = envelope.get("pqc_ml_dsa", {})

    ci_context_consistent = True
    if ci_in_manifest is True:
        ci_context_consistent = bool(github_actions.get("run_id")) and bool(github_actions.get("repository"))
    else:
        ci_context_consistent = (
            local_execution.get("allowed") is True
            and sigstore.get("present") is False
        )

    sigstore_oidc_requirement_consistent = (
        sigstore.get("required_in_ci") is True
        and "present" in sigstore
        and "oidc_identity_bound" in sigstore
    )

    pqc_ml_dsa_intent_consistent = False
    if pqc.get("present") is False:
        pqc_ml_dsa_intent_consistent = (
            pqc.get("algorithm") == "ML-DSA"
            and pqc.get("standard") == "NIST FIPS 204"
            and pqc.get("mode") == "intent_only"
            and pqc.get("private_key_published") is False
        )
    elif pqc.get("present") is True:
        pqc_ml_dsa_intent_consistent = bool(pqc.get("signature_path")) and bool(pqc.get("public_key_path"))

    no_fake_signature_claim = True
    for name, item in envelope.items():
        if item.get("present") is False and item.get("verified") is True:
            no_fake_signature_claim = False

    def contains_forbidden_private_key_reference(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in {
                    "private_key_path",
                    "secret_key_path",
                    "raw_secret",
                    "private_key_material"
                }:
                    return True
                if contains_forbidden_private_key_reference(v):
                    return True
            return False
        if isinstance(obj, list):
            return any(contains_forbidden_private_key_reference(v) for v in obj)
        return False

    no_private_key_reference = not contains_forbidden_private_key_reference(stage351)

    checks = {
        "stage351_manifest_exists": stage351_exists,
        "stage350_enforcement_exists": stage350_exists,
        "required_fields_present": required_fields_present,
        "stage351_stage_is_351": stage351.get("stage") == 351,
        "stage351_source_stage_is_350": stage351.get("source_stage") == 350,
        "stage350_session_hash_match": stage350_session_hash_match,
        "canonical_payload_hash_match": canonical_payload_hash_match,
        "signature_manifest_hash_match": signature_manifest_hash_match,
        "ci_context_consistent": ci_context_consistent,
        "sigstore_oidc_requirement_consistent": sigstore_oidc_requirement_consistent,
        "pqc_ml_dsa_intent_consistent": pqc_ml_dsa_intent_consistent,
        "no_fake_signature_claim": no_fake_signature_claim,
        "no_private_key_reference": no_private_key_reference
    }

    signature_envelope_verification = {
        "gpg": {
            "present": envelope.get("gpg", {}).get("present", False),
            "verified": False,
            "status": "not_present" if not envelope.get("gpg", {}).get("present", False) else "present_not_verified"
        },
        "sigstore_oidc": {
            "present": sigstore.get("present", False),
            "verified": False,
            "required_in_ci": sigstore.get("required_in_ci", True),
            "status": "not_present_local_allowed" if not ci_in_manifest and not sigstore.get("present", False) else "ci_required_or_present"
        },
        "ed25519_witness": {
            "present": envelope.get("ed25519_witness", {}).get("present", False),
            "verified": False,
            "status": "not_present" if not envelope.get("ed25519_witness", {}).get("present", False) else "present_not_verified"
        },
        "pqc_ml_dsa": {
            "present": pqc.get("present", False),
            "verified": False,
            "mode": pqc.get("mode"),
            "status": "intent_only_not_real_signature" if pqc.get("mode") == "intent_only" else "requires_real_signature_verification"
        }
    }

    violations = [k for k, v in checks.items() if v is not True]

    if ci_in_manifest is True and sigstore.get("present") is False:
        violations.append("CI_SIGSTORE_OIDC_SIGNATURE_REQUIRED_BUT_NOT_PRESENT")

    if not stage351_exists or not stage350_exists:
        decision = "reject"
    elif not stage350_session_hash_match:
        decision = "reject"
    elif not canonical_payload_hash_match:
        decision = "reject"
    elif not signature_manifest_hash_match:
        decision = "reject"
    elif not pqc_ml_dsa_intent_consistent:
        decision = "reject"
    elif ci_in_manifest is True and sigstore.get("present") is False:
        decision = "block"
    elif all(checks.values()) and ci_in_manifest is False:
        decision = "accept_metadata_only"
    elif all(checks.values()) and ci_in_manifest is True and sigstore.get("present") is True:
        decision = "accept"
    else:
        decision = "warn"

    reasons = []
    if decision == "accept_metadata_only":
        reasons = [
            "stage351_manifest_structure_valid",
            "stage350_session_sha256_matches",
            "canonical_payload_sha256_matches",
            "signature_manifest_sha256_matches",
            "local_context_consistent",
            "pqc_ml_dsa_intent_only_is_not_claimed_as_signature"
        ]
    else:
        reasons = violations

    output = {
        "stage": 352,
        "engine": "Hybrid Signature Manifest Verification Layer",
        "source_stage": 351,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "verified_target": {
            "stage351_manifest_path": "docs/signatures/stage351_signature_manifest.json",
            "stage350_enforcement_path": "docs/enforcement/enforcement_session.json",
            "stage351_manifest_file_sha256": sha256_file(STAGE351_PATH) if stage351_exists else None,
            "stage350_enforcement_file_sha256": sha256_file(STAGE350_PATH) if stage350_exists else None,
            "stage351_manifest_sha256_recorded": recorded_signature_manifest_sha256,
            "stage351_manifest_sha256_recomputed": recomputed_signature_manifest_sha256,
            "stage350_session_sha256": stage350.get("session_sha256")
        },
        "checks": checks,
        "signature_envelope_verification": signature_envelope_verification,
        "decision": decision,
        "violations": violations,
        "reasons": reasons,
        "fail_closed_rule": {
            "enabled": True,
            "reject_on_hash_mismatch": True,
            "block_ci_without_sigstore_oidc": True,
            "reject_fake_pqc_signature_claim": True
        },
        "safety_boundary": {
            "no_private_keys": True,
            "no_raw_secrets": True,
            "no_signature_forgery_claim": True,
            "no_unverified_pqc_claim": True
        }
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print("Stage352 signature manifest verification generated")
    print(f"decision: {decision}")
    print(f"stage350_session_hash_match: {stage350_session_hash_match}")
    print(f"canonical_payload_hash_match: {canonical_payload_hash_match}")
    print(f"signature_manifest_hash_match: {signature_manifest_hash_match}")

    if decision in {"reject", "block"}:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
