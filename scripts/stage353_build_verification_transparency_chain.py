#!/usr/bin/env python3
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]

STAGE352_PATH = ROOT / "docs/signatures/stage352_signature_manifest_verification.json"

CHAIN_PATH = ROOT / "docs/transparency/stage353_verification_transparency_chain.json"
RESULT_PATH = ROOT / "docs/transparency/stage353_verification_transparency_result.json"
SUMMARY_PATH = ROOT / "docs/transparency/stage353_verification_transparency_summary.txt"

ACCEPTABLE_STAGE352_DECISIONS = {
    "accept",
    "accept_metadata_only"
}

WARNING_STAGE352_DECISIONS = {
    "warn"
}

FAIL_STAGE352_DECISIONS = {
    "reject",
    "block"
}

def canonical_json(obj) -> bytes:
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")

def sha256_obj(obj) -> str:
    return hashlib.sha256(canonical_json(obj)).hexdigest()

def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))

def main():
    created_at = datetime.now(timezone.utc).isoformat()

    checks = {
        "stage352_verification_exists": STAGE352_PATH.exists(),
        "stage352_decision_acceptable": False,
        "verification_result_sha256_present": False,
        "previous_hash_present": False,
        "entry_hash_present": False,
        "chain_link_valid": False
    }

    if not STAGE352_PATH.exists():
        result = {
            "stage": 353,
            "engine": "Verification Transparency Chain Layer",
            "source_stage": 352,
            "created_at": created_at,
            "input": {
                "verification_result_path": "docs/signatures/stage352_signature_manifest_verification.json",
                "verification_result_sha256": None,
                "stage352_decision": None
            },
            "checks": checks,
            "decision": "reject",
            "reasons": [
                "stage352_verification_result_not_found"
            ],
            "safety_boundary": {
                "no_private_keys": True,
                "no_raw_secrets": True,
                "no_fake_signature_claim": True,
                "no_external_rekor_claim": True
            }
        }

        RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
        RESULT_PATH.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("Stage352 verification result not found")
        raise SystemExit(1)

    stage352 = load_json(STAGE352_PATH)
    stage352_decision = stage352.get("decision")
    verification_result_sha256 = sha256_file(STAGE352_PATH)

    checks["verification_result_sha256_present"] = bool(verification_result_sha256)
    checks["stage352_decision_acceptable"] = stage352_decision in ACCEPTABLE_STAGE352_DECISIONS

    previous_hash = "GENESIS"
    entries = []

    if CHAIN_PATH.exists():
        existing_chain = load_json(CHAIN_PATH)
        entries = existing_chain.get("entries", [])
        if entries:
            previous_hash = entries[-1].get("entry_hash", "GENESIS")

    entry_without_hash = {
        "stage": 353,
        "entry_type": "stage352_verification_result",
        "source_stage": 352,
        "created_at": created_at,
        "verification_result_path": "docs/signatures/stage352_signature_manifest_verification.json",
        "verification_result_sha256": verification_result_sha256,
        "stage352_decision": stage352_decision,
        "previous_hash": previous_hash
    }

    entry_hash = sha256_obj(entry_without_hash)

    latest_entry = dict(entry_without_hash)
    latest_entry["entry_hash"] = entry_hash

    checks["previous_hash_present"] = bool(previous_hash)
    checks["entry_hash_present"] = bool(entry_hash)

    if previous_hash == "GENESIS":
        checks["chain_link_valid"] = True
    else:
        checks["chain_link_valid"] = bool(entries) and previous_hash == entries[-1].get("entry_hash")

    entries.append(latest_entry)

    chain = {
        "stage": 353,
        "engine": "Verification Transparency Chain Layer",
        "source_stage": 352,
        "chain_rule": "Each Stage352 verification result entry stores previous_hash and entry_hash.",
        "entries": entries
    }

    if stage352_decision in ACCEPTABLE_STAGE352_DECISIONS and checks["chain_link_valid"]:
        decision = "accept"
        reasons = [
            "stage352_verification_result_bound",
            "verification_result_sha256_created",
            "verification_transparency_entry_created",
            "previous_hash_entry_hash_chain_created",
            "stage352_decision_acceptable"
        ]
    elif stage352_decision in WARNING_STAGE352_DECISIONS:
        decision = "warn"
        reasons = [
            "stage352_decision_warn",
            "verification_result_logged_with_warning"
        ]
    elif stage352_decision in FAIL_STAGE352_DECISIONS:
        decision = "reject"
        reasons = [
            "stage352_decision_failed",
            "verification_result_not_accepted"
        ]
    else:
        decision = "reject"
        reasons = [
            "unknown_stage352_decision",
            "fail_closed"
        ]

    result = {
        "stage": 353,
        "engine": "Verification Transparency Chain Layer",
        "source_stage": 352,
        "created_at": created_at,
        "input": {
            "verification_result_path": "docs/signatures/stage352_signature_manifest_verification.json",
            "verification_result_sha256": verification_result_sha256,
            "stage352_decision": stage352_decision
        },
        "chain": {
            "chain_path": "docs/transparency/stage353_verification_transparency_chain.json",
            "previous_hash": previous_hash,
            "entry_hash": entry_hash,
            "entry_count": len(entries)
        },
        "latest_entry": latest_entry,
        "checks": checks,
        "decision": decision,
        "reasons": reasons,
        "safety_boundary": {
            "no_private_keys": True,
            "no_raw_secrets": True,
            "no_fake_signature_claim": True,
            "no_external_rekor_claim": True
        }
    }

    CHAIN_PATH.parent.mkdir(parents=True, exist_ok=True)

    CHAIN_PATH.write_text(
        json.dumps(chain, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8"
    )

    RESULT_PATH.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8"
    )

    SUMMARY_PATH.write_text(
        "\n".join([
            "Stage353 Verification Transparency Chain Summary",
            f"decision: {decision}",
            f"stage352_decision: {stage352_decision}",
            f"verification_result_sha256: {verification_result_sha256}",
            f"previous_hash: {previous_hash}",
            f"entry_hash: {entry_hash}",
            f"entry_count: {len(entries)}",
            "external_rekor_claim: false",
            "bitcoin_anchor_claim: false",
            "private_keys_published: false",
            ""
        ]),
        encoding="utf-8"
    )

    print("Stage353 verification transparency chain generated")
    print(f"decision: {decision}")
    print(f"stage352_decision: {stage352_decision}")
    print(f"verification_result_sha256: {verification_result_sha256}")
    print(f"entry_hash: {entry_hash}")

    if decision == "reject":
        raise SystemExit(1)

if __name__ == "__main__":
    main()
