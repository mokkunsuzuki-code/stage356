#!/usr/bin/env python3
import json
import os
import hashlib
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]

ENFORCEMENT_PATH = ROOT / "docs/enforcement/enforcement_session.json"
OUTPUT_PATH = ROOT / "docs/signatures/stage351_signature_manifest.json"

def canonical_json(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def sha256_obj(obj) -> str:
    return hashlib.sha256(canonical_json(obj)).hexdigest()

def env(name):
    return os.getenv(name) or None

def is_ci():
    return os.getenv("CI", "").lower() == "true" or os.getenv("GITHUB_ACTIONS", "").lower() == "true"

def main():
    if not ENFORCEMENT_PATH.exists():
        raise FileNotFoundError("docs/enforcement/enforcement_session.json not found")

    enforcement = json.loads(ENFORCEMENT_PATH.read_text(encoding="utf-8"))

    ci = is_ci()

    target = {
        "path": "docs/enforcement/enforcement_session.json",
        "session_sha256": enforcement.get("session_sha256"),
        "stage350_decision": enforcement.get("decision"),
        "stage350_ci_environment": enforcement.get("ci_environment"),
        "stage350_source_git_commit": enforcement.get("source_git_commit")
    }

    context_binding = {
        "ci_environment": ci,
        "github_actions": {
            "repository": env("GITHUB_REPOSITORY"),
            "workflow": env("GITHUB_WORKFLOW"),
            "run_id": env("GITHUB_RUN_ID"),
            "run_attempt": env("GITHUB_RUN_ATTEMPT"),
            "sha": env("GITHUB_SHA"),
            "ref": env("GITHUB_REF"),
            "actor": env("GITHUB_ACTOR")
        },
        "local_execution": {
            "allowed": not ci,
            "signature_decision": "metadata_only" if not ci else "not_applicable",
            "reason": "local execution cannot prove GitHub OIDC identity" if not ci else None
        }
    }

    signature_envelope = {
        "gpg": {
            "present": False,
            "signature_path": None
        },
        "sigstore_oidc": {
            "present": False,
            "required_in_ci": True,
            "bundle_path": None,
            "oidc_identity_bound": False
        },
        "ed25519_witness": {
            "present": False,
            "signature_path": None,
            "public_key_path": None
        },
        "pqc_ml_dsa": {
            "present": False,
            "algorithm": "ML-DSA",
            "standard": "NIST FIPS 204",
            "mode": "intent_only",
            "private_key_published": False,
            "public_key_path": None,
            "signature_path": None
        }
    }

    canonical_payload = {
        "target": target,
        "context_binding": context_binding,
        "signature_envelope": signature_envelope
    }

    canonical_payload_sha256 = sha256_obj(canonical_payload)

    violations = []

    if ci and not context_binding["github_actions"]["run_id"]:
        violations.append("CI_CONTEXT_MISSING_GITHUB_RUN_ID")

    if ci and not context_binding["github_actions"]["repository"]:
        violations.append("CI_CONTEXT_MISSING_GITHUB_REPOSITORY")

    if ci and not signature_envelope["sigstore_oidc"]["present"]:
        violations.append("CI_SIGSTORE_OIDC_SIGNATURE_REQUIRED_BUT_NOT_PRESENT")

    if signature_envelope["pqc_ml_dsa"]["present"] is False and signature_envelope["pqc_ml_dsa"]["mode"] != "intent_only":
        violations.append("PQC_STATE_INCONSISTENT")

    if ci and violations:
        decision = "block"
    elif violations:
        decision = "warn"
    else:
        decision = "pending" if not ci else "accept"

    manifest_without_hash = {
        "stage": 351,
        "engine": "Hybrid PQC-Ready Context-Bound Enforcement Signature Manifest Layer",
        "short_engine": "Hybrid Enforcement Signature Manifest Layer",
        "source_stage": 350,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "context_binding": context_binding,
        "signature_envelope": signature_envelope,
        "hybrid_binding": {
            "canonical_payload_sha256": canonical_payload_sha256,
            "binding_rule": "Stage350 session hash, execution context, and signature envelope are canonically bound."
        },
        "decision": decision,
        "violations": violations,
        "reasons": [
            "stage350_session_sha256_bound",
            "ci_or_local_context_bound",
            "sigstore_oidc_required_for_ci_acceptance",
            "pqc_ml_dsa_recorded_as_intent_only",
            "missing_signatures_are_not_claimed_as_present"
        ],
        "safety_boundary": {
            "no_private_keys": True,
            "no_raw_secrets": True,
            "no_fake_signature_claim": True,
            "no_unverified_pqc_claim": True
        }
    }

    signature_manifest_sha256 = sha256_obj(manifest_without_hash)

    manifest = dict(manifest_without_hash)
    manifest["hybrid_binding"]["signature_manifest_sha256"] = signature_manifest_sha256

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print("Stage351 hybrid signature manifest generated")
    print(f"decision: {decision}")
    print(f"canonical_payload_sha256: {canonical_payload_sha256}")
    print(f"signature_manifest_sha256: {signature_manifest_sha256}")

    if ci and decision == "block":
        raise SystemExit(1)

if __name__ == "__main__":
    main()
