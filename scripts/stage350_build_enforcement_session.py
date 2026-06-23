#!/usr/bin/env python3
import json
import os
import re
import hashlib
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]

BRIDGE_CANDIDATES = [
    ROOT / "docs/supply-chain/slsa_sbom_bridge_result.json",
    ROOT / "docs/bridge/bridge_result.json",
    ROOT / "docs/supply-chain/bridge_result.json",
    ROOT / "docs/artifacts/bridge_result.json",
    ROOT / "docs/stage349/bridge_result.json",
]

ENFORCEMENT_PATH = ROOT / "docs/enforcement/enforcement_session.json"
TRANSPARENCY_PATH = ROOT / "docs/audit/stage350-transparency-log.json"

HEX_RE = re.compile(r"^([0-9a-f]{7}|[0-9a-f]{40})$")

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def canonical_json(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

def load_bridge_result():
    for p in BRIDGE_CANDIDATES:
        if p.exists():
            return p, json.loads(p.read_text(encoding="utf-8"))
    raise FileNotFoundError("bridge_result json was not found under docs/")

def is_ci():
    return os.getenv("CI", "").lower() == "true" or os.getenv("GITHUB_ACTIONS", "").lower() == "true"

def valid_commit(value: str) -> bool:
    if not isinstance(value, str):
        return False
    if value.startswith("local-"):
        return False
    return bool(HEX_RE.match(value.lower()))

def main():
    bridge_path, bridge = load_bridge_result()

    source_git_commit = bridge.get("source_git_commit", "")
    ci = is_ci()

    violations = []

    if ci and not valid_commit(source_git_commit):
        violations.append("CI_ENFORCEMENT_REJECTED_NON_CANONICAL_SOURCE_GIT_COMMIT")

    if isinstance(source_git_commit, str) and source_git_commit.startswith("local-"):
        violations.append("SOURCE_GIT_COMMIT_IS_LOCAL_UNCOMMITTED")

    wrap_signature_required = True
    signature_present = bool(
        bridge.get("signature_present")
        or bridge.get("wrap_signature_present")
        or bridge.get("sigstore_bundle")
        or bridge.get("gpg_signature")
        or bridge.get("signature")
    )

    if wrap_signature_required and not signature_present:
        violations.append("WRAP_SIGNATURE_REQUIRED_BUT_NOT_PRESENT")

    if ci and violations:
        decision = "block"
    elif violations:
        decision = "warn"
    else:
        decision = "accept"

    enforcement_without_hash = {
        "stage": 350,
        "engine": "Supply-Chain Evidence Enforcement Session Layer",
        "source_stage": 349,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "ci_environment": ci,
        "bridge_result_path": str(bridge_path.relative_to(ROOT)),
        "bridge_result_sha256": sha256_bytes(canonical_json(bridge)),
        "source_git_commit": source_git_commit,
        "source_git_commit_valid": valid_commit(source_git_commit),
        "wrap_signature_required": wrap_signature_required,
        "signature_present": signature_present,
        "decision": decision,
        "violations": violations,
        "fail_closed_rule": {
            "enabled": True,
            "ci_blocks_local_uncommitted": True,
            "accepted_commit_formats": [
                "40-character hexadecimal Git commit hash",
                "7-character hexadecimal short Git commit hash"
            ]
        },
        "bridge_result": bridge
    }

    session_sha256 = sha256_bytes(canonical_json(enforcement_without_hash))
    enforcement = dict(enforcement_without_hash)
    enforcement["session_sha256"] = session_sha256

    ENFORCEMENT_PATH.write_text(
        json.dumps(enforcement, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8"
    )

    previous_hash = "GENESIS"
    entries = []

    if TRANSPARENCY_PATH.exists():
        existing = json.loads(TRANSPARENCY_PATH.read_text(encoding="utf-8"))
        entries = existing.get("entries", [])
        if entries:
            previous_hash = entries[-1].get("entry_hash", "GENESIS")

    entry_without_hash = {
        "stage": 350,
        "entry_type": "enforcement_session",
        "created_at": enforcement["created_at"],
        "previous_hash": previous_hash,
        "session_sha256": session_sha256,
        "decision": decision,
        "source_git_commit": source_git_commit,
        "ci_environment": ci,
        "violations": violations
    }

    entry_hash = sha256_bytes(canonical_json(entry_without_hash))
    entry = dict(entry_without_hash)
    entry["entry_hash"] = entry_hash

    entries.append(entry)

    transparency = {
        "stage": 350,
        "engine": "Stage350 Enforcement Transparency Chain",
        "chain_rule": "Each entry stores previous_hash and entry_hash",
        "entries": entries
    }

    TRANSPARENCY_PATH.write_text(
        json.dumps(transparency, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8"
    )

    print("Stage350 enforcement session generated")
    print(f"bridge_result_path: {bridge_path.relative_to(ROOT)}")
    print(f"decision: {decision}")
    print(f"session_sha256: {session_sha256}")
    print(f"entry_hash: {entry_hash}")

    if ci and decision == "block":
        raise SystemExit(1)

if __name__ == "__main__":
    main()
