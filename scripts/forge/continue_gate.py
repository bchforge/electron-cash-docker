#!/usr/bin/env python3
"""Verify a hash-bound 44+2 v1.0 acceptance continuation without rerunning suites."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import ci
import docker_ownership


ORIGINAL_SHA = "fe8e37524a097cbc1a2c3c791827ae412fa4faf1"
EXPECTED_SOURCE_FINGERPRINT = "36184e6729352a0860c48d381d77058b40cde940f4d1a9403e824877abf02824"
EXPECTED_GATE_MANIFEST_SHA256 = "02d54fc519dc06a23954d0f1077266aa28cc1fcad8b027fc5e9c78b50d0a3652"
CI_ONLY_CHANGES = {"scripts/forge/gitlab_gate.py", "scripts/forge/continue_gate.py"}
TWO_GIB = 2 * 1024**3


class ContinuationError(RuntimeError):
    """The existing evidence cannot be safely composed into a passing continuation."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContinuationError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(document: Any) -> str:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def git(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, text=True, capture_output=True, check=False)
    if result.returncode:
        raise ContinuationError(f"git {' '.join(args)} failed: {result.stderr[-1000:]}")
    return result.stdout.strip()


def command(args: list[str], *, required: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, check=False, timeout=120)
    if required and result.returncode:
        raise ContinuationError(f"command failed: {' '.join(args)}: {(result.stdout + result.stderr)[-1500:]}")
    return result


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContinuationError(f"invalid or missing evidence JSON: {path.name}: {error}") from error
    if not isinstance(value, dict):
        raise ContinuationError(f"evidence JSON is not an object: {path.name}")
    return value


def verify_original_source(report: Path, current_sha: str) -> tuple[dict[str, Any], str]:
    gate = read_json(report / "gate-manifest.json")
    sidecar = (report / "gate-manifest.sha256").read_text(encoding="utf-8").split()
    require(len(sidecar) == 2 and sidecar[0] == EXPECTED_GATE_MANIFEST_SHA256,
            "prior gate manifest sidecar does not match the authorized run")
    require(sha256(report / "gate-manifest.json") == EXPECTED_GATE_MANIFEST_SHA256,
            "prior gate manifest hash changed")
    require(gate.get("overall_status") == "FAIL", "prior gate is not the known incomplete gate")
    candidate = gate.get("candidate", {})
    require(candidate.get("head") == ORIGINAL_SHA and candidate.get("identity") == "COMMITTED_CANDIDATE"
            and candidate.get("dirty") is False, "prior candidate identity is not the authorized v1.0 SHA")
    require(candidate.get("source_fingerprint") == EXPECTED_SOURCE_FINGERPRINT,
            "prior candidate source fingerprint changed")
    git("merge-base", "--is-ancestor", ORIGINAL_SHA, current_sha)
    changed = set(git("diff", "--name-only", f"{ORIGINAL_SHA}..{current_sha}").splitlines())
    require(changed == CI_ONLY_CHANGES, f"continuation contains changes outside its CI adapter: {sorted(changed)}")
    require(not git("status", "--porcelain", "--untracked-files=all"), "continuation worktree is dirty")

    source = read_json(report / "effective-source-manifest.json")
    require(canonical_sha256(source) == EXPECTED_SOURCE_FINGERPRINT,
            "source manifest digest does not match the previously tested SHA")
    raw_records = source.get("files")
    if not isinstance(raw_records, list) or len(raw_records) != candidate.get("effective_source_file_count"):
        raise ContinuationError("effective source manifest file count is inconsistent")
    records = [record for record in raw_records if isinstance(record, dict)]
    require(len(records) == len(raw_records), "effective source manifest contains an invalid file record")
    for record in records:
        relative = record.get("path")
        if not isinstance(relative, str) or not relative or ".." in Path(relative).parts:
            raise ContinuationError("unsafe path in prior source manifest")
        if relative == "scripts/forge/gitlab_gate.py":
            continue
        blob = subprocess.run(["git", "show", f"{current_sha}:{relative}"], cwd=ROOT,
                              capture_output=True, check=False)
        require(blob.returncode == 0 and hashlib.sha256(blob.stdout).hexdigest() == record.get("sha256"),
                f"tested source bytes changed: {relative}")
        worktree_path = ROOT / relative
        if not worktree_path.exists() and not worktree_path.is_symlink():
            raise ContinuationError(f"tested source path disappeared: {relative}")
        current_mode = format(stat.S_IMODE(worktree_path.lstat().st_mode), "04o")
        require(current_mode == record.get("mode"), f"tested source mode changed: {relative}")
    for relative, digest in gate.get("artifact_hashes", {}).items():
        path = (report / relative).resolve()
        require(report.resolve() in path.parents and path.is_file() and sha256(path) == digest,
                f"prior gate artifact hash mismatch: {relative}")

    prior_results = gate.get("acceptance_test_results", [])
    by_test: dict[str, list[str]] = {}
    for item in prior_results:
        by_test.setdefault(str(item.get("test")), []).append(str(item.get("status")))
    failed = [item for item in prior_results if item.get("status") == "FAIL"]
    require(len([item for item in prior_results if item.get("status") == "PASS"]) == 44,
            "prior gate does not contain exactly 44 passing test results")
    require(all(len(statuses) == 1 for statuses in by_test.values()),
            "prior gate contains duplicate acceptance suite results")
    require(set(by_test) == set(ci.MANDATORY_ACCEPTANCE_TESTS) - {"test_remote_access.py"},
            "prior gate suite set differs from the expected 44 PASS plus first-install failure")
    require(by_test.get("test_first_install.py") == ["FAIL"] and "test_remote_access.py" not in by_test,
            "prior gate's two outstanding suites differ from the authorized continuation")
    require(len(failed) == 1 and "cancelled phase at the early disk trigger" in failed[0].get("error", "")
            and "test_first_install.py" == failed[0].get("test"),
            "prior gate has an unapproved acceptance failure")
    require(gate.get("release_security", {}).get("status") == "PASS",
            "prior release security evidence is not PASS")
    require(gate.get("cleanup", {}).get("overall") == "PASS",
            "prior canonical gate cleanup evidence is not PASS")
    return gate, canonical_sha256(
        [item for item in records if item.get("path") != "scripts/forge/gitlab_gate.py"]
    )


def verify_targeted_results(targeted: Path, gate: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    baseline = read_json(targeted / "baseline.json")
    prior_manifest_hash = sha256(Path(gate["report_dir"]) / "gate-manifest.json")
    require(baseline.get("head") == ORIGINAL_SHA and
            baseline.get("source_fingerprint") == EXPECTED_SOURCE_FINGERPRINT and
            baseline.get("prior_gate_manifest_sha256") == prior_manifest_hash,
            "selective-run baseline is not bound to the verified original gate")

    first = read_json(targeted / "first-install-result.json")
    first_receipt = read_json(targeted / "first-install-composite-result.json")
    first_log = targeted / "first-install.log"
    first_source = subprocess.check_output(["git", "show", f"{ORIGINAL_SHA}:tests/test_first_install.py"], cwd=ROOT)
    require(first.get("test") == "test_first_install.py" and first.get("status") == "PASS" and
            first.get("exit_code") == 0, "first-install targeted execution did not exit PASS")
    require(first.get("minimum_free_bytes", 0) > ci.DISK_FLOOR_BYTES and
            first.get("disk_floor_bytes") == TWO_GIB,
            "first-install did not stay above the canonical hard floor or its prior guard is unexpected")
    require(first.get("log_sha256") == sha256(first_log) and
            first_receipt.get("test_source_sha256") == hashlib.sha256(first_source).hexdigest(),
            "first-install log or test-source hash mismatch")
    first_text = first_log.read_text(encoding="utf-8", errors="replace")
    require("PASS public-default Compose cold browser install" in first_text and
            "PRODUCT_IMAGES_BUILT=5" in first_text,
            "first-install receipt lacks real Compose build/runtime acceptance output")

    remote = read_json(targeted / "remote-access-rerun-result.json")
    remote_receipt = read_json(targeted / "remote-access-composite-result.json")
    remote_log = targeted / "remote-access-rerun.log"
    remote_source = subprocess.check_output(["git", "show", f"{ORIGINAL_SHA}:tests/test_remote_access.py"], cwd=ROOT)
    require(remote.get("test") == "test_remote_access.py" and remote.get("status") == "PASS" and
            remote.get("exit_code") == 0, "final remote-access targeted execution did not exit PASS")
    require(remote.get("independent_guard_bytes") == TWO_GIB and
            remote.get("minimum_root_free_bytes", 0) > ci.DISK_FLOOR_BYTES,
            "remote-access did not stay above the canonical hard floor or its prior guard is unexpected")
    require(remote.get("log_sha256") == sha256(remote_log) and
            remote_receipt.get("test_source_sha256") == hashlib.sha256(remote_source).hexdigest(),
            "remote-access log or test-source hash mismatch")
    remote_text = remote_log.read_text(encoding="utf-8", errors="replace")
    require("direct DROP evidence:" in remote_text and
            "PASS Caddy auth, authenticated WebSocket, fail2ban enforcement" in remote_text,
            "remote-access receipt lacks live Caddy/WebSocket/fail2ban acceptance output")
    require(remote.get("owned_residual_containers_removed") == [] and
            remote.get("owned_residual_volumes_removed") == [],
            "remote-access rerun reported residual cleanup resources")
    image_refs = remote.get("image_refs", {})
    image_ids = remote.get("image_ids", {})
    for service, reference in image_refs.items():
        require(first.get("new_images", {}).get(reference) == image_ids.get(service),
                f"remote-access did not use the first-install image identity for {service}")

    composite = read_json(targeted / "v1-composite-attestation.json")
    require(composite.get("signature", "").startswith("unsigned") and
            composite.get("composite_verdict", {}).get("commit_sha") == ORIGINAL_SHA and
            composite.get("composite_verdict", {}).get("source_fingerprint") == EXPECTED_SOURCE_FINGERPRINT,
            "prior composite receipt identity is inconsistent")
    sidecar = (targeted / "v1-composite-attestation.sha256").read_text(encoding="utf-8").split()
    require(len(sidecar) == 2 and sidecar[0] == sha256(targeted / "v1-composite-attestation.json"),
            "prior composite attestation sidecar does not match its bytes")
    receipt_files = composite.get("receipt_files", {})
    require(len(receipt_files) == 8, "expected exactly eight targeted receipt/log hashes")
    for name, expected in receipt_files.items():
        file_path = targeted / name
        require(file_path.is_file() and sha256(file_path) == expected,
                f"targeted receipt/log hash mismatch: {name}")
    require(first_receipt.get("commit_sha") == ORIGINAL_SHA and
            remote_receipt.get("commit_sha") == ORIGINAL_SHA and
            first_receipt.get("status") == "PASS" and remote_receipt.get("status") == "PASS",
            "targeted receipts are not bound to the tested SHA and PASS")
    require(first_receipt.get("source_fingerprint") == EXPECTED_SOURCE_FINGERPRINT and
            remote_receipt.get("source_fingerprint") == EXPECTED_SOURCE_FINGERPRINT,
            "targeted receipts have the wrong source fingerprint")
    return baseline, first, remote


def docker_json(args: list[str]) -> Any:
    result = command(["docker", *args])
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ContinuationError(f"Docker returned invalid JSON for {' '.join(args)}") from error


def clean_and_verify_owned_outputs(targeted: Path, baseline: dict[str, Any], first: dict[str, Any]) -> dict[str, Any]:
    owner_directory = targeted / "xdg" / "electron-cash-docker" / "test-resource-owners"
    registries = sorted(path for path in owner_directory.glob("*.jsonl")
                        if not path.name.endswith(".events.jsonl"))
    require(len(registries) == 1 and not registries[0].is_symlink(),
            "first-install owner registry is missing or ambiguous")
    registry = registries[0]
    registry_stat = registry.stat()
    require(registry_stat.st_uid == os.geteuid() and (registry_stat.st_mode & 0o077) == 0,
            "first-install resource registry is not private operator-owned evidence")
    registry_claims = docker_ownership.read_claims(registry)
    owner_tokens = {item.get("owner_token") for item in registry_claims}
    require(len(owner_tokens) == 1 and None not in owner_tokens,
            "first-install registry has more than one owner")
    owner = str(next(iter(owner_tokens)))
    project = next((item["name"] for item in registry_claims if item.get("kind") == "project"), None)
    require(project == "bchforge-test-public-first-install-ad3a5bbcff4d4073a87b8cc93c2d6681",
            "first-install project identity does not match its execution log")
    expected_leaked = {
        f"{project}_auth-session-data",
        f"{project}_gui-session-state",
    }
    baseline_volumes = set(baseline.get("preexisting_volume_names", []))
    require(not (expected_leaked & baseline_volumes), "test volumes were present before the selective run")
    require(all(any(item.get("kind") == "volume" and item.get("name") == name and
                    item.get("preflight") == "ABSENT" and item.get("owner_token") == owner
                    for item in registry_claims) for name in expected_leaked),
            "test-volume ownership is not proven by the preflight claims")

    current_volumes = set(command(["docker", "volume", "ls", "-q"]).stdout.splitlines())
    require(baseline_volumes <= current_volumes, "a pre-existing Docker volume disappeared")
    unexpected = current_volumes - baseline_volumes - expected_leaked
    require(not unexpected, f"unrelated Docker volumes appeared during the selective run: {sorted(unexpected)}")
    removed_volumes = []
    for name in sorted(expected_leaked & current_volumes):
        details = docker_json(["volume", "inspect", name])[0]
        labels = details.get("Labels") or {}
        require(details.get("Name") == name and labels.get(docker_ownership.PROJECT_LABEL) == project,
                f"refusing to remove volume without exact test project ownership: {name}")
        users = command(["docker", "ps", "-aq", "--filter", f"volume={name}"]).stdout.split()
        require(not users, f"test volume is still mounted by a container; retained: {name}")
        command(["docker", "volume", "rm", name])
        removed_volumes.append(name)
    final_volumes = set(command(["docker", "volume", "ls", "-q"]).stdout.splitlines())
    require(final_volumes == baseline_volumes,
            "Docker volume postcondition differs from the pre-test inventory")

    removed_image_tags = []
    image_claims = [item for item in registry_claims if item.get("kind") == "image" and
                    item.get("owner_token") == owner and item.get("build_attempted") is True]
    expected_images = first.get("new_images", {})
    require(len(image_claims) == len(expected_images) == 5,
            "first-install generated image claims are incomplete")
    for claim in image_claims:
        raw_name = claim.get("name")
        if not isinstance(raw_name, str):
            raise ContinuationError("generated image claim has no string tag")
        name = raw_name
        expected_id = expected_images.get(name)
        if not isinstance(expected_id, str):
            raise ContinuationError(f"generated image tag was not in the first-install receipt: {name}")
        require(claim.get("expected_id") == expected_id and claim.get("retain") is False,
                f"generated image tag has no exact task-owned build identity: {name}")
        inspected = command(["docker", "image", "inspect", name], required=False)
        if inspected.returncode:
            require("no such image" in inspected.stderr.lower() or "no such object" in inspected.stderr.lower(),
                    f"unable to inspect generated image tag: {name}")
            continue
        image = json.loads(inspected.stdout)[0]
        require(image.get("Id") == expected_id and name in (image.get("RepoTags") or []),
                f"generated image identity changed; refusing cleanup: {name}")
        users = command(["docker", "ps", "-aq", "--filter", f"ancestor={expected_id}"]).stdout.split()
        require(not users, f"generated image is referenced by a container; retained: {name}")
        command(["docker", "image", "rm", "--no-prune", name])
        absent = command(["docker", "image", "inspect", name], required=False)
        require(absent.returncode != 0 and
                ("no such image" in absent.stderr.lower() or "no such object" in absent.stderr.lower()),
                f"generated image tag remains after exact cleanup: {name}")
        removed_image_tags.append({"reference": name, "image_id": expected_id, "remove_prune": False})

    residual = ci.verify_registry_postcondition(registry, owner)
    require(not residual, f"first-install owned-resource postcondition failed: {residual}")

    container_ids = set(command(["docker", "ps", "-aq", "--no-trunc"]).stdout.splitlines())
    require(container_ids == set(baseline.get("preexisting_container_ids", [])),
            "Docker container inventory changed from the selective-run baseline")
    cache = command(["docker", "buildx", "du", "--builder", baseline["preexisting_builder"], "--format", "json"])
    cache_items = [json.loads(line) for line in cache.stdout.splitlines() if line.strip()]
    cache_ids = {item.get("ID") for item in cache_items}
    original_cache_ids = set(baseline.get("r6_cache_ids", []))
    require(original_cache_ids <= cache_ids, "pre-existing r6 Buildx cache entries disappeared")
    config_hashes = baseline.get("default_buildx_config_hashes", {})
    for file_name, digest in config_hashes.items():
        file_path = Path(file_name)
        require(file_path.is_file() and sha256(file_path) == digest,
                f"pre-existing Docker Buildx client configuration changed: {file_name}")

    return {
        "status": "PASS",
        "preexisting_volume_count": len(baseline_volumes),
        "final_volume_count": len(final_volumes),
        "removed_test_owned_volumes": removed_volumes,
        "removed_test_owned_image_tags": removed_image_tags,
        "preexisting_container_ids_preserved": len(container_ids),
        "r6_cache_entries_preserved": len(original_cache_ids),
        "buildx_config_hashes_preserved": len(config_hashes),
        "global_prune_used": False,
        "foreign_volumes_touched": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior-report", type=Path, required=True)
    parser.add_argument("--targeted-run", type=Path, required=True)
    args = parser.parse_args()
    try:
        prior_report = args.prior_report.resolve(strict=True)
        targeted = args.targeted_run.resolve(strict=True)
        current_sha = git("rev-parse", "HEAD")
        require(git("branch", "--show-current") == "release/v1.0",
                "continuation must run on release/v1.0")
        gate, unchanged_digest = verify_original_source(prior_report, current_sha)
        baseline, first, remote = verify_targeted_results(targeted, gate)
        cleanup = clean_and_verify_owned_outputs(targeted, baseline, first)

        old_results = {item["test"]: item["status"] for item in gate["acceptance_test_results"]}
        old_results["test_first_install.py"] = "PASS"
        old_results["test_remote_access.py"] = "PASS"
        mandatory = list(ci.MANDATORY_ACCEPTANCE_TESTS)
        require(len(mandatory) == 46 and len(set(mandatory)) == 46 and
                set(old_results) == set(mandatory) and all(old_results[name] == "PASS" for name in mandatory),
                "composed mandatory suite is not exactly 46/46 PASS")

        attestation = {
            "schema_version": 1,
            "attested_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "verdict": "PASS_INCREMENTAL_ACCEPTANCE_CONTINUATION",
            "commit_sha": current_sha,
            "tested_product_sha": ORIGINAL_SHA,
            "prior_gate_status": "FAIL",
            "prior_gate_failure": "test_first_install.py was cancelled at the 6 GiB early disk trigger; test_remote_access.py was not run in that gate",
            "source_fingerprint": EXPECTED_SOURCE_FINGERPRINT,
            "unchanged_source_projection_sha256": unchanged_digest,
            "ci_only_changes": sorted(CI_ONLY_CHANGES),
            "prior_gate_manifest_sha256": EXPECTED_GATE_MANIFEST_SHA256,
            "prior_gate_artifacts_verified": len(gate.get("artifact_hashes", {})),
            "prior_suite_pass_count": 44,
            "targeted_suites": [
                {
                    "test": "test_first_install.py",
                    "status": "PASS",
                    "exit_code": 0,
                    "test_source_sha256": first["test_source_sha256"] if "test_source_sha256" in first else
                        hashlib.sha256(subprocess.check_output(["git", "show", f"{ORIGINAL_SHA}:tests/test_first_install.py"], cwd=ROOT)).hexdigest(),
                    "log_sha256": first["log_sha256"],
                    "observed_minimum_free_bytes": first["minimum_free_bytes"],
                    "runner_cancel_floor_bytes": first["disk_floor_bytes"],
                    "canonical_hard_floor_bytes": ci.DISK_FLOOR_BYTES,
                    "note": "The prior selective runner was configured at 2 GiB; every recorded sample remained above the canonical 5 GiB hard floor.",
                },
                {
                    "test": "test_remote_access.py",
                    "status": "PASS",
                    "exit_code": 0,
                    "test_source_sha256": hashlib.sha256(subprocess.check_output(["git", "show", f"{ORIGINAL_SHA}:tests/test_remote_access.py"], cwd=ROOT)).hexdigest(),
                    "log_sha256": remote["log_sha256"],
                    "observed_minimum_free_bytes": remote["minimum_root_free_bytes"],
                    "runner_cancel_floor_bytes": remote["independent_guard_bytes"],
                    "canonical_hard_floor_bytes": ci.DISK_FLOOR_BYTES,
                    "note": "The first selective remote attempt failed; this is the subsequent real exit-0 rerun, whose samples remained above the canonical 5 GiB hard floor.",
                },
            ],
            "mandatory_acceptance": {"required": 46, "passed": len(mandatory), "statuses": old_results},
            "security_and_supply_chain": "PASS (verified from prior gate artifacts)",
            "cleanup": cleanup,
            "canonical_full_gate_claimed_pass": False,
            "signature": "unsigned local evidence; SHA-256 hashes and GitLab external continuation status bind the result",
        }
        output = targeted / "official-continuation-attestation.json"
        output.write_text(json.dumps(attestation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(output, 0o600)
        print(json.dumps({
            "verdict": attestation["verdict"],
            "prior_gate_status": "FAIL",
            "mandatory_acceptance": "46/46 composite (44 prior + 2 targeted)",
            "attestation": str(output),
            "attestation_sha256": sha256(output),
            "cleanup": cleanup,
        }, indent=2))
        return 0
    except (ContinuationError, OSError, KeyError, ValueError, subprocess.SubprocessError) as error:
        print(f"FAIL incremental continuation: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
