#!/usr/bin/env python3
"""Acceptance must compare Docker state to the gate-start snapshot before building."""
from __future__ import annotations

import inspect
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ci


def protected_state(*, image_id: str = "sha256:foreign-any-id",
                    container_status: str = "running", volume_size: str = "275.8MB") -> dict:
    return {
        "images": [{"repository": "pbc-app", "tag": "v0.1-local-accepted",
                    "ID": image_id, "Digest": "sha256:pbc", "created_at": "2026-09-26T17:06:23Z",
                    "size": "605MB", "metadata": {"labels": {"pbc.accepted": "true"},
                                                         "repo_tags": ["pbc-app:v0.1-local-accepted"]}}],
        "containers": [{"id": "pbc-container", "name": "poweredby-app",
                         "configured_image": "pbc-app:v0.1-local-accepted", "image_id": image_id,
                         "created": "2026-09-26T17:07:09Z", "status": container_status,
                         "running": container_status == "running", "health": "healthy",
                         "state_details": {"StartedAt": "2026-09-26T17:07:10Z"}, "restart_count": 0,
                         "labels": {"com.docker.compose.project": "poweredbycash-v01-local"},
                         "mounts": [], "networks": {}, "ports": {}, "host_config": {}}],
        "volumes": [{"name": "poweredby-data", "driver": "local", "scope": "local",
                     "created_at": "2026-09-24T10:00:00Z", "mountpoint": "/var/lib/docker/volumes/poweredby-data/_data",
                     "options": {}, "labels": {"owner": "foreign"},
                     "usage_data": {"Size": 289197056, "RefCount": 1}, "size": volume_size}],
        "networks": [{"id": "pbc-network", "name": "poweredby-network", "driver": "bridge",
                       "scope": "local", "internal": False, "attachable": False, "ingress": False,
                       "labels": {}, "subnets": ["172.20.0.0/16"]}],
        "builders": [{"name": "default", "cache_items": [{"ID": "foreign-cache", "Size": "1GB"}],
                       "cache_total_bytes": 1_000_000_000, "inspect": "Name: default\nNodes: default\n"}],
        "root_filesystem": {"free_bytes": 60 * 1024**3},
        "daemon": "engine-id|/var/lib/docker|overlay2|29.0|linux|linux|x86_64",
    }


def write_preflight(report_dir: Path, *, baseline: dict, confirmation: dict) -> dict:
    baseline_path = report_dir / "docker-protection-preflight.json"
    confirmation_path = report_dir / "docker-protection-preflight-confirmation.json"
    baseline_sha = ci.write_immutable_private_json(baseline_path, baseline)
    confirmation_sha = ci.write_immutable_private_json(confirmation_path, confirmation)
    return {"docker_protection_preflight": {
        "report": str(baseline_path), "sha256": baseline_sha,
        "confirmation_report": str(confirmation_path), "confirmation_sha256": confirmation_sha,
        "status": "PASS"}}


def test_buildx_snapshot_context_and_unavailable_backend() -> None:
    listing = [
        {"Name": "default", "Driver": "docker", "Dynamic": False,
         "Nodes": [{"Name": "default", "Endpoint": "default", "Status": "running"}]},
        {"Name": "desktop-linux", "Driver": "docker", "Dynamic": False,
         "Nodes": [{"Name": "desktop-linux", "Endpoint": "desktop-linux", "Status": "running"}]},
        {"Name": "orbstack", "Driver": "", "Dynamic": False, "Err": "backend unavailable",
         "Nodes": [{"Name": "", "Endpoint": "", "Status": ""}]},
    ]
    contexts = [
        {"Name": "default", "DockerEndpoint": "unix:///var/run/docker.sock"},
        {"Name": "desktop-linux", "DockerEndpoint": "unix:///Users/operator/.docker/run/docker.sock"},
        {"Name": "orbstack", "DockerEndpoint": "unix:///Users/operator/.orbstack/run/docker.sock"},
    ]
    calls = []

    def fake_run(command, **_kwargs):
        calls.append(command)
        if command == ["docker", "buildx", "ls", "--format", "{{json .}}"]:
            return type("Result", (), {"returncode": 0,
                "stdout": "".join(json.dumps(row) + "\n" for row in listing), "stderr": ""})()
        if command == ["docker", "context", "ls", "--format", "{{json .}}"]:
            return type("Result", (), {"returncode": 0,
                "stdout": "".join(json.dumps(row) + "\n" for row in contexts), "stderr": ""})()
        if command[1:4] in (["--context=default", "buildx", "inspect"],
                            ["--context=desktop-linux", "buildx", "inspect"]):
            name = command[-1]
            return type("Result", (), {"returncode": 0,
                "stdout": f"Name: {name}\nDriver: docker\nNodes:\nName: {name}\nEndpoint: {name}\nStatus: running\n",
                "stderr": ""})()
        if command[1:4] in (["--context=default", "buildx", "du"],
                            ["--context=desktop-linux", "buildx", "du"]):
            return type("Result", (), {"returncode": 0,
                "stdout": json.dumps({"ID": "cache-" + command[5], "Size": "1kB"}) + "\n",
                "stderr": ""})()
        raise AssertionError(command)

    with patch.object(ci, "run", side_effect=fake_run):
        snapshots = ci.capture_buildx_protection_state()
    assert [item["name"] for item in snapshots] == ["default", "desktop-linux", "orbstack"]
    assert snapshots[0]["cache_items"][0]["Size"] == "1kB"
    assert snapshots[1]["cache_items"][0]["Size"] == "1kB"
    assert snapshots[2]["cache_status"] == "UNAVAILABLE"
    assert not any("orbstack" in " ".join(command) for command in calls
                   if "inspect" in command or "du" in command)
    assert any(command[:3] == ["docker", "--context=default", "buildx"] for command in calls)
    assert any(command[:3] == ["docker", "--context=desktop-linux", "buildx"] for command in calls)

    def cache_failure(command, **kwargs):
        result = fake_run(command, **kwargs)
        if "du" in command:
            return type("Result", (), {"returncode": 1, "stdout": "", "stderr": "cache unavailable"})()
        return result

    with patch.object(ci, "run", side_effect=cache_failure):
        try:
            ci.capture_buildx_protection_state()
        except ci.ValidationError as error:
            assert "unable to snapshot Buildx cache" in str(error)
        else:
            raise AssertionError("an inaccessible cache for a reachable builder was accepted")


def test_root_filesystem_capacity_portability() -> None:
    mac_output = ("Filesystem     1024-blocks      Used Available Capacity  Mounted on\n"
                  "/dev/disk3s1s1   482797652  12350364  50798980    20%    /\n")
    linux_output = ("Filesystem     1024-blocks      Used Available Capacity Mounted on\n"
                    "/dev/vda1      100000000  40000000  60000000    40%    /\n")
    assert ci._root_filesystem_capacity(mac_output) == {
        "device": "/dev/disk3s1s1", "total_bytes": 482797652 * 1024,
        "used_bytes": 12350364 * 1024, "free_bytes": 50798980 * 1024,
        "capacity_percent": "20%"}
    assert ci._root_filesystem_capacity(linux_output)["free_bytes"] == 60_000_000 * 1024


def test_linux_x11_acceptance_stays_in_linux_profile() -> None:
    assert ci.acceptance_skip_reason("test_linux_gui.py", "Darwin") is not None
    assert ci.acceptance_skip_reason("test_linux_gui.py", "Linux") is None
    assert ci.acceptance_skip_reason("test_platform_runner.py", "Darwin") is None


def test_trivy_host_architecture_pins() -> None:
    assert ci.trivy_archive_pin("Darwin", "arm64") == (
        "trivy_0.74.0_macOS-ARM64.tar.gz",
        "1caada5e0e2091909357c7525d3aa76f4b660b13821bc143b190c7483e31cc11")
    assert ci.trivy_archive_pin("Linux", "x86_64") == (
        "trivy_0.74.0_Linux-64bit.tar.gz",
        "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a")
    try:
        ci.trivy_archive_pin("Windows", "arm64")
    except ci.ValidationError as error:
        assert "unavailable for host Windows/arm64" in str(error)
    else:
        raise AssertionError("Trivy archive selection accepted an unpinned host architecture")


def main() -> None:
    test_buildx_snapshot_context_and_unavailable_backend()
    test_root_filesystem_capacity_portability()
    test_linux_x11_acceptance_stays_in_linux_profile()
    test_trivy_host_architecture_pins()
    driver_details = ci._buildx_protection_metadata(
        "Name: ecd-v04-task-acceptance-test\nDriver:          docker-container\nNodes:\n")
    assert driver_details["driver"] == "docker-container"

    with tempfile.TemporaryDirectory(prefix="ecd-ci-protection-") as temporary:
        report_dir = Path(temporary)
        baseline = protected_state()
        manifest = write_preflight(report_dir, baseline=baseline, confirmation=baseline)

        with patch.object(ci, "capture_docker_protection_state", return_value=protected_state()):
            baseline, build_start, protection_info = ci.acceptance_protection_snapshots(report_dir, manifest)
        assert baseline == build_start
        assert protection_info["sha256"] == manifest["docker_protection_preflight"]["sha256"]
        assert baseline["images"][0]["ID"] == "sha256:foreign-any-id"
        assert json.loads((report_dir / "docker-protection-before.json").read_text()) == baseline
        assert json.loads((report_dir / "docker-protection-build-start.json").read_text()) == build_start

        telemetry_only = protected_state(volume_size="275.7MB")
        with patch.object(ci, "capture_docker_protection_state", return_value=telemetry_only):
            telemetry_baseline, telemetry_start, _ = ci.acceptance_protection_snapshots(report_dir, manifest)
        assert telemetry_baseline != telemetry_start
        assert ci.docker_ownership.strict_protection_fingerprint(telemetry_baseline) == \
               ci.docker_ownership.strict_protection_fingerprint(telemetry_start)
        volume_usage_diffs = [item for item in manifest["docker_protection_telemetry_before_acceptance"]
                              if item.get("kind") == "volume" and item.get("field") == "size"]
        assert volume_usage_diffs and volume_usage_diffs[0]["before"] == "275.8MB"
        assert volume_usage_diffs[0]["after"] == "275.7MB"

        telemetry_run_dir = report_dir / "telemetry-run"
        telemetry_run_dir.mkdir()
        telemetry_manifest = write_preflight(telemetry_run_dir, baseline=baseline, confirmation=baseline)
        telemetry_manifest["report_dir"] = str(telemetry_run_dir)
        with patch.object(ci, "assert_safe_docker_endpoint"), \
             patch.object(ci, "load_vulnerability_exceptions", return_value=[]), \
             patch.object(ci, "capture_docker_protection_state", return_value=telemetry_only), \
             patch.object(ci, "task_builder_record_path", return_value=telemetry_run_dir / "missing-builder-record.json"), \
             patch.object(ci, "persist_manifest"), \
             patch.object(ci, "ensure_task_buildx_builder", side_effect=RuntimeError("reached owned-builder setup")) as setup:
            try:
                ci.acceptance(report_dir=telemetry_run_dir, manifest=telemetry_manifest)
            except RuntimeError as error:
                assert "reached owned-builder setup" in str(error)
            else:
                raise AssertionError("size-only foreign telemetry drift prevented the allowed acceptance path")
        setup.assert_called_once()
        assert telemetry_manifest["docker_protection_telemetry_before_acceptance"]

        changed = protected_state(image_id="sha256:foreign-new", container_status="exited")
        consecutive_failures = ci.verify_gate_protection_state(
            baseline, changed,
            task_builder={"name": None, "container_id": None, "volume_names": []})
        assert any("FOREIGN_STATE_DRIFT" in failure for failure in consecutive_failures)
        drift_dir = report_dir / "drift"
        drift_dir.mkdir()
        drift_manifest = write_preflight(drift_dir, baseline=baseline, confirmation=baseline)
        with patch.object(ci, "assert_safe_docker_endpoint"), \
             patch.object(ci, "load_vulnerability_exceptions", return_value=[]), \
             patch.object(ci, "capture_docker_protection_state", return_value=changed), \
             patch.object(ci, "ensure_task_buildx_builder") as create_builder:
            try:
                ci.acceptance(report_dir=drift_dir, manifest=drift_manifest)
            except ci.ValidationError as error:
                assert "FOREIGN_STATE_DRIFT" in str(error)
            else:
                raise AssertionError("Docker drift between gate preflight and acceptance was accepted")
        create_builder.assert_not_called()
        drift = drift_manifest["foreign_state_drift_before_acceptance"]
        assert any("image identity changed" in failure for failure in drift["failures"])
        assert any("container identity changed" in failure for failure in drift["failures"])
        assert json.loads((drift_dir / "docker-protection-build-start.json").read_text()) == changed

        after_during_gate = protected_state(image_id="sha256:changed-during-gate", container_status="exited")
        preflight = drift_manifest["docker_protection_preflight"]
        final_failures = ci.verify_gate_protection_state(
            baseline, after_during_gate, task_builder={"name": None, "container_id": None, "volume_names": []},
            baseline_path=Path(preflight["report"]), baseline_sha256=preflight["sha256"],
            immutable_snapshots=[(Path(preflight["confirmation_report"]), preflight["confirmation_sha256"])])
        assert any("FOREIGN_STATE_DRIFT" in failure and "image identity changed" in failure
                   for failure in final_failures)
        assert any("FOREIGN_STATE_DRIFT" in failure and "container identity changed" in failure
                   for failure in final_failures)

        baseline_path = Path(preflight["report"])
        original_sha = ci.sha256_file(baseline_path)
        try:
            ci.write_immutable_private_json(baseline_path, after_during_gate)
        except FileExistsError:
            pass
        else:
            raise AssertionError("gate-start baseline was replaced by later state")
        assert ci.sha256_file(baseline_path) == original_sha
        baseline_path.write_text(json.dumps(after_during_gate), encoding="utf-8")
        integrity_failures = ci.verify_gate_protection_state(
            baseline, baseline, task_builder={"name": None, "container_id": None, "volume_names": []},
            baseline_path=baseline_path, baseline_sha256=original_sha)
        assert any("integrity changed: docker-protection-preflight.json" in failure
                   for failure in integrity_failures)

        source = inspect.getsource(ci)
        assert "PROTECTED_IMAGE_AUTHORITY" not in source
        assert "75a7bbc9cbc766d769381ef320f0aafeac1564126cadba8347660a89061c1edc" not in source

    print("PASS dynamic foreign Docker baseline, drift detection, and immutable snapshot checks")


if __name__ == "__main__":
    main()
