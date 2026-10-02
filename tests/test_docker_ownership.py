#!/usr/bin/env python3
"""Ownership cleanup selection excludes foreign and merely dangling resources."""
from __future__ import annotations

import tempfile
import copy
import os
import json
import shutil
from types import SimpleNamespace
from pathlib import Path
import sys
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import docker_ownership as ownership

TEST_REAL_DOCKER = shutil.which("docker") or sys.executable


def _main() -> None:
    owner = "run-" + "a" * 32
    project = "ecd-ci-" + "b" * 32
    claims = [
        {"kind": "project", "name": project, "owner_token": owner, "preflight": "ABSENT"},
        {"kind": "volume", "name": "task-wallet", "owner_token": owner, "preflight": "ABSENT"},
        {"kind": "image", "name": "electron-cash-ci:task", "owner_token": owner,
         "preflight": "ABSENT", "build_attempted": True, "expected_id": "sha256:task"},
        {"kind": "image", "name": "electron-cash-ci:unbuilt", "owner_token": owner,
         "preflight": "ABSENT", "build_attempted": False, "expected_id": None},
        {"kind": "image", "name": "electron-cash:4.4.6", "owner_token": owner,
         "preflight": "ABSENT", "build_attempted": True, "expected_id": "sha256:product",
         "retain": True},
        {"kind": "project", "name": "bchforge-test-foreign", "owner_token": "foreign", "preflight": "ABSENT"},
    ]
    selected = ownership.select_cleanup_targets(owner, claims,
        containers=[
            {"id": "container-task", "labels": {ownership.PROJECT_LABEL: project}},
            {"id": "container-prefix", "labels": {ownership.PROJECT_LABEL: project + "-foreign"}},
            {"id": "container-foreign", "labels": {ownership.OWNER_LABEL: "foreign"}},
            {"id": "container-owned", "labels": {ownership.OWNER_LABEL: owner}},
        ],
        networks=[
            {"id": "network-task", "labels": {ownership.PROJECT_LABEL: project}},
            {"id": "network-prefix", "labels": {ownership.PROJECT_LABEL: project + "-foreign"}},
        ],
        volumes=[
            {"name": "task-wallet", "labels": {ownership.PROJECT_LABEL: project}},
            {"name": "task-rollback", "labels": {ownership.OWNER_LABEL: owner}},
            {"name": "task-wallet-foreign", "labels": {ownership.PROJECT_LABEL: project + "-foreign"}},
            {"name": "other-wallet", "labels": {ownership.OWNER_LABEL: "foreign"}},
        ],
        images=[
            {"id": "sha256:task", "repo_tags": ["electron-cash-ci:task"]},
            {"id": "sha256:replacement", "repo_tags": ["electron-cash-ci:task"]},
            {"id": "sha256:foreign", "repo_tags": ["electron-cash-ci:foreign"]},
            {"id": "sha256:dangling", "repo_tags": ["<none>:<none>"]},
            {"id": "sha256:product", "repo_tags": ["electron-cash:4.4.6"]},
        ])

    assert selected == {
        "containers": ["container-owned", "container-task"],
        "networks": ["network-task"],
        "volumes": ["task-rollback", "task-wallet"],
        "images": ["electron-cash-ci:task"],
    }, selected
    assert ownership.resource_is_owned("container", {"labels": {ownership.PROJECT_LABEL: project}}, owner, claims)
    assert not ownership.resource_is_owned("container", {"labels": {ownership.PROJECT_LABEL: project + "-foreign"}}, owner, claims)
    assert ownership.resource_is_owned("volume", {"name": "task-wallet", "labels": {ownership.PROJECT_LABEL: project}}, owner, claims)
    assert not ownership.resource_is_owned("volume", {"name": "task-wallet", "labels": {ownership.PROJECT_LABEL: project + "-foreign"}}, owner, claims)
    assert ownership.resource_is_owned("image", {"id": "sha256:task", "repo_tags": ["electron-cash-ci:task"]}, owner, claims)
    assert ownership.resource_is_owned("image", {"id": "sha256:product", "repo_tags": ["electron-cash:4.4.6"]}, owner, claims)
    assert not ownership.resource_is_owned("image", {"id": "sha256:replacement", "repo_tags": ["electron-cash-ci:task"]}, owner, claims)

    with tempfile.TemporaryDirectory(prefix="ecd-retained-image-claim-") as temporary:
        registry = Path(temporary) / "claims.jsonl"
        registry.write_text(json.dumps({"schema_version": ownership.SCHEMA_VERSION,
            "claim_id": "3" * 32, "kind": "image", "name": "electron-cash:4.4.6",
            "owner_token": owner, "preflight": "ABSENT"}) + "\n", encoding="utf-8")
        ownership.record_image_attempt(registry, "electron-cash:4.4.6", owner,
                                        "sha256:product", retain=True)
        ownership.record_image_attempt(registry, "electron-cash:4.4.6", owner,
                                        "sha256:product")
        retained_claim = ownership.read_claims(registry)[0]
        assert retained_claim["retain"] is True and retained_claim["expected_id"] == "sha256:product"

    verified_claims = [
        {"kind": "project", "name": project, "owner_token": owner, "preflight": "ABSENT"},
        {"kind": "image", "name": "electron-cash-ci:unit", "owner_token": owner,
         "preflight": "ABSENT", "build_attempted": True, "expected_id": "sha256:verified"},
    ]
    def verified_image_runner(command, **_kwargs):
        return type("Result", (), {"returncode": 0, "stdout": "sha256:verified\n", "stderr": ""})()
    with patch.object(ownership, "_docker", side_effect=verified_image_runner):
        assert ownership._verified_image_id("electron-cash-ci:unit", verified_claims, owner) == "sha256:verified"
        plan_calls = []

        def compose_image_runner(command, **_kwargs):
            plan_calls.append(command)
            if command[:4] == ["compose", "-p", project, "config"]:
                model = {"services": {"wallet": {"image": "electron-cash-ci:unit", "volumes": []}},
                         "volumes": {}}
                return type("Result", (), {"returncode": 0, "stdout": json.dumps(model), "stderr": ""})()
            return type("Result", (), {"returncode": 0, "stdout": "sha256:verified\n", "stderr": ""})()
        with patch.object(ownership, "_docker", side_effect=compose_image_runner):
            plan = ownership._compose_up_plan(
                ["compose", "-p", project, "up", "-d"], "up", verified_claims, owner)
        assert plan["service_image_ids"] == {"wallet": "sha256:verified"}
        assert len(plan_calls) == 2

    compose_up_claims = [
        {"schema_version": ownership.SCHEMA_VERSION, "claim_id": "1" * 32,
         "kind": "project", "name": project, "owner_token": owner, "preflight": "ABSENT"},
        {"schema_version": ownership.SCHEMA_VERSION, "claim_id": "2" * 32,
         "kind": "volume", "name": "task-wallet", "owner_token": owner, "preflight": "ABSENT"},
    ]
    with tempfile.TemporaryDirectory(prefix="ecd-compose-up-plan-") as temporary:
        registry = Path(temporary) / "claims.jsonl"
        registry.write_text("\n".join(json.dumps(claim) for claim in compose_up_claims) + "\n")
        plan = {"project": project, "operation": "up", "volumes": ["task-wallet"],
                "services": ["wallet"], "service_images": {}, "service_image_ids": {}}

        compose_up_timeouts = []

        def compose_up_runner(command, **kwargs):
            if command[:2] == ["volume", "inspect"]:
                return SimpleNamespace(returncode=0,
                                        stdout=json.dumps([{"Name": "task-wallet", "Labels": {}}]),
                                        stderr="")
            if command[0] == "compose":
                compose_up_timeouts.append(kwargs.get("timeout"))
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            raise AssertionError(f"unexpected compose-up verification command: {command}")

        with patch.dict(os.environ, {"CI_REAL_DOCKER": TEST_REAL_DOCKER, "CI_RESOURCE_OWNER": owner,
                                     "CI_RESOURCE_REGISTRY": str(registry)}, clear=False), \
             patch.object(ownership, "_docker", side_effect=compose_up_runner), \
             patch.object(ownership, "_compose_up_plan", return_value=plan), \
             patch.object(ownership, "_project_resource_snapshot",
                          return_value={"containers": [], "networks": [], "volumes": []}), \
             patch.object(ownership, "_emit_resource_event"):
            with patch.object(ownership.sys, "argv", ["docker", "compose", "-p", project, "up", "-d"]):
                assert ownership.docker_shim_main() == 0
            with patch.object(ownership.sys, "argv", ["docker", "compose", "-p", project, "up",
                                                       "--no-build", "--no-deps", "electron-cash"]):
                assert ownership.docker_shim_main() == 0
        assert compose_up_timeouts == [600, None], compose_up_timeouts

    def replaced_image_runner(_command, **_kwargs):
        return type("Result", (), {"returncode": 0, "stdout": "sha256:replaced\n", "stderr": ""})()
    with patch.object(ownership, "_docker", side_effect=replaced_image_runner):
        try:
            ownership._verified_image_id("electron-cash-ci:unit", verified_claims, owner)
        except ownership.OwnershipError as error:
            assert "changed identity" in str(error)
        else:
            raise AssertionError("replaced candidate image ID was accepted for runtime")

    with tempfile.TemporaryDirectory(prefix="ecd-ownership-test-") as temporary:
        registry = Path(temporary) / "claims.jsonl"
        answers = iter([
            (0, "", ""), (0, "", ""), (0, "", ""),  # exact project container/network/volume lists
            (1, "", "Error response from daemon: get task-wallet: no such volume"),
        ])

        def fake_runner(command, **_kwargs):
            code, stdout, stderr = next(answers)
            return type("Result", (), {"returncode": code, "stdout": stdout, "stderr": stderr})()

        project_claim = ownership.append_claim(registry, "project", project, owner, runner=fake_runner)
        volume_claim = ownership.append_claim(registry, "volume", "task-wallet", owner, runner=fake_runner)
        def missing_network_runner(command, **_kwargs):
            assert command == ["docker", "network", "inspect", "task-network"]
            return type("Result", (), {"returncode": 1, "stdout": "",
                                       "stderr": "Error response from daemon: network task-network not found"})()
        network_claim = ownership.append_claim(
            registry, "network", "task-network", owner, runner=missing_network_runner)
        reread = ownership.read_claims(registry)
        assert project_claim["preflight"] == volume_claim["preflight"] == "ABSENT"
        assert network_claim["preflight"] == "ABSENT"
        assert [(claim["kind"], claim["name"]) for claim in reread] == [
            ("project", project), ("volume", "task-wallet"), ("network", "task-network")]

    def collision_runner(_command, **_kwargs):
        return type("Result", (), {"returncode": 0, "stdout": "foreign-id\n", "stderr": ""})()
    try:
        ownership.reserve_claim("project", "foreign-project", owner, runner=collision_runner)
    except ownership.OwnershipError as error:
        assert "collision" in str(error)
    else:
        raise AssertionError("pre-existing exact project label was accepted as task-owned")
    try:
        ownership.reserve_claim("volume", "poweredbycash-private-data", owner, runner=collision_runner)
    except ownership.OwnershipError as error:
        assert "collision" in str(error)
    else:
        raise AssertionError("pre-existing foreign volume was accepted as a task claim")

    before = {
        "images": [{"repository": "pbc-app", "tag": "v0.1-local-accepted", "ID": "sha256:pbc", "Digest": "sha256:pbc",
                    "created_at": "2026-09-01T00:00:00Z", "size": "605MB",
                    "metadata": {"labels": {"accepted": "true"}, "rootfs_layers": ["layer-1"]}}],
        "containers": [{"id": "pbc-container", "name": "poweredby-app", "configured_image": "pbc-app:v0.1-local-accepted",
                        "image_id": "sha256:pbc", "created": "2026-09-01T00:00:00Z",
                        "status": "running", "running": True, "health": "healthy",
                        "health_details": {"failing_streak": 0}, "state_details": {"StartedAt": "now"},
                        "restart_count": 0,
                        "config_identity": {"User": "10001", "environment_sha256": "env-hash",
                                            "launch_sha256": "launch-hash"},
                        "labels": {"com.docker.compose.project": "poweredbycash"},
                        "mounts": [{"name": "poweredby-data", "destination": "/data"}],
                        "networks": {"pbc-network": {"NetworkID": "pbc-net", "EndpointID": "endpoint-1",
                                                       "IPAddress": "172.20.0.2", "Aliases": ["app"]}},
                        "ports": {}, "host_config": {"Privileged": False, "Devices": []}}],
        "volumes": [{"name": "poweredby-data", "driver": "local", "scope": "local",
                     "created_at": "2026-09-01T00:00:00Z",
                     "labels": {"service": "pbc"}, "mountpoint": "/var/lib/docker/volumes/poweredby-data/_data",
                     "options": {}, "usage_data": {"Size": 1_000_000, "RefCount": 1}, "size": "1MB"}],
        "networks": [{"id": "pbc-net", "name": "poweredby-net", "driver": "bridge", "scope": "local",
                      "internal": False, "attachable": False, "ingress": False, "labels": {}, "subnets": ["172.20.0.0/16"],
                      "containers": {"pbc-container": {"EndpointID": "endpoint-1"}}}],
        "builders": [{"name": "default", "driver": "docker", "nodes": [{"name": "default", "endpoint": "default"}],
                      "configuration": "Name: default\nDriver: docker\nNodes:\nName: default\n",
                      "inspect_telemetry": {"last_activity": ["now"], "statuses": ["running"]},
                      "cache_items": [{"ID": "foreign-cache", "Size": "1GB"}],
                      "cache_total_bytes": 1_000_000_000, "inspect": "Name: default\nNodes: default\n"}],
        "captured_at": "2026-09-26T18:00:00Z",
        "root_filesystem": {"device": "/dev/test", "total_bytes": 1000,
                             "used_bytes": 500, "free_bytes": 500, "capacity_percent": "50%"},
        "docker_system_df": "Images: 1GB\nBuild cache: 1GB\n",
        "daemon": "engine-id|/var/lib/docker|overlay2|29.0|linux|linux|x86_64",
    }
    after = copy.deepcopy(before)
    after["containers"].append({"id": "task-buildkit", "name": "buildx_buildkit_task0",
                                "configured_image": "moby/buildkit:buildx-stable-1",
                                "image_id": "sha256:buildkit", "status": "running", "running": True, "health": None})
    after["volumes"].append({"name": "buildx_task_state", "driver": "local", "scope": "local",
                             "labels": {"owner": owner}, "size": "2MB"})
    after["builders"].append({"name": "task-builder", "cache_items": []})
    task_builder = {"name": "task-builder", "container_id": "task-buildkit", "volume_name": "buildx_task_state"}
    assert ownership.compare_preexisting_state(before, after, task_builder=task_builder) == []

    first_install = copy.deepcopy(before)
    first_install["images"].append({"repository": "electron-cash", "tag": "4.4.6",
                                    "ID": "sha256:first-install", "Digest": None,
                                    "created_at": "now", "size": 100, "metadata": {}})
    retained_identity = {"name": None, "container_id": None,
                         "volume_names": [], "image_ids": ["sha256:first-install"]}
    assert ownership.compare_preexisting_state(before, first_install, task_builder=retained_identity) == []
    foreign_addition = copy.deepcopy(first_install)
    foreign_addition["images"].append({"repository": "foreign", "tag": "unclaimed",
                                       "ID": "sha256:foreign-new", "Digest": None,
                                       "created_at": "now", "size": 100, "metadata": {}})
    assert any("unexpected images additions" in failure for failure in
               ownership.compare_preexisting_state(before, foreign_addition,
                                                   task_builder=retained_identity))

    telemetry_only = copy.deepcopy(before)
    telemetry_only["volumes"][0]["size"] = "2MB"
    telemetry_only["volumes"][0]["usage_data"]["Size"] = 2_000_000
    telemetry_only["containers"][0]["status"] = "exited"
    telemetry_only["containers"][0]["health_details"] = {"failing_streak": 1}
    telemetry_only["containers"][0]["networks"]["pbc-network"]["IPAddress"] = "172.20.0.3"
    telemetry_only["builders"][0]["cache_items"][0]["ID"] = "other-cache-content"
    telemetry_only["builders"][0]["cache_total_bytes"] = 2_000_000_000
    telemetry_only["builders"][0]["inspect_telemetry"]["last_activity"] = ["later"]
    telemetry_only["captured_at"] = "2026-09-26T18:01:00Z"
    telemetry_only["root_filesystem"].update({"used_bytes": 600, "free_bytes": 400,
                                              "capacity_percent": "60%"})
    telemetry_only["docker_system_df"] = "Images: 2GB\nBuild cache: 2GB\n"
    assert before != telemetry_only
    assert ownership.strict_protection_fingerprint(before) == ownership.strict_protection_fingerprint(telemetry_only)
    telemetry = ownership.compare_snapshot_telemetry(before, telemetry_only)
    assert any(item["kind"] == "volume" and item["field"] == "size" for item in telemetry)
    assert any(item["kind"] == "volume" and item["field"] == "usage_data" for item in telemetry)
    assert any(item["kind"] == "builder" and item["field"] == "cache_items" for item in telemetry)
    assert any(item["kind"] == "filesystem" and item["field"] == "free_bytes" for item in telemetry)
    assert any(item["kind"] == "docker" and item["field"] == "system_df" for item in telemetry)
    assert "volumes.size/usage_data" in ownership.TELEMETRY_ONLY_FIELD_POLICY
    assert ownership.compare_preexisting_state(
        before, telemetry_only, task_builder={"name": None, "container_id": None, "volume_names": []}) == []

    mutated = copy.deepcopy(after)
    mutated["images"][0]["ID"] = "sha256:replaced"
    mutated["containers"][0]["status"] = "exited"
    mutated["volumes"][0]["size"] = "2MB"
    mutated["builders"][0]["cache_items"][0]["ID"] = "deleted-foreign-cache"
    mutated["containers"][0]["labels"]["com.docker.compose.project"] = "changed-project"
    mutated["containers"][0]["config_identity"]["environment_sha256"] = "changed-env-hash"
    mutated["containers"][0]["host_config"]["Devices"] = [{"PathOnHost": "/dev/foreign"}]
    mutated["volumes"][0]["options"]["type"] = "changed"
    mutated["volumes"][0]["driver"] = "foreign-driver"
    mutated["volumes"][0]["labels"]["service"] = "changed-service"
    mutated["networks"][0]["containers"]["pbc-container"]["EndpointID"] = "changed-endpoint"
    mutated["builders"][0]["nodes"][0]["endpoint"] = "replaced-endpoint"
    mutated["builders"][0]["configuration"] = "Name: default\nDriver: changed\n"
    mutated["daemon"] = "different-engine"
    failures = ownership.compare_preexisting_state(before, mutated, task_builder=task_builder)
    assert any("image identity changed" in failure for failure in failures)
    assert any("container identity changed" in failure for failure in failures)
    assert any("volume identity changed" in failure for failure in failures)
    assert any("builder identity changed" in failure for failure in failures)
    assert any("network identity changed" in failure for failure in failures)
    assert any("Docker daemon identity" in failure for failure in failures)

    container_image_replaced = copy.deepcopy(before)
    container_image_replaced["containers"][0]["image_id"] = "sha256:replacement"
    assert any("container identity changed" in failure for failure in ownership.compare_preexisting_state(
        before, container_image_replaced,
        task_builder={"name": None, "container_id": None, "volume_names": []}))

    volume_recreated = copy.deepcopy(before)
    volume_recreated["volumes"][0]["created_at"] = "2026-09-27T00:00:00Z"
    assert any("volume identity changed" in failure for failure in ownership.compare_preexisting_state(
        before, volume_recreated, task_builder={"name": None, "container_id": None, "volume_names": []}))
    volume_deleted = copy.deepcopy(before)
    volume_deleted["volumes"] = []
    assert any("volume identity disappeared" in failure for failure in ownership.compare_preexisting_state(
        before, volume_deleted, task_builder={"name": None, "container_id": None, "volume_names": []}))
    builder_deleted = copy.deepcopy(before)
    builder_deleted["builders"] = []
    assert any("builder identity disappeared" in failure for failure in ownership.compare_preexisting_state(
        before, builder_deleted, task_builder={"name": None, "container_id": None, "volume_names": []}))

    tag_replaced = copy.deepcopy(before)
    tag_replaced["images"][0]["ID"] = "sha256:new-image"
    assert any("image identity changed" in failure for failure in ownership.compare_preexisting_state(
        before, tag_replaced, task_builder={"name": None, "container_id": None, "volume_names": []}))
    retagged = copy.deepcopy(before)
    retagged["images"][0].update({"tag": "new-local-tag", "ID": "sha256:new-image"})
    retag_failures = ownership.compare_preexisting_state(
        before, retagged, task_builder={"name": None, "container_id": None, "volume_names": []})
    assert any("image identity disappeared" in failure or "unexpected images additions" in failure
               for failure in retag_failures)
    recreated = copy.deepcopy(before)
    recreated["containers"][0]["id"] = "replacement-container"
    assert any("container identity disappeared" in failure or "unexpected containers additions" in failure
               for failure in ownership.compare_preexisting_state(
                   before, recreated, task_builder={"name": None, "container_id": None, "volume_names": []}))

    with patch.dict(os.environ, {"CI_REAL_DOCKER": TEST_REAL_DOCKER, "CI_RESOURCE_OWNER": owner}, clear=False), \
         patch.object(ownership.sys, "argv", ["docker", "system", "prune", "--all", "--force"]):
        assert ownership.docker_shim_main() == 95
    with patch.dict(os.environ, {"CI_REAL_DOCKER": TEST_REAL_DOCKER, "CI_RESOURCE_OWNER": owner}, clear=False), \
         patch.object(ownership.sys, "argv", ["docker", "buildx", "rm", "default"]):
        assert ownership.docker_shim_main() == 95

    with tempfile.TemporaryDirectory(prefix="ecd-rollback-claim-") as rollback_directory:
        rollback_registry = Path(rollback_directory) / "claims.jsonl"
        rollback_events = Path(rollback_directory) / "events.jsonl"
        rollback_registry.write_text(json.dumps({"schema_version": 1, "kind": "project", "name": project,
                                                 "owner_token": owner, "preflight": "ABSENT"}) + "\n")
        rollback_labels = ["--label", "com.bchforge.electron-cash-docker.managed=rollback",
                           "--label", f"{ownership.ROLLBACK_PROJECT_LABEL}={project}",
                           "--label", f"{ownership.OWNER_LABEL}={owner}"]

        def rollback_runner(command, **_kwargs):
            if command[:2] == ["volume", "create"]:
                return SimpleNamespace(returncode=0, stdout="task-rollback-volume\n", stderr="")
            if command[:2] == ["volume", "inspect"]:
                item = {"Name": "task-rollback-volume", "Labels": {
                    ownership.OWNER_LABEL: owner,
                    "com.bchforge.electron-cash-docker.managed": "rollback",
                    ownership.ROLLBACK_PROJECT_LABEL: project}}
                return SimpleNamespace(returncode=0, stdout=json.dumps([item]), stderr="")
            raise AssertionError(f"unexpected rollback-volume Docker call: {command}")

        with patch.dict(os.environ, {"CI_REAL_DOCKER": TEST_REAL_DOCKER, "CI_RESOURCE_OWNER": owner,
                                     "CI_RESOURCE_REGISTRY": str(rollback_registry),
                                     "CI_RESOURCE_EVENT_LOG": str(rollback_events)}, clear=False), \
             patch.object(ownership.sys, "argv", ["docker", "volume", "create", *rollback_labels]), \
             patch.object(ownership, "_real_docker", return_value="/mock/docker"), \
             patch.object(ownership, "_docker", side_effect=rollback_runner):
            assert ownership.docker_shim_main() == 0
            rollback_claims = ownership.read_claims(rollback_registry)
            claim = ownership._claimed_volume("task-rollback-volume", rollback_claims, owner)
            assert claim.get("preflight") == "CREATED_ROLLBACK"
            assert ownership.resource_is_owned(
                "volume", {"name": "task-rollback-volume", "labels": {
                    ownership.OWNER_LABEL: owner,
                    ownership.ROLLBACK_PROJECT_LABEL: project,
                    "com.bchforge.electron-cash-docker.managed": "rollback",
                }}, owner, rollback_claims)
            assert not ownership.resource_is_owned(
                "volume", {"name": "foreign-rollback", "labels": {
                    ownership.OWNER_LABEL: owner,
                    ownership.ROLLBACK_PROJECT_LABEL: "foreign-project",
                    "com.bchforge.electron-cash-docker.managed": "rollback",
                }}, owner, rollback_claims)

    foreign_project = "pbc-foreign-project"
    foreign_volume = "pbc-foreign-wallet"
    compose_registry = [
        {"schema_version": ownership.SCHEMA_VERSION, "kind": "project", "name": project,
         "owner_token": owner, "preflight": "ABSENT"},
        {"schema_version": ownership.SCHEMA_VERSION, "kind": "volume", "name": foreign_volume,
         "owner_token": owner, "preflight": "ABSENT"},
    ]
    with tempfile.TemporaryDirectory(prefix="ecd-foreign-volume-guard-") as temporary:
        registry = Path(temporary) / "claims.jsonl"
        registry.write_text("\n".join(json.dumps(item) for item in compose_registry) + "\n")
        environment = {"CI_REAL_DOCKER": TEST_REAL_DOCKER, "CI_RESOURCE_OWNER": owner,
                       "CI_RESOURCE_REGISTRY": str(registry)}

        def direct_volume_fake(command, **_kwargs):
            if command[:2] == ["volume", "inspect"]:
                item = {"Name": foreign_volume, "Labels": {ownership.PROJECT_LABEL: foreign_project}}
                return SimpleNamespace(returncode=0, stdout=json.dumps([item]), stderr="")
            raise AssertionError(f"foreign Docker run reached an unexpected daemon call: {command}")

        with patch.dict(os.environ, environment, clear=False), \
             patch.object(ownership, "_real_docker", return_value="/mock/docker"), \
             patch.object(ownership, "_docker", side_effect=direct_volume_fake), \
             patch.object(ownership.sys, "argv", ["docker", "run", "--rm", "--mount",
                                                  f"type=volume,src={foreign_volume},dst=/wallet", "alpine"]), \
             patch.object(ownership.subprocess, "Popen", side_effect=AssertionError("foreign mount must not start")):
            assert ownership.docker_shim_main() == 95

        with patch.dict(os.environ, environment, clear=False), \
             patch.object(ownership, "_real_docker", return_value="/mock/docker"), \
             patch.object(ownership, "_docker", side_effect=direct_volume_fake), \
             patch.object(ownership.sys, "argv", ["docker", "volume", "create", foreign_volume]):
            assert ownership.docker_shim_main() == 95

        def bind_volume_fake(command, **_kwargs):
            if command[:2] == ["info", "--format"]:
                return SimpleNamespace(returncode=0, stdout="/var/lib/docker\n", stderr="")
            if command[:2] == ["volume", "inspect"]:
                item = {"Name": foreign_volume, "Mountpoint": f"/var/lib/docker/volumes/{foreign_volume}/_data",
                        "Labels": {ownership.PROJECT_LABEL: foreign_project}}
                return SimpleNamespace(returncode=0, stdout=json.dumps([item]), stderr="")
            raise AssertionError(f"foreign bind mount reached an unexpected daemon call: {command}")

        with patch.dict(os.environ, environment, clear=False), \
             patch.object(ownership, "_real_docker", return_value="/mock/docker"), \
             patch.object(ownership, "_docker", side_effect=bind_volume_fake), \
             patch.object(ownership.sys, "argv", ["docker", "run", "--rm", "--mount",
                                                  f"type=bind,src=/var/lib/docker/volumes/{foreign_volume}/_data,dst=/wallet",
                                                  "alpine"]), \
             patch.object(ownership.subprocess, "Popen", side_effect=AssertionError("foreign bind mount must not start")):
            assert ownership.docker_shim_main() == 95

        unclaimed_registry = Path(temporary) / "unclaimed.jsonl"
        unclaimed_registry.touch()
        unclaimed_environment = {**environment, "CI_RESOURCE_REGISTRY": str(unclaimed_registry)}
        with patch.dict(os.environ, unclaimed_environment, clear=False), \
             patch.object(ownership, "_real_docker", return_value="/mock/docker"), \
             patch.object(ownership.sys, "argv", ["docker", "run", "--rm", "--mount",
                                                  f"type=volume,src={foreign_volume},dst=/wallet", "alpine"]), \
             patch.object(ownership, "_docker", side_effect=AssertionError("unclaimed mount must not be inspected")), \
             patch.object(ownership.subprocess, "Popen", side_effect=AssertionError("unclaimed mount must not start")):
            assert ownership.docker_shim_main() == 95

        def compose_fake(command, **_kwargs):
            if command[:2] == ["compose", "-p"] and "config" in command:
                model = {"services": {"wallet": {"volumes": [
                    {"type": "volume", "source": "wallet-data", "target": "/wallet"}]}},
                         "volumes": {"wallet-data": {"name": foreign_volume, "external": True}}}
                return SimpleNamespace(returncode=0, stdout=json.dumps(model), stderr="")
            if command[:2] == ["volume", "inspect"]:
                item = {"Name": foreign_volume, "Labels": {ownership.PROJECT_LABEL: foreign_project}}
                return SimpleNamespace(returncode=0, stdout=json.dumps([item]), stderr="")
            raise AssertionError(f"foreign Compose volume check reached an unexpected daemon call: {command}")

        with patch.dict(os.environ, environment, clear=False), \
             patch.object(ownership, "_real_docker", return_value="/mock/docker"), \
             patch.object(ownership, "_docker", side_effect=compose_fake), \
             patch.object(ownership.sys, "argv", ["docker", "compose", "-p", project, "up", "-d"]):
            assert ownership.docker_shim_main() == 95

        def delete_fake(command, **_kwargs):
            if command[:2] == ["volume", "inspect"]:
                item = {"Name": foreign_volume, "Labels": {ownership.PROJECT_LABEL: foreign_project}}
                return SimpleNamespace(returncode=0, stdout=json.dumps([item]), stderr="")
            raise AssertionError(f"foreign volume deletion reached an unexpected daemon call: {command}")

        with patch.dict(os.environ, environment, clear=False), \
             patch.object(ownership, "_real_docker", return_value="/mock/docker"), \
             patch.object(ownership, "_docker", side_effect=delete_fake), \
             patch.object(ownership.sys, "argv", ["docker", "volume", "rm", foreign_volume]):
            assert ownership.docker_shim_main() == 95

    with patch.dict(os.environ, {"CI_REAL_DOCKER": TEST_REAL_DOCKER, "CI_DISK_START_BYTES": "100",
                                "CI_DISK_FLOOR_BYTES": "50", "CI_DISK_CANCEL_BYTES": "60",
                                "CI_DISK_PATHS": ""}), \
         patch.object(ownership.shutil, "disk_usage", return_value=SimpleNamespace(free=99)), \
         patch.object(ownership.subprocess, "Popen", side_effect=AssertionError("build must not start")):
        assert ownership._run_build_with_disk_guard(["compose", "build"]) == 87

    class FakeBuild:
        pid = 4321
        returncode = None
        def poll(self): return self.returncode
        def wait(self, timeout=None): self.returncode = -15; return self.returncode

    free_values = iter((100, 49, 49))
    fake_build = FakeBuild()
    with patch.dict(os.environ, {"CI_REAL_DOCKER": TEST_REAL_DOCKER, "CI_DISK_START_BYTES": "100",
                                "CI_DISK_FLOOR_BYTES": "50", "CI_DISK_CANCEL_BYTES": "60",
                                "CI_DISK_PATHS": ""}), \
         patch.object(ownership.shutil, "disk_usage", side_effect=lambda _path: SimpleNamespace(free=next(free_values))), \
         patch.object(ownership.subprocess, "Popen", return_value=fake_build), \
         patch.object(ownership.os, "killpg"), patch.object(ownership.time, "sleep"):
        assert ownership._run_build_with_disk_guard(["compose", "build"]) == 86

    completed_build = FakeBuild()
    completed_build.returncode = 0
    completed_free = iter((100, 49))
    with patch.dict(os.environ, {"CI_REAL_DOCKER": TEST_REAL_DOCKER, "CI_DISK_START_BYTES": "100",
                                "CI_DISK_FLOOR_BYTES": "50", "CI_DISK_CANCEL_BYTES": "60",
                                "CI_DISK_PATHS": ""}), \
         patch.object(ownership.shutil, "disk_usage", side_effect=lambda _path: SimpleNamespace(free=next(completed_free))), \
         patch.object(ownership.subprocess, "Popen", return_value=completed_build):
        assert ownership._run_build_with_disk_guard(["compose", "build"]) == 86

    multi_path_free = iter((100, 100, 100, 59, 100, 59))
    multi_path_build = FakeBuild()
    with patch.dict(os.environ, {"CI_REAL_DOCKER": TEST_REAL_DOCKER, "CI_DISK_START_BYTES": "100",
                                "CI_DISK_FLOOR_BYTES": "50", "CI_DISK_CANCEL_BYTES": "60",
                                "CI_DISK_PATHS": "/checkout:/docker-root"}), \
         patch.object(ownership.shutil, "disk_usage",
                      side_effect=lambda _path: SimpleNamespace(free=next(multi_path_free))), \
         patch.object(ownership.subprocess, "Popen", return_value=multi_path_build), \
         patch.object(ownership.os, "killpg"), patch.object(ownership.time, "sleep"):
        assert ownership._run_build_with_disk_guard(["compose", "build"]) == 86

    state_before = {
        "images": [], "containers": [], "volumes": [],
        "networks": [{"id": "bridge-id", "name": "bridge", "driver": "bridge", "containers": {}}],
        "builders": [{"name": "default", "driver": "docker", "nodes": [], "configuration": "default"}],
        "daemon": "engine", "root_filesystem": {"device": "/dev/root", "total_bytes": 1000},
    }
    state_after = json.loads(json.dumps(state_before))
    task_container_id = "task-buildkit-container"
    task_builder_name = "ecd-v04-task-acceptance-test"
    task_volume_name = "buildx_buildkit_ecd-v04-task-acceptance-test0_state"
    state_after["containers"].append({"id": task_container_id, "name": "buildkit-task"})
    state_after["volumes"].append({"name": task_volume_name})
    state_after["networks"][0]["containers"][task_container_id] = {"EndpointID": "task-endpoint"}
    state_after["builders"].append({"name": task_builder_name, "driver": "docker-container",
                                     "nodes": [], "configuration": "task"})
    task_builder = {"name": task_builder_name, "container_id": task_container_id,
                    "volume_names": [task_volume_name]}
    assert ownership.compare_preexisting_state(state_before, state_after, task_builder=task_builder) == []
    state_after["networks"][0]["containers"]["foreign-container"] = {"EndpointID": "foreign-endpoint"}
    assert any("network identity changed" in failure for failure in
               ownership.compare_preexisting_state(state_before, state_after, task_builder=task_builder))

    print("PASS Docker cleanup selects exact owner-token resources and protects foreign/prefix/dangling identities")


def main() -> None:
    # This unit suite uses fake owners and resource registries. Never append its
    # simulated events to the live acceptance run's durable event ledger.
    with patch.dict(os.environ, {"CI_RESOURCE_EVENT_LOG": ""}, clear=False):
        _main()


if __name__ == "__main__":
    main()
