#!/usr/bin/env python3
"""Ownership claims and fail-closed cleanup planning for Docker test resources."""
from __future__ import annotations

import json
import fcntl
import subprocess
import os
import shutil
import signal
import sys
import time
import tempfile
import uuid
import re
from pathlib import Path
from typing import Any, Callable


OWNER_LABEL = "com.bchforge.electron-cash-docker.test-owner"
PROJECT_LABEL = "com.docker.compose.project"
ROLLBACK_PROJECT_LABEL = "com.bchforge.electron-cash-docker.project"
SCHEMA_VERSION = 1
TASK_BUILDKIT_IMAGE = "moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8"
TELEMETRY_ONLY_FIELD_POLICY = {
    "captured_at": "snapshot wall-clock time changes on every observation",
    "root_filesystem.used_bytes/free_bytes/capacity_percent": "ordinary builds and foreign workloads change disk usage",
    "docker_system_df": "aggregate usage changes as images, volumes, and caches are read or written",
    "volumes.size/usage_data": "volume contents are mutable runtime data; name/driver/labels/options/creation identity remain strict",
    "containers.status/running/health/health_details/state_details/restart_count/ports": "runtime lifecycle, health, endpoint and counter observations can change without container replacement",
    "containers.networks.Gateway/IPAddress/GlobalIPv6Address/MacAddress": "endpoint addressing is runtime telemetry; NetworkID/EndpointID/aliases remain strict",
    "networks.containers.MacAddress/IPv4Address/IPv6Address": "network endpoint addressing is runtime telemetry; container/EndpointID attachment identity remains strict",
    "builders.cache_items/cache_total_bytes": "BuildKit cache contents and usage evolve during legitimate builds",
    "builders.inspect.Last Activity/Status": "activity and liveness can change without builder/node replacement or reconfiguration",
}


class OwnershipError(RuntimeError):
    """A resource could not be proven absent/owned by this test run."""


def _run(command: list[str], runner: Callable[..., Any] | None = None) -> Any:
    execute = runner or subprocess.run
    return execute(command, text=True, capture_output=True, check=False, timeout=60)


def assert_absent(kind: str, name: str, *, runner: Callable[..., Any] | None = None) -> None:
    """Refuse a task-generated name if an object already occupies it."""
    if kind == "project":
        checks = (
            ["docker", "ps", "-aq", "--filter", f"label={PROJECT_LABEL}={name}"],
            ["docker", "network", "ls", "-q", "--filter", f"label={PROJECT_LABEL}={name}"],
            ["docker", "volume", "ls", "-q", "--filter", f"label={PROJECT_LABEL}={name}"],
        )
    elif kind == "volume":
        checks = (["docker", "volume", "inspect", name],)
    elif kind == "network":
        checks = (["docker", "network", "inspect", name],)
    elif kind == "container":
        checks = (["docker", "inspect", name],)
    elif kind == "image":
        checks = (["docker", "image", "inspect", name],)
    else:
        raise OwnershipError(f"unsupported Docker resource claim kind: {kind}")

    for command in checks:
        result = _run(command, runner)
        if kind == "project":
            if result.returncode != 0:
                raise OwnershipError(f"unable to verify Compose project is absent: {name}")
            if result.stdout.strip():
                raise OwnershipError(f"refusing resource-name collision for project {name}")
            continue
        if result.returncode == 0 and result.stdout.strip():
            raise OwnershipError(f"refusing resource-name collision for {kind} {name}")
        if result.returncode != 0:
            output = (result.stdout + result.stderr).lower()
            absent_phrases = {
                "volume": ("no such volume",),
                "network": ("no such network", f"network {name.lower()} not found"),
                "container": ("no such object", "no such container"),
                "image": ("no such image", "no such object"),
            }
            if not any(phrase in output for phrase in absent_phrases[kind]):
                raise OwnershipError(f"unable to verify {kind} is absent: {name}")


def reserve_claim(kind: str, name: str, owner_token: str, *, runner: Callable[..., Any] | None = None) -> dict[str, Any]:
    if not owner_token or not name:
        raise OwnershipError("resource claim requires a nonempty owner token and name")
    assert_absent(kind, name, runner=runner)
    return {
        "schema_version": SCHEMA_VERSION,
        "claim_id": uuid.uuid4().hex,
        "kind": kind,
        "name": name,
        "owner_token": owner_token,
        "preflight": "ABSENT",
    }


def read_claims(registry: Path) -> list[dict[str, Any]]:
    claims = []
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    if not registry.exists():
        return claims
    for line_number, line in enumerate(registry.read_text(encoding="utf-8").splitlines(), 1):
        try:
            claim = json.loads(line)
        except json.JSONDecodeError as error:
            raise OwnershipError(f"resource-claim ledger line {line_number} is invalid JSON") from error
        if (not isinstance(claim, dict) or claim.get("schema_version") != SCHEMA_VERSION or
                claim.get("preflight") != "ABSENT" or claim.get("kind") not in
                ("project", "volume", "network", "container", "image") or
                not isinstance(claim.get("name"), str) or not claim["name"] or
                not isinstance(claim.get("owner_token"), str) or not claim["owner_token"]):
            raise OwnershipError(f"resource-claim ledger line {line_number} is incomplete")
        key = claim["kind"], claim["name"]
        prior = seen.get(key)
        if prior and prior["owner_token"] != claim["owner_token"]:
            raise OwnershipError(f"resource claim changed owner for {key[0]} {key[1]}")
        if prior:
            prior.update({name: value for name, value in claim.items()
                          if name not in ("claim_id", "schema_version", "kind", "name", "owner_token", "preflight")})
        else:
            claims.append(claim)
            seen[key] = claim
    return claims


def append_claim(registry: Path, kind: str, name: str, owner_token: str,
                 *, runner: Callable[..., Any] | None = None) -> dict[str, Any]:
    claim = reserve_claim(kind, name, owner_token, runner=runner)
    registry.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with registry.open("a+", encoding="utf-8") as output:
        fcntl.flock(output.fileno(), fcntl.LOCK_EX)
        output.seek(0, 2)
        output.write(json.dumps(claim, sort_keys=True, separators=(",", ":")) + "\n")
        output.flush()
    return claim


def record_image_attempt(registry: Path, name: str, owner_token: str, expected_id: str | None,
                         *, retain: bool | None = None) -> None:
    """Append the image tag/ID observed after this run attempted its build."""
    prior = [claim for claim in read_claims(registry)
             if claim.get("kind") == "image" and claim.get("name") == name and
             claim.get("owner_token") == owner_token and claim.get("preflight") == "ABSENT"]
    if not prior:
        raise OwnershipError(f"image build has no matching preflight ownership claim: {name}")
    update = {"schema_version": SCHEMA_VERSION, "claim_id": uuid.uuid4().hex,
              "kind": "image", "name": name, "owner_token": owner_token,
              "preflight": "ABSENT", "build_attempted": True, "expected_id": expected_id}
    if retain is not None:
        update["retain"] = retain
    with registry.open("a+", encoding="utf-8") as output:
        fcntl.flock(output.fileno(), fcntl.LOCK_EX)
        output.seek(0, 2)
        output.write(json.dumps(update, sort_keys=True, separators=(",", ":")) + "\n")
        output.flush()


def select_cleanup_targets(owner_token: str, claims: list[dict[str, Any]], *,
                           containers: list[dict[str, Any]], networks: list[dict[str, Any]],
                           volumes: list[dict[str, Any]], images: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Select exact resources carrying this run's claim or exact Compose token."""
    valid = [claim for claim in claims if claim.get("owner_token") == owner_token and
             claim.get("preflight") == "ABSENT"]
    project_names = {claim["name"] for claim in valid if claim["kind"] == "project"}
    volume_claims = {claim["name"] for claim in valid if claim["kind"] == "volume"}
    network_claims = {claim["name"] for claim in valid if claim["kind"] == "network"}
    container_claims = {claim["name"] for claim in valid if claim["kind"] == "container"}
    image_claims = {claim["name"]: claim for claim in valid if claim["kind"] == "image"}

    selected_containers = []
    for item in containers:
        labels = item.get("labels") or {}
        identifier = item.get("id")
        if not identifier:
            continue
        if labels.get(OWNER_LABEL) == owner_token:
            selected_containers.append(identifier)
        elif labels.get(PROJECT_LABEL) in project_names:
            selected_containers.append(identifier)
        elif identifier in container_claims and labels.get(OWNER_LABEL) == owner_token:
            selected_containers.append(identifier)

    selected_networks = []
    for item in networks:
        labels = item.get("labels") or {}
        identifier = item.get("id")
        if identifier and (labels.get(OWNER_LABEL) == owner_token or labels.get(PROJECT_LABEL) in project_names):
            selected_networks.append(identifier)
        elif identifier and item.get("name") in network_claims and labels.get(OWNER_LABEL) == owner_token:
            selected_networks.append(identifier)

    selected_volumes = []
    for item in volumes:
        labels = item.get("labels") or {}
        name = item.get("name")
        if not name:
            continue
        task_label = labels.get(OWNER_LABEL) == owner_token
        project_label = labels.get(PROJECT_LABEL) in project_names
        rollback_label = labels.get(ROLLBACK_PROJECT_LABEL) in project_names
        exact_claim = name in volume_claims
        if task_label or (exact_claim and (project_label or rollback_label)):
            selected_volumes.append(name)

    selected_images = []
    for item in images:
        image_id = item.get("id")
        for tag in item.get("repo_tags") or []:
            claim = image_claims.get(tag)
            if (claim and image_id and claim.get("build_attempted") is True and
                    claim.get("expected_id") == image_id and claim.get("preflight") == "ABSENT" and
                    claim.get("retain") is not True):
                selected_images.append(tag)
    return {"containers": sorted(set(selected_containers)), "networks": sorted(set(selected_networks)),
            "volumes": sorted(set(selected_volumes)), "images": sorted(set(selected_images))}


def resource_is_owned(kind: str, item: dict[str, Any], owner_token: str,
                      claims: list[dict[str, Any]]) -> bool:
    labels = item.get("labels") or {}
    projects = _claimed_projects(claims, owner_token)
    if kind == "volume":
        name = item.get("name")
        rollback_project = labels.get(ROLLBACK_PROJECT_LABEL)
        rollback_owned = (labels.get(OWNER_LABEL) == owner_token and
                          labels.get("com.bchforge.electron-cash-docker.managed") == "rollback" and
                          rollback_project in projects)
        volume_claimed = any(claim.get("kind") == "volume" and claim.get("name") == name and
                             claim.get("owner_token") == owner_token and claim.get("preflight") == "ABSENT"
                             for claim in claims)
        return rollback_owned or (volume_claimed and
                                  (labels.get(OWNER_LABEL) == owner_token or
                                   labels.get(PROJECT_LABEL) in projects or rollback_project in projects))
    if labels.get(OWNER_LABEL) == owner_token:
        return True
    if kind in ("container", "network"):
        return labels.get(PROJECT_LABEL) in projects
    if kind == "image":
        image_id = item.get("id")
        tags = item.get("repo_tags") or []
        return any(claim.get("kind") == "image" and claim.get("owner_token") == owner_token and
                   claim.get("preflight") == "ABSENT" and claim.get("build_attempted") is True and
                   claim.get("expected_id") == image_id and claim.get("name") in tags for claim in claims)
    return False


def strict_protection_fingerprint(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Return only stable Docker identity/configuration; runtime metrics stay telemetry."""
    images = [{key: item.get(key) for key in
               ("repository", "tag", "ID", "Digest", "created_at", "size", "metadata")}
              for item in snapshot.get("images", [])]
    containers = []
    for item in snapshot.get("containers", []):
        networks = {}
        for name, endpoint in (item.get("networks") or {}).items():
            networks[name] = {key: endpoint.get(key) for key in
                              ("NetworkID", "EndpointID", "Aliases", "DriverOpts")}
        containers.append({key: item.get(key) for key in
                           ("id", "name", "configured_image", "image_id", "created", "labels", "config_identity",
                            "mounts", "host_config")} | {"networks": networks})
    volumes = [{key: item.get(key) for key in
                ("name", "driver", "scope", "created_at", "mountpoint", "options", "labels")}
               for item in snapshot.get("volumes", [])]
    networks = []
    for item in snapshot.get("networks", []):
        attachments = {container_id: {"EndpointID": (endpoint or {}).get("EndpointID")}
                       for container_id, endpoint in (item.get("containers") or {}).items()}
        networks.append({key: item.get(key) for key in
                         ("id", "name", "driver", "scope", "internal", "attachable", "ingress", "labels",
                          "subnets", "ipam", "options", "config_only", "config_from")} |
                        {"attachments": attachments})
    builders = [{key: item.get(key) for key in ("name", "driver", "nodes", "configuration")}
                for item in snapshot.get("builders", [])]
    filesystem = snapshot.get("root_filesystem") or {}
    return {
        "daemon": snapshot.get("daemon"),
        "filesystem_identity": {key: filesystem.get(key) for key in ("device", "total_bytes")},
        "images": sorted(images, key=lambda item: (str(item.get("repository")), str(item.get("tag")), str(item.get("ID")))),
        "containers": sorted(containers, key=lambda item: str(item.get("id"))),
        "volumes": sorted(volumes, key=lambda item: str(item.get("name"))),
        "networks": sorted(networks, key=lambda item: str(item.get("id"))),
        "builders": sorted(builders, key=lambda item: str(item.get("name"))),
    }


def compare_snapshot_telemetry(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    """Report volatile observations separately from the strict protection result."""
    differences: list[dict[str, Any]] = []

    def add(kind: str, identity: Any, field: str, old: Any, new: Any) -> None:
        if old != new:
            differences.append({"kind": kind, "identity": identity, "field": field,
                                "before": old, "after": new})

    add("snapshot", "docker", "captured_at", before.get("captured_at"), after.get("captured_at"))
    for field in ("used_bytes", "free_bytes", "capacity_percent"):
        add("filesystem", "/", field,
            (before.get("root_filesystem") or {}).get(field),
            (after.get("root_filesystem") or {}).get(field))
    add("docker", "daemon", "system_df", before.get("docker_system_df"), after.get("docker_system_df"))

    for section, identity_key, telemetry_fields in (
        ("volumes", "name", ("size", "usage_data")),
        ("containers", "id", ("status", "running", "health", "health_details", "state_details",
                                "restart_count", "ports")),
        ("builders", "name", ("cache_items", "cache_total_bytes", "cache_status", "inspect_telemetry")),
    ):
        old_items = {item.get(identity_key): item for item in before.get(section, [])}
        new_items = {item.get(identity_key): item for item in after.get(section, [])}
        for identity in old_items.keys() & new_items.keys():
            old_item, new_item = old_items[identity], new_items[identity]
            for field in telemetry_fields:
                add(section[:-1] if section.endswith("s") else section, identity, field,
                    old_item.get(field), new_item.get(field))
            if section == "containers":
                old_networks, new_networks = old_item.get("networks") or {}, new_item.get("networks") or {}
                for network_name in old_networks.keys() & new_networks.keys():
                    for field in ("Gateway", "IPAddress", "GlobalIPv6Address", "MacAddress"):
                        add("container", identity, f"networks.{network_name}.{field}",
                            (old_networks[network_name] or {}).get(field),
                            (new_networks[network_name] or {}).get(field))
    old_networks = {item.get("id"): item for item in before.get("networks", [])}
    new_networks = {item.get("id"): item for item in after.get("networks", [])}
    for identity in old_networks.keys() & new_networks.keys():
        old_attachments = old_networks[identity].get("containers") or {}
        new_attachments = new_networks[identity].get("containers") or {}
        for container_id in old_attachments.keys() & new_attachments.keys():
            for field in ("MacAddress", "IPv4Address", "IPv6Address"):
                add("network", identity, f"containers.{container_id}.{field}",
                    (old_attachments[container_id] or {}).get(field),
                    (new_attachments[container_id] or {}).get(field))
    return differences


def compare_preexisting_state(before: dict[str, Any], after: dict[str, Any], *,
                              task_builder: dict[str, Any]) -> list[str]:
    """Require every baseline identity to survive unchanged; allow only the claimed builder additions."""
    before = strict_protection_fingerprint(before)
    after = strict_protection_fingerprint(after)
    failures: list[str] = []
    task_container_id = task_builder.get("container_id")
    if task_container_id:
        # The task-owned BuildKit container may attach to the pre-existing
        # default bridge. Ignore only that exact owned endpoint; unrelated
        # attachment changes remain strict foreign-state drift.
        for snapshot in (before, after):
            for network in snapshot.get("networks", []):
                (network.get("attachments") or {}).pop(task_container_id, None)
    task_volume_name = task_builder.get("volume_name")
    task_volume_names = set(task_builder.get("volume_names") or ([task_volume_name] if task_volume_name else []))
    task_builder_name = task_builder.get("name")
    expected_additions = {"containers": {task_container_id} - {None},
                          "volumes": task_volume_names, "networks": set(),
                          "images": set(task_builder.get("image_ids") or []),
                          "builders": {task_builder_name} - {None}}
    key_specs = {
        "images": ("repository", "tag", "ID", "Digest", "created_at", "size", "metadata"),
        "containers": ("id", "name", "configured_image", "image_id", "created", "labels", "mounts",
                       "networks", "ports", "host_config"),
        "volumes": ("name", "driver", "scope", "labels", "created_at", "mountpoint", "options"),
        "networks": ("id", "name", "driver", "scope", "internal", "attachable", "ingress", "labels",
                     "subnets", "ipam", "options", "config_only", "config_from", "attachments"),
        "builders": ("name", "driver", "nodes", "configuration"),
    }
    identity_keys = {
        "images": lambda item: (("untagged", item.get("ID"))
                                 if item.get("repository") in (None, "<none>") or item.get("tag") in (None, "<none>")
                                 else ("tagged", item.get("repository"), item.get("tag"))),
        "containers": lambda item: item.get("id"),
        "volumes": lambda item: item.get("name"),
        "networks": lambda item: item.get("id"),
        "builders": lambda item: item.get("name"),
    }
    for section, fields in key_specs.items():
        old_items = before.get(section, [])
        new_items = after.get(section, [])
        old_by_key = {identity_keys[section](item): item for item in old_items}
        new_by_key = {identity_keys[section](item): item for item in new_items}
        for key, old in old_by_key.items():
            new = new_by_key.get(key)
            if new is None:
                resource = key
                if section in ("containers", "networks"):
                    resource = f"{old.get('name')} ({key})"
                failures.append(f"pre-existing {section[:-1]} identity disappeared: {resource}")
                continue
            compared_fields = fields
            if section == "builders" and key == task_builder_name:
                compared_fields = ("name",)
            old_identity = {field: old.get(field) for field in compared_fields}
            new_identity = {field: new.get(field) for field in compared_fields}
            if old_identity != new_identity:
                changed_fields = [field for field in compared_fields if old.get(field) != new.get(field)]
                resource = key
                if section in ("containers", "networks"):
                    resource = f"{new.get('name')} ({key})"
                failures.append(
                    f"pre-existing {section[:-1]} identity changed: {resource}; fields={changed_fields}"
                )
        additions = set(new_by_key) - set(old_by_key)
        expected = expected_additions[section]
        if section == "containers" and task_container_id in old_by_key:
            expected = set()
        elif section == "volumes":
            expected = task_volume_names - set(old_by_key)
        elif section == "builders" and task_builder_name in old_by_key:
            expected = set()
        observed_additions = set()
        if section == "containers":
            observed_additions = {item.get("id") for item in new_items if identity_keys[section](item) in additions}
        elif section == "images":
            observed_additions = {item.get("ID") for item in new_items if identity_keys[section](item) in additions}
        else:
            observed_additions = {key for key in additions}
        if observed_additions != expected:
            failures.append(f"unexpected {section} additions: {sorted(map(str, observed_additions - expected))}")
            if expected - observed_additions:
                failures.append(f"expected task-owned {section} resource is missing: {sorted(map(str, expected - observed_additions))}")
    if before.get("daemon") != after.get("daemon"):
        failures.append("Docker daemon identity or storage configuration changed")
    if before.get("filesystem_identity") != after.get("filesystem_identity"):
        failures.append("Docker root filesystem identity or capacity changed")
    return failures


def _owner_claims_from_environment() -> list[dict[str, Any]]:
    registry = os.environ.get("CI_RESOURCE_REGISTRY")
    if not registry:
        return []
    return read_claims(Path(registry))


def _emit_resource_event(event: dict[str, Any]) -> None:
    path = os.environ.get("CI_RESOURCE_EVENT_LOG")
    if not path:
        return
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        event.setdefault("owner_token", os.environ.get("CI_RESOURCE_OWNER", ""))
        os.write(descriptor, (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _real_docker() -> str:
    executable = os.environ.get("CI_REAL_DOCKER")
    if not executable or not Path(executable).is_file():
        raise OwnershipError("Docker owner shim has no trusted real Docker executable")
    return executable


def _docker(args: list[str], *, timeout: int | None = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run([_real_docker(), *args], text=True, capture_output=True,
                          check=False, timeout=timeout)


def _owner_token() -> str:
    value = os.environ.get("CI_RESOURCE_OWNER", "")
    if not value:
        raise OwnershipError("Docker owner shim requires the current task owner token")
    return value


def _project_from_compose(args: list[str]) -> str:
    for index, value in enumerate(args[:-1]):
        if value in ("-p", "--project-name"):
            return args[index + 1]
        if value.startswith("--project-name="):
            return value.partition("=")[2]
    return os.environ.get("COMPOSE_PROJECT_NAME", "")


def _claimed_projects(claims: list[dict[str, Any]], owner: str) -> set[str]:
    return {item["name"] for item in claims if item.get("kind") == "project" and
            item.get("owner_token") == owner and item.get("preflight") == "ABSENT"}


def _inspect_ids(kind: str, ids: list[str]) -> list[dict[str, Any]]:
    if not ids:
        return []
    command = {"container": ["inspect"], "network": ["network", "inspect"]}[kind]
    result = _docker([*command, *ids], timeout=120)
    if result.returncode:
        raise OwnershipError(f"unable to inspect {kind} identities before cleanup")
    raw = json.loads(result.stdout)
    items = []
    for item in raw:
        if kind == "container":
            items.append({"id": item["Id"], "name": item.get("Name", "").lstrip("/"),
                          "labels": item.get("Config", {}).get("Labels") or {},
                          "image_id": item.get("Image"), "configured_image": item.get("Config", {}).get("Image"),
                          "volumes": [mount.get("Name") for mount in item.get("Mounts", [])
                                      if mount.get("Type") == "volume" and mount.get("Name")]})
        else:
            items.append({"id": item["Id"], "name": item.get("Name"), "labels": item.get("Labels") or {}})
    return items


def _compose_down_plan(args: list[str], claims: list[dict[str, Any]], owner: str) -> dict[str, Any]:
    project = _project_from_compose(args)
    projects = _claimed_projects(claims, owner)
    if not project or project not in projects:
        raise OwnershipError("refusing Compose cleanup without an exact preflighted project claim")
    container_list = _docker(["ps", "-aq", "--filter", f"label={PROJECT_LABEL}={project}"])
    network_list = _docker(["network", "ls", "-q", "--filter", f"label={PROJECT_LABEL}={project}"])
    volume_list = _docker(["volume", "ls", "-q", "--filter", f"label={PROJECT_LABEL}={project}"])
    if container_list.returncode or network_list.returncode or volume_list.returncode:
        raise OwnershipError("unable to inventory exact Compose resources before down")
    containers = _inspect_ids("container", container_list.stdout.split())
    networks = _inspect_ids("network", network_list.stdout.split())
    volumes = []
    volume_claims = {item["name"] for item in claims if item.get("kind") == "volume" and
                     item.get("owner_token") == owner and item.get("preflight") == "ABSENT"}
    volumes_to_check = set(volume_list.stdout.split())
    removes_volumes = any(arg in ("-v", "--volumes") for arg in args)
    if removes_volumes:
        for container in containers:
            inspected = _docker(["inspect", container["id"]])
            if inspected.returncode:
                raise OwnershipError(f"unable to inspect project container mounts before down: {container['id']}")
            raw_container = json.loads(inspected.stdout)[0]
            for mount in raw_container.get("Mounts", []):
                if mount.get("Type") == "volume" and mount.get("Name"):
                    volumes_to_check.add(mount["Name"])
    for name in sorted(volumes_to_check):
        inspected = _docker(["volume", "inspect", name])
        if inspected.returncode:
            raise OwnershipError(f"unable to inspect Compose volume before down: {name}")
        item = json.loads(inspected.stdout)[0]
        labels = item.get("Labels") or {}
        if (name not in volume_claims or
                not resource_is_owned("volume", {"name": name, "labels": labels}, owner, claims)):
            raise OwnershipError(f"refusing Compose down: volume ownership is not proven for {name}")
        volumes.append({"name": name, "labels": labels})
    for item in containers:
        if item["labels"].get(PROJECT_LABEL) != project:
            raise OwnershipError(f"refusing Compose down: container label changed for {item['id']}")
    for item in networks:
        if item["labels"].get(PROJECT_LABEL) != project:
            raise OwnershipError(f"refusing Compose down: network label changed for {item['id']}")
    return {"project": project, "containers": containers, "networks": networks,
            "volumes": volumes if removes_volumes else []}


def _claimed_volume(name: str, claims: list[dict[str, Any]], owner: str) -> dict[str, Any]:
    claim = next((item for item in claims if item.get("kind") == "volume" and item.get("name") == name and
                  item.get("owner_token") == owner and item.get("preflight") == "ABSENT"), None)
    if claim is not None:
        return claim
    if _rollback_volume_creation_recorded(name, claims, owner):
        return {"schema_version": SCHEMA_VERSION, "claim_id": None, "kind": "volume",
                "name": name, "owner_token": owner, "preflight": "CREATED_ROLLBACK"}
    raise OwnershipError(f"volume {name} has no exact preflighted claim or verified rollback ownership")


def _rollback_volume_creation_recorded(name: str, claims: list[dict[str, Any]], owner: str) -> bool:
    """Authorize a generated rollback volume only after this run's create shim recorded it."""
    event_path = os.environ.get("CI_RESOURCE_EVENT_LOG", "")
    if not event_path:
        return False
    path = Path(event_path)
    if path.is_symlink() or not path.is_file():
        return False
    projects = _claimed_projects(claims, owner)
    try:
        records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except (OSError, json.JSONDecodeError) as error:
        raise OwnershipError(f"unable to verify rollback volume creation event: {error}") from error
    return any(event.get("kind") == "volume-created" and event.get("owner_token") == owner and
               event.get("name") == name and event.get("owner_label") == owner and
               event.get("returncode") == 0 and event.get("rollback_project") in projects
               for event in records if isinstance(event, dict))


def _volume_is_missing(result: subprocess.CompletedProcess[str]) -> bool:
    return result.returncode != 0 and ("no such volume" in result.stderr.lower() or
                                       "no such object" in result.stderr.lower())


def _inspect_claimed_volume(name: str, claims: list[dict[str, Any]], owner: str) -> bool:
    volume_claim = next((item for item in claims if item.get("kind") == "volume" and
                         item.get("name") == name and item.get("owner_token") == owner and
                         item.get("preflight") == "ABSENT"), None)
    inspected = _docker(["volume", "inspect", name])
    if inspected.returncode == 0:
        item = json.loads(inspected.stdout)[0]
        labels = item.get("Labels") or {}
        if not resource_is_owned("volume", {"name": name, "labels": labels}, owner, claims):
            raise OwnershipError(f"refusing to mount or reference foreign volume {name}")
        return True
    if _volume_is_missing(inspected):
        if volume_claim is None:
            raise OwnershipError(f"volume {name} has neither a task creation claim nor an owner label")
        return False
    raise OwnershipError(f"unable to verify claimed volume {name}: {inspected.stderr}")


def _ensure_claimed_volume(name: str, claims: list[dict[str, Any]], owner: str, *,
                           create_if_missing: bool, compose_project: str | None = None,
                           compose_logical_name: str | None = None) -> None:
    """Require an exact preflighted volume claim before ECD can mount/reference it."""
    if _inspect_claimed_volume(name, claims, owner):
        return
    if not create_if_missing:
        raise OwnershipError(f"required task-owned volume does not exist: {name}")

    create = ["volume", "create", "--label", f"{OWNER_LABEL}={owner}"]
    if compose_project is not None:
        create.extend(["--label", f"{PROJECT_LABEL}={compose_project}"])
        if compose_logical_name:
            create.extend(["--label", f"com.docker.compose.volume={compose_logical_name}"])
    create.append(name)
    result = _docker(create)
    if result.returncode:
        raise OwnershipError(f"unable to create claimed task volume {name}: {result.stderr}")
    verify = _docker(["volume", "inspect", name])
    if verify.returncode:
        raise OwnershipError(f"created task volume cannot be inspected: {name}")
    item = json.loads(verify.stdout)[0]
    labels = item.get("Labels") or {}
    if labels.get(OWNER_LABEL) != owner:
        raise OwnershipError(f"claimed volume name was concurrently occupied by a foreign volume: {name}")
    _emit_resource_event({"kind": "volume-created", "name": name, "owner_label": owner,
                          "project": compose_project, "returncode": 0})


def _verified_image_id(image_ref: str, claims: list[dict[str, Any]], owner: str) -> str:
    claim = next((item for item in claims if item.get("kind") == "image" and
                  item.get("name") == image_ref and item.get("owner_token") == owner and
                  item.get("preflight") == "ABSENT" and item.get("build_attempted") is True and
                  isinstance(item.get("expected_id"), str) and item.get("expected_id")), None)
    if claim is None and os.environ.get("CI_CANDIDATE_IMAGES") == "1":
        raise OwnershipError(f"candidate image {image_ref} has no completed task-owned build/ID claim")
    inspected = _docker(["image", "inspect", "--format", "{{.Id}}", image_ref])
    if inspected.returncode:
        raise OwnershipError(f"runtime image is not locally available; pulls are forbidden: {image_ref}")
    actual_id = inspected.stdout.strip()
    if claim is not None and actual_id != claim["expected_id"]:
        raise OwnershipError(f"candidate image reference changed identity: {image_ref}")
    if not actual_id:
        raise OwnershipError(f"runtime image resolved to an empty ID: {image_ref}")
    return actual_id


def _docker_volume_mounts(args: list[str]) -> tuple[list[str], list[str], list[str], str, int]:
    """Return volume/bind/volumes-from refs and exact image position for run/create flags."""
    named: list[str] = []
    binds: list[str] = []
    volumes_from: list[str] = []
    image_ref = ""
    image_index = -1
    value_options = {
        "--add-host", "--annotation", "--attach", "--blkio-weight", "--blkio-weight-device",
        "--cap-add", "--cap-drop", "--cgroup-parent", "--cgroupns", "--cpu-period", "--cpu-quota",
        "--cpu-rt-period", "--cpu-rt-runtime", "--cpu-shares", "--cpus", "--cpuset-cpus",
        "--cpuset-mems", "--device", "--device-cgroup-rule", "--dns", "--dns-option", "--dns-search",
        "--domainname", "--entrypoint", "--env", "--env-file", "--expose", "--gpus", "--group-add",
        "--health-cmd", "--health-interval", "--health-retries", "--health-start-interval",
        "--health-start-period", "--health-timeout", "--hostname", "--init-path", "--ip", "--ip6",
        "--ipc", "--isolation", "--kernel-memory", "--label", "--label-file", "--link", "--log-driver",
        "--log-opt", "--memory", "--memory-reservation", "--memory-swap", "--memory-swappiness",
        "--mount", "--name", "--network", "--network-alias", "--oom-score-adj", "--pid", "--pids-limit",
        "--platform", "--preserve-fds", "--publish", "--pull", "--restart", "--runtime", "--security-opt",
        "--shm-size", "--stop-signal", "--stop-timeout", "--storage-opt", "--sysctl", "--tmpfs",
        "--ulimit", "--user", "--userns", "--uts", "--volume-driver", "--volumes-from", "--workdir",
        "-a", "-c", "-e", "-h", "-m", "-p", "-u", "-w",
    }
    index = 2 if args[:2] == ["container", "create"] else 1
    while index < len(args):
        value = args[index]
        mount_value = None
        if value in ("-v", "--volume"):
            if index + 1 >= len(args):
                raise OwnershipError(f"{value} is missing its mount specification")
            mount_value = args[index + 1]
            index += 1
        elif value.startswith("--volume="):
            mount_value = value.partition("=")[2]
        if mount_value is not None:
            source, separator, _target = mount_value.partition(":")
            if not separator or not source:
                raise OwnershipError("anonymous Docker volumes are forbidden without an exact task name claim")
            if source.startswith(("/", "./", "../", "~/")):
                binds.append(source)
            else:
                named.append(source)
        elif value == "--mount" or value.startswith("--mount="):
            if value == "--mount":
                if index + 1 >= len(args):
                    raise OwnershipError("--mount is missing its mount specification")
                mount_value = args[index + 1]
                index += 1
            else:
                mount_value = value.partition("=")[2]
            fields = {}
            for field in mount_value.split(","):
                key, separator, field_value = field.partition("=")
                if separator:
                    fields[key.strip()] = field_value.strip()
            mount_type = fields.get("type")
            source = fields.get("source", fields.get("src", ""))
            if mount_type == "volume":
                if not source:
                    raise OwnershipError("anonymous Docker volume mounts are forbidden without an exact task name claim")
                named.append(source)
            elif mount_type == "bind":
                if not source:
                    raise OwnershipError("bind mount is missing its source")
                binds.append(source)
        elif value == "--volumes-from" or value.startswith("--volumes-from="):
            if value == "--volumes-from":
                if index + 1 >= len(args):
                    raise OwnershipError("--volumes-from is missing its container reference")
                source = args[index + 1]
                index += 1
            else:
                source = value.partition("=")[2]
            volumes_from.append(source.rsplit(":", 1)[0])
        elif value in value_options:
            if index + 1 >= len(args):
                raise OwnershipError(f"Docker option {value} is missing its value")
            index += 1
        elif value.startswith("-"):
            # Other boolean and combined short options do not consume a separate value.
            pass
        else:
            # The first positional token after options is the image; command arguments
            # after it are not Docker mount declarations.
            image_ref = value
            image_index = index
            break
        index += 1
    if not image_ref:
        raise OwnershipError("Docker run/create has no image reference")
    return sorted(set(named)), sorted(set(binds)), sorted(set(volumes_from)), image_ref, image_index


def _volume_create_name(args: list[str]) -> str | None:
    positional: list[str] = []
    index = 2
    value_options = {"--driver", "--label", "-o", "--opt"}
    while index < len(args):
        value = args[index]
        if value in value_options:
            index += 2
            continue
        if any(value.startswith(option + "=") for option in value_options):
            index += 1
            continue
        if not value.startswith("-"):
            positional.append(value)
        index += 1
    if not positional:
        return None
    if len(positional) != 1:
        raise OwnershipError("docker volume create requires one exact claimed volume name")
    return positional[0]


def _docker_labels_from_args(args: list[str]) -> dict[str, str]:
    labels: dict[str, str] = {}
    index = 2
    while index < len(args):
        value = args[index]
        if value == "--label" and index + 1 < len(args):
            label = args[index + 1]
            key, separator, content = label.partition("=")
            if separator:
                labels[key] = content
            index += 2
            continue
        if value.startswith("--label="):
            key, separator, content = value.partition("=")[2].partition("=")
            if separator:
                labels[key] = content
        index += 1
    return labels


def _docker_root_dir() -> Path:
    result = _docker(["info", "--format", "{{.DockerRootDir}}"])
    root = result.stdout.strip()
    if result.returncode or not root:
        raise OwnershipError("unable to identify Docker storage root for bind-mount validation")
    return Path(root)


def _validate_bind_source(source: str, owner: str, claims: list[dict[str, Any]]) -> None:
    resolved = Path(source).expanduser().resolve(strict=False)
    volume_root = (_docker_root_dir() / "volumes").resolve(strict=False)
    try:
        relative = resolved.relative_to(volume_root)
    except ValueError:
        return
    if not relative.parts:
        raise OwnershipError("binding the Docker volumes directory is forbidden")
    volume_name = relative.parts[0]
    inspected = _docker(["volume", "inspect", volume_name])
    if inspected.returncode:
        raise OwnershipError(f"unable to map Docker volume storage bind to a volume: {source}")
    item = json.loads(inspected.stdout)[0]
    mountpoint = Path(item.get("Mountpoint") or "").resolve(strict=False)
    try:
        resolved.relative_to(mountpoint)
    except ValueError as error:
        raise OwnershipError(f"bind source is inside Docker volume storage but not its mountpoint: {source}") from error
    _ensure_claimed_volume(volume_name, claims, owner, create_if_missing=False)


def _validate_docker_volume_references(args: list[str], claims: list[dict[str, Any]], owner: str
                                      ) -> tuple[int, str]:
    named, binds, containers, image_ref, image_index = _docker_volume_mounts(args)
    for name in named:
        _claimed_volume(name, claims, owner)
        _inspect_claimed_volume(name, claims, owner)
    for source in binds:
        _validate_bind_source(source, owner, claims)
    for container_ref in containers:
        inspected = _docker(["inspect", container_ref])
        if inspected.returncode:
            raise OwnershipError(f"unable to inspect --volumes-from container {container_ref}")
        container = json.loads(inspected.stdout)[0]
        item = {"id": container.get("Id"),
                "labels": (container.get("Config") or {}).get("Labels") or {}}
        if not resource_is_owned("container", item, owner, claims):
            raise OwnershipError(f"refusing --volumes-from foreign container {container_ref}")
        for mount in container.get("Mounts", []):
            if mount.get("Type") == "volume" and mount.get("Name"):
                _inspect_claimed_volume(mount["Name"], claims, owner)
    image_id = _verified_image_id(image_ref, claims, owner)
    for name in named:
        _ensure_claimed_volume(name, claims, owner, create_if_missing=True)
    return image_index, image_id


def _ensure_pull_never(args: list[str], image_index: int, option_index: int) -> int:
    index = 2 if args[:2] == ["container", "create"] else 1
    while index < image_index:
        value = args[index]
        if value.startswith("--pull="):
            if value.partition("=")[2] != "never":
                raise OwnershipError("runtime image pulls are forbidden; use the verified local artifact")
            return image_index
        if value == "--pull":
            if index + 1 >= image_index or args[index + 1] != "never":
                raise OwnershipError("runtime image pulls are forbidden; use --pull=never")
            return image_index
        index += 1
    args.insert(option_index, "--pull=never")
    return image_index + 1


def _compose_selected_services(args: list[str], action: str, model: dict[str, Any]) -> set[str]:
    services = model.get("services") or {}
    service_names = set(services)
    try:
        action_index = args.index(action)
    except ValueError as error:
        raise OwnershipError(f"unable to locate Compose {action} operation") from error
    profiles = {value for value in os.environ.get("COMPOSE_PROFILES", "").split(",") if value}
    index = 1
    while index < len(args):
        value = args[index]
        if value == "--profile" and index + 1 < len(args):
            profiles.add(args[index + 1])
            index += 2
            continue
        if value.startswith("--profile="):
            profiles.add(value.partition("=")[2])
        index += 1

    selected: set[str] = set()
    value_options = {"--scale", "--pull", "--timeout", "--wait-timeout", "--exit-code-from",
                     "--attach", "--no-attach", "-e", "--env", "--env-from-file"}
    index = action_index + 1
    while index < len(args):
        value = args[index]
        if value in value_options:
            index += 2
            continue
        if any(value.startswith(option + "=") for option in value_options if option.startswith("--")):
            index += 1
            continue
        if value in service_names:
            selected.add(value)
        index += 1

    if not selected:
        selected = {name for name, service in services.items()
                    if not (service.get("profiles") or []) or profiles.intersection(service.get("profiles") or [])}
    if selected and "--no-deps" not in args:
        pending = list(selected)
        while pending:
            service = services.get(pending.pop(), {})
            dependencies = service.get("depends_on") or {}
            names = dependencies.keys() if isinstance(dependencies, dict) else dependencies
            for dependency in names:
                if dependency in service_names and dependency not in selected:
                    selected.add(dependency)
                    pending.append(dependency)
    return selected


def _compose_up_plan(args: list[str], action: str, claims: list[dict[str, Any]], owner: str) -> dict[str, Any]:
    project = _project_from_compose(args[1:])
    if project not in _claimed_projects(claims, owner):
        raise OwnershipError(f"refusing Compose {action} without an exact project claim")
    try:
        action_index = args.index(action)
    except ValueError as error:
        raise OwnershipError(f"unable to locate Compose {action} operation") from error
    config = _docker([*args[:action_index], "config", "--format", "json"], timeout=120)
    if config.returncode:
        raise OwnershipError(f"unable to resolve Compose volumes before {action}: {config.stderr}")
    model = json.loads(config.stdout)
    definitions = model.get("volumes") or {}
    selected_services = _compose_selected_services(args, action, model)
    service_images = {}
    service_image_ids = {}
    for service_name in sorted(selected_services):
        service = (model.get("services") or {}).get(service_name, {})
        image_ref = service.get("image")
        if image_ref:
            service_images[service_name] = image_ref
            service_image_ids[service_name] = _verified_image_id(image_ref, claims, owner)
    references: dict[str, str] = {}
    for service_name in sorted(selected_services):
        service = (model.get("services") or {}).get(service_name, {})
        for mount in service.get("volumes") or []:
            if not isinstance(mount, dict):
                raise OwnershipError(f"unable to verify Compose volume declaration for {service_name}")
            mount_type = mount.get("type")
            source = mount.get("source")
            if mount_type == "volume":
                if not source or source not in definitions:
                    raise OwnershipError(f"Compose service {service_name} has an anonymous/unresolved volume mount")
                definition = definitions[source] or {}
                name = definition.get("name") or f"{project}_{source}"
                _claimed_volume(name, claims, owner)
                references[name] = source
            elif mount_type == "bind":
                bind_source = mount.get("source")
                if not bind_source:
                    raise OwnershipError(f"Compose bind mount for {service_name} is missing its source")
                _validate_bind_source(bind_source, owner, claims)
    missing_volumes: list[tuple[str, str]] = []
    for name, logical_name in references.items():
        definition = next((value for logical, value in definitions.items()
                           if logical == logical_name and
                           (value.get("name") or f"{project}_{logical}") == name), {}) or {}
        external = bool(definition.get("external"))
        exists = _inspect_claimed_volume(name, claims, owner)
        if not exists:
            if external:
                raise OwnershipError(f"external Compose volume is missing: {name}")
            missing_volumes.append((name, logical_name))
    for name, logical_name in missing_volumes:
        _ensure_claimed_volume(name, claims, owner, create_if_missing=True,
                               compose_project=project, compose_logical_name=logical_name)
    return {"project": project, "operation": action, "volumes": sorted(references),
            "services": sorted(selected_services), "service_images": service_images,
            "service_image_ids": service_image_ids}


def _project_resource_snapshot(project: str) -> dict[str, list[dict[str, Any]]]:
    containers = _docker(["ps", "-aq", "--filter", f"label={PROJECT_LABEL}={project}"])
    networks = _docker(["network", "ls", "-q", "--filter", f"label={PROJECT_LABEL}={project}"])
    volumes = _docker(["volume", "ls", "-q", "--filter", f"label={PROJECT_LABEL}={project}"])
    if containers.returncode or networks.returncode or volumes.returncode:
        raise OwnershipError(f"unable to inspect Docker resources for task project {project}")
    volume_items = []
    for name in volumes.stdout.split():
        inspected = _docker(["volume", "inspect", name])
        if inspected.returncode:
            raise OwnershipError(f"unable to inspect project volume {name}")
        volume = json.loads(inspected.stdout)[0]
        volume_items.append({"name": name, "labels": volume.get("Labels") or {}})
    return {"containers": _inspect_ids("container", containers.stdout.split()),
            "networks": _inspect_ids("network", networks.stdout.split()), "volumes": volume_items}


def _task_builder_record() -> dict[str, Any]:
    path = os.environ.get("CI_TASK_BUILDER_RECORD", "")
    if not path:
        raise OwnershipError("Buildx prune is not bound to an owned builder record")
    target = Path(path)
    if target.is_symlink() or not target.is_file() or target.stat().st_mode & 0o077:
        raise OwnershipError("task-owned Buildx record is missing or has unsafe permissions")
    record = json.loads(target.read_text(encoding="utf-8"))
    if (record.get("schema_version") != 1 or record.get("owner") != "electron-cash-docker-v0.4-task" or
            record.get("repository_root") != os.environ.get("ECD_REPOSITORY_ROOT") or
            record.get("builder") != os.environ.get("CI_PRUNE_TASK_BUILDER") or
            record.get("driver_image") != TASK_BUILDKIT_IMAGE or record.get("state") != "ready"):
        raise OwnershipError("Buildx prune target does not match the task-owned builder record")
    return record


def _builder_cache_items(builder: str) -> list[dict[str, Any]]:
    result = _docker(["buildx", "du", "--builder", builder, "--format", "json"], timeout=240)
    if result.returncode:
        raise OwnershipError(f"unable to inspect task-owned Buildx cache: {result.stderr}")
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


def _compose_build_targets(args: list[str], action: str, claims: list[dict[str, Any]], owner: str
                           ) -> tuple[str, dict[str, str]]:
    action_index = args.index(action)
    prefix = args[:action_index]
    config = _docker([*prefix, "config", "--format", "json"], timeout=120)
    if config.returncode:
        raise OwnershipError(f"unable to resolve Compose image claims before build: {config.stderr}")
    services = json.loads(config.stdout).get("services", {})
    service_names = set(services)
    requested = [value for value in args[action_index + 1:] if value in service_names]
    if not requested:
        requested = [name for name, service in services.items() if service.get("build")]
    images = {}
    claimed_images = {claim.get("name"): claim for claim in claims if claim.get("kind") == "image" and
                      claim.get("owner_token") == owner and claim.get("preflight") == "ABSENT"}
    for service_name in requested:
        service = services[service_name]
        if not service.get("build"):
            continue
        image = service.get("image")
        claim = claimed_images.get(image)
        if not image or not claim:
            raise OwnershipError(f"Compose build target {service_name} has no task-owned image claim")
        current = _docker(["image", "inspect", image])
        if current.returncode == 0:
            image_id = json.loads(current.stdout)[0].get("Id")
            if claim.get("expected_id") != image_id:
                raise OwnershipError(f"candidate image tag changed outside its task build: {image}")
        elif "no such image" not in current.stderr.lower() and "no such object" not in current.stderr.lower():
            raise OwnershipError(f"unable to verify candidate image before build: {image}")
        record_image_attempt(Path(os.environ["CI_RESOURCE_REGISTRY"]), image, owner, claim.get("expected_id"))
        images[service_name] = image
    if not images:
        raise OwnershipError("Compose build operation has no claimed buildable image targets")
    return ",".join(requested), images


def _run_compose_build(args: list[str], action: str, claims: list[dict[str, Any]], owner: str) -> int:
    target_summary, images = _compose_build_targets(args, action, claims, owner)
    result_code = _run_build_with_disk_guard(args)
    observed = []
    registry = Path(os.environ["CI_RESOURCE_REGISTRY"])
    for service_name, image in images.items():
        inspected = _docker(["image", "inspect", image])
        if inspected.returncode == 0:
            image_id = json.loads(inspected.stdout)[0].get("Id")
            record_image_attempt(registry, image, owner, image_id)
            observed.append({"service": service_name, "reference": image, "id": image_id})
        elif "no such image" not in inspected.stderr.lower() and "no such object" not in inspected.stderr.lower():
            raise OwnershipError(f"unable to record attempted Compose build output for {image}")
    _emit_resource_event({"kind": "compose-image-build", "targets": target_summary,
                          "attempted_images": observed, "returncode": result_code})
    return result_code


def _event_identities(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{key: item.get(key) for key in ("ID", "Type", "Size", "Mutable", "Reclaimable", "UsageCount")}
            for item in sorted(items, key=lambda value: str(value.get("ID")))]


def _build_disk_samples() -> list[dict[str, Any]]:
    configured = os.environ.get("CI_DISK_PATHS")
    paths = configured.split(os.pathsep) if configured else ["/"]
    samples = []
    for path in dict.fromkeys(item for item in paths if item):
        try:
            free_bytes = shutil.disk_usage(path).free
        except OSError as error:
            raise OwnershipError(f"unable to measure build storage path {path}: {error}") from error
        samples.append({"path": path, "free_bytes": free_bytes})
    if not samples:
        raise OwnershipError("Docker build disk guard has no monitored storage paths")
    return samples


def _run_build_with_disk_guard(args: list[str]) -> int:
    floor = int(os.environ.get("CI_DISK_FLOOR_BYTES", str(5 * 1024**3)))
    cancel_at = int(os.environ.get("CI_DISK_CANCEL_BYTES", str(6 * 1024**3)))
    start_budget = int(os.environ.get("CI_DISK_START_BYTES", str(7 * 1024**3)))
    if cancel_at < floor:
        raise OwnershipError("Docker build cancellation trigger is below the hard disk floor")
    if start_budget <= cancel_at:
        raise OwnershipError("Docker build admission budget does not leave cancellation headroom")
    start_samples = _build_disk_samples()
    start_free = min(item["free_bytes"] for item in start_samples)
    minimum_free = start_free
    minimum_by_path = {item["path"]: item["free_bytes"] for item in start_samples}
    if start_free < start_budget:
        _emit_resource_event({"kind": "docker-build-disk-usage", "argv": args[:3],
                              "start_free_bytes": start_free, "minimum_free_bytes": start_free,
                              "end_free_bytes": start_free, "storage_free_bytes": start_samples,
                              "minimum_storage_free_bytes": start_samples, "floor_bytes": floor,
                              "cancel_trigger_bytes": cancel_at,
                              "returncode": 87, "refused_before_start": True})
        print(f"resource guard refused Docker build: {start_free} bytes free; {start_budget} required", file=sys.stderr)
        return 87
    process = subprocess.Popen([_real_docker(), *args], start_new_session=True)
    while process.poll() is None:
        time.sleep(0.25)
        samples = _build_disk_samples()
        free = min(item["free_bytes"] for item in samples)
        minimum_free = min(minimum_free, free)
        for item in samples:
            minimum_by_path[item["path"]] = min(minimum_by_path.get(item["path"], item["free_bytes"]),
                                                item["free_bytes"])
        if free <= cancel_at:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            _emit_resource_event({"kind": "docker-build-disk-usage", "argv": args[:3],
                                  "start_free_bytes": start_free, "minimum_free_bytes": minimum_free,
                                  "end_free_bytes": min(item["free_bytes"] for item in _build_disk_samples()),
                                  "storage_free_bytes": start_samples,
                                  "minimum_storage_free_bytes":[{"path": path, "free_bytes": size}
                                                                 for path, size in sorted(minimum_by_path.items())],
                                  "floor_bytes": floor,
                                  "cancel_trigger_bytes": cancel_at, "returncode": 86,
                                  "aborted_at_cancel_trigger": True, "aborted_at_floor": free <= floor})
            print(f"resource guard cancelled Docker build at the early disk trigger: {free} bytes free; "
                  f"hard floor {floor}", file=sys.stderr)
            return 86
    end_samples = _build_disk_samples()
    end_free = min(item["free_bytes"] for item in end_samples)
    minimum_free = min(minimum_free, end_free)
    for item in end_samples:
        minimum_by_path[item["path"]] = min(minimum_by_path.get(item["path"], item["free_bytes"]),
                                            item["free_bytes"])
    if end_free <= cancel_at:
        _emit_resource_event({"kind": "docker-build-disk-usage", "argv": args[:3],
                              "start_free_bytes": start_free, "minimum_free_bytes": minimum_free,
                              "end_free_bytes": end_free, "storage_free_bytes": start_samples,
                              "minimum_storage_free_bytes":[{"path": path, "free_bytes": size}
                                                             for path, size in sorted(minimum_by_path.items())],
                              "floor_bytes": floor,
                              "cancel_trigger_bytes": cancel_at, "returncode": 86,
                              "aborted_at_cancel_trigger": True, "aborted_at_floor": end_free <= floor,
                              "docker_process_returncode": process.returncode})
        print(f"resource guard observed completed Docker build at/below the early trigger: {end_free} bytes free",
              file=sys.stderr)
        return 86
    _emit_resource_event({"kind": "docker-build-disk-usage", "argv": args[:3],
                          "start_free_bytes": start_free, "minimum_free_bytes": minimum_free,
                          "end_free_bytes": end_free, "storage_free_bytes": start_samples,
                          "minimum_storage_free_bytes":[{"path": path, "free_bytes": size}
                                                         for path, size in sorted(minimum_by_path.items())],
                          "floor_bytes": floor,
                          "cancel_trigger_bytes": cancel_at,
                          "returncode": process.returncode or 0})
    return process.returncode or 0


def docker_shim_main() -> int:
    """Proxy the acceptance Docker CLI while enforcing owner-token delete rules."""
    try:
        real = _real_docker()
        args = sys.argv[1:]
        owner = _owner_token()
        claims = _owner_claims_from_environment()
        projects = _claimed_projects(claims, owner)
        if not args:
            return subprocess.call([real])

        if args[0] in ("system", "image", "volume", "network", "container", "builder") and \
                len(args) > 1 and args[1] == "prune":
            raise OwnershipError("global Docker prune commands are forbidden in acceptance")
        if args[:2] in (["image", "tag"], ["image", "push"], ["image", "load"], ["image", "import"],
                        ["image", "save"], ["buildx", "build"]):
            raise OwnershipError("unclaimed direct image mutation is forbidden in acceptance")
        if args[:2] == ["buildx", "rm"]:
            raise OwnershipError("Buildx builder removal is forbidden in acceptance")

        if args[:2] == ["buildx", "prune"]:
            record = _task_builder_record()
            builder = record["builder"]
            selected = None
            for index, value in enumerate(args[:-1]):
                if value == "--builder":
                    selected = args[index + 1]
                elif value.startswith("--builder="):
                    selected = value.partition("=")[2]
            if selected != builder:
                raise OwnershipError("Buildx prune requested a builder outside the task-owned claim")
            before = _builder_cache_items(builder)
            result = _docker(args, timeout=600)
            after = _builder_cache_items(builder)
            before_ids = {item.get("ID"): item for item in before}
            after_ids = {item.get("ID"): item for item in after}
            _emit_resource_event({"kind": "buildx-cache-prune", "builder": builder,
                                  "removed_cache_items": _event_identities(
                                      [item for key, item in before_ids.items() if key not in after_ids]),
                                  "remaining_cache_items": _event_identities(after),
                                  "returncode": result.returncode})
            sys.stdout.write(result.stdout)
            sys.stderr.write(result.stderr)
            return result.returncode

        compose_actions = {"up", "start", "run", "create", "stop", "restart", "kill", "down", "rm", "build"}
        compose_action = next((value for value in args[1:] if value in compose_actions), None) if args[0] == "compose" else None
        if compose_action is not None:
            project = _project_from_compose(args[1:])
            if not project or project not in projects:
                raise OwnershipError(f"refusing Compose {compose_action} without an exact project claim")
            if compose_action == "down" and "--rmi" in args:
                raise OwnershipError("Compose down --rmi is forbidden; candidate images use exact image claims")
            if compose_action in ("up", "run", "create") and "--build" in args:
                raise OwnershipError("runtime Compose build is forbidden; build the claimed artifact once before use")
            plan: dict[str, Any]
            if compose_action in ("down", "rm"):
                plan = _compose_down_plan(args[1:], claims, owner)
            elif compose_action in ("up", "start", "run", "create"):
                plan = _compose_up_plan(args, compose_action, claims, owner)
            else:
                plan = {"project": project, "operation": compose_action}
            if compose_action == "build":
                return _run_compose_build(args, "build", claims, owner)
            execution_args = list(args)
            if compose_action in ("up", "run", "create"):
                pull_option = next((index for index, value in enumerate(execution_args)
                                    if value == "--pull" or value.startswith("--pull=")), None)
                if pull_option is not None:
                    pull_value = (execution_args[pull_option].partition("=")[2]
                                  if "=" in execution_args[pull_option] else
                                  execution_args[pull_option + 1] if pull_option + 1 < len(execution_args) else "")
                    if pull_value != "never":
                        raise OwnershipError("runtime Compose pulls are forbidden for task acceptance images")
                else:
                    action_index = execution_args.index(compose_action)
                    execution_args[action_index + 1:action_index + 1] = ["--pull", "never"]
                if "--no-build" not in execution_args:
                    action_index = execution_args.index(compose_action)
                    execution_args[action_index + 1:action_index + 1] = ["--no-build"]
            attached_gui = (compose_action == "up" and args[-1:] == ["electron-cash"] and
                            "--no-deps" in args and
                            not any(value in ("-d", "--detach", "--wait") for value in args))
            result = _docker(execution_args, timeout=None if attached_gui else 600)
            remaining = {"containers": [], "networks": [], "volumes": []}
            for item in plan.get("containers", []):
                identifier = item if isinstance(item, str) else item.get("id") if isinstance(item, dict) else None
                if not identifier:
                    raise OwnershipError("Compose container postcondition has an invalid resource identity")
                check = _docker(["inspect", identifier])
                if check.returncode == 0:
                    remaining["containers"].append(identifier)
            for item in plan.get("networks", []):
                identifier = item if isinstance(item, str) else item.get("id") if isinstance(item, dict) else None
                if not identifier:
                    raise OwnershipError("Compose network postcondition has an invalid resource identity")
                check = _docker(["network", "inspect", identifier])
                if check.returncode == 0:
                    remaining["networks"].append(identifier)
            for item in plan.get("volumes", []):
                name = item if isinstance(item, str) else item.get("name") if isinstance(item, dict) else None
                if not name:
                    raise OwnershipError("Compose volume postcondition has an invalid resource identity")
                check = _docker(["volume", "inspect", name])
                if check.returncode == 0:
                    remaining["volumes"].append(name)
            current = (_project_resource_snapshot(plan["project"])
                       if compose_action in ("up", "start", "run", "create") and result.returncode == 0 else None)
            if current is not None:
                expected_image_ids = plan.get("service_image_ids") or {}
                expected_image_refs = plan.get("service_images") or {}
                for container in current["containers"]:
                    service = (container.get("labels") or {}).get("com.docker.compose.service")
                    expected_image = expected_image_ids.get(service)
                    if expected_image and container.get("image_id") != expected_image:
                        raise OwnershipError(
                            f"Compose service {service} started with an image ID outside its verified task artifact"
                        )
                    expected_reference = expected_image_refs.get(service)
                    if expected_reference and container.get("configured_image") != expected_reference:
                        raise OwnershipError(
                            f"Compose service {service} started with an unexpected configured image reference"
                        )
            _emit_resource_event({"kind": "compose-lifecycle", **plan, "current_resources": current,
                                  "returncode": result.returncode, "remaining": remaining})
            sys.stdout.write(result.stdout)
            sys.stderr.write(result.stderr)
            return result.returncode

        container_actions = {"rm", "stop", "kill", "start", "restart", "pause", "unpause", "update", "rename"}
        if args[0] in container_actions or args[:2] in (["container", action] for action in container_actions):
            offset = 2 if args[0] == "container" else 1
            ids = [value for value in args[offset:] if not value.startswith("-")]
            items = _inspect_ids("container", ids)
            if not ids or any(not resource_is_owned("container", item, owner, claims) for item in items):
                raise OwnershipError("refusing container mutation without an exact owner/project label")
            if "-v" in args or "--volumes" in args:
                project_names = _claimed_projects(claims, owner)
                for item in items:
                    for volume_name in item.get("volumes", []):
                        inspected = _docker(["volume", "inspect", volume_name])
                        if inspected.returncode:
                            raise OwnershipError(f"unable to inspect container volume before rm -v: {volume_name}")
                        volume = json.loads(inspected.stdout)[0]
                        labels = volume.get("Labels") or {}
                        if (labels.get(OWNER_LABEL) != owner and labels.get(PROJECT_LABEL) not in project_names and
                                labels.get(ROLLBACK_PROJECT_LABEL) not in project_names):
                            raise OwnershipError(f"refusing docker rm -v for unowned volume {volume_name}")
            result = _docker(args, timeout=120)
            remaining = [item["id"] for item in items if _docker(["inspect", item["id"]]).returncode == 0]
            _emit_resource_event({"kind": "container-mutation", "operation": args[0],
                                  "resources": items, "returncode": result.returncode, "remaining": remaining})
            sys.stdout.write(result.stdout)
            sys.stderr.write(result.stderr)
            return result.returncode

        if args[:2] == ["volume", "create"]:
            volume_name = _volume_create_name(args)
            labels_from_command = _docker_labels_from_args(args)
            if volume_name is None:
                rollback_project = labels_from_command.get(ROLLBACK_PROJECT_LABEL)
                if (labels_from_command.get(OWNER_LABEL) != owner or
                        labels_from_command.get("com.bchforge.electron-cash-docker.managed") != "rollback" or
                        not rollback_project or
                        not re.fullmatch(r"[A-Za-z0-9._-]+", rollback_project) or
                        rollback_project not in projects):
                    raise OwnershipError(
                        "anonymous volumes are allowed only for an owner-labeled claimed backup rollback snapshot"
                    )
                result = _docker(args, timeout=120)
                created_name = result.stdout.strip()
                if result.returncode == 0:
                    inspected = _docker(["volume", "inspect", created_name])
                    if inspected.returncode:
                        raise OwnershipError("anonymous rollback volume could not be verified after creation")
                    labels = json.loads(inspected.stdout)[0].get("Labels") or {}
                    if (labels.get(OWNER_LABEL) != owner or
                            labels.get(ROLLBACK_PROJECT_LABEL) != rollback_project or
                            labels.get("com.bchforge.electron-cash-docker.managed") != "rollback"):
                        raise OwnershipError("anonymous rollback volume did not retain its exact owner/project labels")
                    _emit_resource_event({"kind": "volume-created", "name": created_name,
                                          "owner_label": owner, "rollback_project": rollback_project,
                                          "returncode": result.returncode})
                sys.stdout.write(result.stdout)
                sys.stderr.write(result.stderr)
                return result.returncode
            _claimed_volume(volume_name, claims, owner)
            _inspect_claimed_volume(volume_name, claims, owner)
            owner_flag = f"{OWNER_LABEL}={owner}"
            if owner_flag not in args:
                args[2:2] = ["--label", owner_flag]
            result = _docker(args, timeout=120)
            if result.returncode == 0:
                if not _inspect_claimed_volume(volume_name, claims, owner):
                    raise OwnershipError(f"created volume disappeared before ownership verification: {volume_name}")
                _emit_resource_event({"kind": "volume-created", "name": volume_name,
                                      "owner_label": owner, "returncode": result.returncode})
            sys.stdout.write(result.stdout)
            sys.stderr.write(result.stderr)
            return result.returncode

        if args[:2] in (["volume", "rm"], ["network", "rm"]):
            kind = args[0]
            offset = 2
            identifiers = [value for value in args[offset:] if not value.startswith("-")]
            if not identifiers:
                raise OwnershipError(f"refusing empty {kind} cleanup request")
            resources = []
            for identifier in identifiers:
                command = ["volume", "inspect", identifier] if kind == "volume" else ["network", "inspect", identifier]
                inspected = _docker(command)
                if inspected.returncode:
                    raise OwnershipError(f"unable to inspect {kind} identity before deletion: {identifier}")
                item = json.loads(inspected.stdout)[0]
                labels = item.get("Labels") or {}
                resource = {"id": item.get("Id"), "name": item.get("Name"), "labels": labels}
                if not resource_is_owned(kind, resource, owner, claims):
                    raise OwnershipError(f"refusing to remove foreign {kind}: {identifier}")
                resources.append({"id": item.get("Id"), "name": item.get("Name"), "labels": labels})
            result = _docker(args, timeout=120)
            remaining = []
            for resource in resources:
                check = _docker([kind, "inspect", resource.get("name") or resource.get("id")])
                if check.returncode == 0:
                    remaining.append(resource.get("name") or resource.get("id"))
            _emit_resource_event({"kind": f"{kind}-remove", "resources": resources,
                                  "returncode": result.returncode, "remaining": remaining})
            sys.stdout.write(result.stdout)
            sys.stderr.write(result.stderr)
            return result.returncode

        if args[:2] == ["image", "rm"] or args[0] == "rmi":
            offset = 2 if args[0] == "image" else 1
            identifiers = [value for value in args[offset:] if not value.startswith("-")]
            image_claims = {claim["name"]: claim for claim in claims if claim.get("kind") == "image" and
                            claim.get("owner_token") == owner and claim.get("build_attempted") is True}
            resources = []
            for identifier in identifiers:
                claim = image_claims.get(identifier)
                if not claim:
                    raise OwnershipError(f"refusing image deletion by unclaimed tag/ID: {identifier}")
                inspected = _docker(["image", "inspect", identifier])
                if inspected.returncode:
                    raise OwnershipError(f"unable to inspect image identity before deletion: {identifier}")
                item = json.loads(inspected.stdout)[0]
                tags = item.get("RepoTags") or []
                if claim.get("expected_id") != item.get("Id") or identifier not in tags:
                    raise OwnershipError(f"refusing to remove unclaimed/replaced image reference: {identifier}")
                resources.append({"id": item["Id"], "repo_tags": tags, "requested": identifier})
            if "--no-prune" not in args:
                args.insert(2 if args[0] == "image" else 1, "--no-prune")
            result = _docker(args, timeout=120)
            remaining = []
            for resource in resources:
                requested = resource.get("requested")
                if requested and _docker(["image", "inspect", requested]).returncode == 0:
                    remaining.append(requested)
            _emit_resource_event({"kind": "image-remove", "resources": resources,
                                  "returncode": result.returncode, "remaining": remaining})
            sys.stdout.write(result.stdout)
            sys.stderr.write(result.stderr)
            return result.returncode

        is_build = ((args and args[0] == "build") or (args[:2] == ["image", "build"]) or
                    (args and args[0] == "compose" and "build" in args[1:]))
        if is_build:
            if args[0] == "compose":
                project = _project_from_compose(args[1:])
                if not project or project not in projects:
                    raise OwnershipError("refusing Compose build without an exact project claim")
            return _run_build_with_disk_guard(args)

        run_cidfile: str | None = None
        if args[:2] in (["image", "pull"], ["image", "tag"]):
            raise OwnershipError("direct image pull/tag is not part of the task-owned acceptance build path")
        if args[0] == "build" or args[:2] == ["image", "build"]:
            raise OwnershipError("direct docker build is forbidden; acceptance images require Compose image claims")
        if args[0] in ("run", "create") or args[:2] == ["container", "create"]:
            image_index, expected_image_id = _validate_docker_volume_references(args, claims, owner)
            owner_flag = f"{OWNER_LABEL}={owner}"
            create_container = args[0] == "create" or args[:2] == ["container", "create"]
            insert_at = 2 if args[:2] == ["container", "create"] else 1
            if owner_flag not in args:
                args[insert_at:insert_at] = ["--label", owner_flag]
                image_index += 2
            image_index = _ensure_pull_never(args, image_index, insert_at)
            args[image_index] = expected_image_id
            if create_container:
                result = _docker(args, timeout=120)
                container_id = result.stdout.strip() if result.returncode == 0 else ""
                current = _docker(["inspect", container_id]) if container_id else None
                if current is not None and current.returncode == 0:
                    item = json.loads(current.stdout)[0]
                    labels = (item.get("Config") or {}).get("Labels") or {}
                    if labels.get(OWNER_LABEL) != owner:
                        raise OwnershipError("created container did not retain its exact task owner label")
                    if item.get("Image") != expected_image_id:
                        raise OwnershipError("created container did not retain its verified task image ID")
                _emit_resource_event({"kind": "docker-create", "container_id": container_id or None,
                                      "returncode": result.returncode})
                sys.stdout.write(result.stdout)
                sys.stderr.write(result.stderr)
                return result.returncode
            if "--cidfile" not in args:
                descriptor, run_cidfile = tempfile.mkstemp(prefix="ecd-owned-container-")
                os.close(descriptor)
                os.unlink(run_cidfile)
                args[1:1] = ["--cidfile", run_cidfile]
                image_index += 2
            else:
                cid_index = args.index("--cidfile")
                run_cidfile = args[cid_index + 1] if cid_index + 1 < len(args) else None
            process = subprocess.Popen([_real_docker(), *args])
            try:
                returncode = process.wait()
            except KeyboardInterrupt:
                try:
                    process.send_signal(signal.SIGINT)
                    returncode = process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    returncode = process.wait()
            identifier = ""
            if run_cidfile:
                try:
                    identifier = Path(run_cidfile).read_text(encoding="utf-8").strip()
                except OSError:
                    pass
                if "--cidfile" not in sys.argv:
                    Path(run_cidfile).unlink(missing_ok=True)
            current = _docker(["inspect", identifier]) if identifier else None
            remaining = None
            if current is not None and current.returncode == 0:
                item = json.loads(current.stdout)[0]
                if item.get("Image") != expected_image_id:
                    raise OwnershipError("started container does not match its verified task image ID")
                remaining = {"id": item["Id"], "name": item.get("Name", "").lstrip("/"),
                             "image_id": item.get("Image"),
                             "labels": item.get("Config", {}).get("Labels") or {}}
            _emit_resource_event({"kind": "docker-run", "container_id": identifier or None,
                                  "remaining": remaining, "auto_remove": "--rm" in args,
                                  "returncode": returncode})
            return returncode
        elif args[:2] == ["network", "create"]:
            owner_flag = f"{OWNER_LABEL}={owner}"
            if owner_flag not in args:
                args[2:2] = ["--label", owner_flag]
        result = _docker(args, timeout=1800 if "build" in args else 120)
        if args[:2] == ["network", "create"] and result.returncode == 0:
            _emit_resource_event({"kind": "network-created", "id": result.stdout.strip(),
                                  "owner_label": owner, "returncode": result.returncode})
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result.returncode
    except (OwnershipError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        _emit_resource_event({"kind": "cleanup-denied-or-unverifiable", "reason": str(error)})
        print(f"Docker owner shim refused operation: {error}", file=sys.stderr)
        return 95


if __name__ == "__main__":
    raise SystemExit(docker_shim_main())
