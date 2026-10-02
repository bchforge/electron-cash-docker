"""Checked Electron Cash archive and Docker-volume copy operations."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from network_selection import NETWORK_FLAGS


FORMAT = "ecd-wallet-backup"
FORMAT_VERSION = 1
EXCLUDED_NAMES = {".env", "logs", "log", "cache", "caches", "tmp", "run"}
RUNTIME_UID = 10001
RUNTIME_GID = 10001
CONFIG_SECRET_KEYS = {
    "password",
    "proxy_password",
    "rpc_password",
    "rpc_password_file",
    "rpc_user",
    "rpc_username",
    "rpcpassword",
    "rpcuser",
}


def _config_path(network: str) -> Path:
    if network not in NETWORK_FLAGS:
        raise RuntimeError(f"unsupported backup network: {network}")
    if network == "mainnet":
        return Path("config")
    return Path(network) / "config"


def _included_roots(network: str) -> tuple[str, ...]:
    if network not in NETWORK_FLAGS:
        raise RuntimeError(f"unsupported backup network: {network}")
    if network == "mainnet":
        return (".electron-cash-docker", "config", "wallets", "mainnet")
    return (".electron-cash-docker", network)


def _relative_files(source: Path, network: str) -> list[Path]:
    files: list[Path] = []
    for root_name in _included_roots(network):
        root = source / root_name
        if not root.exists():
            continue
        if root.is_symlink():
            raise RuntimeError(f"backup source contains an unsafe entry: {root_name}")
        if root.is_file():
            candidates = [root]
        elif root.is_dir():
            candidates = []
            for path in root.rglob("*"):
                mode = path.lstat().st_mode
                if stat.S_ISLNK(mode):
                    raise RuntimeError(f"backup source contains an unsafe entry: {path.relative_to(source)}")
                if stat.S_ISREG(mode):
                    candidates.append(path)
                elif not stat.S_ISDIR(mode):
                    raise RuntimeError(f"backup source contains an unsupported entry: {path.relative_to(source)}")
        else:
            raise RuntimeError(f"backup source contains an unsupported root: {root_name}")
        for path in candidates:
            relative = path.relative_to(source)
            if any(part in EXCLUDED_NAMES for part in relative.parts):
                continue
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                raise RuntimeError(f"backup source contains an unsupported entry: {relative}")
            files.append(relative)
    return sorted(set(files), key=lambda path: path.as_posix())


def _is_network_config(relative: Path, network: str) -> bool:
    if relative.name != "config":
        return False
    if network == "mainnet":
        return relative.parts[:1] in {("config",), ("mainnet",)}
    return relative == _config_path(network)


def _sanitize_config(value):
    if isinstance(value, dict):
        return {
            key: _sanitize_config(item)
            for key, item in value.items()
            if key.lower() not in CONFIG_SECRET_KEYS
        }
    if isinstance(value, list):
        return [_sanitize_config(item) for item in value]
    return value


def _payload_bytes(path: Path, relative: Path, network: str) -> bytes | None:
    if not _is_network_config(relative, network):
        return None
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("Electron Cash config is not valid UTF-8 JSON") from error
    if not isinstance(config, dict):
        raise RuntimeError("Electron Cash config must be a JSON object")
    sanitized = _sanitize_config(config)
    return (json.dumps(sanitized, indent=4, sort_keys=True) + "\n").encode("utf-8")


def _manifest(source: Path, files: list[Path], network: str, ec_version: str) -> dict:
    entries = []
    for relative in files:
        path = source / relative
        digest = hashlib.sha256()
        size = 0
        payload = _payload_bytes(path, relative, network)
        if payload is None:
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
                    size += len(chunk)
        else:
            digest.update(payload)
            size = len(payload)
        entries.append(
            {
                "path": relative.as_posix(),
                "type": "file",
                "mode": stat.S_IMODE(path.stat().st_mode),
                "size": size,
                "sha256": digest.hexdigest(),
            }
        )
    return {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "electron_cash_version": ec_version,
        "network": network,
        "entries": entries,
    }


def create_archive(source: Path, network: str, ec_version: str) -> None:
    files = _relative_files(source, network)
    manifest = _manifest(source, files, network, ec_version)
    manifest_bytes = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with tarfile.open(fileobj=sys.stdout.buffer, mode="w|gz") as archive:
        manifest_info = tarfile.TarInfo("manifest.json")
        manifest_info.size = len(manifest_bytes)
        manifest_info.mode = 0o600
        archive.addfile(manifest_info, __import__("io").BytesIO(manifest_bytes))
        for relative in files:
            path = source / relative
            payload = _payload_bytes(path, relative, network)
            info = tarfile.TarInfo(f"payload/{relative.as_posix()}")
            info.size = len(payload) if payload is not None else path.stat().st_size
            info.mode = stat.S_IMODE(path.stat().st_mode)
            if payload is None:
                with path.open("rb") as handle:
                    archive.addfile(info, handle)
            else:
                archive.addfile(info, __import__("io").BytesIO(payload))


def _safe_member_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise RuntimeError(f"unsafe archive path: {name}")
    return path


def _read_archive(archive_path: Path) -> tuple[dict, list[tarfile.TarInfo], tarfile.TarFile]:
    archive = tarfile.open(archive_path, mode="r:gz")
    members = archive.getmembers()
    names = set()
    for member in members:
        path = _safe_member_name(member.name)
        if member.name in names:
            raise RuntimeError(f"duplicate archive path: {member.name}")
        names.add(member.name)
        if member.name == "manifest.json":
            if not member.isfile():
                raise RuntimeError("manifest is not a regular file")
        elif not member.name.startswith("payload/") or not member.isfile():
            raise RuntimeError(f"unsupported archive entry: {member.name}")
        if path.is_reserved():
            raise RuntimeError(f"reserved archive path: {member.name}")
    try:
        manifest_member = archive.getmember("manifest.json")
    except KeyError as error:
        archive.close()
        raise RuntimeError("archive has no manifest") from error
    manifest_file = archive.extractfile(manifest_member)
    if manifest_file is None:
        archive.close()
        raise RuntimeError("manifest cannot be read")
    try:
        manifest = json.load(manifest_file)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        archive.close()
        raise RuntimeError("manifest is invalid JSON") from error
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
        archive.close()
        raise RuntimeError("unsupported backup format")
    if manifest.get("format_version") != FORMAT_VERSION:
        archive.close()
        raise RuntimeError("unsupported backup format version")
    if not isinstance(manifest.get("network"), str) or not manifest["network"]:
        archive.close()
        raise RuntimeError("manifest has no network")
    if not isinstance(manifest.get("entries"), list):
        archive.close()
        raise RuntimeError("manifest entries are invalid")
    return manifest, members, archive


def _validate_manifest(
    manifest: dict,
    members: list[tarfile.TarInfo],
    network: str,
    ec_version: str,
) -> list[tuple[dict, tarfile.TarInfo]]:
    if manifest["network"] not in NETWORK_FLAGS:
        raise RuntimeError("backup has an unsupported network identity")
    if manifest["network"] != network:
        raise RuntimeError(f"backup network {manifest['network']} does not match {network}")
    if manifest.get("electron_cash_version") != ec_version:
        raise RuntimeError("backup Electron Cash version does not match the restore image")
    member_map = {member.name.removeprefix("payload/"): member for member in members if member.name.startswith("payload/")}
    seen = set()
    pairs = []
    for entry in manifest["entries"]:
        if not isinstance(entry, dict):
            raise RuntimeError("manifest entry is not an object")
        name = entry.get("path")
        if not isinstance(name, str):
            raise RuntimeError("manifest path is invalid")
        _safe_member_name(name)
        if name in seen or name not in member_map or not any(
            name == root or name.startswith(f"{root}/") for root in _included_roots(network)
        ):
            raise RuntimeError(f"manifest path is invalid or missing: {name}")
        if entry.get("type") != "file" or not isinstance(entry.get("mode"), int):
            raise RuntimeError(f"manifest type is invalid: {name}")
        if not isinstance(entry.get("size"), int) or entry["size"] < 0:
            raise RuntimeError(f"manifest size is invalid: {name}")
        if not isinstance(entry.get("sha256"), str) or len(entry["sha256"]) != 64:
            raise RuntimeError(f"manifest hash is invalid: {name}")
        member = member_map[name]
        if member.size != entry["size"]:
            raise RuntimeError(f"archive size does not match manifest: {name}")
        seen.add(name)
        pairs.append((entry, member))
    if seen != set(member_map):
        raise RuntimeError("archive and manifest entry sets differ")
    return pairs


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_runtime_ownership(root: Path) -> None:
    """Make a restored runtime tree writable by Electron Cash without changing modes."""
    if root.is_symlink() or not root.exists():
        raise RuntimeError(f"runtime path is not a safe entry: {root}")
    if root.is_dir():
        _reject_unsafe_tree(root)
        paths = [root, *sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())]
    elif root.is_file():
        paths = [root]
    else:
        raise RuntimeError(f"runtime path is not a regular file or directory: {root}")

    for path in paths:
        if path.is_symlink():
            raise RuntimeError(f"runtime tree contains an unsafe symbolic link: {path}")
        try:
            os.chown(path, RUNTIME_UID, RUNTIME_GID)
        except OSError as error:
            raise RuntimeError(f"unable to set restored ownership: {path}") from error


def _validate_config_payload(path: Path, relative: str) -> None:
    if Path(relative).name != "config":
        return
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"restored config is not valid UTF-8 JSON: {relative}") from error
    if not isinstance(config, dict) or _sanitize_config(config) != config:
        raise RuntimeError(f"restored config contains unsanitized secrets: {relative}")


def _check_archive_contents(
    archive_path: Path, network: str, ec_version: str
) -> tuple[dict, list[tuple[dict, tarfile.TarInfo]]]:
    manifest, members, archive = _read_archive(archive_path)
    try:
        pairs = _validate_manifest(manifest, members, network, ec_version)
        for entry, member in pairs:
            source = archive.extractfile(member)
            if source is None:
                raise RuntimeError(f"archive entry cannot be read: {entry['path']}")
            digest = hashlib.sha256()
            size = 0
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
            if size != entry["size"] or digest.hexdigest() != entry["sha256"]:
                raise RuntimeError(f"archive hash does not match manifest: {entry['path']}")
            payload = archive.extractfile(member)
            if payload is None:
                raise RuntimeError(f"archive entry cannot be read: {entry['path']}")
            if entry["path"].endswith("/config") or entry["path"] == "config":
                config_fd, config_name = tempfile.mkstemp(prefix="ecd-config-", dir="/tmp")
                os.close(config_fd)
                config_path = Path(config_name)
                try:
                    config_path.write_bytes(payload.read())
                    _validate_config_payload(config_path, entry["path"])
                finally:
                    config_path.unlink(missing_ok=True)
        return manifest, pairs
    finally:
        archive.close()


def validate_archive(archive_path: Path, network: str, ec_version: str) -> None:
    _check_archive_contents(archive_path, network, ec_version)


def validate_target(archive_path: Path, target: Path, network: str, ec_version: str) -> None:
    _manifest, pairs = _check_archive_contents(archive_path, network, ec_version)
    if not target.is_dir() or target.is_symlink():
        raise RuntimeError("restore target must be a directory")
    allowed = {Path(entry["path"]) for entry, _member in pairs}
    for path in target.rglob("*"):
        if path.is_symlink():
            raise RuntimeError(f"restored target contains an unsafe entry: {path.relative_to(target)}")
        if not path.is_file() and not path.is_dir():
            raise RuntimeError(f"restored target contains an unsupported entry: {path.relative_to(target)}")
        if path.is_file() and path.relative_to(target) not in allowed:
            raise RuntimeError(f"restored target contains an unexpected entry: {path.relative_to(target)}")
    for entry, _member in pairs:
        destination = target / entry["path"]
        if destination.is_symlink() or not destination.is_file():
            raise RuntimeError(f"restored entry is not a regular file: {entry['path']}")
        if destination.stat().st_size != entry["size"] or _hash_file(destination) != entry["sha256"]:
            raise RuntimeError(f"restored hash does not match manifest: {entry['path']}")
        _validate_config_payload(destination, entry["path"])


def restore_archive(archive_path: Path, target: Path, network: str, ec_version: str) -> None:
    target.mkdir(parents=True, exist_ok=True)
    if target.is_symlink() or list(target.iterdir()):
        raise RuntimeError("restore destination must be an empty directory")
    stage = Path(tempfile.mkdtemp(prefix="ecd-restore-", dir="/tmp"))
    try:
        manifest, pairs = _check_archive_contents(archive_path, network, ec_version)
        _extract_pairs(archive_path, stage, pairs)
        validate_target(archive_path, stage, network, ec_version)
        for entry, _member in pairs:
            source = stage / entry["path"]
            destination = target / entry["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            _copy_file(source, destination)
            os.chmod(destination, entry["mode"] & 0o777)
        for directory in sorted(
            {(target / entry["path"]).parent for entry, _ in pairs},
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            if directory.exists():
                os.chmod(directory, 0o700)
        os.chmod(target, 0o700)
        normalize_runtime_ownership(target)
        validate_target(archive_path, target, network, ec_version)
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _extract_pairs(archive_path: Path, target: Path, pairs: list[tuple[dict, tarfile.TarInfo]]) -> None:
    archive = tarfile.open(archive_path, mode="r:gz")
    try:
        for entry, member in pairs:
            destination = target / entry["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise RuntimeError(f"archive entry cannot be read: {entry['path']}")
            with destination.open("xb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            os.chmod(destination, entry["mode"] & 0o777)
            if destination.stat().st_size != entry["size"] or _hash_file(destination) != entry["sha256"]:
                raise RuntimeError(f"restored hash does not match manifest: {entry['path']}")
            _validate_config_payload(destination, entry["path"])
        for directory in sorted(
            {(target / entry["path"]).parent for entry, _ in pairs},
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            if directory.exists():
                os.chmod(directory, 0o700)
    finally:
        archive.close()


def _copy_file(source: Path, destination: Path) -> None:
    with source.open("rb") as input_file, destination.open("xb") as output:
        shutil.copyfileobj(input_file, output, length=1024 * 1024)
        output.flush()
        os.fsync(output.fileno())
    source_stat = source.stat()
    os.chmod(destination, stat.S_IMODE(source_stat.st_mode))
    os.chown(destination, source_stat.st_uid, source_stat.st_gid)
    os.utime(destination, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns))


def _reject_unsafe_tree(root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError(f"volume path is not a safe directory: {root}")
    for path in root.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise RuntimeError(f"volume contains an unsafe symbolic link: {path.relative_to(root)}")
        if not stat.S_ISREG(mode) and not stat.S_ISDIR(mode):
            raise RuntimeError(f"volume contains an unsupported entry: {path.relative_to(root)}")


def _remove_tree_contents(root: Path) -> None:
    _reject_unsafe_tree(root)
    for path in sorted(root.iterdir(), key=lambda item: len(item.parts), reverse=True):
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()


def _tree_signature(root: Path) -> list[tuple]:
    _reject_unsafe_tree(root)
    result = []
    root_stat = root.stat()
    result.append((".", "dir", stat.S_IMODE(root_stat.st_mode), root_stat.st_uid, root_stat.st_gid))
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        metadata = path.stat()
        kind = "dir" if path.is_dir() else "file"
        digest = _hash_file(path) if kind == "file" else ""
        result.append((relative, kind, stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid, digest))
    return result


def _copy_tree(source: Path, target: Path, *, replace: bool, preserve_target_root: bool = False) -> None:
    _reject_unsafe_tree(source)
    target.mkdir(parents=True, exist_ok=True)
    if target.is_symlink() or not target.is_dir():
        raise RuntimeError(f"volume path is not a safe directory: {target}")
    target_root_stat = target.stat() if preserve_target_root else None
    if replace:
        _remove_tree_contents(target)
    elif any(target.iterdir()):
        raise RuntimeError("snapshot destination must be empty")

    for source_path in sorted(source.rglob("*"), key=lambda item: (len(item.relative_to(source).parts), item.relative_to(source).as_posix())):
        relative = source_path.relative_to(source)
        destination = target / relative
        source_stat = source_path.stat()
        if source_path.is_dir():
            destination.mkdir()
            os.chmod(destination, stat.S_IMODE(source_stat.st_mode))
            os.chown(destination, source_stat.st_uid, source_stat.st_gid)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            _copy_file(source_path, destination)

    root_stat = target_root_stat or source.stat()
    os.chmod(target, stat.S_IMODE(root_stat.st_mode))
    os.chown(target, root_stat.st_uid, root_stat.st_gid)
    source_signature = _tree_signature(source)
    target_signature = _tree_signature(target)
    if preserve_target_root:
        # The staging directory is helper-owned; the live volume root keeps
        # its runtime ownership and mode during an in-place replacement.
        source_signature = source_signature[1:]
        target_signature = target_signature[1:]
    if source_signature != target_signature:
        raise RuntimeError("volume copy verification failed")


def snapshot_volume(source: Path, target: Path) -> None:
    _copy_tree(source, target, replace=False)
    normalize_runtime_ownership(target)


def restore_snapshot(snapshot: Path, target: Path) -> None:
    _copy_tree(snapshot, target, replace=True)
    normalize_runtime_ownership(target)


def replace_archive(archive_path: Path, target: Path, network: str, ec_version: str) -> None:
    if not target.is_dir() or target.is_symlink():
        raise RuntimeError("restore target must be a directory")
    stage = Path(tempfile.mkdtemp(prefix="ecd-restore-", dir="/tmp"))
    try:
        manifest, pairs = _check_archive_contents(archive_path, network, ec_version)
        _extract_pairs(archive_path, stage, pairs)
        normalize_runtime_ownership(stage)
        validate_target(archive_path, stage, network, ec_version)
        # Preserve every other network in the shared named volume. The host
        # wrapper has already taken a verified full-volume rollback snapshot.
        merged = Path(tempfile.mkdtemp(prefix="ecd-merged-", dir="/tmp"))
        try:
            _copy_tree(target, merged, replace=False)
            for name in _included_roots(network):
                old = merged / name
                if old.is_dir():
                    shutil.rmtree(old)
                elif old.exists():
                    old.unlink()
            for name in _included_roots(network):
                fresh = stage / name
                if fresh.is_dir():
                    shutil.copytree(fresh, merged / name)
                elif fresh.is_file():
                    shutil.copy2(fresh, merged / name)
            normalize_runtime_ownership(merged)
            _copy_tree(merged, target, replace=True, preserve_target_root=True)
        finally:
            shutil.rmtree(merged, ignore_errors=True)
        normalize_runtime_ownership(target)
        for entry, _member in pairs:
            restored = target / entry["path"]
            if not restored.is_file() or _hash_file(restored) != entry["sha256"]:
                raise RuntimeError(f"restored hash does not match manifest: {entry['path']}")
        del manifest
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: backup_tool.py create|verify|restore|replace|snapshot|restore-snapshot ...", file=sys.stderr)
        return 2
    try:
        operation = sys.argv[1]
        if operation == "create":
            create_archive(Path(sys.argv[2]), os.environ["BACKUP_NETWORK"], os.environ["EC_VERSION"])
        elif operation == "verify":
            validate_archive(Path(sys.argv[2]), os.environ["BACKUP_NETWORK"], os.environ["EC_VERSION"])
        elif operation == "restore":
            restore_archive(Path(sys.argv[2]), Path(sys.argv[3]), os.environ["BACKUP_NETWORK"], os.environ["EC_VERSION"])
        elif operation == "replace":
            replace_archive(Path(sys.argv[2]), Path(sys.argv[3]), os.environ["BACKUP_NETWORK"], os.environ["EC_VERSION"])
        elif operation == "snapshot":
            snapshot_volume(Path(sys.argv[2]), Path(sys.argv[3]))
        elif operation == "restore-snapshot":
            restore_snapshot(Path(sys.argv[2]), Path(sys.argv[3]))
        else:
            raise RuntimeError("unknown backup operation")
    except (IndexError, KeyError):
        print("[!] backup operation arguments are incomplete", file=sys.stderr)
        return 2
    except Exception as error:
        print(f"[!] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
