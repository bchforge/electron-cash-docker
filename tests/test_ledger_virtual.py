#!/usr/bin/env python3
"""Explicit, unattended Speculos regression against the current wallet image.

No production changes, USB emulation, personal wallet, display or full gate.
Pinned test tools/app are cached externally; disposable runtime is always removed.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ci

STATE = Path.home() / ".local/state/electron-cash-docker"
CACHE = Path.home() / ".cache/ecd-ledger-virtual"
PYTHON = "/opt/electroncash-venv/bin/python"
SPECULOS = "ghcr.io/ledgerhq/speculos@sha256:82e1b0716aec72dbc9c2639d8e2f2beb16e630cf35b61a9e82186d52f373ca85"
SPECULOS_COMMIT = "23f17c58fe213dfa1b94b731953c2860731b8050"
BUILDER = "ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite@sha256:a9d41278aa7398ea8fe118782d1b9124c9e8b56a7b778d7a61edb9abb2ee812c"
APP_REPO = "https://github.com/LedgerHQ/app-bitcoin-legacy.git"
APP_COMMIT = "fdace8fa97901c5edb13997cfd47a2ef78db82c0"
APP_LIBRARY = "e4671b5588099d61725db316813096285143aac2"
APP_HASH = "de57955efcd503128aea96f60862b374af992df8569df063294da1be11f71337"
SDK_COMMIT = "6709cd2bdfebb224ee070f7c1211b54254262579"
MNEMONIC = "abandon " * 11 + "about"  # PUBLIC TEST ONLY, NEVER FUND.
BTCHIP_URL = "https://files.pythonhosted.org/packages/30/fd/16394adaff5736840aeda77163d5f6f593091d687a1807ff02dedcfc7bca/btchip-python-0.1.32.tar.gz"
BTCHIP_HASH = "34f5e0c161c08f65dc0d070ba2ff4c315ed21c4b7e0faa32a46862d0dc1b8f55"
HID_URL = "https://files.pythonhosted.org/packages/ba/c8/52134f7d3e09fd4feb7756ccd872c55bfd1899ee81ceed4f8ad5ae39f457/hidapi-0.14.0.post4-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
HID_HASH = "fedb9c3be6a2376de436d13fcb37a686a9b6bc988585bcc4f5ec61cad925e794"
OWNER_LABEL = "org.bchforge.ecd.ledger-virtual-owner"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def verified_download(url, digest):
    cached = CACHE / digest
    if cached.exists() and ci.sha256_file(cached) == digest:
        return cached.read_bytes()
    for attempt in range(3):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                data = response.read()
            require(hashlib.sha256(data).hexdigest() == digest, "download hash mismatch: " + url)
            cached.write_bytes(data)
            return data
        except OSError:
            if attempt == 2:
                raise
            time.sleep(2)
    raise RuntimeError("download exhausted")


def verify_evidence(directory):
    """Reopen durable bytes and validate the manifest and required outcomes."""
    directory = Path(directory)
    manifest = json.loads((directory / "manifest.json").read_text())
    digest = ci.sha256_file(directory / "manifest.json")
    valid = digest == (directory / "manifest.sha256").read_text().split()[0]
    for name, expected_hash in manifest["files"].items():
        require(Path(name).name == name, "invalid manifest member")
        valid = valid and ci.sha256_file(directory / name) == expected_hash
    names = ("result", "speculos", "ledger-app", "transport", "plugin", "derivation", "reconnect",
             "ledger-contract", "cleanup")
    valid = valid and all(json.loads((directory / (name + ".json")).read_text())["status"] == "PASS" for name in names)
    return {"status": "PASS" if valid else "FAIL", "manifest_sha256": digest,
            "files_verified": len(manifest["files"]), "independent_process": True}


class Validation:
    def __init__(self, evidence):
        self.evidence = evidence
        self.owner = uuid.uuid4().hex
        self.names = []
        self.network = None
        self.env = {**os.environ, "BASIC_AUTH_PASSWORD": "LedgerVirtualPublicFixtureOnly"}
        self.temp: Path | None = None
        self.candidate = {}
        self.wallet: str | None = None

    def write(self, name, value):
        ci.json_write(self.evidence / name, value)

    def command(self, args, *, timeout=120, check=True):
        result = subprocess.run(args, cwd=ROOT, env=self.env, text=True, capture_output=True, timeout=timeout)
        # Public fixture seed is represented by an ID in the command ledger.
        safe_args = ["BIP39_ABANDON_11_ABOUT_TEST_ONLY" if arg == MNEMONIC else str(arg) for arg in args]
        with (self.evidence / "command.log").open("a") as log:
            log.write(json.dumps({"command": safe_args, "exit_code": result.returncode}) + "\n")
        if check:
            require(result.returncode == 0, f"command failed ({result.returncode}): {safe_args}: " +
                    (result.stdout + result.stderr)[-4000:])
        return (result.stdout + result.stderr).strip() if args[:2] == ["docker", "logs"] else result.stdout.strip()

    def pull(self, image):
        if not self.command(["docker", "image", "inspect", image], check=False):
            self.command(["docker", "pull", "--platform", "linux/amd64", image], timeout=900)
        info = json.loads(self.command(["docker", "image", "inspect", image]))[0]
        require(info["Os"] == "linux" and info["Architecture"] == "amd64", "tool image platform mismatch")
        return info

    def owned_run(self, suffix, args, *, timeout=120):
        name = "ecd-ledger-virtual-" + self.owner + "-" + suffix
        self.names.append(name)
        return self.command(["docker", "run", "--name", name, "--label", OWNER_LABEL + "=" + self.owner,
                             "--platform", "linux/amd64", "--pull=never", *args], timeout=timeout)

    def configuration_fingerprint(self):
        return ci.sha256_bytes(json.dumps({n: ci.sha256_file(ROOT / n) for n in
            (".env.example", "docker-compose.yml", "docker-compose.gui.yml", "docker-compose.headless.yml",
             "docker-compose.hw.yml", "docker-compose.rpc.yml")}, sort_keys=True, separators=(",", ":")).encode())

    def resolve_wallet(self):
        base = ["docker", "compose", "--env-file", str(ROOT / ".env.example"), "-f", str(ROOT / "docker-compose.yml")]
        model = json.loads(self.command([*base, "config", "--format", "json"]))
        descriptor = ci.image_build_configuration(model, "electron-cash", model["services"]["electron-cash"]["image"],
            variant="electron-cash-normal", compose_files=[ROOT / "docker-compose.yml"])
        paths = sorted([*STATE.glob("**/focused-images*.json"), *STATE.glob("**/image-proof.json")],
                       key=lambda p: p.stat().st_mtime, reverse=True)
        for path in paths:
            try:
                proof = json.loads(path.read_text())["proof"]["electron-cash"]
                ci.validate_image_reuse(descriptor, proof)
                info = json.loads(self.command(["docker", "image", "inspect", proof["image_id"]]))[0]
                require(info["Os"] == "linux" and info["Architecture"] == "amd64", "wallet platform mismatch")
            except (OSError, ValueError, KeyError, IndexError, RuntimeError, ci.ValidationError):
                continue
            selected = {**descriptor, "image_id": info["Id"], "input_modes": proof["input_modes"],
                        "reused": True, "proof_path": str(path), "proof_sha256": ci.sha256_file(path)}
            break
        else:
            tag = "ecd-ledger-virtual-wallet:" + descriptor["configuration_sha256"][:32]
            self.env["ELECTRON_CASH_IMAGE"] = tag
            self.command([*base, "build", "electron-cash"], timeout=1800)
            info = json.loads(self.command(["docker", "image", "inspect", tag]))[0]
            selected = {**descriptor, "image_id": info["Id"], "reused": False,
                "input_modes": {p: format((Path(descriptor["context"]) / p).stat().st_mode & 0o777, "04o")
                                for p in descriptor["inputs"]}}
        self.write("image-proof.json", {"proof": {"electron-cash": selected}})
        self.wallet = selected["image_id"]

    def dependencies(self):
        # These are the exact HW overlay libraries, mounted read-only into the
        # ordinary candidate image for this test. No image is altered/rebuilt.
        deps = CACHE / "deps-btchip-0.1.32-hidapi-0.14.0.post4-cp312"
        deps.mkdir(exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(verified_download(BTCHIP_URL, BTCHIP_HASH)), mode="r:gz") as archive:
            for member in archive.getmembers():
                parts = Path(member.name).parts
                if member.isfile() and len(parts) > 2 and parts[1] == "btchip":
                    require(".." not in parts, "unsafe dependency archive")
                    target = deps.joinpath(*parts[1:])
                    target.parent.mkdir(parents=True, exist_ok=True)
                    handle = archive.extractfile(member)
                    if handle is None:
                        raise RuntimeError("dependency archive member missing")
                    target.write_bytes(handle.read())
        with zipfile.ZipFile(io.BytesIO(verified_download(HID_URL, HID_HASH))) as archive:
            for name in archive.namelist():
                path = Path(name)
                require(not path.is_absolute() and ".." not in path.parts, "unsafe HID wheel")
                if not name.endswith("/"):
                    target = deps / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.read(name))
        return deps

    def application(self):
        artifact = CACHE / (APP_HASH + ".elf")
        record = {"repository": APP_REPO, "commit": APP_COMMIT, "version": "2.4.12",
                  "library_commit": APP_LIBRARY, "model": "nanox", "coin": "bitcoin_cash",
                  "builder": BUILDER, "sdk_commit": SDK_COMMIT, "api_level": 27,
                  "build": "make BOLOS_SDK=$NANOX_SDK COIN=bitcoin_cash -j2",
                  "sha256": APP_HASH, "artifact": str(artifact)}
        if not artifact.exists() or ci.sha256_file(artifact) != APP_HASH:
            self.pull(BUILDER)
            if self.temp is None:
                raise RuntimeError("temporary build directory missing")
            source = self.temp / "app-source"
            self.command(["git", "clone", APP_REPO, str(source)], timeout=300)
            self.command(["git", "-C", str(source), "checkout", "--detach", APP_COMMIT])
            self.command(["git", "-c", "url.https://github.com/.insteadOf=git@github.com:", "-C", str(source),
                          "submodule", "update", "--init", "--recursive"], timeout=300)
            require(self.command(["git", "-C", str(source / "lib-app-bitcoin"), "rev-parse", "HEAD"]) == APP_LIBRARY,
                    "application library pin mismatch")
            self.owned_run("app-build", ["--rm", "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
                "-v", f"{source}:/app", "--entrypoint", "bash", BUILDER, "-c",
                f'test "$(git -C "$NANOX_SDK" rev-parse HEAD)" = {SDK_COMMIT} && '
                'make -C /app BOLOS_SDK=$NANOX_SDK COIN=bitcoin_cash -j2'], timeout=600)
            built = source / "build/nanox/bin/app.elf"
            require(ci.sha256_file(built) == APP_HASH, "built application hash does not match pin")
            shutil.copyfile(built, artifact)
        require(ci.sha256_file(artifact) == APP_HASH, "cached application hash mismatch")
        self.write("ledger-app.json", {**record, "status": "PASS"})
        return artifact

    def hardware_audit(self):
        from test_electron_cash_version import test_declared_pins
        from test_integrity_pins import test_current_os_pins_and_ledger_source
        current_pins = test_declared_pins()
        test_current_os_pins_and_ledger_source()
        # Resolve today's supported GUI/HW stack, without requiring an old tag
        # or textual equality to a released implementation.
        self.env.update(DISPLAY=":0", HW_USB_GID="10001")
        model = json.loads(self.command(["docker", "compose", "--env-file", str(ROOT / ".env.example"),
            "-f", str(ROOT / "docker-compose.yml"), "-f", str(ROOT / "docker-compose.gui.yml"),
            "-f", str(ROOT / "docker-compose.hw.yml"), "config", "--format", "json"]))
        wallet = model["services"]["electron-cash"]
        checks = {}
        checks["opt-in HW build and runtime"] = (wallet["build"]["args"]["HW_SUPPORT"] == "1" and
            wallet["environment"]["HW_SUPPORT"] == "1" and wallet["environment"]["ECD_GUI_OVERLAY"] == "true" and
            wallet["environment"]["HW_USB_GID"] == "10001")
        checks["Electron Cash version/commit/archive"] = all(wallet["build"]["args"][key] == current_pins[key]
            for key in ("EC_VERSION", "EC_COMMIT", "EC_ARCHIVE_SHA256"))
        dockerfile = (ROOT / "docker/Dockerfile").read_text()
        block = dockerfile.split('RUN if [ "${HW_SUPPORT}" = 1 ]; then', 1)[1].split("COPY --from=plugin-builder", 1)[0]
        checks["Ledger dependency/install block"] = all(token in block for token in
            ("libhidapi-libusb0=0.14.0-1build1", "hidapi==0.14.0.post4", BTCHIP_HASH,
             "sha256sum -c -", "pip install --no-cache-dir --no-deps /tmp/btchip-source"))
        entrypoint = (ROOT / "docker/entrypoint.sh").read_text()
        checks["HW entrypoint guard and non-root USB group"] = all(token in entrypoint for token in
            ('[ "${HW_SUPPORT:-0}" = 1 ] && [ "${ECD_GUI_OVERLAY:-false}" != true ]',
             '[ -d /dev/bus/usb ]', "''|*[!0-9]*)", 'runtime_groups=(--groups "${HW_USB_GID:',
             'exec setpriv --reuid 10001 --regid 10001 "${runtime_groups[@]}"'))
        wrapper = (ROOT / "docker/electroncash-wrapper.py").read_text()
        checks["wrapper has no Ledger-specific override"] = not re.search(r"ledger|btchip|hidapi", wrapper, re.I)
        checks["wallet-only physical USB scope"] = (wallet.get("devices") ==
            [{"source": "/dev/bus/usb", "target": "/dev/bus/usb", "permissions": "rwm"}] and
            wallet.get("device_cgroup_rules") == ["c 189:* rw"] and
            all(not service.get("devices") and not service.get("device_cgroup_rules")
                for name, service in model["services"].items() if name != "electron-cash"))
        checks["no privileged escalation"] = all(not service.get("privileged") and service.get("read_only") and
            service.get("cap_drop") == ["ALL"] and "no-new-privileges:true" in service.get("security_opt", [])
            for service in model["services"].values())
        record = {"status": "PASS" if all(checks.values()) else "FAIL",
                  "checks": checks, "pins": {key: current_pins[key] for key in ("EC_VERSION", "EC_COMMIT", "EC_ARCHIVE_SHA256")},
                  "permissions": "wallet-only USB mapping, numeric GID, non-root runtime and hardened services",
                  "scope": "Ledger transport, HW dependency block, pinned plugin, device permissions, HW entrypoint/wrapper"}
        self.write("ledger-contract.json", record)
        require(all(checks.values()), "current Ledger hardware contract failed: " + str(checks))
    def execute(self):
        require(shutil.which("docker") and shutil.which("git"), "Docker and git required")
        self.command(["docker", "info", "--format", "{{.ServerVersion}}"])
        self.resolve_wallet()
        self.candidate = ci.candidate_identity(self.evidence)
        self.candidate.update(configuration_fingerprint=self.configuration_fingerprint(), wallet_image=self.wallet)
        self.write("candidate.json", self.candidate)
        self.hardware_audit()
        tools = self.pull(SPECULOS)
        require(tools["Config"]["Labels"]["org.opencontainers.image.version"] == "v0.27.1", "Speculos version mismatch")
        deps = self.dependencies()
        app = self.application()
        self.network = "ecd-ledger-virtual-" + self.owner
        self.command(["docker", "network", "create", "--internal", "--label", OWNER_LABEL + "=" + self.owner, self.network])
        self.owned_run("speculos", ["-d", "--network", self.network, "--network-alias", "speculos",
            "--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "-v", f"{app}:/app.elf:ro",
            SPECULOS, "/app.elf", "--model", "nanox", "--display", "headless", "--seed", MNEMONIC,
            "--deterministic-rng", "0", "--apdu-port", "9999", "--api-port", "5000"])
        speculos_name = self.names[-1]
        diagnostic = 'import json,urllib.request; r=urllib.request.Request("http://127.0.0.1:5000/apdu", data=b\'{"data":"e0c4000000"}\',headers={"Content-Type":"application/json"}); print(urllib.request.urlopen(r,timeout=5).read().decode())'
        deadline, response = time.monotonic() + 60, None
        while time.monotonic() < deadline:
            try:
                raw = self.command(["docker", "exec", speculos_name, "python", "-c", diagnostic], check=False)
                response = json.loads(raw)
                if response.get("data", "").endswith("9000"):
                    break
            except ValueError:
                pass
            time.sleep(1)
        require(response and response.get("data") == "1a3002040c0100039000", "virtual BCH application not responding: " + str(response))
        self.write("speculos.json", {"status": "PASS", "version": "v0.27.1", "repository": "https://github.com/LedgerHQ/speculos",
            "commit": SPECULOS_COMMIT, "image": SPECULOS, "image_id": tools["Id"], "model": "nanox",
            "fixture": "BIP39_ABANDON_11_ABOUT_TEST_ONLY", "mnemonic_sha256": hashlib.sha256(MNEMONIC.encode()).hexdigest(),
            "passphrase": "empty", "deterministic_rng": "0", "app_sha256": APP_HASH,
            "firmware_apdu": "e0c4000000", "firmware_response": response, "host_ports_published": []})
        output = self.owned_run("wallet", ["--rm", "--network", self.network, "--read-only", "--cap-drop=ALL",
            "--security-opt", "no-new-privileges:true", "--user", "10001:10001", "--tmpfs", "/tmp:size=32m,mode=1777",
            "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "PYTHONPATH=/ledger-deps", "-v", f"{deps}:/ledger-deps:ro",
            "-v", f"{ROOT / 'tests/ledger_virtual_guest.py'}:/ledger-test.py:ro", "--entrypoint", PYTHON,
            self.wallet, "/ledger-test.py", "speculos"], timeout=180)
        result = json.loads(output.splitlines()[-1])
        require(result["status"] == "PASS", "plugin acceptance failed")
        for name in ("plugin", "derivation", "reconnect", "transport"):
            self.write(name + ".json", {"status": "PASS", **result[name]})
        self.write("signing.json", {"status": "NOT_REQUIRED_FOR_CURRENT_REGRESSION",
            "reason": "historical physical compatibility scope was read-only BCH public-path interaction; no offline transaction signing acceptance added"})
        self.write("dependency.json", {"btchip": {"version": "0.1.32", "source_sha256": BTCHIP_HASH},
            "hidapi": {"version": "0.14.0.post4", "wheel_sha256": HID_HASH},
            "isolation": "test-only read-only mount; ordinary production image unchanged"})
        with tempfile.TemporaryDirectory(dir=CACHE) as directory:
            end = ci.candidate_identity(Path(directory))
        require(end["source_fingerprint"] == self.candidate["source_fingerprint"], "source changed during validation")
        require(self.configuration_fingerprint() == self.candidate["configuration_fingerprint"], "configuration changed during validation")

    def cleanup(self):
        failures, removed = [], []
        for name in reversed(self.names):
            raw = self.command(["docker", "container", "inspect", name], check=False)
            if not raw or not json.loads(raw):
                continue
            item = json.loads(raw)[0]
            if item["Config"]["Labels"].get(OWNER_LABEL) != self.owner:
                failures.append("container ownership mismatch: " + name)
                continue
            if name.endswith("-speculos"):
                logs = self.command(["docker", "logs", name], check=False)
                (self.evidence / "speculos.log").write_text(logs + "\n")
            if item["State"]["Running"]:
                self.command(["docker", "stop", "-t", "10", name], check=False)
            self.command(["docker", "rm", "-f", name])
            removed.append(name)
        if self.network:
            self.command(["docker", "network", "rm", self.network])
        if self.temp:
            shutil.rmtree(self.temp)
        for kind, args in (("containers", ["docker", "ps", "-aq"]), ("networks", ["docker", "network", "ls", "-q"]),
                           ("volumes", ["docker", "volume", "ls", "-q"])):
            if self.command([*args, "--filter", "label=" + OWNER_LABEL + "=" + self.owner]):
                failures.append("owned " + kind + " remain")
        require(not self.temp or not self.temp.exists(), "temporary state remains")
        self.write("cleanup.json", {"status": "PASS" if not failures else "FAIL", "owner": self.owner,
            "removed_containers": removed, "remaining_resources": failures, "temporary_state_removed": True,
            "ports_published": [], "retained": "verified dependency/app/image caches and durable evidence only"})
        require(not failures, "cleanup failed: " + str(failures))

    def seal(self):
        manifest = {"schema_version": 1, "files": {p.name: ci.sha256_file(p) for p in sorted(self.evidence.iterdir())
            if p.is_file() and p.name not in ("manifest.json", "manifest.sha256", "verification-result.json")}}
        self.write("manifest.json", manifest)
        digest = ci.sha256_file(self.evidence / "manifest.json")
        (self.evidence / "manifest.sha256").write_text(digest + "  manifest.json\n")
        # A separate Python process reopens the saved bytes, rather than trusting
        # in-memory result objects. It also validates mandatory outcomes.
        verifier = 'import json,sys; from test_ledger_virtual import verify_evidence; v=verify_evidence(sys.argv[1]); print(json.dumps(v)); sys.exit(0 if v["status"]=="PASS" else 1)'
        verification = subprocess.run([sys.executable, "-c", verifier, str(self.evidence)],
            cwd=ROOT / "tests", text=True, capture_output=True, timeout=30)
        self.write("verification-result.json", json.loads(verification.stdout))
        require(verification.returncode == 0, "independent evidence verification failed")
        return digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    STATE.mkdir(parents=True, exist_ok=True)
    CACHE.mkdir(parents=True, exist_ok=True)
    evidence = args.evidence_dir or STATE / ("v" + (ROOT / "VERSION").read_text().strip() + "-ledger-virtual-" +
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8])
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    validation = Validation(evidence)
    def interrupted(_signum, _frame):
        raise RuntimeError("Ledger virtual validation interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    error = None
    with (CACHE / "cache.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        validation.temp = Path(tempfile.mkdtemp(prefix="runtime-", dir=CACHE))
        try:
            validation.execute()
        except Exception as exception:
            error = str(exception)
        finally:
            try:
                validation.cleanup()
            except Exception as exception:
                error = (error + "; " if error else "") + str(exception)
    validation.write("result.json", {"status": "FAIL" if error else "PASS", "exit_code": 1 if error else 0,
        "command": "./scripts/ci.sh ledger-virtual", "class": "CURRENT_VIRTUAL_RUNTIME", "error": error,
        "source_fingerprint": validation.candidate.get("source_fingerprint"), "wallet_image": validation.wallet})
    if error:
        print("RESULT: FAIL\n" + error + "\nEvidence: " + str(evidence), file=sys.stderr)
        return 1
    digest = validation.seal()
    print("Ledger virtual validation\n-------------------------")
    print("Candidate: " + validation.candidate["source_fingerprint"])
    print(f"Wallet image: {validation.wallet}\n")
    print("Speculos: PASS (v0.27.1)\nLedger app: Bitcoin Cash 2.4.12 (Nano X)")
    print("Virtual Ledger: PASS\nElectron Cash Ledger plugin: PASS\nLedger protocol/APDU: PASS")
    print("BCH derivation/xpub/address: PASS\nReconnect: PASS\nSigning: NOT_REQUIRED_FOR_CURRENT_REGRESSION\nCleanup: PASS")
    print("\nPhysical Ledger validation is separate and is not rerun by this virtual test.")
    print("Evidence: " + str(evidence) + "\nManifest SHA-256: " + digest + "\n\nRESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
