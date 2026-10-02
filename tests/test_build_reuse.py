#!/usr/bin/env python3
"""Build recipe identity follows actual build inputs, not runtime consumers."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ci


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ecd-build-recipe-") as temporary:
        context = Path(temporary)
        docker = context / "docker"
        docker.mkdir()
        dockerfile = context / "Dockerfile"
        dockerfile.write_text(
            "FROM ubuntu:24.04@sha256:immutable\n"
            "ARG HW_SUPPORT=0\n"
            "COPY docker/entrypoint.sh /entrypoint.sh\n"
            "ENTRYPOINT [\"/entrypoint.sh\"]\n",
            encoding="utf-8",
        )
        input_path = docker / "entrypoint.sh"
        input_path.write_text("#!/bin/sh\necho task\n", encoding="utf-8")
        (context / ".dockerignore").write_text("**\n!docker/\n", encoding="utf-8")
        docs = context / "docs.md"
        tests = context / "tests.py"
        docs.write_text("docs one\n", encoding="utf-8")
        tests.write_text("test one\n", encoding="utf-8")

        def model(hw_support: str) -> dict:
            return {"services": {"electron-cash": {"build": {
                "context": str(context), "dockerfile": "Dockerfile",
                "args": {"EC_VERSION": "4.4.6", "HW_SUPPORT": hw_support}},
                "platform": None}}}

        normal = ci.image_build_configuration(
            model("0"), "electron-cash", "electron-cash-ci:normal",
            variant="electron-cash-normal", compose_files=[context / "docker-compose.yml"])
        gui_runtime = ci.image_build_configuration(
            model("0"), "electron-cash", "electron-cash-ci:gui",
            variant="electron-cash-normal", compose_files=[context / "docker-compose.yml",
                                                           context / "docker-compose.gui.yml"])
        hardware = ci.image_build_configuration(
            model("1"), "electron-cash", "electron-cash-ledger-ci:hardware",
            variant="electron-cash-hw", compose_files=[context / "docker-compose.yml",
                                                       context / "docker-compose.gui.yml",
                                                       context / "docker-compose.hw.yml"])
        assert normal["configuration_sha256"] == gui_runtime["configuration_sha256"]
        assert normal["configuration_sha256"] != hardware["configuration_sha256"]
        tracked_inputs = normal["inputs"]
        assert "docs.md" not in tracked_inputs and "tests.py" not in tracked_inputs
        assert "docker/entrypoint.sh" in tracked_inputs

        docs.write_text("docs two\n", encoding="utf-8")
        tests.write_text("test two\n", encoding="utf-8")
        after_non_input_change = ci.image_build_configuration(
            model("0"), "electron-cash", "electron-cash-ci:normal",
            variant="electron-cash-normal", compose_files=[context / "docker-compose.yml"])
        assert after_non_input_change["configuration_sha256"] == normal["configuration_sha256"]

        input_path.write_text("#!/bin/sh\necho changed build input\n", encoding="utf-8")
        after_input_change = ci.image_build_configuration(
            model("0"), "electron-cash", "electron-cash-ci:normal",
            variant="electron-cash-normal", compose_files=[context / "docker-compose.yml"])
        assert after_input_change["configuration_sha256"] != normal["configuration_sha256"]

    print("PASS distinct normal/HW recipes, shared runtime variant reuse, and input-scoped invalidation")


if __name__ == "__main__":
    main()
