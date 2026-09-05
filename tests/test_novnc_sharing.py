#!/usr/bin/env python3
"""Static regression checks for the x11vnc/noVNC sharing configuration."""

import shlex
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "docker" / "entrypoint.sh"


def test_x11vnc_uses_shared_server_mode() -> None:
    entrypoint = ENTRYPOINT.read_text(encoding="utf-8")
    command = next(
        line.strip()
        for line in entrypoint.splitlines()
        if line.strip().startswith("x11vnc ")
    )

    arguments = shlex.split(command)
    shared_index = arguments.index("-shared")

    # x11vnc 0.9.16's -alwaysshared path does not enable alwaysShared.
    assert arguments[shared_index - 1] == "-forever"
    assert not {"-alwaysshared", "-nevershared", "-dontdisconnect"}.intersection(
        arguments
    )


def main() -> None:
    test_x11vnc_uses_shared_server_mode()
    print("PASS x11vnc shared server mode")


if __name__ == "__main__":
    main()
