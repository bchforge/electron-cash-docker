#!/usr/bin/env python3
"""Generate the XQuartz-only Compose mounts without enabling Linux X11 prep."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: mac-compose-overlay.py OUTPUT XAUTHORITY")
    output = Path(sys.argv[1])
    authority = Path(sys.argv[2])
    document = {"services": {"electron-cash": {
        "environment": {"XAUTHORITY": "/home/electroncash/.Xauthority"},
        "volumes": [
            {"type": "volume", "source": "electron-cash-data",
             "target": "/home/electroncash/.electron-cash"},
            {"type": "bind", "source": str(authority),
             "target": "/home/electroncash/.Xauthority", "read_only": True,
             "bind": {"create_host_path": False}},
        ],
    }}}
    rendered = json.dumps(document, separators=(",", ":")).replace(
        '"volumes":[', '"volumes": !override [', 1)
    output.write_text(rendered + "\n", encoding="utf-8")
    os.chmod(output, 0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
