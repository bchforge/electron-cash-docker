#!/usr/bin/env python3
"""Prepare a private, UID-10001 Xauthority copy for the Linux GUI overlay."""

from __future__ import annotations

import os
import re
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import NoReturn


APP_UID = 10001
APP_GID = 10001
SOURCE = Path(os.environ.get("XAUTHORITY_SOURCE", "/run/host-x11-authority"))
SOCKETS = Path(os.environ.get("X11_SOCKET_DIR", "/run/host-x11-sockets"))
OUTPUT = Path("/run/ecd-x11/authority")
DISPLAY = os.environ.get("DISPLAY", "")
stopping = False


def fail(message: str) -> NoReturn:
    print(f"[!] Linux X11 setup: {message}", file=sys.stderr, flush=True)
    raise SystemExit(1)


def normalize_xauth_display(display: str) -> str:
    match = re.fullmatch(r"(?P<prefix>(?:unix)?):(?P<number>[0-9]+)(?:\.[0-9]+)?", display)
    if not match or display == ":99":
        raise ValueError("DISPLAY must name a local X11/XWayland socket as :N or :N.S")
    return f"{match.group('prefix')}:{match.group('number')}"


def display_number(display: str) -> str:
    return normalize_xauth_display(display).rsplit(":", 1)[1]


def run_private(command: list[str], *, input_text: str | None = None,
                env: dict[str, str] | None = None, timeout: int = 5) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, input=input_text, text=True, capture_output=True,
                              env=env, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(command, 1, "", "")


def remove_private_copy() -> None:
    try:
        OUTPUT.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass
    if OUTPUT.parent.is_dir() and not OUTPUT.parent.is_symlink():
        for path in OUTPUT.parent.glob(".authority-*"):
            try:
                path.unlink()
            except OSError:
                pass


def matching_records(authority: Path) -> list[str]:
    try:
        lookup_display = normalize_xauth_display(DISPLAY)
        number = display_number(DISPLAY).encode("ascii")
        descriptor, temporary_name = tempfile.mkstemp(prefix=".authority-source-", dir=OUTPUT.parent)
    except (OSError, UnicodeEncodeError, ValueError):
        return []

    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as copied, authority.open("rb") as source:
            shutil.copyfileobj(source, copied)
        os.chmod(temporary, 0o600)
        # xauth creates an adjacent lock file even for nlist. The host authority
        # is mounted read-only, so query a private copy in our writable volume.
        # Do not filter nlist by DISPLAY here: FamilyLocal records name the host,
        # while this lookup runs inside the container. Filter the returned
        # entries by the normalized display number and MIT cookie below.
        listing = run_private(["xauth", "-f", str(temporary), "nlist"])
        if listing.returncode:
            return []
        records = []
        for line in listing.stdout.splitlines():
            fields = line.split()
            if len(fields) != 9 or not re.fullmatch(r"[0-9a-fA-F]{4}", fields[0]):
                continue
            try:
                address_length, number_length, name_length, data_length = (
                    int(fields[index], 16) for index in (1, 3, 5, 7))
            except ValueError:
                continue
            if (len(fields[2]) != address_length * 2 or len(fields[4]) != number_length * 2 or
                    len(fields[6]) != name_length * 2 or len(fields[8]) != data_length * 2 or
                    fields[4].lower() != number.hex() or
                    fields[6].lower() != b"MIT-MAGIC-COOKIE-1".hex() or data_length != 16 or
                    not re.fullmatch(r"[0-9a-fA-F]{32}", fields[8])):
                continue
            records.append("ffff" + line[4:])
        return records
    except OSError:
        return []
    finally:
        temporary.unlink(missing_ok=True)


def socket_available(number: str) -> bool:
    try:
        return stat.S_ISSOCK((SOCKETS / f"X{number}").stat().st_mode)
    except OSError:
        return False


def authenticated(authority: Path) -> bool:
    environment = {**os.environ, "XAUTHORITY": str(authority)}
    return run_private(["xdpyinfo", "-display", DISPLAY], env=environment).returncode == 0


def make_private_copy() -> None:
    remove_private_copy()
    try:
        number = display_number(DISPLAY)
    except ValueError as error:
        fail(str(error))
    try:
        source_info = SOURCE.stat()
    except OSError:
        fail("the selected XAUTHORITY file is missing or unreadable; set XAUTHORITY to this session's file")
    if source_info is None or not stat.S_ISREG(source_info.st_mode) or stat.S_IMODE(source_info.st_mode) & 0o077:
        fail("the selected XAUTHORITY must be a private regular file (mode 0600 or stricter)")

    if not socket_available(number):
        fail(f"the X11 socket for DISPLAY={DISPLAY} is unavailable; use a local X11/XWayland session")

    candidates = matching_records(SOURCE)
    if not candidates:
        fail(f"no MIT-MAGIC-COOKIE-1 entry matches DISPLAY={DISPLAY}; check the current desktop session")

    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".authority-", dir=OUTPUT.parent)
        os.close(descriptor)
        temporary = Path(temporary_name)
    except OSError:
        fail("the private Xauthority volume is not writable")
    try:
        merged = run_private(["xauth", "-f", str(temporary), "nmerge", "-"], input_text=candidates[0])
        if merged.returncode:
            fail("the selected Xauthority entry could not be copied safely")
        os.chmod(temporary, 0o400)
        os.chown(temporary, APP_UID, APP_GID)
        os.replace(temporary, OUTPUT)
    except OSError:
        fail("the private Xauthority copy could not be installed")
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    if not authenticated(OUTPUT):
        remove_private_copy()
        fail(f"the X server rejected its current cookie for DISPLAY={DISPLAY}; refresh the desktop session")
    print(f"[+] Prepared a private X11 cookie for DISPLAY={DISPLAY} (UID {APP_UID}).", flush=True)


def check_private_copy() -> int:
    try:
        info = OUTPUT.stat()
        source_info = SOURCE.stat()
    except OSError:
        return health_failure("the authority file is no longer available")
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != APP_UID or info.st_gid != APP_GID or
            stat.S_IMODE(info.st_mode) != 0o400):
        return health_failure("the private UID-10001 Xauthority copy has unsafe ownership or permissions")
    if not stat.S_ISREG(source_info.st_mode) or stat.S_IMODE(source_info.st_mode) & 0o077:
        return health_failure("the session XAUTHORITY is no longer a private regular file")
    try:
        number = display_number(DISPLAY)
    except ValueError:
        return health_failure("DISPLAY no longer names a supported local X11/XWayland display")
    if not socket_available(number):
        return health_failure(f"the X11 socket for DISPLAY={DISPLAY} is no longer available")
    source_records = matching_records(SOURCE)
    prepared_records = matching_records(OUTPUT)
    if not source_records:
        return health_failure(f"no current MIT-MAGIC-COOKIE-1 entry matches DISPLAY={DISPLAY}")
    if not prepared_records or prepared_records[0] != source_records[0]:
        return health_failure("the prepared cookie no longer matches the mounted session authority")
    if not authenticated(OUTPUT):
        return health_failure(f"the X server no longer accepts the cookie for DISPLAY={DISPLAY}")
    return 0


def health_failure(message: str) -> int:
    print("[!] Linux X11 setup: " + message +
          "; stop the GUI Compose project and start it again after the desktop session is ready.",
          file=sys.stderr, flush=True)
    return 1


def request_stop(_signum, _frame) -> None:
    global stopping
    stopping = True


def main() -> int:
    if sys.argv[1:] == ["--check"]:
        return check_private_copy()
    if sys.argv[1:]:
        fail("unsupported helper argument")
    make_private_copy()
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        while not stopping:
            time.sleep(1)
    finally:
        remove_private_copy()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
