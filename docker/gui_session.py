"""Narrow, project-owned GUI lifetime state. No Docker API or wallet data."""
import os
import re
import tempfile
import uuid
from pathlib import Path

DIRECTORY = Path('/run/ecd-gui-session')
STATE = DIRECTORY / 'state'


def enabled():
    return os.environ.get('ECD_GUI_SESSION', 'false') == 'true'


def read_state():
    try:
        value = STATE.read_text(encoding='ascii')
    except FileNotFoundError:
        return None
    match = re.fullmatch(r'([0-9a-f]{32}) (active|ended)\n', value)
    if not match:
        raise RuntimeError('invalid GUI lifecycle state')
    return match.group(1), match.group(2)


def write_state(generation, state):
    if DIRECTORY.is_symlink() or not DIRECTORY.is_dir() or STATE.is_symlink():
        raise RuntimeError('unsafe GUI lifecycle directory')
    fd, name = tempfile.mkstemp(prefix='.state-', dir=DIRECTORY)
    try:
        with os.fdopen(fd, 'w', encoding='ascii') as handle:
            handle.write(f'{generation} {state}\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, 0o644)
        os.replace(name, STATE)
    finally:
        Path(name).unlink(missing_ok=True)


def initialize():
    if enabled():
        # Discard a previous GUI's locale before the new effective config loads.
        (DIRECTORY / 'login-language').unlink(missing_ok=True)
        write_state(uuid.uuid4().hex, 'active')


def end():
    if enabled():
        current = read_state()
        if current is None:
            raise RuntimeError('GUI lifecycle was not initialized')
        write_state(current[0], 'ended')
        print('[+] Intentional GUI session end published', flush=True)


if __name__ == '__main__':
    initialize()
