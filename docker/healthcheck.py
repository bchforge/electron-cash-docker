"""Check the actual wallet process and mode transport, never a pgrep self-match."""
import os
import ast
import base64
import http.client
import json
import socket
import subprocess
from pathlib import Path

from network_selection import effective_network, network_directory


def check_daemon():
    # Never instantiate SimpleConfig/the CLI here: CLI startup can save config
    # concurrently with daemon/plugin initialization and lose deployment policy.
    directory = Path(network_directory(effective_network()))
    (host, port), _created = ast.literal_eval((directory / 'daemon').read_text())
    if host not in ('localhost', '127.0.0.1', '0.0.0.0', '::', '::1') or not isinstance(port, int) or not 1 <= port <= 65535:
        raise RuntimeError('invalid local daemon endpoint')
    config = json.loads((directory / 'config').read_text())
    user, password = config['rpcuser'], config['rpcpassword']
    if not isinstance(user, str) or not isinstance(password, str):
        raise RuntimeError('invalid local daemon credentials')
    headers = {'Content-Type': 'application/json'}
    if password:
        encoded = base64.b64encode((user + ':' + password).encode()).decode()
        headers['Authorization'] = 'Basic ' + encoded
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
    try:
        connection.request('POST', '/', json.dumps({'id': 'health', 'method': 'ping', 'params': []}), headers)
        response = connection.getresponse()
        data = response.read(65536)
        if response.status != 200 or json.loads(data).get('result') is not True:
            raise RuntimeError('local daemon ping failed')
    finally:
        connection.close()


def main():
    processes = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            args = (entry / 'cmdline').read_bytes().split(b'\0')
            status = (entry / 'status').read_text()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if any(arg in (b'/home/electroncash/electroncash-wrapper.py',
                       b'/home/electroncash/electroncash-daemon-wrapper.py') for arg in args):
            processes.append(status)
    if not processes or not all('Uid:\t10001\t10001\t10001\t10001' in s for s in processes):
        raise SystemExit(1)
    if os.environ.get('MODE', 'novnc') == 'headless':
        check_daemon()
    elif os.environ.get('MODE', 'novnc') == 'novnc':
        for port in (5900, 6080):
            with socket.create_connection(('127.0.0.1', port), timeout=2):
                pass
    else:
        subprocess.run(['xdpyinfo'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=5, check=True)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Health output must not serialize a config, credential or response.
        raise SystemExit(1)
