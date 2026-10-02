"""Private Unix-socket relay for an SSH-forwarded host X11 display."""
from __future__ import annotations

import os
import re
import select
import socket
import stat
import threading
from pathlib import Path


class X11RelayError(RuntimeError):
    """The forwarded display endpoint or its private relay is unavailable."""


def parse_forwarded_display(display: str) -> tuple[str, int, int]:
    """Return (loopback host, SSH-forwarded TCP port, screen) from DISPLAY."""
    match = re.fullmatch(r"(localhost|127\.0\.0\.1):([0-9]+)(?:\.([0-9]+))?", display)
    if not match:
        raise X11RelayError("DISPLAY must be a local display or an SSH-forwarded loopback display")
    display_text = match.group(2)
    screen_text = match.group(3) or "0"
    if len(display_text) > 5 or len(screen_text) > 3:
        raise X11RelayError("SSH-forwarded DISPLAY number or screen is malformed")
    display_number = int(display_text)
    port = 6000 + display_number
    if port > 65535:
        raise X11RelayError("SSH-forwarded DISPLAY number is outside the TCP port range")
    screen = int(screen_text)
    if screen > 255:
        raise X11RelayError("SSH-forwarded DISPLAY screen is outside the X11 screen range")
    return match.group(1), port, screen


def display_number_from_socket(socket_path: Path) -> int:
    """Read the X11 display number from the relay's configured X<n> socket."""
    match = re.fullmatch(r"X([0-9]{1,5})", socket_path.name)
    if not match:
        raise X11RelayError("relay socket must use the X<display-number> filename")
    display_number = int(match.group(1))
    if socket_path.name != f"X{display_number}":
        raise X11RelayError("relay socket display number must use its canonical decimal form")
    return display_number


class ForwardedX11Relay:
    """Relay one X11 socket to the live SSH forwarding endpoint."""

    def __init__(self, socket_path: Path, target_host: str, target_port: int):
        self.socket_path = socket_path
        self.target_host = target_host
        self.target_port = target_port
        self._listener: socket.socket | None = None
        self._listener_thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self._failed = threading.Event()
        self._failure_reason = "SSH X11 forwarding endpoint disconnected"
        self._lock = threading.Lock()
        self._connections: set[socket.socket] = set()
        self._socket_identity: tuple[int, int] | None = None

    def start(self) -> None:
        parent = self.socket_path.parent
        try:
            parent_stat = parent.stat(follow_symlinks=False)
        except OSError as error:
            raise X11RelayError("private X11 socket directory is inaccessible") from error
        if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != os.getuid():
            raise X11RelayError("private X11 socket directory must be owned by the runner")
        if stat.S_IMODE(parent_stat.st_mode) != 0o711:
            raise X11RelayError("private X11 socket directory must have mode 0711")
        if self.socket_path.exists() or self.socket_path.is_symlink():
            raise X11RelayError("refusing to replace an existing X11 socket path")

        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.socket_path))
            self._socket_identity = (self.socket_path.stat().st_dev, self.socket_path.stat().st_ino)
            self.socket_path.chmod(0o666)
            listener.listen(8)
            listener.settimeout(0.25)
        except OSError as error:
            listener.close()
            self._unlink_owned_socket()
            raise X11RelayError("unable to create the private X11 relay socket") from error
        self._listener = listener
        self._listener_thread = threading.Thread(target=self._accept_connections,
                                                 name="ecd-x11-relay", daemon=True)
        self._listener_thread.start()

    def _mark_failed(self, reason: str = "SSH X11 forwarding endpoint disconnected") -> None:
        self._failure_reason = reason
        self._failed.set()

    def check(self) -> None:
        if self._failed.is_set():
            raise X11RelayError(self._failure_reason)
        if self._stopping.is_set() or self._listener is None:
            raise X11RelayError("SSH X11 relay is not running")

    def _accept_connections(self) -> None:
        assert self._listener is not None
        while not self._stopping.is_set():
            try:
                client, _address = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self._stopping.is_set():
                    self._mark_failed("private X11 relay listener stopped unexpectedly")
                return
            try:
                remote = socket.create_connection((self.target_host, self.target_port), timeout=5)
            except OSError:
                client.close()
                self._mark_failed("SSH X11 forwarding endpoint is inaccessible")
                continue
            with self._lock:
                if self._stopping.is_set():
                    client.close()
                    remote.close()
                    return
                self._connections.update((client, remote))
            threading.Thread(target=self._relay_connection, args=(client, remote),
                             name="ecd-x11-connection", daemon=True).start()

    def _relay_connection(self, client: socket.socket, remote: socket.socket) -> None:
        client_closed = threading.Event()

        def copy(source: socket.socket, destination: socket.socket, *, from_client: bool) -> None:
            try:
                while not self._stopping.is_set():
                    readable, _, exceptional = select.select([source], [], [source], 0.5)
                    if exceptional:
                        break
                    if not readable:
                        continue
                    payload = source.recv(65536)
                    if not payload:
                        if from_client:
                            client_closed.set()
                        elif not client_closed.is_set() and not self._stopping.is_set():
                            try:
                                pending = client.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
                                if not pending:
                                    client_closed.set()
                            except BlockingIOError:
                                pass
                            except OSError:
                                client_closed.set()
                            if not client_closed.is_set():
                                self._mark_failed()
                        break
                    destination.sendall(payload)
            except (OSError, ValueError):
                if not from_client and not client_closed.is_set() and not self._stopping.is_set():
                    self._mark_failed()
            finally:
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        client_to_remote = threading.Thread(target=copy, args=(client, remote),
                                            kwargs={"from_client": True}, daemon=True)
        remote_to_client = threading.Thread(target=copy, args=(remote, client),
                                            kwargs={"from_client": False}, daemon=True)
        client_to_remote.start()
        remote_to_client.start()
        while not self._stopping.is_set():
            client_to_remote.join(0.25)
            remote_to_client.join(0.25)
            if not client_to_remote.is_alive() and not remote_to_client.is_alive():
                break
        client.close()
        remote.close()
        with self._lock:
            self._connections.discard(client)
            self._connections.discard(remote)

    def _unlink_owned_socket(self) -> None:
        if self._socket_identity is None:
            return
        try:
            metadata = self.socket_path.lstat()
            if (metadata.st_dev, metadata.st_ino) == self._socket_identity and stat.S_ISSOCK(metadata.st_mode):
                self.socket_path.unlink()
        except OSError:
            pass

    def close(self) -> None:
        if self._stopping.is_set():
            return
        self._stopping.set()
        if self._listener is not None:
            self._listener.close()
        with self._lock:
            connections = list(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        if self._listener_thread is not None:
            self._listener_thread.join(timeout=2)
        self._unlink_owned_socket()
