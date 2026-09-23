#!/usr/bin/env python3
"""Static Compose and Caddy checks for the session-authenticated gateway."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def static_main() -> None:
    command = ["docker", "compose", "--env-file", str(ROOT / ".env.example"), "config", "--format", "json"]
    environment = os.environ.copy()
    environment.pop("BASIC_AUTH_PASSWORD", None)
    missing = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert missing.returncode != 0
    assert "BASIC_AUTH_PASSWORD must be set to a real password before starting Electron Cash Docker" in missing.stderr
    environment["BASIC_AUTH_PASSWORD"] = "synthetic-auth-secret"
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    model = json.loads(result.stdout)
    services = model["services"]
    assert {"electron-cash", "tor-proxy", "auth-session", "caddy", "fail2ban"} == set(services)
    assert not services["electron-cash"].get("ports")
    assert not services["auth-session"].get("ports")
    assert "BASIC_AUTH_USERNAME" not in services["auth-session"]["environment"]
    assert services["auth-session"]["environment"]["BASIC_AUTH_PASSWORD"] is not None
    caddy = services["caddy"]
    assert "BASIC_AUTH_USERNAME" not in caddy.get("environment", {})
    assert "BASIC_AUTH_PASSWORD" not in caddy.get("environment", {})
    assert caddy["environment"]["AUTH_SESSION_UPSTREAM"] == "auth-session:8080"
    assert services["fail2ban"]["network_mode"] == "service:caddy"
    assert services["fail2ban"]["cap_add"] == ["NET_ADMIN"]
    assert services["fail2ban"]["cap_drop"] == ["ALL"]

    entrypoint = (ROOT / "docker/caddy-entrypoint.sh").read_text(encoding="utf-8")
    dockerfile = (ROOT / "docker/Dockerfile").read_text(encoding="utf-8")
    session = (ROOT / "docker/auth-session/server.py").read_text(encoding="utf-8")
    landing = (ROOT / "docker/novnc-index.html").read_text(encoding="utf-8")
    favicon = (ROOT / "docker/auth-session/favicon.svg").read_bytes()
    assert "forward_auth" in entrypoint and "basic_auth" not in entrypoint
    assert "CADDY_TLS_MODE" in entrypoint
    assert "CADDY_TLS_MODE must be auto or internal" in entrypoint
    assert "tls internal" in entrypoint
    assert "header_up -Cookie" in entrypoint
    assert "localStorage" not in session and "sessionStorage" not in session
    assert '<form method="post" action="/auth/login">' in landing
    assert 'name="password"' in session and 'name="username"' not in session
    assert 'name="password"' in landing and 'name="username"' not in landing
    assert "Electron Cash Docker" in session
    assert '<h1>Electron Cash Docker <span class="version">&middot; v{{VERSION}}</span></h1>' in session
    assert session.count("v{{VERSION}}") == 1
    assert '<div class="version">v{{VERSION}}</div>' not in session
    assert landing.count("<title>Electron Cash Docker</title>") == 1
    assert '<link rel="icon" href="/favicon.svg" type="image/svg+xml">' in landing
    assert "/favicon.svg" in session and "/favicon.svg" in landing
    assert "COPY docker/auth-session/favicon.svg /opt/noVNC/favicon.svg" in dockerfile
    assert favicon.startswith(b"<svg") and b"#4ade80" in favicon
    assert "/favicon.svg" in entrypoint
    for color in ("#0f1419", "#1a1f2e", "#2a3142", "#e8e8e8", "#8b95a7", "#4ade80", "#22c55e", "#f87171"):
        assert color in session
    assert "localStorage" not in landing and "sessionStorage" not in landing
    assert "user:pass@" not in landing and "Authorization" not in landing
    assert "Secure" in session and "HttpOnly" in session
    print("PASS session gateway Compose and Caddy configuration")


if __name__ == "__main__":
    static_main()
