#!/usr/bin/env python3
"""Inspect and record the Electron Cash Docker browser demo.

The demo stack must already be running and configured for CHIPNET. From the
repository root, regenerate the public demo GIF with:

    python3 scripts/demo.py --mode record \
      --url https://ecd-demo.bchforge.org/ \
      --env-file ~/.local/state/electron-cash-docker/demo-ecd-demo-20260923T054928Z/demo.env \
      --project-name ecd-demo-20260923t054928z \
      --output docs/assets/electron-cash-docker-demo.gif

The env file stays local; never put its password in the repository. Recording
opens UI/status/settings only and never starts CashFusion or makes transactions.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import time
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from mss import MSS
from PIL import Image, ImageChops
from playwright.sync_api import sync_playwright


DEFAULT_ENV_FILE = Path(
    "/home/ubuntu/.local/state/electron-cash-docker/"
    "demo-ecd-demo-20260923T054928Z/demo.env"
)
DEFAULT_URL = "https://ecd-demo.bchforge.org/"
DEFAULT_PROJECT_NAME = "ecd-demo-20260923t054928z"
DEFAULT_OUTPUT = Path("docs/assets/electron-cash-docker-demo.gif")
DEFAULT_WORK_DIR = Path("/tmp/ecd-demo-fluid")
HIDE_CURSOR_STYLE = """
#ecd-demo-cursor, .ecd-demo-click-ripple { visibility: hidden !important; }
"""


CURSOR_INIT_SCRIPT = r"""
(() => {
  const install = () => {
    const root = document.documentElement;
    if (!root) return false;

    let style = document.getElementById("ecd-demo-overlay-style");
    if (!style) {
      style = document.createElement("style");
      style.id = "ecd-demo-overlay-style";
      style.textContent = `
        #ecd-demo-address-bar {
          position: fixed !important; inset: 0 0 auto 0 !important;
          height: 38px !important; box-sizing: border-box !important;
          display: flex !important; align-items: center !important;
          gap: 10px !important; padding: 0 16px !important;
          color: #29313a !important; background: #edf0f3 !important;
          border-bottom: 1px solid #c4cbd2 !important;
          font: 14px/1.2 Arial, sans-serif !important;
          z-index: 2147483647 !important; pointer-events: none !important;
        }
        #ecd-demo-address-field {
          display: block !important; min-width: 280px !important;
          max-width: 760px !important; overflow: hidden !important;
          white-space: nowrap !important; text-overflow: ellipsis !important;
          padding: 5px 12px !important; border: 1px solid #cbd1d7 !important;
          border-radius: 14px !important; background: #fff !important;
        }
        #ecd-demo-lock { font-size: 15px !important; }
        #ecd-demo-cursor {
          position: fixed !important; left: 0; top: 0;
          width: 23px !important; height: 23px !important;
          box-sizing: border-box !important; border-radius: 50% !important;
          border: 3px solid #fff !important;
          background: rgba(238, 48, 83, .86) !important;
          box-shadow: 0 0 0 2px #18212b, 0 2px 8px #0009 !important;
          transform: translate(-50%, -50%) !important;
          z-index: 2147483647 !important; pointer-events: none !important;
        }
        #ecd-demo-cursor::after {
          content: "" !important; position: absolute !important;
          left: 13px !important; top: 12px !important;
          width: 0 !important; height: 0 !important;
          border-left: 8px solid #fff !important;
          border-top: 12px solid transparent !important;
          filter: drop-shadow(1px 1px 1px #111) !important;
        }
        .ecd-demo-click-ripple {
          position: fixed !important; width: 18px !important;
          height: 18px !important; border: 3px solid #ffcf32 !important;
          border-radius: 50% !important; box-sizing: border-box !important;
          transform: translate(-50%, -50%) scale(.35) !important;
          opacity: .95 !important; z-index: 2147483647 !important;
          pointer-events: none !important;
          animation: ecd-demo-ripple .62s ease-out forwards !important;
        }
        @keyframes ecd-demo-ripple {
          to { transform: translate(-50%, -50%) scale(4.2); opacity: 0; }
        }
        #ecd-demo-address-bar, #ecd-demo-cursor,
        .ecd-demo-click-ripple { pointer-events: none !important; }
      `;
      root.appendChild(style);
    }

    let bar = document.getElementById("ecd-demo-address-bar");
    if (!bar) {
      bar = document.createElement("div");
      bar.id = "ecd-demo-address-bar";
      bar.innerHTML = '<span id="ecd-demo-lock">🔒</span>' +
        '<span id="ecd-demo-address-field"></span>';
      root.appendChild(bar);
    }
    const address = document.getElementById("ecd-demo-address-field");
    if (address) address.textContent = window.location.origin;

    let cursor = document.getElementById("ecd-demo-cursor");
    if (!cursor) {
      cursor = document.createElement("div");
      cursor.id = "ecd-demo-cursor";
      root.appendChild(cursor);
    }
    if (!window.__ecdDemoCursorPosition) {
      window.__ecdDemoCursorPosition = { x: 80, y: 80 };
    }
    const position = window.__ecdDemoCursorPosition;
    cursor.style.left = `${position.x}px`;
    cursor.style.top = `${position.y}px`;
    window.__ecdDemoMoveCursor = (x, y) => {
      window.__ecdDemoCursorPosition = { x, y };
      const node = document.getElementById("ecd-demo-cursor");
      if (node) {
        node.style.left = `${x}px`;
        node.style.top = `${y}px`;
      }
    };
    window.__ecdDemoClickFeedback = (x, y) => {
      const ripple = document.createElement("div");
      ripple.className = "ecd-demo-click-ripple";
      ripple.style.left = `${x}px`;
      ripple.style.top = `${y}px`;
      root.appendChild(ripple);
      window.setTimeout(() => ripple.remove(), 750);
    };
    return true;
  };

  install();
  document.addEventListener("DOMContentLoaded", install, { once: true });
})();
"""


def load_demo_password(env_file: Path) -> str:
    """Load the auth password from the environment, then a local env file."""
    password = os.environ.get("BASIC_AUTH_PASSWORD")
    if password is not None:
        if password:
            return password
        raise RuntimeError("BASIC_AUTH_PASSWORD is empty")

    try:
        lines = Path(env_file).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RuntimeError("could not read BASIC_AUTH_PASSWORD from env file") from exc

    for line in lines:
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        if entry.startswith("export "):
            entry = entry[len("export ") :].lstrip()
        key, separator, value = entry.partition("=")
        if separator and key.strip() == "BASIC_AUTH_PASSWORD":
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if value:
                return value
            raise RuntimeError("BASIC_AUTH_PASSWORD is empty in env file")
    raise RuntimeError("BASIC_AUTH_PASSWORD is missing from environment and env file")


def find_playwright_ffmpeg() -> str:
    """Return system ffmpeg or an executable bundled with Playwright."""
    system_ffmpeg = shutil.which("ffmpeg")
    if system_ffmpeg:
        return system_ffmpeg

    cache = Path.home() / ".cache" / "ms-playwright"
    if cache.is_dir():
        bundled = [
            candidate
            for candidate in cache.rglob("ffmpeg*")
            if candidate.is_file() and os.access(candidate, os.X_OK)
        ]
        if bundled:
            bundled.sort(
                key=lambda path: (
                    0 if path.name == "ffmpeg-linux" else
                    1 if path.name == "ffmpeg" else 2,
                    str(path),
                )
            )
            return str(bundled[0])
    raise FileNotFoundError("ffmpeg was not found on PATH or in Playwright's cache")


def move_cursor(page, x: float, y: float, duration_ms: int = 500, steps: int = 15) -> None:
    """Move the visible overlay and Playwright pointer along an interpolated path."""
    steps = max(1, int(steps))
    duration_ms = max(0, int(duration_ms))
    start = page.evaluate(
        """() => window.__ecdDemoCursorPosition || {x: 80, y: 80}"""
    )
    start_x, start_y = float(start["x"]), float(start["y"])
    started = time.monotonic()
    for step in range(1, steps + 1):
        progress = step / steps
        current_x = start_x + (float(x) - start_x) * progress
        current_y = start_y + (float(y) - start_y) * progress
        page.mouse.move(current_x, current_y)
        page.evaluate(
            """p => window.__ecdDemoMoveCursor?.(p.x, p.y)""",
            {"x": current_x, "y": current_y},
        )
        target_elapsed = duration_ms / 1000 * progress
        remaining = target_elapsed - (time.monotonic() - started)
        if remaining > 0:
            time.sleep(remaining)


def click_cursor(
    page,
    x: float,
    y: float,
    duration_ms: int = 500,
    button: str = "left",
) -> None:
    """Animate the pointer to a target, click it, and show click feedback."""
    move_cursor(page, x, y, duration_ms=duration_ms)
    page.mouse.click(x, y, button=button)
    page.evaluate(
        """p => window.__ecdDemoClickFeedback?.(p.x, p.y)""",
        {"x": x, "y": y},
    )


def convert_webm_to_gif(
    ffmpeg: str | Path,
    webm: str | Path,
    candidate_gif: str | Path,
    fps: int,
    target_width: int = 1024,
) -> None:
    """Convert WebM to a palette-optimized GIF at candidate_gif."""
    if fps < 1 or target_width < 1:
        raise ValueError("fps and target_width must be positive integers")
    candidate = Path(candidate_gif)
    candidate.parent.mkdir(parents=True, exist_ok=True)
    filters = (
        f"[0:v]fps={fps},scale={target_width}:-2:flags=lanczos,split[a][b];"
        "[a]palettegen[p];[b][p]paletteuse=dither=bayer:bayer_scale=5"
    )
    subprocess.check_call(
        [
            str(ffmpeg), "-y", "-i", str(webm), "-filter_complex", filters,
            "-loop", "0", str(candidate),
        ]
    )


def gif_metadata(path: str | Path) -> dict[str, Any]:
    """Return GIF dimensions, frame count, duration when encoded, and size."""
    gif_path = Path(path)
    with Image.open(gif_path) as image:
        width, height = image.size
        frame_count = int(getattr(image, "n_frames", 1))
        duration_ms = 0
        for frame in range(frame_count):
            image.seek(frame)
            duration_ms += int(image.info.get("duration", 0) or 0)
    return {
        "resolution": f"{width}x{height}",
        "frame_count": frame_count,
        "file_size_bytes": gif_path.stat().st_size,
        "duration_seconds": duration_ms / 1000 if duration_ms else None,
    }


def save_screen(name: str, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    with MSS() as sct:
        monitor = sct.monitors[1]
        shot = sct.grab(monitor)
        image = Image.frombytes("RGB", shot.size, shot.rgb)
    image.save(output_dir / name)


def save_stage(page, work_dir: Path, name: str) -> Path:
    path = work_dir / name
    page.screenshot(path=str(path), full_page=False)
    return path


def inspect_page(page) -> None:
    print("URL:", page.url)
    print("TITLE:", page.title())
    print("HEADINGS:", page.locator("h1,h2,h3").all_text_contents())
    fields = page.locator("input").evaluate_all(
        "els => els.map(e => ({type:e.type,name:e.name,id:e.id,placeholder:e.placeholder}))"
    )
    buttons = page.locator("button,input[type=submit]").evaluate_all(
        "els => els.map(e => ({tag:e.tagName,text:(e.innerText||e.value||'').trim(),type:e.type}))"
    )
    print("FIELDS:", fields)
    print("BUTTONS:", buttons)


def launch_browser(playwright, url: str = DEFAULT_URL):
    browser = playwright.chromium.launch(
        headless=False,
        args=[
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--no-first-run",
            "--no-default-browser-check",
            "--window-position=0,0",
            "--window-size=1280,900",
        ],
    )
    context = browser.new_context(no_viewport=True, ignore_https_errors=False)
    page = context.new_page()
    page.goto(url, wait_until="domcontentloaded", timeout=60000)
    page.wait_for_load_state("networkidle", timeout=60000)
    return browser, context, page


def run_inspection(args) -> None:
    args.work_dir.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser, context, page = launch_browser(playwright, args.url)
        try:
            inspect_page(page)
            if args.mode in (
                "login", "wallet", "scale", "network-menu", "network",
                "network-key", "proxy", "fusion-tab", "fusion-status", "icons",
                "preferences", "transactions", "plugins", "wallet-menu",
                "fusion-context", "fusion-settings",
            ):
                password = load_demo_password(args.env_file)
                page.locator('input[type="password"]').fill(password)
                page.locator('button[type="submit"],input[type="submit"]').click()
                page.wait_for_timeout(12000)
                print("AFTER_LOGIN_URL:", page.url)
                print("AFTER_LOGIN_TITLE:", page.title())
                print("IFRAMES:", page.locator("iframe").count())
                print("CANVASES:", page.locator("canvas").count())
                print("CANVAS_BOX:", page.locator("canvas").first.bounding_box())
            if args.mode in (
                "scale", "network-menu", "network", "network-key", "proxy",
                "fusion-tab", "fusion-status", "icons", "preferences",
                "transactions", "plugins", "wallet-menu", "fusion-context",
                "fusion-settings",
            ):
                page.goto(
                    args.url.rstrip("/")
                    + "/vnc.html?autoconnect=true&reconnect=true&resize=scale",
                    wait_until="domcontentloaded",
                )
                page.wait_for_timeout(12000)
                print("SCALED_CANVAS_BOX:", page.locator("canvas").first.bounding_box())
            if args.mode in ("network-menu", "network"):
                page.mouse.click(122, 66)
                page.wait_for_timeout(700)
            if args.mode == "network":
                page.mouse.click(151, 101)
                page.wait_for_timeout(2500)
            if args.mode == "network-key":
                page.mouse.click(500, 300)
                page.keyboard.press("Control+k")
                page.wait_for_timeout(2500)
            if args.mode in ("proxy", "fusion-tab", "fusion-status"):
                page.mouse.click(500, 300)
                page.keyboard.press("Control+k")
                page.wait_for_timeout(1500)
                page.mouse.click(578 if args.mode == "proxy" else 646, 207)
                page.wait_for_timeout(1800)
            if args.mode == "fusion-status":
                page.mouse.click(786, 314)
                page.wait_for_timeout(2200)
            if args.mode == "icons":
                page.mouse.click(838, 285)
                page.wait_for_timeout(700)
                page.mouse.click(796, 542)
                page.wait_for_timeout(1200)
                save_screen("ecd-icons-main.png", args.work_dir)
                for x in (1142, 1170, 1195, 1218, 1245, 1265):
                    page.mouse.move(x, 748)
                    page.wait_for_timeout(1300)
                    save_screen(f"ecd-icon-{x}.png", args.work_dir)
            if args.mode == "preferences":
                page.mouse.click(122, 66)
                page.wait_for_timeout(600)
                page.mouse.click(160, 84)
                page.wait_for_timeout(2000)
            if args.mode == "transactions":
                page.mouse.click(672, 201)
                page.wait_for_timeout(1800)
            if args.mode == "plugins":
                page.mouse.click(736, 562)
                page.wait_for_timeout(700)
                page.mouse.click(122, 66)
                page.wait_for_timeout(600)
                page.mouse.click(176, 136)
                page.wait_for_timeout(1800)
            if args.mode == "wallet-menu":
                page.mouse.click(830, 501)
                page.wait_for_timeout(600)
                page.mouse.click(50, 66)
                page.wait_for_timeout(800)
            if args.mode == "fusion-context":
                page.mouse.click(500, 300)
                page.wait_for_timeout(300)
                page.mouse.click(1170, 748, button="right")
                page.wait_for_timeout(900)
            if args.mode == "fusion-settings":
                page.mouse.click(500, 300)
                page.wait_for_timeout(300)
                page.mouse.click(1170, 748, button="right")
                page.wait_for_timeout(700)
                page.mouse.click(1180, 702)
                page.wait_for_timeout(1800)
            if args.mode == "wallet":
                page.mouse.click(708, 330)
                page.wait_for_timeout(3000)
                print("AFTER_DISMISS_TITLE:", page.title())
            time.sleep(1)
            save_screen(f"ecd-{args.mode}.png", args.work_dir)
        finally:
            context.close()
            browser.close()


def vnc_url(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path.rstrip("/") + "/vnc.html",
            "autoconnect=true&reconnect=true&resize=scale",
            "",
        )
    )


def connect_control(page):
    controls = page.locator('button[type="submit"],input[type="submit"]')
    for index in range(controls.count()):
        control = controls.nth(index)
        label = control.evaluate(
            "e => (e.innerText || e.value || e.getAttribute('aria-label') || '').trim()"
        )
        if label.casefold() == "connect":
            return control
    raise AssertionError("login page has no visible Connect submit control")


def screenshot_changed(before: bytes, after: bytes) -> bool:
    with Image.open(BytesIO(before)) as before_image:
        first = before_image.convert("RGB")
    with Image.open(BytesIO(after)) as after_image:
        second = after_image.convert("RGB")
    if first.size != second.size:
        return True
    difference = ImageChops.difference(first, second).convert("L")
    mask = difference.point(lambda pixel: 255 if pixel > 32 else 0)
    bounds = mask.getbbox()
    if not bounds:
        return False
    changed_area = (bounds[2] - bounds[0]) * (bounds[3] - bounds[1])
    return changed_area >= first.width * first.height * 0.001


def open_network_and_proxy(page, work_dir: Path) -> None:
    # Match the successful `mode == "network"` route: Tools > Network opens
    # the Proxy tab with the configured Tor proxy and connected status.
    click_cursor(page, 122, 66)
    page.wait_for_timeout(700)
    click_cursor(page, 151, 101)
    page.wait_for_timeout(2500)
    save_stage(page, work_dir, "tor.png")

    # Escape closes the Network dialog without selecting a network action.
    page.keyboard.press("Escape")
    page.wait_for_timeout(600)


def record_sequence(page, args) -> None:
    password = load_demo_password(args.env_file)
    password_input = page.locator('input[type="password"]')
    password_input.wait_for(state="visible", timeout=60000)
    bounds = password_input.bounding_box()
    if not bounds:
        raise AssertionError("login password field has no visible bounds")
    click_cursor(
        page,
        bounds["x"] + bounds["width"] / 2,
        bounds["y"] + bounds["height"] / 2,
    )
    page.keyboard.type(password, delay=120)
    connect = connect_control(page)
    connect_bounds = connect.bounding_box()
    if not connect_bounds:
        raise AssertionError("Connect control has no visible bounds")
    click_cursor(
        page,
        connect_bounds["x"] + connect_bounds["width"] / 2,
        connect_bounds["y"] + connect_bounds["height"] / 2,
    )
    page.wait_for_timeout(12000)

    page.goto(vnc_url(args.url), wait_until="domcontentloaded", timeout=60000)
    page.locator("canvas").first.wait_for(state="visible", timeout=60000)
    page.wait_for_function(
        """() => Array.from(document.querySelectorAll('canvas')).some(canvas => {
          const rect = canvas.getBoundingClientRect();
          return rect.width >= 500 && rect.height >= 300;
        })""",
        timeout=60000,
    )
    page.wait_for_timeout(12000)
    save_stage(page, args.work_dir, "login.png")

    open_network_and_proxy(page, args.work_dir)

    # CashFusion's existing status-icon position; click, then require a visible
    # state change with cursor/ripple overlays excluded from the comparison.
    before = page.screenshot(
        path=str(args.work_dir / "cashfusion-click-before.png"),
        style=HIDE_CURSOR_STYLE,
    )
    click_cursor(page, 1170, 840, button="left")
    page.wait_for_timeout(1000)
    after = page.screenshot(
        path=str(args.work_dir / "cashfusion-click-after.png"),
        style=HIDE_CURSOR_STYLE,
    )
    if not screenshot_changed(before, after):
        raise AssertionError("CashFusion icon click produced no visible state change")
    save_stage(page, args.work_dir, "cashfusion-click-result.png")

    # Open the known CashFusion status-icon context menu and its Settings item.
    page.keyboard.press("Escape")
    click_cursor(page, 500, 300, duration_ms=250)
    page.wait_for_timeout(300)
    before_settings = page.screenshot(style=HIDE_CURSOR_STYLE)
    click_cursor(page, 1170, 840, button="right")
    page.wait_for_timeout(700)
    click_cursor(page, 1180, 702)
    page.wait_for_timeout(1800)
    after_settings = page.screenshot(style=HIDE_CURSOR_STYLE)
    if not screenshot_changed(before_settings, after_settings):
        raise AssertionError("CashFusion settings did not produce a visible state change")
    save_stage(page, args.work_dir, "cashfusion-settings.png")

    page.wait_for_timeout(max(0, int(args.final_hold * 1000)))


def record_demo(args) -> None:
    args.work_dir.mkdir(parents=True, exist_ok=True)
    video_dir = args.work_dir / "video"
    video_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=False,
            args=[
                "--no-sandbox", "--disable-dev-shm-usage", "--no-first-run",
                "--no-default-browser-check", "--window-position=0,0",
                "--window-size=1280,900",
            ],
        )
        context = browser.new_context(
            viewport={"width": 1280, "height": 850},
            record_video_dir=str(video_dir),
            record_video_size={"width": 1280, "height": 850},
            ignore_https_errors=False,
        )
        context.add_init_script(script=CURSOR_INIT_SCRIPT)
        page = context.new_page()
        page.goto(args.url, wait_until="domcontentloaded", timeout=60000)
        video = page.video
        try:
            if video is None:
                raise RuntimeError("Playwright video recording did not initialize")
            record_sequence(page, args)
        finally:
            try:
                context.close()
            finally:
                browser.close()

    if video is None:
        raise RuntimeError("Playwright video recording did not initialize")
    video_path = Path(video.path())
    ffmpeg = find_playwright_ffmpeg()
    candidate = args.work_dir / "candidate.gif"
    convert_webm_to_gif(ffmpeg, video_path, candidate, args.fps)
    metadata = gif_metadata(candidate)
    if metadata["file_size_bytes"] <= 0 or metadata["frame_count"] < 1:
        raise AssertionError("candidate GIF is empty")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(candidate, args.output)
    print(
        json.dumps(
            {
                "url": args.url,
                "project_name": args.project_name,
                "output": str(args.output),
                "video_path": str(video_path),
                "resolution": metadata["resolution"],
                "duration_seconds": metadata["duration_seconds"],
                "fps": args.fps,
                "candidate_size_bytes": metadata["file_size_bytes"],
                "cashfusion_clicked": True,
                "tor_opened": True,
                "no_transaction_actions": True,
            },
            sort_keys=True,
        )
    )


def build_parser() -> argparse.ArgumentParser:
    description = "Inspect the Electron Cash Docker demo or record its CHIPNET UI."
    epilog = """Common CHIPNET demo GIF refresh (run from the repository root):
  python3 scripts/demo.py --mode record --url https://ecd-demo.bchforge.org/ \\
    --env-file ~/.local/state/electron-cash-docker/demo-ecd-demo-20260923T054928Z/demo.env \\
    --project-name ecd-demo-20260923t054928z \\
    --output docs/assets/electron-cash-docker-demo.gif

The demo stack must already be running. The env-file default is a local
maintainer path; BASIC_AUTH_PASSWORD is never stored by this script.
"""
    parser = argparse.ArgumentParser(
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=(
            "record", "inspect", "login", "wallet", "scale", "network-menu",
            "network", "network-key", "proxy", "fusion-tab", "fusion-status",
            "icons", "preferences", "transactions", "plugins", "wallet-menu",
            "fusion-context", "fusion-settings",
        ),
        default="inspect",
        help="record the CHIPNET demo or run one of the existing UI inspection routes",
    )
    parser.add_argument("--url", default=DEFAULT_URL, help="demo base URL")
    parser.add_argument(
        "--env-file",
        type=Path,
        default=DEFAULT_ENV_FILE,
        help="local env file containing BASIC_AUTH_PASSWORD (environment overrides it)",
    )
    parser.add_argument(
        "--project-name", default=DEFAULT_PROJECT_NAME, help="label in the record summary"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="destination GIF (record mode only)",
    )
    parser.add_argument("--fps", type=int, default=12, help="GIF frame rate")
    parser.add_argument(
        "--final-hold", type=float, default=7.0, help="seconds to hold final settings view"
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=DEFAULT_WORK_DIR,
        help="directory for WebM, candidate GIF, and stage screenshots",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.fps < 1:
        parser.error("--fps must be at least 1")
    if args.final_hold < 0:
        parser.error("--final-hold cannot be negative")
    if args.mode == "record":
        record_demo(args)
    else:
        run_inspection(args)


if __name__ == "__main__":
    main()
