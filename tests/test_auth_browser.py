#!/usr/bin/env python3
"""Browser regression for the form login and authenticated noVNC session."""

from __future__ import annotations

import os
import time
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import BrowserContext, Page, sync_playwright


PASSWORD = os.environ.get("BROWSER_AUTH_PASSWORD", "canonical-meta-password")
ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()


RFB_PROBE = r"""
async () => {
  const socketUrl = new URL("/websockify", window.location.href);
  socketUrl.protocol = socketUrl.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(socketUrl);
  socket.binaryType = "arraybuffer";
  let buffer = new Uint8Array(0);
  const pending = [];
  const append = (data) => {
    const incoming = new Uint8Array(data);
    const joined = new Uint8Array(buffer.length + incoming.length);
    joined.set(buffer);
    joined.set(incoming, buffer.length);
    buffer = joined;
    while (pending.length && buffer.length >= pending[0].length) {
      const item = pending.shift();
      item.resolve(buffer.slice(0, item.length));
      buffer = buffer.slice(item.length);
    }
  };
  socket.onmessage = (event) => append(event.data);
  const take = (length) => new Promise((resolve, reject) => {
    if (buffer.length >= length) {
      const result = buffer.slice(0, length);
      buffer = buffer.slice(length);
      resolve(result);
    } else {
      pending.push({length, resolve, reject});
    }
  });
  const waitOpen = new Promise((resolve, reject) => {
    socket.onopen = resolve;
    socket.onerror = reject;
  });
  const send = (values) => socket.send(new Uint8Array(values));
  await Promise.race([waitOpen, new Promise((_, reject) => setTimeout(() => reject(new Error("WebSocket open timeout")), 5000))]);
  send(new TextEncoder().encode("RFB 003.008\n"));
  const banner = new TextDecoder().decode(await take(12));
  if (banner !== "RFB 003.008\n") throw new Error("unexpected RFB banner");
  const securityCount = (await take(1))[0];
  const securityTypes = await take(securityCount);
  if (!Array.from(securityTypes).includes(1)) throw new Error("None security type was not offered");
  send([1]);
  const securityResult = await take(4);
  if (securityResult.some((value) => value !== 0)) throw new Error("RFB security negotiation failed");
  send([1]);
  const serverInit = await take(24);
  const view = new DataView(serverInit.buffer, serverInit.byteOffset, serverInit.byteLength);
  const width = view.getUint16(0);
  const height = view.getUint16(2);
  const nameLength = view.getUint32(20);
  if (!width || !height) throw new Error("invalid RFB ServerInit dimensions");
  await take(nameLength);
   send([2, 0, 0, 1, 0, 0, 0, 0]);
   send([3, 0, 0, 0, 0, 0, (width >> 8) & 255, width & 255, (height >> 8) & 255, height & 255]);
   const update = await take(4);
   if (update[0] !== 0 || ((update[2] << 8) | update[3]) === 0) throw new Error("empty RFB framebuffer update");
  socket.close();
  return {width, height, framebufferUpdate: true};
}
"""


def run_browser_acceptance(base_url: str, *, ignore_https_errors: bool = False) -> dict[str, object]:
    with sync_playwright() as playwright:
        hostname = urlsplit(base_url).hostname or ""
        launch_args = ["--disable-dev-shm-usage"]
        if hostname not in {"localhost", "127.0.0.1", "::1"}:
            launch_args.append(f"--host-resolver-rules=MAP {hostname} 127.0.0.1")
        browser = playwright.chromium.launch(headless=True, args=launch_args)
        context: BrowserContext = browser.new_context(ignore_https_errors=ignore_https_errors)
        page: Page = context.new_page()
        dialogs: list[str] = []
        def dismiss_dialog(dialog) -> None:
            dialogs.append(dialog.type)
            dialog.dismiss()

        page.on("dialog", dismiss_dialog)

        page.goto(f"{base_url}/", wait_until="domcontentloaded")
        assert page.title() == "Electron Cash Docker"
        assert page.locator("h1").inner_text() == f"Electron Cash Docker · v{VERSION}"
        assert page.locator("body").inner_text().count(f"v{VERSION}") == 1
        assert page.locator("h1 .version").count() == 1
        assert not page.locator('input[name="username"]').count()
        assert page.locator('input[name="password"]').is_visible()
        assert page.locator("button[type=submit]").is_visible()
        unauthenticated = page.goto(f"{base_url}/vnc.html", wait_until="domcontentloaded")
        assert unauthenticated is not None and unauthenticated.status == 401
        assert "www-authenticate" not in {key.lower() for key in unauthenticated.headers}
        page.goto(f"{base_url}/", wait_until="domcontentloaded")

        page.locator('input[name="password"]').fill("wrong-password")
        page.locator("button[type=submit]").click()
        page.get_by_text("Invalid password.").wait_for()

        page.locator('input[name="password"]').fill(PASSWORD)
        page.locator("button[type=submit]").click()
        page.wait_for_url("**/vnc.html**", wait_until="domcontentloaded")
        assert "/vnc.html" in page.url
        assert PASSWORD not in page.url
        assert not page.evaluate("Object.keys(localStorage).length || Object.keys(sessionStorage).length")

        page.wait_for_timeout(500)
        rfb = page.evaluate(RFB_PROBE)
        assert rfb["framebufferUpdate"] and rfb["width"] > 0 and rfb["height"] > 0
        assert not dialogs, dialogs

        page.reload(wait_until="domcontentloaded")
        assert "/vnc.html" in page.url
        assert not page.locator('input[name="password"]').count()
        assert not page.evaluate("Object.keys(localStorage).length || Object.keys(sessionStorage).length")

        temporary_cookie = next(cookie for cookie in context.cookies() if cookie.get("name") == "ecd_session")
        assert temporary_cookie.get("expires", -1) == -1
        page.goto(f"{base_url}/", wait_until="domcontentloaded")
        assert page.locator('input[name="password"]').is_visible()
        page.locator('input[name="password"]').fill(PASSWORD)
        page.locator('input[name="remember"]').check()
        page.locator("button[type=submit]").click()
        page.wait_for_url("**/vnc.html**", wait_until="domcontentloaded")
        remembered_cookie = next(cookie for cookie in context.cookies() if cookie.get("name") == "ecd_session")
        assert remembered_cookie.get("expires", -1) > time.time() + 8 * 60 * 60
        page.goto(f"{base_url}/", wait_until="domcontentloaded")
        assert "/vnc.html" in page.url
        assert not page.locator('input[name="password"]').count()

        # The unauthenticated probe above was an ordinary HTTP 401, never a
        # browser Basic-Auth challenge that could show a native prompt.
        assert not dialogs, dialogs
        context.close()
        browser.close()
    return {"url": urlsplit(base_url).scheme, "rfb": True, "native_prompts": 0}


def main() -> None:
    base_url = os.environ.get("CI_BROWSER_URL")
    if not base_url:
        raise AssertionError("CI_BROWSER_URL is required for browser acceptance")
    run_browser_acceptance(base_url, ignore_https_errors=os.environ.get("CI_BROWSER_IGNORE_HTTPS") == "1")
    print("PASS Playwright login UI, session semantics, no leakage, and browser RFB/framebuffer")


if __name__ == "__main__":
    main()
