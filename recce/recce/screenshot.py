"""Optional web screenshot capture for finding write-ups.

Airgapped-safe and tool-gated, like the rest of recce: if a headless browser is
present on the box (Chromium ships on Kali), recce can screenshot HTTP/HTTPS
targets and embed them in the report. If no browser is found, capture is simply
skipped and the tester adds screenshots by hand in Word.

Only web-facing findings have a meaningful auto-screenshot; everything else is
evidenced by the raw tool output the report already includes.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

# Chromium/Chrome variants first (support --screenshot), then simple grabbers.
_CHROME = ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
           "chrome", "headless-shell"]
_TIMEOUT = 30


def browser_tool() -> str | None:
    # Explicit override wins - lets the tester point at a browser not on PATH.
    override = os.environ.get("RECCE_BROWSER")
    if override and (os.path.isfile(override) or shutil.which(override)):
        return override
    for name in _CHROME:
        if shutil.which(name):
            return name
    return None


def available() -> bool:
    return browser_tool() is not None


def _web_url(port) -> str | None:
    svc = (port.service or "").lower()
    tls = port.tunnel == "ssl" or "https" in svc or "ssl" in svc \
        or port.portid in (443, 8443, 9443, 4443, 10443)
    is_http = "http" in svc or tls or port.portid in (80, 8080, 8000, 8888, 8081)
    if not is_http:
        return None
    scheme = "https" if tls else "http"
    return f"{scheme}://HOST:{port.portid}/"


def capture(url: str, timeout: int = _TIMEOUT) -> bytes | None:
    """Screenshot a URL with a headless browser. Returns PNG bytes or None."""
    tool = browser_tool()
    if not tool:
        return None
    tmpdir = tempfile.mkdtemp(prefix="recce-shot-")
    out = os.path.join(tmpdir, "shot.png")
    cmd = [
        tool, "--headless", "--disable-gpu", "--no-sandbox",
        "--hide-scrollbars", "--ignore-certificate-errors",
        "--virtual-time-budget=5000", "--window-size=1280,900",
        f"--screenshot={out}", url,
    ]
    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout)
        if os.path.exists(out) and os.path.getsize(out) > 0:
            with open(out, "rb") as fh:
                return fh.read()
        # Some builds want --headless=new
        cmd[1] = "--headless=new"
        subprocess.run(cmd, capture_output=True, timeout=timeout)
        if os.path.exists(out) and os.path.getsize(out) > 0:
            with open(out, "rb") as fh:
                return fh.read()
        return None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def capture_for_host(host, max_shots: int = 2) -> list[tuple[str, bytes]]:
    """Screenshot a host's web ports. Returns [(url, png_bytes)]."""
    if not available():
        return []
    shots: list[tuple[str, bytes]] = []
    for port in host.open_ports:
        if len(shots) >= max_shots:
            break
        tmpl = _web_url(port)
        if not tmpl:
            continue
        url = tmpl.replace("HOST", host.ip)
        png = capture(url)
        if png:
            shots.append((url, png))
    return shots
