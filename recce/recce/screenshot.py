"""Optional web screenshot capture for finding write-ups.

Airgapped-safe and tool-gated, like the rest of recce: if a headless browser is
present on the box, recce can screenshot HTTP/HTTPS targets and embed them in the
report. Both browser families ship on Kali and are supported out of the box -
Firefox (the Kali default) and Chromium/Chrome. If no browser is found, capture
is simply skipped and the tester adds screenshots by hand in Word.

Only web-facing findings have a meaningful auto-screenshot; everything else is
evidenced by the raw tool output the report already includes.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

# Chromium/Chrome variants (headless --screenshot), then Firefox (the Kali
# default). Chrome is preferred first because it can ignore self-signed cert
# errors on HTTPS; Firefox has no clean equivalent (see _capture_firefox).
_CHROME = ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
           "chrome", "headless-shell"]
_FIREFOX = ["firefox", "firefox-esr"]
_TIMEOUT = 30


def browser_tool() -> str | None:
    # Explicit override wins - lets the tester point at a browser not on PATH.
    override = os.environ.get("RECCE_BROWSER")
    if override and (os.path.isfile(override) or shutil.which(override)):
        return override
    for name in _CHROME + _FIREFOX:
        if shutil.which(name):
            return name
    return None


def _is_firefox(tool: str) -> bool:
    return "firefox" in os.path.basename(tool).lower()


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


def _read_png(out: str) -> bytes | None:
    if os.path.exists(out) and os.path.getsize(out) > 0:
        with open(out, "rb") as fh:
            return fh.read()
    return None


def _capture_chrome(tool: str, url: str, out: str, timeout: int) -> bytes | None:
    cmd = [
        tool, "--headless", "--disable-gpu", "--no-sandbox",
        "--hide-scrollbars", "--ignore-certificate-errors",
        "--virtual-time-budget=5000", "--window-size=1280,900",
        f"--screenshot={out}", url,
    ]
    subprocess.run(cmd, capture_output=True, timeout=timeout)
    png = _read_png(out)
    if png is not None:
        return png
    # Some builds want --headless=new
    cmd[1] = "--headless=new"
    subprocess.run(cmd, capture_output=True, timeout=timeout)
    return _read_png(out)


def _capture_firefox(tool: str, url: str, out: str, timeout: int) -> bytes | None:
    # Firefox needs a throwaway profile so it doesn't touch the tester's, and
    # so first-run/telemetry pages don't clobber the shot. Prefs disable those.
    # NB: Firefox has no clean way to bypass self-signed cert errors headlessly,
    # so an HTTPS target with a bad cert screenshots the warning page - still
    # useful evidence, and Chrome (tried first) handles those cleanly anyway.
    profile = tempfile.mkdtemp(prefix="recce-ffprof-")
    try:
        prefs = (
            'user_pref("browser.shell.checkDefaultBrowser", false);\n'
            'user_pref("datareporting.policy.dataSubmissionEnabled", false);\n'
            'user_pref("toolkit.telemetry.enabled", false);\n'
            'user_pref("browser.aboutwelcome.enabled", false);\n'
            'user_pref("startup.homepage_welcome_url", "");\n'
            'user_pref("browser.startup.firstrunSkipsHomepage", true);\n'
        )
        with open(os.path.join(profile, "user.js"), "w") as fh:
            fh.write(prefs)
        # Screenshot path is a positional arg (no `=` form), URL last.
        cmd = [
            tool, "--headless", "-profile", profile, "-no-remote",
            "--window-size=1280,900", "--screenshot", out, url,
        ]
        subprocess.run(cmd, capture_output=True, timeout=timeout)
        return _read_png(out)
    finally:
        shutil.rmtree(profile, ignore_errors=True)


def capture(url: str, timeout: int = _TIMEOUT) -> bytes | None:
    """Screenshot a URL with a headless browser. Returns PNG bytes or None."""
    tool = browser_tool()
    if not tool:
        return None
    tmpdir = tempfile.mkdtemp(prefix="recce-shot-")
    out = os.path.join(tmpdir, "shot.png")
    try:
        if _is_firefox(tool):
            return _capture_firefox(tool, url, out, timeout)
        return _capture_chrome(tool, url, out, timeout)
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
