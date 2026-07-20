"""Fold on-target local-enum output back into the workbook.

The `ingest` phase parses the text a tester brings back from running the bundled
recce-enum.sh (Linux) or recce-enum.ps1 (Windows) on a compromised host, and
turns its `[!]` findings into Priv-Esc rows for the matching host. No network,
no tools - just text parsing of output recce itself produced, so it stays
airgapped-safe.

Both scripts share one line grammar:
    recce-enum  host=<name>  user=<u>  <date>   <- banner (identifies the tool)
    ==== Section title ====                      <- section header
    [!] a finding worth attention                <- a finding (what we harvest)
The 'How to exploit' reference section is skipped so its guidance lines are
never mistaken for findings.
"""

from __future__ import annotations

import re

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_SEC = re.compile(r"^=+\s*(.*?)\s*=+$")
_FIND = re.compile(r"^\[!\]\s+(.*\S)\s*$")
_BANNER = re.compile(r"recce-enum\b.*?host=(\S+)(?:.*?user=(\S+))?", re.I)

# Strong per-OS markers so we can label the host even when the tester didn't
# pass --os. Counted across the whole loot; the higher count wins.
_WIN_MARKERS = ("seimpersonate", "alwaysinstallelevated", "whoami /priv",
                "computername", "c:\\windows", "unquoted service", "printspoofer",
                "ntlm", "hklm\\", "named pipe")
_LINUX_MARKERS = ("/etc/passwd", "/etc/shadow", "suid", "sudo", "uid=",
                  "gtfobins", "ld_preload", "docker", "/etc/sudoers", "capability")

# Map a finding's section header to the short Priv-Esc "Category" tag.
_SECTION_CATEGORY = [
    ("sudo", "sudo"), ("suid", "suid"), ("capab", "suid"),
    ("kernel", "kernel"), ("system", "kernel"),
    ("cron", "cron"), ("timer", "cron"),
    ("service", "service"), ("process", "service"),
    ("writable", "writable"), ("path", "writable"),
    ("container", "container"), ("docker", "container"),
    ("credential", "creds"), ("password", "creds"), ("ssh", "creds"),
    ("network", "network"), ("nfs", "network"),
    ("privilege", "token"), ("token", "token"), ("context", "token"),
    ("alwaysinstall", "installer"), ("autorun", "autorun"),
    ("harden", "hardening"), ("av", "av"), ("pipe", "ipc"), ("ifeo", "ipc"),
    ("software", "software"),
]


def _categorize(section: str) -> str:
    low = (section or "").lower()
    for needle, tag in _SECTION_CATEGORY:
        if needle in low:
            return tag
    return "local"


def _detect_os(text: str) -> str:
    low = text.lower()
    win = sum(low.count(m) for m in _WIN_MARKERS)
    lin = sum(low.count(m) for m in _LINUX_MARKERS)
    if win > lin:
        return "windows"
    if lin > win:
        return "linux"
    return ""


def parse_loot(text: str) -> dict:
    """Parse recce-enum.sh/.ps1 output. Returns:
        {"is_recce": bool, "hostname": str, "os": "linux"|"windows"|"",
         "findings": [{"section": str, "category": str, "text": str}]}
    Duplicate findings (same section+text) are collapsed.
    """
    hostname = ""
    is_recce = False
    section = ""
    in_howto = False
    seen: set[tuple[str, str]] = set()
    findings: list[dict] = []
    for raw in text.splitlines():
        line = _ANSI.sub("", raw).strip()
        if not line:
            continue
        b = _BANNER.search(line)
        if b:
            is_recce = True
            if not hostname and b.group(1):
                hostname = b.group(1)
            continue
        m = _SEC.match(line)
        if m:
            section = m.group(1).strip()
            in_howto = "how to exploit" in section.lower()
            continue
        if in_howto:
            continue
        fm = _FIND.match(line)
        if fm:
            text_ = fm.group(1).strip()
            key = (section, text_)
            if key in seen:
                continue
            seen.add(key)
            findings.append({"section": section, "category": _categorize(section),
                             "text": text_})
    return {"is_recce": is_recce, "hostname": hostname,
            "os": _detect_os(text), "findings": findings}


def to_local_findings(parsed: dict, source: str) -> list[dict]:
    """Shape parsed findings into the dicts stored on Host.local_findings."""
    return [{"category": f["category"], "vector": f["text"],
             "section": f["section"], "source": source}
            for f in parsed["findings"]]
