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

from .models import Vuln

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


# High-signal on-target findings worth promoting to first-class Vulnerabilities
# (so they count toward severity totals and get a write-up), not just a Priv-Esc
# row. Each: (regex over the finding text, severity, cwes, short title, remediation).
# These are confirmed local observations of an exploitable misconfiguration -
# deliberately a curated shortlist; weaker signals stay Priv-Esc-only.
_PROMOTE = [
    (r"/etc/passwd is writable", "critical", ["CWE-732"],
     "Writable /etc/passwd (add a UID 0 user)",
     "Restrict /etc/passwd to root:root 0644."),
    (r"/etc/shadow is writable", "critical", ["CWE-732"],
     "Writable /etc/shadow", "Restrict /etc/shadow to root:shadow 0640."),
    (r"/etc/shadow is readable", "high", ["CWE-732"],
     "Readable /etc/shadow (offline hash cracking)",
     "Restrict /etc/shadow to root:shadow 0640."),
    (r"/etc/sudoers is writable", "critical", ["CWE-732"],
     "Writable /etc/sudoers", "Restrict sudoers to root:root 0440."),
    (r"nopasswd|sudo grants \(all\)", "high", ["CWE-250", "CWE-732"],
     "Sudo misconfiguration -> root (NOPASSWD / ALL)",
     "Remove NOPASSWD/ALL grants; scope sudo to specific commands."),
    (r"ld_preload", "high", ["CWE-426"],
     "LD_PRELOAD preserved in sudo env -> library injection to root",
     "Remove env_keep+=LD_PRELOAD from sudoers."),
    (r"suid .*gtfobins|gtfobins escalation", "high", ["CWE-269"],
     "SUID GTFOBins escalation candidate",
     "Remove the SUID bit or replace the binary."),
    (r"\bcapability\b.*privesc|cap_setuid|cap_sys_admin", "high", ["CWE-269"],
     "Dangerous file capability -> privesc",
     "Strip the capability (setcap -r) or restrict the binary."),
    (r"docker\.sock|docker group|in the 'docker' group", "high", ["CWE-250"],
     "Docker access -> trivial host root",
     "Remove the user from the docker group; protect the socket."),
    (r"lxd/lxc group|'lxd|'lxc", "high", ["CWE-250"],
     "lxd/lxc group -> root via privileged container",
     "Remove the user from the lxd/lxc group."),
    (r"'disk' group", "high", ["CWE-732"],
     "disk group -> raw device read (/etc/shadow)",
     "Remove the user from the disk group."),
    (r"pwnkit|cve-2021-4034", "critical", ["CWE-269"],
     "PwnKit (CVE-2021-4034, pkexec) local root",
     "Patch polkit/pkexec (fixed Jan-2022)."),
    (r"dirty pipe|cve-2022-0847", "high", ["CWE-269"],
     "Dirty Pipe (CVE-2022-0847) kernel LPE",
     "Patch the kernel (fixed 5.16.11/5.15.25/5.10.102)."),
    (r"writable cron|writable .*timer|world/.*writable cron", "high", ["CWE-732"],
     "Writable cron/timer script -> root code exec",
     "Fix ownership/permissions on the scheduled job."),
    (r"writable service unit|runs a writable binary", "high", ["CWE-732"],
     "Writable service/binary run as root",
     "Restrict write access on the unit/binary."),
    (r"no_root_squash", "high", ["CWE-269"],
     "NFS no_root_squash -> remote root via SUID",
     "Set root_squash on the NFS export."),
    (r"writable dir in path", "medium", ["CWE-426"],
     "Writable directory in PATH (binary planting)",
     "Remove the writable directory from PATH."),
    # Windows
    (r"seimpersonate|seassignprimarytoken", "high", ["CWE-269", "CWE-250"],
     "SeImpersonate/SeAssignPrimaryToken -> Potato -> SYSTEM",
     "Remove the privilege from the service account where feasible."),
    (r"alwaysinstallelevated", "high", ["CWE-269"],
     "AlwaysInstallElevated -> malicious MSI as SYSTEM",
     "Disable the AlwaysInstallElevated policy (HKLM+HKCU)."),
    (r"unquoted service path", "high", ["CWE-428"],
     "Unquoted service path with writable parent",
     "Quote the ImagePath; restrict write on the parent directory."),
    (r"sebackup|serestore|setakeownership|seloaddriver|sedebug", "high", ["CWE-269"],
     "Dangerous Windows privilege held -> SYSTEM",
     "Remove the privilege from the account."),
    (r"cpassword|gpp password", "high", ["CWE-256", "CWE-260"],
     "GPP cpassword (decryptable domain credential)",
     "Remove the GPP; rotate the exposed credential."),
    (r"cleartext|stored credential|autologon.*password", "high", ["CWE-256"],
     "Stored/cleartext credential on host",
     "Remove the stored secret; rotate it."),
]
_PROMOTE = [(re.compile(rx, re.I), sev, cwes, title, rem)
            for rx, sev, cwes, title, rem in _PROMOTE]


def promote_to_vulns(ip: str, findings: list[dict]) -> list[Vuln]:
    """Turn the high-signal on-target findings into first-class Vulns (confirmed
    local observations), so they show up in severity totals and get write-ups.
    Findings that don't match the curated shortlist stay Priv-Esc-only. Each
    distinct (title) is emitted once per host."""
    out: list[Vuln] = []
    seen: set[str] = set()
    for f in findings:
        text = f.get("vector") or f.get("text") or ""
        for rx, sev, cwes, title, rem in _PROMOTE:
            if rx.search(text) and title not in seen:
                seen.add(title)
                out.append(Vuln(
                    ip=ip, port=None, protocol="tcp", script_id="local-enum",
                    state="finding", title=title, severity=sev, source="local",
                    confidence="confirmed", cwes=list(cwes),
                    output=f"On-target enum: {text}", remediation=rem))
                break
    return out
