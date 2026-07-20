"""Scan orchestration.

Wraps nmap (and optionally masscan) via subprocess. The workflow is:

  1. discovery   - find live hosts across all subnets (skippable with -Pn mindset)
  2. full ports  - full TCP port sweep per live host (nmap -p- or masscan)
  3. deep enum   - -sV -sC (-O) plus vuln / AD NSE scripts on discovered open ports

Each phase writes nmap XML to the run's raw/ directory; the parser consumes it.
No scanning happens on import - callers drive the phases explicitly.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


@dataclass
class ScanProfile:
    """Tunable knobs for a scan run."""

    name: str = "standard"
    all_ports: bool = True            # full 65535 TCP sweep vs --top-ports
    top_ports: int = 1000
    min_rate: int = 1500              # packets/sec hint for nmap
    timing: int = 4                   # nmap -T
    os_detect: bool = True
    ad_enrich: bool = True            # SMB / LDAP NSE scripts (enum phase)
    udp_top: int = 0                  # >0 -> also scan N top UDP ports (vulns phase)
    ping_discovery: bool = True       # discovery; False => treat all as up (-Pn)
    offline: bool = False             # drop internet-dependent scripts (vulners)
    extra_nse: list[str] = field(default_factory=list)
    scanner: str = "nmap"             # nmap | masscan (masscan for the port sweep)
    host_timeout: int = 20            # minutes; per-host ceiling (nmap --host-timeout)
    version_intensity: int = 8        # -sV probe intensity 0-9 (higher = better ID)
    version_all: bool = False         # --version-all: try every probe (thorough)


PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(name="quick", all_ports=False, top_ports=200,
                         os_detect=False, min_rate=2000, host_timeout=10,
                         version_intensity=6),
    "standard": ScanProfile(name="standard"),
    "thorough": ScanProfile(name="thorough", min_rate=800, udp_top=100,
                            extra_nse=["banner"], host_timeout=40,
                            version_all=True),
}


@dataclass
class ScanIssue:
    """A scan that errored or didn't fully complete - surfaced to the operator."""

    level: str        # "error" (nothing usable) | "warning" (partial results)
    message: str


@dataclass
class RunOutcome:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False    # subprocess hard timeout (nmap itself hung)
    missing: bool = False      # the tool wasn't on PATH

# AD / Windows enrichment scripts (safe, non-intrusive category).
_AD_SCRIPTS = [
    "smb-os-discovery", "smb-security-mode", "smb2-security-mode",
    "smb-enum-shares", "smb-enum-users", "smb-enum-domains",
    "smb-enum-groups", "smb-enum-sessions", "smb-protocols", "smb2-time",
    "ldap-rootdse", "ldap-search", "rdp-ntlm-info", "krb5-enum-users",
    "nbstat", "msrpc-enum",
]

# Service-aware enumeration scripts. nmap only runs those whose portrule matches
# the detected service, so listing many here is cheap - non-matching are skipped.
_SERVICE_SCRIPTS = [
    # HTTP / web
    "http-title", "http-headers", "http-server-header", "http-methods",
    "http-enum", "http-robots.txt", "http-webdav-scan", "http-auth",
    "http-cors", "http-git", "http-open-proxy",
    # TLS / SSL
    "ssl-cert", "ssl-enum-ciphers", "tls-nextprotoneg", "ssl-known-key",
    # SSH
    "ssh2-enum-algos", "ssh-auth-methods", "ssh-hostkey",
    # FTP / mail
    "ftp-anon", "ftp-syst", "smtp-commands", "smtp-open-relay",
    "pop3-capabilities", "imap-capabilities",
    # DNS
    "dns-nsid", "dns-recursion", "dns-zone-transfer",
    # Databases
    "mysql-info", "mysql-empty-password", "ms-sql-info", "ms-sql-ntlm-info",
    "ms-sql-empty-password", "oracle-tns-version", "mongodb-info",
    "redis-info", "pgsql-info",
    # SNMP / other UDP
    "snmp-info", "snmp-interfaces", "snmp-sysdescr",
    # Remote access / misc
    "rdp-enum-encryption", "vnc-info", "telnet-encryption",
    "nfs-showmount", "rpcinfo", "finger", "ntp-info",
]


class ScannerError(RuntimeError):
    pass


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def check_environment(profile: ScanProfile) -> list[str]:
    """Return a list of human-readable warnings about the runtime environment."""
    warnings: list[str] = []
    if not _have("nmap"):
        raise ScannerError("nmap is required but was not found on PATH. Install nmap.")
    if not _is_root():
        warnings.append(
            "Not running as root: falling back to TCP connect scan (-sT); "
            "OS detection and SYN scan need root/CAP_NET_RAW."
        )
    if profile.scanner == "masscan" and not _have("masscan"):
        warnings.append("masscan requested but not found; using nmap for port sweep.")
        profile.scanner = "nmap"
    return warnings


def _run(cmd: list[str], timeout: int | None = None) -> RunOutcome:
    """Run a command, capturing output. Never raises for timeout/missing tool -
    returns a RunOutcome the caller inspects, so one bad host can't stall a run."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return RunOutcome(p.returncode, p.stdout or "", p.stderr or "")
    except subprocess.TimeoutExpired as e:
        return RunOutcome(returncode=124, stdout=e.stdout or "", stderr=e.stderr or "",
                          timed_out=True)
    except FileNotFoundError:
        return RunOutcome(returncode=127, missing=True)


def _timeout_args(profile: ScanProfile, minutes: int | None = None):
    """Return (nmap --host-timeout args, subprocess-kill-timeout seconds).

    The nmap host-timeout fires first and lets nmap skip the slow host and still
    write its XML; the subprocess timeout is a hard backstop for a truly hung
    nmap. 0/None disables both."""
    m = profile.host_timeout if minutes is None else minutes
    if not m or m <= 0:
        return [], None
    return ["--host-timeout", f"{m}m"], m * 60 + 120


def _version_args(profile: ScanProfile) -> list[str]:
    """Service-detection flags. --version-all (intensity 9, every probe) when the
    profile asks for it, else an explicit intensity."""
    if profile.version_all:
        return ["-sV", "--version-all"]
    return ["-sV", "--version-intensity", str(profile.version_intensity)]


def _issue_from(outcome: RunOutcome, out_xml: str, phase: str,
                minutes: int | None) -> ScanIssue | None:
    """Classify a run's outcome into an operator-facing issue, or None if fine."""
    if outcome.missing:
        return ScanIssue("error", f"{phase}: nmap not found on PATH")
    if outcome.timed_out:
        return ScanIssue("error",
                         f"{phase}: hard-timed-out (nmap unresponsive); results "
                         f"may be missing")
    blob = f"{outcome.stdout}\n{outcome.stderr}".lower()
    if "host timeout" in blob or "due to host timeout" in blob:
        span = f" after {minutes}m" if minutes else ""
        return ScanIssue("warning",
                         f"{phase}: host timed out{span} - partial results kept")
    if outcome.returncode not in (0, None) and (
            not os.path.exists(out_xml) or os.path.getsize(out_xml) < 80):
        err = (outcome.stderr or outcome.stdout or "").strip().splitlines()
        detail = err[-1] if err else f"exit {outcome.returncode}"
        return ScanIssue("error", f"{phase}: nmap failed ({detail})")
    return None


# --- phase 1: discovery ----------------------------------------------------------

def discover_hosts(targets_file: str, out_xml: str) -> tuple[str, ScanIssue | None]:
    """Ping-sweep the targets; return (xml path, issue|None) listing live hosts."""
    cmd = [
        "nmap", "-sn", "-PE", "-PP",
        "-PS21,22,23,25,80,135,139,443,445,3389,3306,8080",
        "-PA80,443,3389", "-n", "--max-retries", "1", "--host-timeout", "3m",
        "-iL", targets_file, "-oX", out_xml,
    ]
    outcome = _run(cmd)
    if outcome.missing:
        return out_xml, ScanIssue("error", "discovery: nmap not found on PATH")
    if outcome.returncode not in (0, None) and not os.path.exists(out_xml):
        detail = (outcome.stderr or "").strip().splitlines()
        return out_xml, ScanIssue(
            "error", f"discovery: nmap failed ({detail[-1] if detail else 'error'})")
    return out_xml, _issue_from(outcome, out_xml, "discovery", None)


# --- phase 2: full port sweep ----------------------------------------------------

def full_port_scan(ip: str, out_xml: str,
                   profile: ScanProfile) -> tuple[str, ScanIssue | None]:
    """Full/top TCP port sweep for one host; returns (xml path, issue|None)."""
    if profile.scanner == "masscan" and _have("masscan"):
        return _masscan_ports(ip, out_xml, profile)

    scan_type = "-sS" if _is_root() else "-sT"
    port_spec = ["-p-"] if profile.all_ports else ["--top-ports", str(profile.top_ports)]
    to_args, kill = _timeout_args(profile)
    cmd = [
        "nmap", scan_type, "-Pn", "-n", f"-T{profile.timing}",
        "--min-rate", str(profile.min_rate), "--max-retries", "2", "--open",
        *to_args, *port_spec, ip, "-oX", out_xml,
    ]
    outcome = _run(cmd, timeout=kill)
    return out_xml, _issue_from(outcome, out_xml, "port-sweep", profile.host_timeout)


def _masscan_ports(ip: str, out_xml: str,
                   profile: ScanProfile) -> tuple[str, ScanIssue | None]:
    port_range = "0-65535" if profile.all_ports else f"0-{profile.top_ports}"
    tmp = out_xml + ".masscan.xml"
    _run(["masscan", ip, "-p", port_range, "--rate", str(profile.min_rate * 10),
          "-oX", tmp], timeout=(profile.host_timeout * 60 + 120) or None)
    # Re-emit as an nmap-shaped XML by re-scanning just the open ports with nmap.
    ports = _extract_masscan_ports(tmp)
    if not ports:
        return _empty_xml(out_xml), None
    scan_type = "-sS" if _is_root() else "-sT"
    to_args, kill = _timeout_args(profile)
    outcome = _run(["nmap", scan_type, "-Pn", "-n", "--open", *to_args,
                    "-p", ",".join(str(p) for p in ports), ip, "-oX", out_xml],
                   timeout=kill)
    return out_xml, _issue_from(outcome, out_xml, "port-sweep", profile.host_timeout)


def masscan_sweep(ips: list[str], out_xml: str, profile: ScanProfile) -> dict[str, list[int]]:
    """Fast network-wide port sweep of many hosts in a single masscan run.

    Returns {ip: [open_ports]}. This collapses per-host full scans into one
    high-rate sweep - the biggest single speedup for large scopes. Falls back to
    an empty map (caller then uses nmap) if masscan is unavailable.
    """
    if not _have("masscan"):
        return {}
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(ips))
        list_file = tf.name
    port_range = "0-65535" if profile.all_ports else f"0-{profile.top_ports}"
    # masscan rate is packets/sec across the whole sweep; scale up from min_rate.
    rate = max(profile.min_rate * 10, 5000)
    _run(["masscan", "-iL", list_file, "-p", port_range,
          "--rate", str(rate), "-oX", out_xml])
    try:
        os.unlink(list_file)
    except OSError:
        pass
    return parse_masscan_sweep_xml(out_xml)


def parse_masscan_sweep_xml(out_xml: str) -> dict[str, list[int]]:
    """Parse a masscan XML file into {ip: [sorted open ports]}."""
    result: dict[str, list[int]] = {}
    if not os.path.exists(out_xml):
        return result
    try:
        tree = ET.parse(out_xml)
    except ET.ParseError:
        return result
    for host in tree.getroot().findall("host"):
        addr = host.find("address")
        ip = addr.get("addr") if addr is not None else None
        if not ip:
            continue
        for port in host.iter("port"):
            try:
                result.setdefault(ip, []).append(int(port.get("portid")))
            except (TypeError, ValueError):
                continue
    for ip in result:
        result[ip] = sorted(set(result[ip]))
    return result


def _extract_masscan_ports(path: str) -> list[int]:
    if not os.path.exists(path):
        return []
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return []
    ports = []
    for port in tree.getroot().iter("port"):
        try:
            ports.append(int(port.get("portid")))
        except (TypeError, ValueError):
            continue
    return sorted(set(ports))


# --- phase 3a: light service enumeration (feeds the sheet fast) ------------------

def _empty_xml(out_xml: str) -> str:
    with open(out_xml, "w") as fh:
        fh.write('<?xml version="1.0"?><nmaprun start="0"></nmaprun>')
    return out_xml


def _creds_args(creds: dict | None) -> list[str]:
    if not (creds and creds.get("username")):
        return []
    args = [f"smbusername={creds['username']}", f"smbpassword={creds.get('password', '')}"]
    if creds.get("domain"):
        args.append(f"smbdomain={creds['domain']}")
    args += [f"ldap.username={creds['username']}", f"ldap.password={creds.get('password', '')}"]
    return ["--script-args", ",".join(args)]


def enum_scan(ip: str, ports: list[int], out_xml: str, profile: ScanProfile,
              creds: dict | None = None) -> tuple[str, ScanIssue | None]:
    """Light pass: version/OS detection + safe default scripts + AD facts.

    Deliberately cheap so the spreadsheet populates fast. This is where accurate
    service detection happens (it feeds the offline vuln DB), so version probing
    is turned up here. No vuln scanning here - that is the separate vuln_scan().
    """
    if not ports:
        return _empty_xml(out_xml), None
    scan_type = "-sS" if _is_root() else "-sT"
    scripts = ["default"]                 # safe, gives http-title, ssl-cert, etc.
    if profile.ad_enrich:
        scripts += _AD_SCRIPTS            # smb-os-discovery, signing, ldap-rootdse
    scripts += profile.extra_nse
    to_args, kill = _timeout_args(profile)
    cmd = [
        "nmap", scan_type, "-Pn", "-n", f"-T{profile.timing}",
        *_version_args(profile),          # thorough service ID (feeds vuln DB)
        "-p", ",".join(str(p) for p in sorted(set(ports))),
        "--script", ",".join(dict.fromkeys(scripts)),
        "--script-timeout", "120s", *to_args,
    ]
    cmd += _creds_args(creds)
    if profile.os_detect and _is_root():
        cmd.append("-O")
    cmd += [ip, "-oX", out_xml]
    outcome = _run(cmd, timeout=kill)
    return out_xml, _issue_from(outcome, out_xml, "enum", profile.host_timeout)


# --- phase 3b: vulnerability scan (targeted, safe-by-default) --------------------

def vuln_scan(ip: str, ports: list[int], out_xml: str, profile: ScanProfile,
              creds: dict | None = None, aggressive: bool = False) -> str:
    """Per-open-port vulnerability pass.

    Safe by default: nmap `vuln and safe` (detection-only scripts) plus the
    safe service weak-config scripts. `aggressive=True` runs the full `vuln`
    category (intrusive checks that can hang fragile services) and, if online,
    the `vulners` CVE lookup.
    """
    if not ports:
        return _empty_xml(out_xml), None
    scan_type = "-sS" if _is_root() else "-sT"

    if aggressive:
        selection = "vuln"
        if not profile.offline:
            selection += " or vulners"
    else:
        # Intersection of vuln + safe = non-intrusive detection scripts only.
        selection = "vuln and safe"
    # Add the safe service weak-config scripts (TLS/FTP/HTTP/SNMP/DB checks).
    script_expr = f"({selection}) or ({','.join(_SERVICE_SCRIPTS)})"

    # enum already did the heavy -sV; here we only need service names for NSE
    # portrules, so a light version probe (not a full re-scan) is enough.
    to_args, kill = _timeout_args(profile, profile.host_timeout * 2 if aggressive
                                  else None)
    cmd = [
        "nmap", scan_type, "-Pn", "-n", f"-T{profile.timing}",
        "-sV", "--version-light",
        "-p", ",".join(str(p) for p in sorted(set(ports))),
        "--script", script_expr,
        "--script-timeout", "180s", *to_args,
    ]
    cmd += _creds_args(creds)
    cmd += [ip, "-oX", out_xml]
    outcome = _run(cmd, timeout=kill)
    return out_xml, _issue_from(outcome, out_xml, "vuln-scan", profile.host_timeout)


def nse_scan(ip: str, ports: list[int], out_xml: str, profile: ScanProfile,
             scripts: list[str], creds: dict | None = None) -> tuple[str, ScanIssue | None]:
    """Generic targeted NSE run on specific ports (used by db / privesc phases)."""
    if not ports or not scripts:
        return _empty_xml(out_xml), None
    scan_type = "-sS" if _is_root() else "-sT"
    to_args, kill = _timeout_args(profile)
    cmd = [
        "nmap", scan_type, "-Pn", "-n", f"-T{profile.timing}",
        "-sV", "--version-light",
        "-p", ",".join(str(p) for p in sorted(set(ports))),
        "--script", ",".join(dict.fromkeys(scripts)),
        "--script-timeout", "180s", *to_args,
    ]
    cmd += _creds_args(creds)
    cmd += [ip, "-oX", out_xml]
    outcome = _run(cmd, timeout=kill)
    return out_xml, _issue_from(outcome, out_xml, "nse", profile.host_timeout)


def udp_scan(ip: str, out_xml: str, profile: ScanProfile) -> tuple[str, ScanIssue | None]:
    """Optional top-N UDP scan with service detection + SNMP/DNS/NTP enumeration."""
    if not _is_root():
        return _empty_xml(out_xml), ScanIssue(
            "warning", "udp: skipped (needs root/CAP_NET_RAW for raw sockets)")
    to_args, kill = _timeout_args(profile)
    outcome = _run(["nmap", "-sU", "-sV", "-Pn", "-n", "--top-ports",
                    str(profile.udp_top), "--open", f"-T{profile.timing}",
                    "--script", "snmp-info,snmp-interfaces,snmp-sysdescr,dns-nsid,"
                                "ntp-info,nbstat,ike-version",
                    "--script-timeout", "90s", *to_args, ip, "-oX", out_xml],
                   timeout=kill)
    return out_xml, _issue_from(outcome, out_xml, "udp", profile.host_timeout)
