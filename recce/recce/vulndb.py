"""Offline vulnerability engine - the part that beats stock Kali airgapped.

Kali's `nmap --script vulners` maps service versions to CVEs, but it queries
vulners.com and returns NOTHING on an airgapped network. This module ships a
curated, no-internet knowledge base of high-value findings you actually hit on
internal engagements, and matches it against the product+version data `enum`
already collected - producing prioritized findings with a description, CVE
references, and *remediation*, none of which raw nmap output gives you.

The database is plain Python data (extensible - add a dict, no code). Matching is
pure standard library.
"""

from __future__ import annotations

import re

from .models import Host, Port, Vuln


def _ver_tuple(v: str) -> tuple[int, ...]:
    """Parse a version string into a comparable numeric tuple.

    '2.4.41' -> (2,4,41); '8.2p1' -> (8,2,1); '1.0.2k' -> (1,0,2,11).
    Trailing letters become their alphabet index so 2.3.4 < 2.3.4a.
    """
    v = v.strip().lower()
    parts: list[int] = []
    for token in re.split(r"[.\-_]", v):
        m = re.match(r"(\d+)([a-z]*)(?:p(\d+))?", token)
        if not m:
            continue
        parts.append(int(m.group(1)))
        if m.group(3):                     # OpenSSH-style p1
            parts.append(int(m.group(3)))
        elif m.group(2):                   # trailing letter (1.0.2k)
            parts.append(ord(m.group(2)[0]) - ord("a") + 1)
    return tuple(parts) or (0,)


def _cmp(a: str, b: str) -> int:
    ta, tb = _ver_tuple(a), _ver_tuple(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def _in_range(version: str, lo: str | None, hi: str | None,
              lo_incl: bool, hi_incl: bool) -> bool:
    if lo is not None:
        c = _cmp(version, lo)
        if c < 0 or (c == 0 and not lo_incl):
            return False
    if hi is not None:
        c = _cmp(version, hi)
        if c > 0 or (c == 0 and not hi_incl):
            return False
    return True


# --- the knowledge base ---------------------------------------------------------
# Each signature: product substring(s) to match against port.product/service,
# an optional version range, and the finding. Ranges use lt/le/ge/gt/eq/exact.
#
# Keep entries high-signal (things that actually matter on internal tests) and
# version-detectable from nmap -sV. Config-only findings live in parser.py.

SIGNATURES: list[dict] = [
    # --- FTP -------------------------------------------------------------------
    {"product": ["vsftpd"], "eq": "2.3.4", "severity": "critical",
     "title": "vsftpd 2.3.4 backdoor (smiley-face) - remote root",
     "cves": ["CVE-2011-2523"],
     "remediation": "Replace this build immediately; upgrade vsftpd.",
     "desc": "This exact build shipped with a backdoor that spawns a root shell "
             "on port 6200 when a ':)' username is sent."},
    {"product": ["proftpd"], "eq": "1.3.3c", "severity": "critical",
     "title": "ProFTPD 1.3.3c compromised source backdoor",
     "cves": ["CVE-2010-4221"],
     "remediation": "Upgrade ProFTPD to a current release.",
     "desc": "The 1.3.3c distribution tarball was trojaned; allows remote code exec."},
    # --- SSH -------------------------------------------------------------------
    {"product": ["openssh"], "lt": "7.7", "severity": "medium",
     "title": "OpenSSH < 7.7 username enumeration",
     "cves": ["CVE-2018-15473"],
     "remediation": "Upgrade OpenSSH to 7.7 or later.",
     "desc": "Timing/response differences let an unauthenticated attacker "
             "enumerate valid usernames - useful for password spraying."},
    {"product": ["openssh"], "lt": "9.3p2", "ge": "8.5", "severity": "high",
     "title": "OpenSSH 8.5-9.3 double-free (potential RCE)",
     "cves": ["CVE-2023-38408", "CVE-2023-25136"],
     "remediation": "Upgrade OpenSSH to 9.3p2+.",
     "desc": "Memory-safety issues in ssh-agent/forwarding paths that have been "
             "shown to be exploitable in some configurations."},
    # --- Apache HTTPD ----------------------------------------------------------
    {"product": ["apache httpd", "apache"], "ge": "2.4.49", "le": "2.4.50",
     "severity": "critical",
     "title": "Apache 2.4.49/2.4.50 path traversal & RCE",
     "cves": ["CVE-2021-41773", "CVE-2021-42013"],
     "remediation": "Upgrade to Apache httpd 2.4.51 or later.",
     "desc": "Unauthenticated path traversal that can read files outside the "
             "docroot and, with mod_cgi enabled, achieve remote code execution."},
    {"product": ["apache httpd", "apache"], "lt": "2.4.53", "ge": "2.4",
     "severity": "high",
     "title": "Apache httpd < 2.4.53 multiple vulns (mod_lua/proxy)",
     "cves": ["CVE-2022-22720", "CVE-2022-23943"],
     "remediation": "Upgrade to the latest Apache httpd 2.4.x.",
     "desc": "HTTP request smuggling and out-of-bounds writes in several modules."},
    # --- nginx -----------------------------------------------------------------
    {"product": ["nginx"], "lt": "1.21.0", "ge": "0.6.18", "severity": "high",
     "title": "nginx < 1.21.0 resolver off-by-one (CVE-2021-23017)",
     "cves": ["CVE-2021-23017"],
     "remediation": "Upgrade nginx to 1.21.0+ or disus the resolver directive.",
     "desc": "Off-by-one in the DNS resolver, potentially exploitable for RCE."},
    # --- Microsoft IIS / Exchange / RDP ----------------------------------------
    {"product": ["microsoft iis", "iis httpd"], "lt": "7.5", "severity": "medium",
     "title": "Legacy Microsoft IIS (<= 7.0) - unsupported",
     "cves": [],
     "remediation": "Migrate off end-of-life IIS/Windows Server.",
     "desc": "Runs on an unsupported Windows Server; multiple public exploits."},
    {"product": ["microsoft terminal services", "ms-wbt-server", "terminal services"],
     "os": "windows", "os_lt": "6.2", "severity": "critical",
     "title": "RDP on Windows <= 7/2008 R2 - BlueKeep exposure",
     "cves": ["CVE-2019-0708"],
     "remediation": "Patch (MS mitigations for CVE-2019-0708) or disable RDP; "
                    "enable Network Level Authentication.",
     "desc": "Pre-auth wormable RDP RCE affecting Windows 7 / Server 2008 R2 and "
             "earlier. Confirm with a dedicated BlueKeep check before exploiting."},
    # --- Samba -----------------------------------------------------------------
    {"product": ["samba"], "ge": "3.5.0", "lt": "4.6.4", "severity": "critical",
     "title": "Samba 'SambaCry' remote code execution",
     "cves": ["CVE-2017-7494"],
     "remediation": "Upgrade Samba to 4.6.4/4.5.10/4.4.14+ or set "
                    "'nt pipe support = no'.",
     "desc": "A malicious client can upload and cause the server to load a shared "
             "library, executing code as root."},
    # --- Databases -------------------------------------------------------------
    {"product": ["mysql"], "lt": "5.7.0", "ge": "5.0", "severity": "medium",
     "title": "End-of-life MySQL (< 5.7) exposed",
     "cves": [],
     "remediation": "Upgrade to a supported MySQL/MariaDB and restrict network access.",
     "desc": "Unsupported MySQL with many public CVEs; should not be network-exposed."},
    {"product": ["mysql"], "ge": "5.5.0", "le": "5.5.63", "severity": "high",
     "title": "MySQL 5.5.x remote pre-auth issues",
     "cves": ["CVE-2012-2122"],
     "remediation": "Upgrade MySQL; enforce strong auth.",
     "desc": "Some 5.5/5.6 builds allow an authentication bypass on repeated tries."},
    {"product": ["postgresql"], "lt": "11.0", "ge": "9.0", "severity": "medium",
     "title": "End-of-life PostgreSQL exposed",
     "cves": [],
     "remediation": "Upgrade to a supported PostgreSQL major version.",
     "desc": "Unsupported PostgreSQL exposed on the network."},
    # --- Web apps / middleware -------------------------------------------------
    {"product": ["jenkins"], "lt": "2.319", "severity": "high",
     "title": "Outdated Jenkins - multiple RCE / auth bypass",
     "cves": ["CVE-2019-1003000"],
     "remediation": "Upgrade Jenkins to the latest LTS; restrict access.",
     "desc": "Old Jenkins is a frequent full-compromise vector (script console, "
             "unauth RCE chains)."},
    {"product": ["apache tomcat", "tomcat"], "lt": "9.0.31", "ge": "6.0",
     "severity": "high",
     "title": "Apache Tomcat AJP 'Ghostcat' file read/inclusion",
     "cves": ["CVE-2020-1938"],
     "remediation": "Upgrade Tomcat; disable/secure the AJP connector (8009).",
     "desc": "The AJP connector allows reading web-app files and, with upload, RCE."},
    {"product": ["php"], "lt": "7.4.0", "ge": "5.0", "severity": "medium",
     "title": "End-of-life PHP (< 7.4) in use",
     "cves": [],
     "remediation": "Upgrade to a supported PHP release.",
     "desc": "Unsupported PHP with many known vulns backing the web app."},
    # --- Mail ------------------------------------------------------------------
    {"product": ["exim"], "lt": "4.92", "ge": "4.87", "severity": "critical",
     "title": "Exim 4.87-4.91 remote code execution",
     "cves": ["CVE-2019-10149"],
     "remediation": "Upgrade Exim to 4.92 or later.",
     "desc": "'Return of the WIZard' - unauthenticated RCE as root in default configs."},
]


def _os_version(host: Host) -> str:
    m = re.search(r"(\d+\.\d+)", host.os_name or "")
    return m.group(1) if m else ""


def _matches(sig: dict, port: Port, host: Host) -> bool:
    blob = f"{port.product} {port.service}".lower()
    if not any(p in blob for p in sig["product"]):
        return False
    # OS gate (e.g. BlueKeep only on old Windows).
    if sig.get("os") and sig["os"] not in (host.os_family or host.os_name).lower():
        return False
    if sig.get("os_lt"):
        osv = _os_version(host)
        if not osv or _cmp(osv, sig["os_lt"]) >= 0:
            return False
        return True   # OS-gated sig without a service version requirement
    version = port.version.strip()
    if any(k in sig for k in ("eq", "lt", "le", "ge", "gt")):
        if not version:
            return False
        if "eq" in sig:
            return _cmp(version, sig["eq"]) == 0
        return _in_range(
            version,
            lo=sig.get("ge") or sig.get("gt"), hi=sig.get("le") or sig.get("lt"),
            lo_incl="ge" in sig, hi_incl="le" in sig,
        )
    return True


def assess_host(host: Host) -> list[Vuln]:
    """Match every service on a host against the offline knowledge base."""
    findings: list[Vuln] = []
    seen = {v.title for v in host.vulns}
    for port in host.open_ports:
        for sig in SIGNATURES:
            if not _matches(sig, port, host):
                continue
            if sig["title"] in seen:
                continue
            seen.add(sig["title"])
            confidence = "potential" if sig.get("os_lt") else "likely"
            findings.append(Vuln(
                ip=host.ip, port=port.portid, protocol=port.protocol,
                script_id="version-db", state="version match",
                title=sig["title"],
                output=f"{port.product} {port.version} on {port.portid}/{port.protocol}"
                       f" - {sig['desc']}",
                severity=sig["severity"], ids=list(sig.get("cves", [])),
                source="version-db", remediation=sig.get("remediation", ""),
                confidence=confidence,
            ))
    return findings


def assess_host_inplace(host: Host) -> int:
    new = assess_host(host)
    host.vulns.extend(new)
    return len(new)


def assess(hosts: list[Host]) -> int:
    """Run the engine over hosts, appending findings in place. Returns count added."""
    return sum(assess_host_inplace(h) for h in hosts)


def signature_count() -> int:
    return len(SIGNATURES)
