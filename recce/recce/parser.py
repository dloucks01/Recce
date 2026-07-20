"""Parse nmap XML output into the normalized data model.

Uses only the stdlib xml.etree parser. Designed to be tolerant: missing
attributes/elements are skipped rather than raising, because real-world scans
produce partial records all the time.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from .models import Account, Host, Port, Script, Vuln

_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)
_CVSS_RE = re.compile(r"CVSS(?:v?\d)?[:\s]*([0-9]+\.[0-9]+)", re.IGNORECASE)
# vulners lines look like:  CVE-2021-42013   9.8   https://vulners.com/...
_VULNERS_RE = re.compile(r"CVE-\d{4}-\d{4,7}\s+([0-9]{1,2}\.[0-9])\b", re.IGNORECASE)


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _parse_elements(node: ET.Element) -> dict:
    """Flatten <elem key=..> and nested <table> into a dict for structured access."""
    result: dict = {}
    for elem in node.findall("elem"):
        key = elem.get("key")
        if key:
            result[key] = (elem.text or "").strip()
    for i, table in enumerate(node.findall("table")):
        key = table.get("key") or f"_table{i}"
        result[key] = _parse_elements(table)
    return result


def _script_from_node(node: ET.Element) -> Script:
    return Script(
        id=node.get("id", ""),
        output=(node.get("output") or "").strip(),
        elements=_parse_elements(node),
    )


def _classify_vuln(host_ip: str, port: Port | None, script: Script) -> Vuln | None:
    """Turn a vuln-flavored NSE script result into a Vuln, or None if not relevant."""
    sid = script.id
    out = script.output or ""
    is_vuln_family = (
        "VULNERABLE" in out.upper()
        or sid.startswith("vuln")
        or sid == "vulners"
        or "CVE-" in out.upper()
    )
    if not is_vuln_family:
        return None
    # Skip scripts that explicitly report not-vulnerable with nothing else useful.
    if "VULNERABLE" not in out.upper() and "CVE-" not in out.upper() and sid != "vulners":
        return None

    state = ""
    m = re.search(r"State:\s*(.+)", out)
    if m:
        state = m.group(1).strip()
    elif "VULNERABLE" in out.upper():
        state = "VULNERABLE"

    ids = sorted(set(_CVE_RE.findall(out)))
    cvss_scores = [float(s) for s in _CVSS_RE.findall(out)]
    cvss_scores += [float(s) for s in _VULNERS_RE.findall(out)]
    severity = _severity_from_cvss(max(cvss_scores)) if cvss_scores else (
        "high" if "VULNERABLE" in out.upper() else "info"
    )

    title = sid
    tm = re.search(r"Title:\s*(.+)", out)
    if tm:
        title = tm.group(1).strip()

    return Vuln(
        ip=host_ip,
        port=port.portid if port else None,
        protocol=port.protocol if port else "",
        script_id=sid,
        state=state,
        title=title,
        output=out,
        severity=severity,
        ids=[i.upper() for i in ids],
    )


# --- weak-configuration findings from enumeration scripts -----------------------

def _weak_config(host_ip: str, port: Port | None, script: Script) -> Vuln | None:
    """Classify notable weak-config / exposure findings from enum NSE scripts.

    These are not CVEs but are real engagement findings (cleartext auth, anonymous
    access, weak TLS, dangerous HTTP methods, exposed data stores, ...).
    """
    sid = script.id
    out = script.output or ""
    low = out.lower()
    sev = title = None
    cwe: list[str] = []

    if sid == "ftp-anon" and "anonymous ftp login allowed" in low:
        sev, title, cwe = "medium", "Anonymous FTP login allowed", ["CWE-1392", "CWE-306"]
    elif sid == "ssl-enum-ciphers":
        if re.search(r"least strength:\s*[c-f]\b", low) or any(
                w in out for w in ("SSLv2", "SSLv3", "RC4", "NULL", "EXPORT",
                                   "SWEET32", "anonymous")):
            sev, title, cwe = "medium", "Weak SSL/TLS ciphers or protocols", ["CWE-327", "CWE-326"]
    elif sid == "ssl-cert":
        if "expired" in low:
            sev, title, cwe = "low", "Expired TLS certificate", ["CWE-298", "CWE-295"]
        elif "self-signed" in low or "self signed" in low:
            sev, title, cwe = "low", "Self-signed TLS certificate", ["CWE-295"]
    elif sid == "http-methods" and ("put" in low or "delete" in low or "trace" in low):
        if "potentially risky methods" in low:
            sev, title, cwe = "low", "Risky HTTP methods enabled (PUT/DELETE/TRACE)", ["CWE-650"]
    elif sid == "http-webdav-scan" and "webdav" in low:
        sev, title, cwe = "low", "WebDAV enabled", ["CWE-650"]
    elif sid == "http-git" and ".git" in low:
        sev, title, cwe = "medium", "Exposed .git repository", ["CWE-527", "CWE-538"]
    elif sid in ("mysql-empty-password", "ms-sql-empty-password") and \
            ("account has empty password" in low or "empty password" in low):
        sev, title, cwe = "high", "Database account with empty password", ["CWE-521", "CWE-287"]
    elif sid == "redis-info" and "version" in low:
        sev, title, cwe = "medium", "Unauthenticated Redis exposed", ["CWE-306"]
    elif sid == "mongodb-info" and "version" in low:
        sev, title, cwe = "medium", "Unauthenticated MongoDB exposed", ["CWE-306"]
    elif sid == "telnet-encryption" and "does not support encryption" in low:
        sev, title, cwe = "medium", "Telnet without encryption (cleartext)", ["CWE-319"]
    elif sid == "smtp-open-relay" and "is an open relay" in low:
        sev, title, cwe = "high", "SMTP open relay", ["CWE-269"]
    elif sid == "nfs-showmount" and "/" in out:
        sev, title, cwe = "low", "NFS exports readable", ["CWE-284"]
    elif sid.startswith("snmp") and ("public" in low or "private" in low):
        sev, title, cwe = "medium", "SNMP community string exposed", ["CWE-1392", "CWE-319"]
    elif sid == "dns-zone-transfer" and "domain" in low and "failed" not in low:
        sev, title, cwe = "medium", "DNS zone transfer allowed", ["CWE-200"]
    elif sid == "vnc-info" and "no authentication" in low:
        sev, title, cwe = "high", "VNC without authentication", ["CWE-306"]
    elif sid == "http-open-proxy" and "potentially open proxy" in low:
        sev, title, cwe = "medium", "Open HTTP proxy", ["CWE-441"]

    if not sev:
        return None
    return Vuln(
        ip=host_ip,
        port=port.portid if port else None,
        protocol=port.protocol if port else "",
        script_id=sid,
        state="finding",
        title=title,
        output=out,
        severity=sev,
        cwes=cwe,
        source="config",
    )


def _classify_any(host_ip: str, port: Port | None, script: Script) -> Vuln | None:
    """A CVE/vuln finding takes precedence; otherwise try weak-config."""
    return _classify_vuln(host_ip, port, script) or _weak_config(host_ip, port, script)


# --- AD / SMB / LDAP host-script harvesting -------------------------------------

def _accounts_from_host_scripts(host_ip: str, script: Script) -> list[Account]:
    accounts: list[Account] = []
    sid = script.id
    out = script.output or ""

    if sid == "smb-enum-users":
        # Lines look like:  DOMAIN\alice (RID: 1001) ...
        for m in re.finditer(r"([\w.-]+)\\([\w.$-]+)\s*\(RID:\s*(\d+)\)", out):
            accounts.append(Account(ip=host_ip, source=sid, kind="user",
                                    domain=m.group(1), name=m.group(2), rid=m.group(3)))
    elif sid in ("smb-enum-shares",):
        for m in re.finditer(r"\\\\[\w.$-]+\\([\w.$ -]+)", out):
            accounts.append(Account(ip=host_ip, source=sid, kind="share", name=m.group(1).strip()))
    elif sid == "smb-os-discovery":
        el = script.elements
        domain = el.get("domain", "") or el.get("Domain", "")
        fqdn = el.get("fqdn", "") or el.get("FQDN", "")
        if domain or fqdn:
            accounts.append(Account(ip=host_ip, source=sid, kind="domain",
                                    domain=domain, name=fqdn, detail=out.replace("\n", "; ")))
    elif sid.startswith("ldap"):
        for m in re.finditer(r"(?:dnsHostName|defaultNamingContext|rootDomainNamingContext):\s*(.+)", out):
            accounts.append(Account(ip=host_ip, source=sid, kind="domain", detail=m.group(1).strip()))
    return accounts


def parse_nmap_xml(path: str) -> list[Host]:
    """Parse one nmap XML file into a list of Host objects (up hosts only)."""
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        # nmap may leave a truncated file if interrupted; try lenient recovery.
        with open(path, "r", errors="replace") as fh:
            data = fh.read()
        end = data.rfind("</nmaprun>")
        if end == -1:
            # Close the last complete <host> block and the run so we salvage partials.
            last_host_end = data.rfind("</host>")
            if last_host_end == -1:
                return []
            data = data[: last_host_end + len("</host>")] + "\n</nmaprun>"
        tree = ET.ElementTree(ET.fromstring(data))

    root = tree.getroot()
    start = root.get("start", "")
    hosts: list[Host] = []

    for hnode in root.findall("host"):
        status = hnode.find("status")
        state = status.get("state", "unknown") if status is not None else "unknown"
        if state == "down":
            continue

        ip = ""
        mac = ""
        vendor = ""
        for addr in hnode.findall("address"):
            atype = addr.get("addrtype")
            if atype in ("ipv4", "ipv6"):
                ip = addr.get("addr", ip)
            elif atype == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")
        if not ip:
            continue

        host = Host(ip=ip, state=state, mac=mac, vendor=vendor, last_scanned=start)

        hn_node = hnode.find("hostnames")
        if hn_node is not None:
            for hn in hn_node.findall("hostname"):
                name = hn.get("name")
                if name and name not in host.hostnames:
                    host.hostnames.append(name)

        # OS detection.
        os_node = hnode.find("os")
        if os_node is not None:
            matches = os_node.findall("osmatch")
            if matches:
                best = max(matches, key=lambda m: int(m.get("accuracy", "0")))
                host.os_name = best.get("name", "")
                host.os_accuracy = int(best.get("accuracy", "0"))
                oclass = best.find("osclass")
                if oclass is not None:
                    host.os_family = oclass.get("osfamily", "")

        dist = hnode.find("distance")
        if dist is not None:
            host.distance = int(dist.get("value", "0"))

        # Ports.
        ports_node = hnode.find("ports")
        if ports_node is not None:
            for pnode in ports_node.findall("port"):
                st = pnode.find("state")
                pstate = st.get("state", "") if st is not None else ""
                if pstate in ("closed", "filtered"):
                    continue  # keep only open / open|filtered
                port = Port(
                    portid=int(pnode.get("portid", "0")),
                    protocol=pnode.get("protocol", "tcp"),
                    state=pstate or "open",
                    reason=st.get("reason", "") if st is not None else "",
                )
                svc = pnode.find("service")
                if svc is not None:
                    port.service = svc.get("name", "")
                    port.product = svc.get("product", "")
                    port.version = svc.get("version", "")
                    port.extrainfo = svc.get("extrainfo", "")
                    port.tunnel = svc.get("tunnel", "")
                    port.ostype = svc.get("ostype", "")
                    port.cpe = [c.text for c in svc.findall("cpe") if c.text]
                for snode in pnode.findall("script"):
                    script = _script_from_node(snode)
                    port.scripts.append(script)
                    vuln = _classify_any(ip, port, script)
                    if vuln:
                        host.vulns.append(vuln)
                host.ports.append(port)

        # Host-level scripts (SMB/LDAP/AD enrichment, host-level vuln scripts).
        hostscript = hnode.find("hostscript")
        if hostscript is not None:
            for snode in hostscript.findall("script"):
                script = _script_from_node(snode)
                host.host_scripts.append(script)
                vuln = _classify_any(ip, None, script)
                if vuln:
                    host.vulns.append(vuln)
                host.accounts.extend(_accounts_from_host_scripts(ip, script))

        hosts.append(host)

    return hosts
