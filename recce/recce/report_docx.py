"""Per-finding Word (.docx) write-ups, matching the walkthrough template.

recce auto-fills every field it can (title, affected systems, CWE, CVE, severity,
tools/techniques, recommendations, a drafted narrative and vuln-type, and the raw
evidence). Fields only the tester can supply - Mission Risk & Impact, Level of
Difficulty, and the step-by-step walkthrough with screenshots - are written as
clearly-marked [TESTER: ...] placeholders. The tester finishes each doc in Word
and pastes screenshots inline; recce never overwrites an edited write-up.

Findings are grouped by title across hosts, so one finding that spans many systems
becomes one write-up listing every affected IP:port.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from .docx import Document
from .models import Host, Vuln

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# First matching CWE -> (vulnerability type, CIA aspects) for auto-draft.
_CWE_TYPE = [
    (("CWE-78", "CWE-77", "CWE-88", "CWE-94", "CWE-95", "CWE-134"),
     "Injection / Remote Code Execution", "Confidentiality, Integrity, Availability"),
    (("CWE-89",), "SQL Injection", "Confidentiality, Integrity"),
    (("CWE-79",), "Cross-Site Scripting", "Integrity"),
    (("CWE-22", "CWE-98"), "Path Traversal / File Inclusion", "Confidentiality, Integrity"),
    (("CWE-287", "CWE-306", "CWE-288", "CWE-1188", "CWE-521", "CWE-307", "CWE-798"),
     "Authentication / Access Control Weakness", "Confidentiality, Integrity"),
    (("CWE-269", "CWE-250", "CWE-264"), "Privilege Escalation", "Confidentiality, Integrity"),
    (("CWE-319",), "Cleartext Transmission of Sensitive Data", "Confidentiality"),
    (("CWE-327", "CWE-326", "CWE-295", "CWE-297", "CWE-298"),
     "Cryptographic / TLS Weakness", "Confidentiality, Integrity"),
    (("CWE-522", "CWE-312", "CWE-256", "CWE-200", "CWE-538", "CWE-527", "CWE-532"),
     "Information / Credential Disclosure", "Confidentiality"),
    (("CWE-693", "CWE-1021", "CWE-16", "CWE-650", "CWE-441", "CWE-284"),
     "Security Misconfiguration", "Integrity"),
    (("CWE-406", "CWE-400"), "Resource Exhaustion / Denial of Service", "Availability"),
    (("CWE-1104", "CWE-1392"), "Unmaintained / Default Components", "Confidentiality, Integrity, Availability"),
    (("CWE-506",), "Embedded Malicious Code / Backdoor", "Confidentiality, Integrity, Availability"),
]

_SOURCE_TOOL = {
    "nse": "nmap NSE scripts",
    "version-db": "recce offline vulnerability database (service-version match)",
    "probe": "recce HTTP/TLS probe (standard library)",
    "config": "nmap NSE weak-configuration checks",
    "cred": "netexec / impacket / ssh (credentialed)",
}

# Severity -> hex colour (no #), matching the workbook + HTML-preview severity ramp.
_SEV_COLOR = {"critical": "C00000", "high": "C15A11", "medium": "9C7A00",
              "low": "2E5AAC", "info": "5F6F6E"}

# --- auto-drafted narrative building blocks (plain, management-level language) ---

# Port -> plain-language description of what the service is/does, for the opening
# context sentence. Falls back to banner keywords, then a generic phrase.
_SERVICE_ROLE = {
    80: "web service", 443: "web service (HTTPS)", 8080: "web service",
    8443: "web service (HTTPS)", 8000: "web service", 8888: "web service",
    8081: "web service", 9443: "web service (HTTPS)",
    21: "file-transfer (FTP) service", 22: "remote-administration (SSH) service",
    23: "remote-terminal (Telnet) service", 25: "mail (SMTP) service",
    110: "mail (POP3) service", 143: "mail (IMAP) service", 53: "DNS service",
    389: "directory (LDAP) service", 636: "directory (LDAPS) service",
    3268: "Active Directory directory service",
    88: "Kerberos authentication service",
    445: "Windows file-sharing (SMB) service",
    139: "Windows file-sharing (SMB) service",
    3389: "remote-desktop (RDP) service",
    5985: "Windows remote-management (WinRM) service",
    5986: "Windows remote-management (WinRM) service",
    3306: "database service (MySQL)", 5432: "database service (PostgreSQL)",
    1433: "database service (Microsoft SQL Server)", 1521: "database service (Oracle)",
    27017: "database service (MongoDB)", 6379: "in-memory data store (Redis)",
    161: "network-management (SNMP) service", 2049: "file-sharing (NFS) service",
}

# Vulnerability type (from _vuln_type) -> plain-language "an attacker could ..."
_TYPE_IMPACT = {
    "Injection / Remote Code Execution":
        "run their own commands on the affected system - in practice this often "
        "means full control of the host, its data, and any credentials stored on it",
    "SQL Injection":
        "read or alter the information held in the application's database, exposing "
        "sensitive records or corrupting data",
    "Cross-Site Scripting":
        "run malicious content in the browser of a legitimate user, which can be "
        "used to steal their session or trick them into unwanted actions",
    "Path Traversal / File Inclusion":
        "read files outside the intended area of the application - and in some cases "
        "run code - exposing configuration, credentials, or source",
    "Authentication / Access Control Weakness":
        "bypass or abuse the service's sign-in and access controls to reach data or "
        "functions that should be restricted",
    "Privilege Escalation":
        "raise their level of access on the system, moving from a limited foothold "
        "toward full administrative control",
    "Cleartext Transmission of Sensitive Data":
        "observe sensitive information - including credentials - as it crosses the "
        "network, because it is not encrypted",
    "Cryptographic / TLS Weakness":
        "undermine the encryption protecting the service, potentially exposing or "
        "tampering with data in transit",
    "Information / Credential Disclosure":
        "obtain sensitive information - such as internal details or credentials - "
        "that makes further attack easier",
    "Security Misconfiguration":
        "take advantage of an insecure default or misconfiguration to gain access or "
        "information they should not have",
    "Resource Exhaustion / Denial of Service":
        "disrupt or disable the service, denying it to legitimate users",
    "Unmaintained / Default Components":
        "exploit publicly known weaknesses in outdated or default components that no "
        "longer receive security fixes",
    "Embedded Malicious Code / Backdoor":
        "use a built-in backdoor to gain direct, unauthenticated access to the system",
}
_FALLBACK_IMPACT = ("weaken the security of the affected service, potentially "
                    "exposing data or functionality to unauthorized access")
_SEV_FRAME = {
    "critical": "This is considered a critical-risk exposure",
    "high": "This is considered a high-risk exposure",
    "medium": "This is considered a moderate-risk issue",
    "low": "This is considered a lower-risk issue",
    "info": "This is an informational observation",
}


def _join(items: list[str]) -> str:
    items = [i for i in items if i]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def _service_role(port: int, banner: str) -> str:
    role = _SERVICE_ROLE.get(port)
    if role:
        return role
    b = (banner or "").lower()
    if "http" in b:
        return "web service"
    if "ssh" in b:
        return "remote-administration (SSH) service"
    if "ftp" in b:
        return "file-transfer (FTP) service"
    if "smb" in b or "microsoft-ds" in b or "netbios" in b:
        return "Windows file-sharing (SMB) service"
    if any(k in b for k in ("sql", "postgres", "mysql", "oracle", "mongo")):
        return "database service"
    if "ldap" in b:
        return "directory (LDAP) service"
    return "network service"


def _narrative(f: Finding) -> list[str]:
    """Auto-draft a 3-paragraph, management-level narrative: what the service is,
    what was found (and where / how sure), and the plain-language impact."""
    if not f.affected:
        return [f"During testing, {f.title.lower()} was identified. {_SEV_FRAME.get(f.severity.lower(), 'This is an issue')}."]
    ip0, port0, _hn0 = f.affected[0]
    banner0 = f.services.get((ip0, port0), "")
    roles = []
    for ip, port, _hn in f.affected:
        r = _service_role(port, f.services.get((ip, port), ""))
        if r not in roles:
            roles.append(r)

    # 1) Context - what the affected component is.
    if len(roles) == 1:
        ctx = f"This finding concerns a {roles[0]}"
        if banner0:
            ctx += f" ({banner0})"
        ctx += ", exposed on the network to the tested environment."
    else:
        ctx = (f"This finding concerns {_join(roles)} exposed on the network to the "
               "tested environment.")

    # 2) What was found, where, and how confident we are.
    n = len(f.affected)
    where = _join([f"{ip}" + (f" ({hn})" if hn else "")
                   for ip, _p, hn in f.affected[:3]])
    more = f", and {n - 3} other system(s)" if n > 3 else ""
    cve = f" (tracked as {', '.join(f.cves[:3])})" if f.cves else ""
    found = (f"During testing, recce identified {f.title.lower()}{cve}, affecting "
             f"{n} system(s) - {where}{more}.")
    if f.confidence == "potential":
        found += (" This was inferred from the service's version and banner data, so "
                  "it should be confirmed through hands-on validation before it is "
                  "relied upon.")
    elif f.confidence == "likely":
        found += " The detected version falls within a range known to be affected."

    # 3) Plain-language impact, framed by severity.
    vtype, _cia = _vuln_type(f.cwes)
    impact = _TYPE_IMPACT.get(vtype, _FALLBACK_IMPACT)
    frame = _SEV_FRAME.get(f.severity.lower(), "This is an issue")
    consequence = (f"{frame}: if exploited, an attacker could {impact}.")
    return [ctx, found, consequence]


@dataclass
class Finding:
    title: str
    severity: str = "info"
    cwes: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    scripts: set[str] = field(default_factory=set)
    remediation: str = ""
    confidence: str = ""
    affected: list[tuple] = field(default_factory=list)   # (ip, port, hostname)
    evidence: list[tuple] = field(default_factory=list)    # (ip, port, output)
    services: dict = field(default_factory=dict)           # (ip,port) -> "product version"
    exploits: list[tuple] = field(default_factory=list)    # (edb_id, title)


def _norm_key(v: Vuln) -> str:
    return re.sub(r"\s+", " ", (v.title or v.script_id or "finding").strip().lower())


def group_findings(hosts: list[Host]) -> list[Finding]:
    """One Finding per distinct title, aggregating every affected host."""
    groups: dict[str, Finding] = {}
    for h in hosts:
        for v in h.vulns:
            key = _norm_key(v)
            f = groups.get(key)
            if f is None:
                f = Finding(title=v.title or v.script_id or "Finding",
                            severity=v.severity, remediation=v.remediation,
                            confidence=v.confidence)
                groups[key] = f
            # Severity: keep the highest seen.
            if _SEV_ORDER.get(v.severity, 9) < _SEV_ORDER.get(f.severity, 9):
                f.severity = v.severity
            for c in v.cwes:
                if c not in f.cwes:
                    f.cwes.append(c)
            for c in v.ids:
                if c not in f.cves:
                    f.cves.append(c)
            f.sources.add(v.source)
            if v.script_id:
                f.scripts.add(v.script_id)
            f.remediation = f.remediation or v.remediation
            entry = (h.ip, v.port, h.hostname)
            if entry not in f.affected:
                f.affected.append(entry)
            if v.output:
                f.evidence.append((h.ip, v.port, v.output))
            # Record the detected service banner + any public exploit on this port.
            port = next((p for p in h.ports if p.portid == v.port), None)
            if port and port.service_banner:
                f.services[(h.ip, v.port)] = port.service_banner
            for e in h.exploits:
                if e.port == v.port and (e.edb_id, e.title) not in f.exploits:
                    f.exploits.append((e.edb_id, e.title))
    ordered = sorted(groups.values(),
                     key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.title.lower()))
    return ordered


def _vuln_type(cwes: list[str]) -> tuple[str, str]:
    for keys, label, cia in _CWE_TYPE:
        if any(c in keys for c in cwes):
            return label, cia
    return "", ""


def _tools_line(f: Finding) -> str:
    tools = sorted({_SOURCE_TOOL.get(s, s) for s in f.sources})
    scripts = sorted(s for s in f.scripts if s and s not in ("version-db",))
    line = "; ".join(tools)
    if scripts:
        line += f" (checks: {', '.join(scripts[:8])})"
    return line


def _slug(text: str, n: int = 40) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:n] or "finding"


def _walkthrough_steps(f: Finding) -> list[str]:
    """Draft concrete reproduction steps from what recce knows about the finding.

    These are the mechanical, repeatable steps (discovery command, confirmation
    check, candidate exploit). The tester still adds the exploitation result and
    screenshots - that part is a placeholder."""
    ip, port, _hn = f.affected[0]
    ports = sorted({p for _i, p, _h in f.affected})
    portspec = ",".join(str(p) for p in ports)
    banner = f.services.get((ip, port), "")
    scripts = sorted(s for s in f.scripts if s and s != "version-db")
    steps: list[str] = []

    # 1. Discovery / service identification.
    ident = f"Enumerate the target service: nmap -sV -p {portspec} {ip}"
    if banner:
        ident += f"  -> identifies \"{banner}\" on {port}/tcp."
    steps.append(ident)

    # 2. Confirmation, tailored to how recce detected it.
    if "version-db" in f.sources or "nse" in f.sources:
        if scripts:
            steps.append(f"Confirm the vulnerability with the NSE check(s): "
                         f"nmap --script {','.join(scripts[:4])} -p {portspec} {ip} "
                         f"(the script reports the vulnerable condition).")
        else:
            cve = f.cves[0] if f.cves else "the associated advisory"
            steps.append(f"Cross-check the detected version against {cve}: the "
                         f"running version falls within the known-vulnerable range.")
    elif "config" in f.sources:
        steps.append(f"Confirm the weak configuration: "
                     f"nmap --script {','.join(scripts[:4]) or 'default'} "
                     f"-p {portspec} {ip} (the check flags the exposed condition).")
    elif "probe" in f.sources:
        low = f.title.lower()
        if "tls" in low or "cipher" in low or "certificate" in low:
            steps.append(f"Enumerate TLS: nmap --script ssl-enum-ciphers,ssl-cert "
                         f"-p {portspec} {ip}  (or: openssl s_client -connect "
                         f"{ip}:{port}) - the weak protocol/cipher/cert is offered.")
        else:
            steps.append(f"Inspect the HTTP response headers: "
                         f"curl -sI http://{ip}:{port}/  - the flagged security "
                         f"header is absent from the response.")
    elif "cred" in f.sources:
        steps.append(f"Authenticate and enumerate with valid credentials, e.g.: "
                     f"netexec smb {ip} -u <user> -p <password> --shares "
                     f"(the tool output above confirms the access).")

    # 3. Candidate public exploit(s), if searchsploit mapped any on this port.
    if f.exploits:
        ids = ", ".join(f"EDB-{eid}" for eid, _t in f.exploits[:5] if eid)
        steps.append(f"Review candidate public exploit(s) indexed for this "
                     f"service: {ids}. Inspect with `searchsploit -x <id>` and, if "
                     f"in scope, weaponize with `searchsploit -m <id>`.")
    elif f.cves:
        steps.append(f"Research a working exploit for {', '.join(f.cves[:3])} and "
                     f"validate it in a controlled manner within the rules of "
                     f"engagement.")

    return steps


def _finding_body(doc: Document, f: Finding, fid: str,
                  shots: dict | None = None) -> None:
    """Render one finding's sections into `doc` (shared by per-finding + combined)."""
    vtype, cia = _vuln_type(f.cwes)
    sev = f.severity.lower()

    # Severity chip under the title, colour-coded like the workbook/preview.
    doc.para(f"● {f.severity.upper()} SEVERITY   ·   {len(f.affected)} "
             f"affected system(s)", bold=True, color=_SEV_COLOR.get(sev, "5F6F6E"))

    doc.heading("Narrative", 2)
    doc.placeholder("Refine the plain-language summary below for management.")
    for paragraph in _narrative(f):
        doc.para(paragraph)

    doc.heading("Finding Details", 2)
    doc.field("Finding ID", fid, mono=True)
    doc.field("Severity", f.severity.upper(), value_color=_SEV_COLOR.get(sev))
    doc.field("Affected systems", ", ".join(
        f"{ip}:{port}" + (f" ({hn})" if hn else "")
        for ip, port, hn in f.affected), mono=True)
    doc.field("Vulnerability Type", vtype, placeholder="classify the vulnerability")
    doc.field("CWE Associated", ", ".join(f.cwes), placeholder="add CWE reference(s)",
              mono=True)
    doc.field("CVE / References", ", ".join(f.cves) or "None mapped", mono=True)
    doc.field("Security Aspect Compromised", cia,
              placeholder="confirm Confidentiality / Integrity / Availability")
    doc.field("Tools/Techniques Used", _tools_line(f))
    doc.field("Level of Difficulty", "", placeholder="rate exploitation difficulty "
              "(e.g. Low / Moderate / High) and justify")

    doc.heading("Mission Risk and Impact", 2)
    doc.placeholder("Describe the mission risk and impact if this finding is "
                    "exploited (engagement/mission specific).")

    doc.heading("Recommendations", 2)
    if f.remediation:
        doc.para(f.remediation)
    else:
        doc.placeholder("Provide remediation and mitigation guidance.")

    doc.heading("Evidence", 2)
    for ip, port, out in f.evidence[:6]:
        doc.para(f"{ip}:{port}", italic=True)
        doc.mono_block(out if len(out) < 1500 else out[:1500] + " ...")

    doc.heading("Technical Walkthrough with screenshots", 2)
    # recce drafts the mechanical steps; the tester adds the exploitation result.
    n = 0
    for step in _walkthrough_steps(f):
        n += 1
        doc.para(f"Step {n}. {step}")
    for ip, _port, _hn in f.affected:
        for url, png in (shots or {}).get(ip, []):
            n += 1
            doc.para(f"Step {n}. Observe the affected service at {url}:")
            doc.image(png, caption=f"Screenshot: {url}")
    doc.para(f"Step {n + 1}. ")
    doc.placeholder("Perform the exploitation/validation, describe the result, "
                    "and capture a screenshot of the outcome above.")


def _write_one(f: Finding, fid: str, path: str,
               shots: dict | None = None) -> None:
    doc = Document()
    doc.title(f"{fid}: {f.title}")
    _finding_body(doc, f, fid, shots)
    doc.save(path)


def build_writeups(hosts: list[Host], out_dir: str, *, min_severity: str = "info",
                   screenshots: dict | None = None,
                   overwrite: bool = False) -> dict:
    """Generate one .docx per finding into out_dir. Returns a summary dict.

    Never overwrites an existing write-up unless overwrite=True, so tester edits
    (narrative, steps, pasted screenshots) survive a regenerate.
    """
    os.makedirs(out_dir, exist_ok=True)
    cutoff = _SEV_ORDER.get(min_severity, 4)
    findings = [f for f in group_findings(hosts)
                if _SEV_ORDER.get(f.severity, 9) <= cutoff]
    written, skipped = [], []
    for i, f in enumerate(findings, 1):
        fid = f"F-{i:03d}"
        fname = f"{fid}_{f.severity}_{_slug(f.title)}.docx"
        path = os.path.join(out_dir, fname)
        if os.path.exists(path) and not overwrite:
            skipped.append(fname)
            continue
        _write_one(f, fid, path, screenshots)
        written.append(fname)
    return {"written": written, "skipped": skipped, "total": len(findings)}


def build_combined(hosts: list[Host], out_path: str, *, title: str = "",
                   min_severity: str = "info",
                   screenshots: dict | None = None) -> dict:
    """One document: title, severity summary, findings-summary table, then every
    finding as a section. Regenerated each run (it's a rollup, not hand-edited)."""
    cutoff = _SEV_ORDER.get(min_severity, 4)
    findings = [f for f in group_findings(hosts)
                if _SEV_ORDER.get(f.severity, 9) <= cutoff]
    doc = Document()
    doc.title(title or "Penetration Test - Findings Report")
    doc.para(f"{len(findings)} finding(s) across "
             f"{len({a[0] for f in findings for a in f.affected})} affected host(s).",
             italic=True, color="666666")

    # Severity counts.
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    doc.heading("Summary", 1)
    doc.table(["Critical", "High", "Medium", "Low", "Info"],
              [[str(counts.get(s, 0)) for s in
                ("critical", "high", "medium", "low", "info")]],
              widths=[1600, 1600, 1600, 1600, 1600])

    # Findings summary table.
    doc.heading("Findings", 1)
    rows = []
    fids = []
    for i, f in enumerate(findings, 1):
        fid = f"F-{i:03d}"
        fids.append(fid)
        hosts_txt = ", ".join(sorted({a[0] for a in f.affected}))
        rows.append([fid, f.severity.upper(), f.title,
                     ", ".join(f.cwes) or "-",
                     hosts_txt if len(hosts_txt) < 60 else f"{len(f.affected)} systems"])
    doc.table(["ID", "Severity", "Finding", "CWE", "Affected"], rows,
              widths=[900, 1100, 3860, 1500, 2000])

    # Each finding as a section.
    for fid, f in zip(fids, findings):
        doc.page_break()
        doc.heading(f"{fid}: {f.title}", 1)
        _finding_body(doc, f, fid, screenshots)

    doc.save(out_path)
    return {"path": out_path, "total": len(findings)}
