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

    doc.heading("Narrative", 2)
    doc.guidance("Write this for non-technical management as a concise overview "
                 "with minimal technical detail. Lead with a brief description of "
                 "the purpose of the affected service for context. No pronouns or "
                 "mission impact; maintain verb tense in context of test actions.")
    doc.placeholder("Refine the plain-language summary below for management.")
    doc.para(f"During testing, {f.title.lower()} was identified on "
             f"{len(f.affected)} system(s). This condition could allow an "
             f"attacker to weaken the security of the affected service.")

    doc.heading("Finding Details", 2)
    doc.field("Finding ID", fid)
    doc.field("Severity", f.severity.upper())
    doc.field("Affected systems", ", ".join(
        f"{ip}:{port}" + (f" ({hn})" if hn else "")
        for ip, port, hn in f.affected))
    doc.field("Vulnerability Type", vtype, placeholder="classify the vulnerability")
    doc.field("CWE Associated", ", ".join(f.cwes), placeholder="add CWE reference(s)")
    doc.field("CVE / References", ", ".join(f.cves) or "None mapped")
    doc.field("Security Aspect Compromised", cia,
              placeholder="confirm Confidentiality / Integrity / Availability")
    doc.field("Tools/Techniques Used", _tools_line(f))
    doc.field("Level of Difficulty", "", placeholder="rate exploitation difficulty "
              "(e.g. Low / Moderate / High) and justify")

    doc.heading("Mission Risk and Impact", 2)
    doc.placeholder("Describe the mission risk and impact if this finding is "
                    "exploited (engagement/mission specific).")

    doc.heading("Recommendations", 2)
    doc.guidance("Recommended fixes and mitigations. Do not include specific "
                 "brands or models.")
    if f.remediation:
        doc.para(f.remediation)
    else:
        doc.placeholder("Provide remediation and mitigation guidance.")

    doc.heading("Evidence", 2)
    doc.guidance("Raw tool output captured during testing (proof of the finding).")
    for ip, port, out in f.evidence[:6]:
        doc.para(f"{ip}:{port}", italic=True)
        doc.mono_block(out if len(out) < 1500 else out[:1500] + " ...")

    doc.heading("Technical Walkthrough with screenshots", 2)
    doc.guidance("List every step used to accomplish objectives, with screenshots.")
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
