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


def _write_one(f: Finding, fid: str, path: str,
               shots: dict | None = None) -> None:
    doc = Document()
    vtype, cia = _vuln_type(f.cwes)
    doc.title(f"{fid}: {f.title}")

    doc.heading("Narrative")
    doc.guidance("Write this for non-technical management as a concise overview "
                 "with minimal technical detail. Lead with a brief description of "
                 "the purpose of the affected service for context. No pronouns or "
                 "mission impact; maintain verb tense in context of test actions.")
    doc.placeholder("Refine the plain-language summary below for management.")
    doc.para(f"During testing, {f.title.lower()} was identified on "
             f"{len(f.affected)} system(s). This condition could allow an "
             f"attacker to weaken the security of the affected service.")

    doc.heading("Finding Details")
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

    doc.heading("Mission Risk and Impact")
    doc.placeholder("Describe the mission risk and impact if this finding is "
                    "exploited (engagement/mission specific).")

    doc.heading("Recommendations")
    doc.guidance("Recommended fixes and mitigations. Do not include specific "
                 "brands or models.")
    if f.remediation:
        doc.para(f.remediation)
    else:
        doc.placeholder("Provide remediation and mitigation guidance.")

    doc.heading("Evidence")
    doc.guidance("Raw tool output captured during testing (proof of the finding).")
    for ip, port, out in f.evidence[:6]:
        doc.para(f"{ip}:{port}", italic=True)
        doc.mono_block(out if len(out) < 1500 else out[:1500] + " ...")

    doc.heading("Technical Walkthrough with screenshots")
    doc.guidance("List every step used to accomplish objectives, with screenshots.")
    embedded = 0
    for ip, port, _hn in f.affected:
        for url, png in (shots or {}).get(ip, []):
            doc.para(f"Step {embedded + 1}. Access {url}", )
            doc.image(png, caption=f"Screenshot: {url}")
            embedded += 1
    doc.para(f"Step {embedded + 1}. ")
    doc.placeholder("Add the reproduction steps and screenshots for this finding.")

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
