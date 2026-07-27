"""Sköll-Fieldkit bridge — round-trip recce <-> Sköll.

Two directions, both stdlib-only so this stays airgap-safe like the rest of recce:

  recce -> Sköll  (seed exploitation from enumeration)
    `skoll_export` writes a small handoff folder the Sköll kit consumes:
      * ports.gnmap      - synthesized nmap-greppable; drops straight into
                           `sweep.py triage --nmap ports.gnmap` with no Sköll change.
      * smb-null.txt     - netexec-style lines for hosts where recce saw a null
                           session / anonymous SMB (Sköll's `triage --nxc` bumps them).
      * recce-bridge.json- the RICH feed: per-host ports+service+version, recce's
                           CONFIRMED findings, and the exact Sköll generator to run,
                           read by `sweep.py triage --recce`.
      * SKOLL.md         - a human, severity-ranked "run THIS on THAT host, because ..."
                           plan an operator can work top-down.

  Sköll -> recce  (fold proven exploitation back into the workbook + report)
    `findings_to_vulns` parses a Sköll findings.json (raw, or the enriched
    `recce_findings.json` that `gen_report.py --export-recce` emits) into recce
    `Vuln`s (source="skoll", confidence="confirmed") so every proven finding lands
    in the Vulnerabilities sheet, the HTML/Markdown report and the DOCX write-ups.

Nothing here scans, connects, or executes; it only transforms data recce already
holds and text a Sköll operator brings back.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from .models import Host, Port, Vuln

BRIDGE_VERSION = 1

# --------------------------------------------------------------------------------------
# Port -> Sköll generator map. Mirrors access/network/sweep.py's WINS table so recce's
# suggestions match what Sköll's own triage would pick; kept here (not imported) so recce
# stays standalone and airgap-safe. (label, "note + generator to run", juiciness 0=best).
# --------------------------------------------------------------------------------------
WINS: dict[int, tuple[str, str, int]] = {
    2375: ("docker-api", "UNAUTH -> root on host: services/gen_container.py docker", 0),
    2376: ("docker-tls", "Docker API (TLS): services/gen_container.py docker", 1),
    6379: ("redis", "often UNAUTH -> RCE: services/gen_db.py --db redis", 0),
    27017: ("mongodb", "often UNAUTH -> data/creds: services/gen_db.py --db mongo", 1),
    9200: ("elastic", "UNAUTH REST -> data (+old RCE): services/gen_db.py --db elastic", 1),
    5984: ("couchdb", "UNAUTH -> add-admin+RCE: services/gen_db.py --db couchdb", 1),
    11211: ("memcached", "UNAUTH -> sessions/creds: services/gen_db.py --db memcached", 2),
    445: ("smb", "null-session/relay/EternalBlue: services/gen_smb + access/gen_relay", 1),
    2049: ("nfs", "exports -> loot/keys: services/gen_nfs.py", 1),
    21: ("ftp", "anon login? services/gen_ftp.py anon", 2),
    161: ("snmp", "community strings: services/gen_snmp.py (UDP - nmap -sU)", 2),
    873: ("rsync", "anon modules: services/gen_remote.py rsync", 2),
    5900: ("vnc", "no-auth/weak: services/gen_remote.py vnc", 2),
    23: ("telnet", "default creds: services/gen_remote.py telnet", 3),
    8080: ("http-alt", "Tomcat/JBoss mgr / web: services/gen_container.py tomcat / web/", 1),
    80: ("http", "web app -> access/web/ (nuclei/ffuf first)", 2),
    443: ("https", "web app -> access/web/", 2),
    8443: ("https-alt", "web app -> access/web/", 2),
    3389: ("rdp", "spray CAREFULLY (lockout): access/gen_spray.py --proto rdp", 3),
    5985: ("winrm", "cred -> shell: access/gen_shell.py --proto winrm", 3),
    5986: ("winrm-tls", "cred -> shell: access/gen_shell.py --proto winrm", 3),
    1433: ("mssql", "SQLi/spray -> xp_cmdshell: access/gen_shell --proto mssql", 2),
    3306: ("mysql", "spray -> UDF/OUTFILE: services/gen_db.py --db mysql", 2),
    5432: ("postgres", "COPY...PROGRAM RCE: services/gen_db.py --db postgres", 2),
    1521: ("oracle", "SID/creds (ODAT): services/gen_db.py --db oracle", 2),
    389: ("ldap", "anon bind? domain enum: access/enum_net --ad", 2),
    88: ("kerberos", "AS-REP roast / kerbrute: access/gen_spray --proto kerberos", 2),
    25: ("smtp", "user-enum/relay: services/gen_remote.py smtp", 3),
}


def skoll_module_for_port(port: int) -> tuple[str, str, int] | None:
    """(label, note+generator, juiciness) for a port, or None if recce has no Sköll route."""
    return WINS.get(port)


# --------------------------------------------------------------------------------------
# recce -> Sköll : synthesize the handoff artifacts from the host model.
# --------------------------------------------------------------------------------------


def _gnmap_service_field(p: Port) -> str:
    """The `<port>/open/<proto>//<service>/<extra>/` cell nmap greppable uses."""
    svc = (p.service or "").replace("/", "_")
    ver = " ".join(x for x in (p.product, p.version) if x).replace("/", "_")
    return f"{p.portid}/open/{p.protocol or 'tcp'}//{svc}//{ver}/"


def build_gnmap(hosts: list[Host]) -> str:
    """Synthesize an nmap-greppable (`-oG`) scan from recce's host/port model.

    Sköll's `sweep.py triage --nmap` only needs `Host: <ip> (<name>)  Ports: <p>/open/...`
    lines, so this is a lossless-enough handoff that needs no change on the Sköll side.
    """
    out: list[str] = ["# recce -> Sköll handoff (synthesized nmap-greppable). "
                      "Feed: sweep.py triage --nmap ports.gnmap"]
    for h in hosts:
        openp = h.open_ports
        if not openp:
            continue
        name = h.hostname or ""
        ports = ", ".join(_gnmap_service_field(p) for p in openp)
        out.append(f"Host: {h.ip} ({name})\tPorts: {ports}\tIgnored State: closed")
    return "\n".join(out) + "\n"


# recce vuln signals (title/script_id substrings) that mean SMB is reachable without creds,
# so Sköll should treat the host as a null-session / relay candidate.
_NULL_SMB = ("null session", "anonymous", "guest", "smb-null", "anonymous access")


def _has_null_smb(h: Host) -> bool:
    for v in h.vulns:
        blob = f"{v.title} {v.script_id} {v.output}".lower()
        if v.port in (445, 139) and any(n in blob for n in _NULL_SMB):
            return True
    for a in h.accounts:
        if a.kind == "share" and str(a.attrs.get("access", "")).lower() in ("read", "read,write", "write"):
            return True
    return False


def build_smb_null(hosts: list[Host]) -> str:
    """netexec-style lines for hosts recce saw a null/anonymous SMB session on.

    Matches the loose shape `sweep.py triage --nxc` scrapes (an IP on a line mentioning
    READ/WRITE or 'Enumerated shares'), so those hosts float to the top of Sköll's board.
    """
    lines: list[str] = ["# recce -> Sköll: hosts with a null/anonymous SMB session "
                        "(feed: sweep.py triage --nxc smb-null.txt)"]
    any_hit = False
    for h in hosts:
        if _has_null_smb(h):
            any_hit = True
            name = h.hostname or ""
            lines.append(f"SMB   {h.ip}   445   {name}   [+] Enumerated shares "
                         "(null session) READ")
    if not any_hit:
        lines.append("# (recce recorded no null/anonymous SMB sessions in this engagement)")
    return "\n".join(lines) + "\n"


def _confirmed(v: Vuln) -> bool:
    return (v.confidence or "").lower() != "potential"


def _suggest_for_host(h: Host) -> list[dict[str, Any]]:
    """Per-open-port Sköll routes for a host, best-first (deduped by generator note)."""
    routes: list[dict[str, Any]] = []
    seen: set[str] = set()
    scored = []
    for p in h.open_ports:
        w = skoll_module_for_port(p.portid)
        if w:
            scored.append((w[2], p, w))
    for _j, p, (label, note, juic) in sorted(scored, key=lambda t: t[0]):
        if note in seen:
            continue
        seen.add(note)
        routes.append({"port": p.portid, "service": p.service or label, "label": label,
                       "module": note, "juiciness": juic})
    return routes


def _host_findings(h: Host) -> list[dict[str, Any]]:
    """recce's CONFIRMED vulns for the bridge, worst-first, with CVE/CWE.

    Deduped by title (the same weakness confirmed on several ports collapses to one
    entry) so the scoreboard/plan stay readable; ports and CVEs are unioned.
    """
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    by_title: dict[str, dict[str, Any]] = {}
    for v in h.vulns:
        if not _confirmed(v):
            continue
        sev = (v.severity or "info").lower()
        cves = [x for x in v.ids if x.upper().startswith("CVE")]
        e = by_title.get(v.title)
        if e is None:
            by_title[v.title] = {
                "title": v.title, "severity": sev,
                "confidence": v.confidence or "confirmed",
                "ports": [v.port] if v.port else [],
                "cves": list(cves), "cwes": list(v.cwes), "source": v.source,
            }
        else:
            if order.get(sev, 5) < order.get(e["severity"], 5):
                e["severity"] = sev
            if v.port and v.port not in e["ports"]:
                e["ports"].append(v.port)
            for c in cves:
                if c not in e["cves"]:
                    e["cves"].append(c)
            for c in v.cwes:
                if c not in e["cwes"]:
                    e["cwes"].append(c)
    return sorted(by_title.values(), key=lambda f: order.get(f["severity"], 5))


def build_bridge(hosts: list[Host], engagement: str = "Recce Engagement",
                 generated: str = "") -> dict[str, Any]:
    """The rich recce -> Sköll feed consumed by `sweep.py triage --recce`."""
    entries = []
    for h in hosts:
        if not h.is_up:
            continue
        entries.append({
            "ip": h.ip,
            "hostname": h.hostname,
            "os": h.os_guess,
            "roles": list(h.roles),
            "smb_signing": h.smb_signing,
            "null_smb": _has_null_smb(h),
            "access_gained": h.access_gained,
            "access_detail": h.access_detail,
            "ports": [{"port": p.portid, "service": p.service,
                       "product": p.product, "version": p.version}
                      for p in h.open_ports],
            "findings": _host_findings(h),
            "suggested": _suggest_for_host(h),
        })
    return {
        "_recce_bridge": BRIDGE_VERSION,
        "engagement": engagement,
        "generated": generated,
        "hosts": entries,
    }


def _host_priority(entry: dict[str, Any]) -> tuple[int, int]:
    """Sort key for the plan: (best juiciness, -confirmed-finding severity). Lower first."""
    juic = min((r["juiciness"] for r in entry["suggested"]), default=9)
    if entry.get("null_smb"):
        juic -= 1
    sevw = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    best_find = min((sevw.get(f["severity"], 5) for f in entry["findings"]), default=9)
    if best_find <= 1:            # a confirmed critical/high floats a host to the top
        juic -= 2
    return (juic, best_find)


def build_plan_md(bridge: dict[str, Any]) -> str:
    """Human, severity-ranked 'run X on host Y, because ...' plan from the bridge."""
    hosts = sorted(bridge.get("hosts", []), key=_host_priority)
    actionable = [h for h in hosts if h["suggested"] or h["findings"]]
    L: list[str] = []
    L.append(f"# Sköll attack plan — from recce engagement '{bridge.get('engagement','')}'")
    L.append("")
    L.append(f"Generated by `recce skoll-export`{(' · ' + bridge['generated']) if bridge.get('generated') else ''}. "
             f"{len(actionable)} of {len(hosts)} live host(s) have a Sköll route. Work top-down "
             "(0 = exposed-RCE/unauth quick-win). **Authorized scope only.**")
    L.append("")
    L.append("Feed the machine-readable version straight into Sköll's mass triage:")
    L.append("")
    L.append("```bash")
    L.append("python3 access/network/sweep.py triage --recce recce-bridge.json")
    L.append("#   (or classic nmap path:  sweep.py triage --nmap ports.gnmap --nxc smb-null.txt)")
    L.append("```")
    L.append("")
    for h in actionable:
        tag = " [NULL-SESSION]" if h.get("null_smb") else ""
        tag += " [ACCESS]" if h.get("access_gained") else ""
        title = f"{h['ip']}" + (f" ({h['hostname']})" if h["hostname"] else "")
        L.append(f"## {title}{tag}")
        meta = []
        if h.get("os"):
            meta.append(h["os"])
        if h.get("roles"):
            meta.append("roles: " + ", ".join(h["roles"]))
        if h.get("smb_signing"):
            meta.append(f"SMB signing: {h['smb_signing']}")
        if meta:
            L.append("*" + " · ".join(meta) + "*")
            L.append("")
        if h["findings"]:
            L.append("**recce confirmed:**")
            for f in h["findings"]:
                cves = (" — " + ", ".join(f["cves"])) if f["cves"] else ""
                L.append(f"- `{f['severity'].upper()}` {f['title']}{cves}")
            L.append("")
        if h["suggested"]:
            L.append("**Run on this host (best-first):**")
            for r in h["suggested"]:
                L.append(f"- `{r['port']}` {r['label']} → {r['module']}")
            L.append("")
        if h.get("access_detail"):
            L.append(f"> Foothold already recorded by recce: {h['access_detail']}")
            L.append("")
    if not actionable:
        L.append("_(No host exposed a service recce maps to a Sköll generator. "
                 "Run `recce vulns`/`sweep` for deeper coverage.)_")
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------------------
# Sköll -> recce : fold a Sköll findings.json back into recce Vulns.
# --------------------------------------------------------------------------------------

_SEV_MAP = {  # Sköll capitalizes; recce stores lowercase
    "critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info",
}
_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def parse_affected_host(s: str) -> tuple[str, str]:
    """Split Sköll's `affected_host` ('10.0.0.5 (WIN-SQL01)') into (ip, hostname).

    Returns ('', hostname-or-raw) when no IP is present, so a hostname-only finding
    still folds onto a synthesized `skoll:<name>` host rather than being dropped.
    """
    s = (s or "").strip()
    ip = ""
    m = _IPV4.search(s)
    if m:
        try:
            ipaddress.ip_address(m.group(1))
            ip = m.group(1)
        except ValueError:
            ip = ""
    name = ""
    pm = re.search(r"\(([^)]*)\)", s)
    if pm:
        name = pm.group(1).split(",")[0].strip()
    elif not ip:
        name = s
    return ip, name


def _proof_blob(f: dict[str, Any]) -> str:
    """Render a finding's evidence + PoC steps into the Vuln.output text kept in recce."""
    parts: list[str] = []
    if f.get("evidence"):
        parts.append(str(f["evidence"]).strip())
    steps = f.get("steps", []) or []
    if steps:
        parts.append("Proof of concept:")
        for s in steps:
            if isinstance(s, str):
                parts.append(f"  $ {s}")
                continue
            cmd = str(s.get("cmd", "")).rstrip()
            outp = str(s.get("output", "")).rstrip()
            if cmd:
                parts.append(f"  $ {cmd}")
            if outp:
                parts.append("    " + outp.replace("\n", "\n    "))
    if f.get("evidence_source"):
        parts.append(f"[evidence: {f['evidence_source']}]")
    return "\n".join(parts).strip()


def finding_to_vuln(f: dict[str, Any]) -> tuple[str, str, Vuln] | None:
    """Map one Sköll finding -> (ip, hostname, Vuln). None if it has no host at all.

    Uses the enriched `_recce` block (from `gen_report.py --export-recce`) when present
    for accurate severity/CWE/remediation without needing Sköll's KB here; otherwise
    degrades gracefully to the finding's own fields.
    """
    kb = f.get("_recce") or {}
    ip = kb.get("ip") or ""
    hostname = kb.get("hostname") or ""
    if not ip and not hostname:
        ip, hostname = parse_affected_host(f.get("affected_host", ""))
    if not ip and not hostname:
        return None
    vt = f.get("vector_type") or "finding"
    title = f.get("title") or kb.get("name") or vt
    sev = (f.get("severity") or kb.get("severity") or "medium").lower()
    sev = _SEV_MAP.get(sev, "medium")
    cwes = list(kb.get("cwes") or ([kb["cwe"]] if kb.get("cwe") else []))
    ids = list(kb.get("ids") or [])
    refs = f.get("references")
    if refs:
        ids += [r.strip() for r in re.split(r"[,\s]+", str(refs)) if r.strip()]
    ids = list(dict.fromkeys(ids))                       # dedupe, keep order
    port = kb.get("port")
    remediation = kb.get("remediation") or ""
    output = _proof_blob(f)
    v = Vuln(
        ip=ip or f"skoll:{hostname}", port=port, protocol="tcp",
        script_id=f"skoll:{vt}", state="finding", title=title,
        severity=sev, source="skoll", confidence="confirmed",
        ids=ids, cwes=cwes, remediation=remediation, output=output,
    )
    return ip, hostname, v


def findings_to_hosts(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Group a Sköll findings.json into {ip: {hostname, vulns[], access_detail}}.

    Accepts both a raw findings.json and the enriched recce_findings.json. Skips the
    advisory `_valid_vector_types` array and any entry with no resolvable host.
    """
    out: dict[str, dict[str, Any]] = {}
    for f in data.get("findings", []):
        if not isinstance(f, dict):
            continue
        res = finding_to_vuln(f)
        if res is None:
            continue
        ip, hostname, v = res
        key = v.ip                                        # real IP, or 'skoll:<name>'
        bucket = out.setdefault(key, {"ip": ip, "hostname": hostname,
                                      "vulns": [], "titles": set()})
        if not bucket["hostname"] and hostname:
            bucket["hostname"] = hostname
        if v.title not in bucket["titles"]:               # dedupe by title per host
            bucket["titles"].add(v.title)
            bucket["vulns"].append(v)
    return out
