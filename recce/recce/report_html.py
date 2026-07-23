"""Self-contained HTML report.

One shareable .html file (inline CSS, no external assets - airgapped-safe) that
renders the engagement for a browser/client: an executive summary + severity
rollup, the findings, the synthesised attack path, an AD summary, and a per-host
table. Built from the same data as the workbook; stdlib-only.
"""
from __future__ import annotations

from html import escape

from .models import Host
from . import ad
from . import attackpath as ap
from . import credentials as cr
from .report_docx import (list_findings, group_findings, cwe_label, _vuln_type,
                          _tools_line)

_SEV = {"critical": "#C00000", "high": "#C15A11", "medium": "#9C7A00",
        "low": "#2E7D32", "info": "#5F6F6E"}
_SEV_BG = {"critical": "#fbe9e9", "high": "#fbf0e7", "medium": "#fbf6e3",
           "low": "#eaf5eb", "info": "#eef1f1"}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]

_CSS = """
:root{--tl:#0f766e;--tl2:#115e59;--ink:#1a2422;--mut:#5f6f6e;--line:#e3e8e7;--bg:#f7faf9}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
  color:var(--ink);background:var(--bg)}
.wrap{max-width:1080px;margin:0 auto;padding:0 20px 64px}
header{background:linear-gradient(135deg,var(--tl),var(--tl2));color:#fff;padding:32px 0 26px;
  margin-bottom:26px}
header .wrap{padding-bottom:0}
h1{margin:0;font-size:26px;letter-spacing:.2px}
.sub{opacity:.9;margin-top:4px;font-size:14px}
h2{font-size:18px;margin:34px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--line)}
h3{font-size:15px;margin:20px 0 8px;color:var(--tl2)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:18px 0}
.tile{background:#fff;border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.tile .n{font-size:26px;font-weight:700;line-height:1}
.tile .l{font-size:12px;color:var(--mut);margin-top:6px;text-transform:uppercase;letter-spacing:.4px}
.tile.alert .n{color:#C00000}
.narr{background:#fff;border:1px solid var(--line);border-left:4px solid var(--tl);
  border-radius:8px;padding:14px 16px;margin:12px 0}
.narr p{margin:6px 0}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);
  border-radius:8px;overflow:hidden;font-size:14px}
th{background:#eef3f2;text-align:left;padding:9px 11px;font-size:12px;text-transform:uppercase;
  letter-spacing:.4px;color:var(--mut)}
td{padding:9px 11px;border-top:1px solid var(--line);vertical-align:top}
tr:nth-child(even) td{background:#fafcfb}
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:12px;font-weight:700;
  color:#fff}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.pill{display:inline-block;background:#eef3f2;border-radius:6px;padding:1px 7px;margin:1px;font-size:12px}
.bars{background:#fff;border:1px solid var(--line);border-radius:8px;padding:16px}
.bar{display:flex;align-items:center;gap:10px;margin:7px 0}
.bar .lab{width:74px;font-size:13px;color:var(--mut)}
.bar .track{flex:1;background:#eef1f1;border-radius:6px;height:16px;overflow:hidden}
.bar .fill{height:100%;border-radius:6px}
.bar .v{width:34px;text-align:right;font-weight:600;font-size:13px}
.stage{margin:14px 0}
.stage .sh{font-weight:700;color:var(--tl2);margin-bottom:4px}
.step{border-left:3px solid var(--line);padding:4px 0 4px 12px;margin:6px 0}
.step .t{font-weight:600}
.muted{color:var(--mut)}
.fcard{background:#fff;border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:14px 0;border-left:4px solid var(--line)}
.fcard h3{margin:0 0 4px;color:var(--ink);font-size:16px}
.fcard .meta{display:flex;flex-wrap:wrap;gap:6px 14px;margin:8px 0;font-size:13px;color:var(--mut)}
.fcard .meta b{color:var(--ink);font-weight:600}
.fcard .rem{background:#f2f8f7;border-radius:8px;padding:10px 12px;margin:10px 0}
.fcard .rem .h{font-size:12px;text-transform:uppercase;letter-spacing:.4px;color:var(--tl2);font-weight:700;margin-bottom:3px}
.fcard pre{background:#0f1a19;color:#d7e2e0;border-radius:8px;padding:10px 12px;overflow:auto;
  font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.4;margin:8px 0 0;max-height:230px}
.tag{font-size:11px;color:var(--mut);border:1px solid var(--line);border-radius:5px;padding:0 5px;margin-left:6px}
footer{color:var(--mut);font-size:12px;margin-top:40px;text-align:center}
@media print{body{background:#fff}header{background:var(--tl2)!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}.tile,table,.bars,.narr{break-inside:avoid}}
"""


def _tile(n, label, alert=False):
    cls = "tile alert" if alert else "tile"
    return f'<div class="{cls}"><div class="n">{escape(str(n))}</div><div class="l">{escape(label)}</div></div>'


def _sev_badge(sev):
    s = sev.lower()
    return f'<span class="badge" style="background:{_SEV.get(s, "#5F6F6E")}">{escape(sev.upper())}</span>'


def _exec_summary(hosts, domains, creds):
    open_ports = sum(len(h.open_ports) for h in hosts)
    findings = group_findings(hosts)
    crit = sum(1 for f in findings if f.severity in ("critical", "high"))
    dcs = ad.domain_controllers(hosts)
    doms = domains or ad.derive_domains(hosts)
    up = sum(1 for h in hosts if h.is_up)          # only confirmed-up hosts
    tiles = [
        _tile(up, "Hosts up"),
        _tile(open_ports, "Open ports"),
        _tile(len(findings), "Findings"),
        _tile(crit, "High / Critical", alert=crit > 0),
        _tile(f"{len(doms)} / {len(dcs)}", "Domains / DCs"),
    ]
    if creds:
        tiles.append(_tile(len(creds), "Credentials"))
    out = ['<section><h2>Executive summary</h2>',
           f'<div class="tiles">{"".join(tiles)}</div>']
    narr = ap.narrative(hosts)
    if narr:
        out.append('<div class="narr">'
                   + "".join(f"<p>{escape(l)}</p>" for l in narr) + "</div>")
    out.append("</section>")
    return "".join(out)


def _severity_rollup(hosts):
    findings = group_findings(hosts)
    counts = {s: sum(1 for f in findings if f.severity == s) for s in _SEV_ORDER}
    total = max(1, len(findings))
    rows = []
    for s in _SEV_ORDER:
        pct = counts[s] * 100 // total
        rows.append(
            f'<div class="bar"><div class="lab">{s.title()}</div>'
            f'<div class="track"><div class="fill" style="width:{pct}%;'
            f'background:{_SEV[s]}"></div></div><div class="v">{counts[s]}</div></div>')
    return ('<section><h2>Findings by severity</h2>'
            f'<div class="bars">{"".join(rows)}</div></section>')


def _findings_table(hosts):
    rows = []
    for f in list_findings(hosts, min_severity="info"):
        aff = ", ".join(f["affected"][:6]) + ("…" if len(f["affected"]) > 6 else "")
        cve = ", ".join(f["cves"][:3])
        tag = "" if f["real"] else '<span class="tag">potential</span>'
        rows.append(
            f'<tr><td class="mono">{escape(f["id"])}</td><td>{_sev_badge(f["severity"])}</td>'
            f'<td>{escape(f["title"])}{tag}</td><td class="mono">{escape(aff)}</td>'
            f'<td class="mono">{escape(cve)}</td></tr>')
    if not rows:
        return '<section><h2>Findings</h2><p class="muted">No findings recorded.</p></section>'
    return ('<section><h2>Findings</h2><table><thead><tr><th>ID</th><th>Severity</th>'
            '<th>Finding</th><th>Affected</th><th>CVE</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table></section>")


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _findings_detail(hosts):
    """One card per grounded finding: type, CWE/CVE, affected systems, tools,
    remediation and an evidence excerpt - the client-facing detail behind the
    summary table (mirrors the DOCX per-finding section, shareable in one file)."""
    findings = sorted(group_findings(hosts),
                      key=lambda f: (_SEV_RANK.get(f.severity, 5), f.title.lower()))
    if not findings:
        return ""
    cards = ['<section><h2>Finding details</h2>']
    for f in findings:
        vtype, cia = _vuln_type(f.cwes)
        aff = ", ".join((f"{ip}:{port}" if port else ip) + (f" ({hn})" if hn else "")
                        for ip, port, hn in f.affected[:12])
        if len(f.affected) > 12:
            aff += f" (+{len(f.affected) - 12} more)"
        cwes = "; ".join(cwe_label(c) for c in f.cwes)
        cves = ", ".join(f.cves[:8])
        meta = [f'<span><b>Severity:</b> {escape(f.severity.upper())}</span>']
        if vtype:
            meta.append(f'<span><b>Type:</b> {escape(vtype)}</span>')
        if cwes:
            meta.append(f'<span><b>CWE:</b> {escape(cwes)}</span>')
        if cves:
            meta.append(f'<span class="mono"><b>CVE:</b> {escape(cves)}</span>')
        if cia:
            meta.append(f'<span><b>Impacts:</b> {escape(cia)}</span>')
        tools = _tools_line(f)
        if tools:
            meta.append(f'<span><b>Tools:</b> {escape(tools)}</span>')
        border = _SEV.get(f.severity, "#5F6F6E")
        card = [f'<div class="fcard" style="border-left-color:{border}">',
                f'<h3>{_sev_badge(f.severity)} {escape(f.title)}</h3>',
                f'<div class="meta">{"".join(meta)}</div>',
                f'<div class="mono muted">Affected: {escape(aff)}</div>']
        if f.remediation:
            card.append('<div class="rem"><div class="h">Recommendation</div>'
                        f'<div>{escape(f.remediation)}</div></div>')
        for ip, port, out in f.evidence[:2]:
            if not out:
                continue
            loc = f"{ip}:{port}" if port else ip
            excerpt = out if len(out) < 600 else out[:600] + " …"
            card.append(f'<pre>{escape(loc)}\n{escape(excerpt)}</pre>')
        card.append("</div>")
        cards.append("".join(card))
    cards.append("</section>")
    return "".join(cards)


def _attack_path(hosts):
    steps = ap.build(hosts)
    if not steps:
        return ""
    out = ['<section><h2>Attack path</h2>']
    cur = None
    for s in steps:
        if s["stage"] != cur:
            if cur is not None:
                out.append("</div>")
            cur = s["stage"]
            out.append(f'<div class="stage"><div class="sh">{escape(cur)}</div>')
        tgt = s["ip"] + (f" ({s['hostname']})" if s["hostname"] else "")
        out.append(
            f'<div class="step"><div class="t">{escape(s["title"])} '
            f'<span class="muted">— {escape(tgt)}</span></div>'
            f'<div class="mono muted">{escape(s["cmd"])}</div></div>')
    out.append("</div>")
    # Copyable graph source (airgapped-friendly: no external JS required; paste
    # into mermaid.live / GitHub, or `dot -Tpng` the DOT form recce writes).
    out.append(
        '<details class="graph"><summary>Attack-path graph (Mermaid — paste into '
        'mermaid.live or GitHub)</summary>'
        f'<pre class="mermaid mono">{escape(ap.mermaid(hosts, steps))}</pre></details>')
    out.append("</section>")
    return "".join(out)


def _hosts_table(hosts):
    rows = []
    for h in sorted(hosts, key=lambda x: x.ip):
        ports = ", ".join(str(p.portid) for p in sorted(h.open_ports, key=lambda p: p.portid))
        roles = "".join(f'<span class="pill">{escape(r)}</span>' for r in h.roles)
        av = "; ".join(h.defenses)
        rows.append(
            f'<tr><td class="mono">{escape(h.ip)}</td><td>{escape(h.hostname)}</td>'
            f'<td>{escape(h.os_guess)}</td><td>{roles}</td>'
            f'<td class="mono">{escape(ports)}</td><td>{len(h.vulns)}</td>'
            f'<td class="muted">{escape(av)}</td></tr>')
    return ('<section><h2>Hosts</h2><table><thead><tr><th>IP</th><th>Hostname</th>'
            '<th>OS</th><th>Roles</th><th>Open ports</th><th># Vulns</th>'
            '<th>AV / EDR</th></tr></thead><tbody>' + "".join(rows)
            + "</tbody></table></section>")


def build_html(hosts: list[Host], out_path: str, *, title: str = "",
               domains=None, credentials=None, generated: str = "") -> str:
    """Write a self-contained HTML report. Returns the path."""
    creds = cr.stack(hosts, credentials or [])
    title = title or "Penetration Test Report"
    body = "".join([
        f'<header><div class="wrap"><h1>{escape(title)}</h1>'
        f'<div class="sub">recce engagement report'
        + (f' · {escape(generated)}' if generated else "") + '</div></div></header>',
        '<div class="wrap">',
        _exec_summary(hosts, domains, creds),
        _severity_rollup(hosts),
        _findings_table(hosts),
        _attack_path(hosts),
        _findings_detail(hosts),
        _hosts_table(hosts),
        '<footer>Generated by recce · references existing published tooling · '
        'use only within your rules of engagement.</footer>',
        '</div>',
    ])
    html = (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{escape(title)}</title><style>{_CSS}</style></head>'
            f'<body>{body}</body></html>')
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return out_path
