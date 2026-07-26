"""Self-contained HTML report.

One shareable .html file (inline CSS, no external assets - airgapped-safe) that
renders the engagement for a browser/client: an executive summary + severity
rollup, the findings, the synthesised attack path, an AD summary, and a per-host
table. Built from the same data as the workbook; stdlib-only.
"""
from __future__ import annotations

import math
from html import escape

from .models import Host
from . import ad
from . import attackpath as ap
from . import credentials as cr
from . import tracking as tr
from .report_docx import (list_findings, group_findings, cwe_label, _vuln_type,
                          _tools_line)

_SEV = {"critical": "#C00000", "high": "#C15A11", "medium": "#9C7A00",
        "low": "#2E7D32", "info": "#5F6F6E"}
_SEV_BG = {"critical": "#fbe9e9", "high": "#fbf0e7", "medium": "#fbf6e3",
           "low": "#eaf5eb", "info": "#eef1f1"}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]

# How sure recce is that a finding is real. Drives the honesty of the report: a
# "potential" finding (inferred from a version/banner) is never shown as fact.
_CONF = {
    "confirmed": ("Confirmed", "#2E7D32"),
    "likely": ("Likely", "#9C7A00"),
    "": ("Reported", "#5F6F6E"),
    "potential": ("Potential", "#C15A11"),
}

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
.dash{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:16px 0}
@media(max-width:720px){.dash{grid-template-columns:1fr}}
.panel{background:#fff;border:1px solid var(--line);border-radius:10px;padding:16px 18px}
.panel h3{margin:0 0 12px;color:var(--tl2)}
.donutwrap{display:flex;align-items:center;gap:20px;flex-wrap:wrap}
.leg{list-style:none;margin:0;padding:0;font-size:13px;flex:1;min-width:150px}
.leg li{display:flex;align-items:center;gap:8px;margin:6px 0}
.leg .sw{width:12px;height:12px;border-radius:3px;flex:0 0 auto}
.leg .c{margin-left:auto;font-weight:700;font-variant-numeric:tabular-nums}
.hbar{display:flex;align-items:center;gap:10px;margin:7px 0;font-size:13px}
.hbar .lab{width:132px;color:var(--mut);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hbar .track{flex:1;background:#eef1f1;border-radius:6px;height:14px;overflow:hidden}
.hbar .fill{height:100%;border-radius:6px;min-width:2px}
.hbar .v{width:28px;text-align:right;font-weight:700;font-variant-numeric:tabular-nums}
.scorelist{margin-top:4px}
.scorerow{display:flex;align-items:baseline;gap:10px;margin:9px 0;font-size:13px;flex-wrap:wrap}
.scorerow .tag{margin-left:auto}
.basis{font-size:12px;color:var(--mut);margin:6px 0 0}
table.cov{font-size:13px}
table.cov th,table.cov td{text-align:center;padding:6px 8px;white-space:nowrap}
table.cov th:first-child,table.cov td:first-child{text-align:left}
.cov .ok{color:#2E7D32;font-weight:700}
.cov .todo{color:#b7c0be}
.cov .na{color:#cdd5d3}
.legendkey{font-size:12px;color:var(--mut);margin:2px 0 12px}
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
@media print{body{background:#fff}header{background:var(--tl2)!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}.tile,table,.bars,.narr,.panel,.dash{break-inside:avoid}}
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
    confirmed = sum(1 for f in findings if (f.confidence or "").lower() == "confirmed")
    potential = sum(1 for f in findings if (f.confidence or "").lower() == "potential")
    accessed = sum(1 for h in hosts if getattr(h, "access_gained", False))
    dcs = ad.domain_controllers(hosts)
    doms = domains or ad.derive_domains(hosts)
    up = sum(1 for h in hosts if h.is_up)          # only confirmed-up hosts
    tiles = [
        _tile(up, "Hosts up"),
        _tile(open_ports, "Open ports"),
        _tile(len(findings), "Findings"),
        _tile(crit, "High / Critical", alert=crit > 0),
        _tile(confirmed, "Confirmed"),
        _tile(f"{len(doms)} / {len(dcs)}", "Domains / DCs"),
    ]
    if accessed:
        tiles.append(_tile(accessed, "Footholds"))
    if creds:
        tiles.append(_tile(len(creds), "Credentials"))
    out = ['<section><h2>Executive summary</h2>',
           f'<div class="tiles">{"".join(tiles)}</div>']

    # A grounded assessment: state plainly what is proven vs. what still needs a human,
    # so nothing in the report reads as fact that recce did not actually observe.
    if findings:
        bits = [f"recce recorded <b>{len(findings)}</b> distinct finding"
                f"{'s' if len(findings) != 1 else ''} across <b>{up}</b> live "
                f"host{'s' if up != 1 else ''}"]
        bits.append(f"<b>{crit}</b> rated high or critical" if crit
                    else "none rated high or critical")
        if confirmed:
            bits.append(f"<b>{confirmed}</b> confirmed by direct observation")
        assess = [", ".join(bits) + "."]
        if potential:
            assess.append(
                f"<b>{potential}</b> {'is' if potential == 1 else 'are'} marked "
                "<b>potential</b> — inferred from a service's version or banner and "
                "flagged for manual verification, not presented as fact.")
        assess.append("Every finding below lists the exact evidence it is based on; "
                      "recce does not exploit — “confirmed” means the condition was "
                      "observed directly (e.g. an unauthenticated read, or an nmap "
                      "detection script's VULNERABLE verdict).")
        out.append('<div class="narr">'
                   + "".join(f"<p>{p}</p>" for p in assess) + "</div>")

    narr = ap.narrative(hosts)
    if narr:
        out.append('<div class="narr">'
                   + "".join(f"<p>{escape(l)}</p>" for l in narr) + "</div>")
    out.append("</section>")
    return "".join(out)


def _donut(counts):
    """An inline-SVG donut of the severity mix (no xmlns / external refs, so the
    page stays fully self-contained). Center shows the total finding count."""
    total = sum(counts.values())
    r, cx, cy, w = 52, 70, 70, 20
    circ = 2 * math.pi * r
    if total == 0:
        segs = (f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
                f'stroke="#e3e8e7" stroke-width="{w}"/>')
    else:
        segs, offset = "", 0.0
        for s in _SEV_ORDER:
            v = counts[s]
            if not v:
                continue
            seg = v / total * circ
            segs += (f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
                     f'stroke="{_SEV[s]}" stroke-width="{w}" '
                     f'stroke-dasharray="{seg:.2f} {circ - seg:.2f}" '
                     f'stroke-dashoffset="{-offset:.2f}" '
                     f'transform="rotate(-90 {cx} {cy})"/>')
            offset += seg
    center = (f'<text x="{cx}" y="{cy - 1}" text-anchor="middle" font-size="26" '
              f'font-weight="700" fill="#1a2422">{total}</text>'
              f'<text x="{cx}" y="{cy + 16}" text-anchor="middle" font-size="11" '
              f'fill="#5f6f6e">findings</text>')
    return (f'<svg viewBox="0 0 140 140" width="132" height="132" role="img" '
            f'aria-label="Findings by severity">{segs}{center}</svg>')


def _hbars(rows, mx, color_fn):
    """rows = [(label, value)]; render as labelled horizontal bars."""
    mx = max(1, mx)
    out = []
    for label, v in rows:
        pct = v * 100 // mx
        out.append(
            f'<div class="hbar"><div class="lab" title="{escape(label)}">'
            f'{escape(label)}</div><div class="track"><div class="fill" '
            f'style="width:{pct}%;background:{color_fn(label, v)}"></div></div>'
            f'<div class="v">{v}</div></div>')
    return "".join(out)


def _dashboard(hosts):
    """Visual 'at a glance' for a non-technical reader: the severity mix as a donut,
    how many machines carry each level of risk, and the most-affected systems."""
    findings = group_findings(hosts)
    counts = {s: sum(1 for f in findings if f.severity == s) for s in _SEV_ORDER}
    legend = "".join(
        f'<li><span class="sw" style="background:{_SEV[s]}"></span>{s.title()}'
        f'<span class="c">{counts[s]}</span></li>'
        for s in _SEV_ORDER if counts[s] or s in ("critical", "high", "medium"))
    panel_sev = (
        '<div class="panel"><h3>Findings by severity</h3>'
        f'<div class="donutwrap">{_donut(counts)}<ul class="leg">{legend}</ul></div></div>')

    # How many *machines* fall into each worst-severity bucket (info counts as clean).
    up = [h for h in hosts if h.is_up]
    order = ["critical", "high", "medium", "low"]
    buckets = {k: 0 for k in order + ["clean"]}
    for h in up:
        sevs = {v.severity for v in h.vulns}
        buckets[next((s for s in order if s in sevs), "clean")] += 1
    risk_rows = [("Critical", buckets["critical"]), ("High", buckets["high"]),
                 ("Medium", buckets["medium"]), ("Low", buckets["low"]),
                 ("No findings", buckets["clean"])]
    risk_color = {"Critical": _SEV["critical"], "High": _SEV["high"],
                  "Medium": _SEV["medium"], "Low": _SEV["low"],
                  "No findings": "#8a9997"}
    panel_risk = (
        f'<div class="panel"><h3>Machines by risk ({len(up)} live)</h3>'
        + _hbars(risk_rows, max(buckets.values()), lambda l, v: risk_color[l])
        + '</div>')

    out = [f'<section><h2>At a glance</h2><div class="dash">{panel_sev}{panel_risk}</div>']

    # Most-affected systems: hosts ranked by their high + critical finding count.
    scored = sorted(
        ((h, sum(1 for v in h.vulns if v.severity in ("critical", "high")))
         for h in hosts),
        key=lambda t: (-t[1], t[0].ip))
    scored = [(h, n) for h, n in scored if n > 0][:8]
    if scored:
        rows = [(h.ip + (f" {h.hostname}" if h.hostname else ""), n) for h, n in scored]
        out.append(
            '<div class="panel" style="margin-top:16px"><h3>Most-affected systems '
            '(high &amp; critical findings)</h3>'
            + _hbars(rows, scored[0][1], lambda l, v: _SEV["high"]) + '</div>')
    out.append('</section>')
    return "".join(out)


def _conf_badge(confidence):
    label, col = _CONF.get((confidence or "").lower(), _CONF[""])
    return f'<span class="badge" style="background:{col}">{escape(label)}</span>'


def _severity_basis(f):
    """A short, honest 'why this rating' line for one finding, from how it was found."""
    src = f.sources
    sev = f.severity.title()
    if f.cves and ("version-db" in src or "nse" in src):
        return (f"Rated <b>{sev}</b> from the published CVSS score of its CVE"
                f"{'s' if len(f.cves) > 1 else ''} ({escape(', '.join(f.cves[:3]))}).")
    if "probe" in src or "config" in src:
        return (f"Rated <b>{sev}</b> by the impact of the misconfiguration recce "
                "observed directly.")
    if "nse" in src:
        return f"Rated <b>{sev}</b> by the nmap detection script's classification."
    if "cred" in src:
        return f"Rated <b>{sev}</b> by the access it grants, confirmed by recce."
    return f"Rated <b>{sev}</b>."


def _scoring_legend():
    """Explain, up front, what the severity and confidence labels mean — so a
    non-technical reader can trust and interpret everything below."""
    sev = [
        ("critical", "Trivially exploitable with severe impact — e.g. unauthenticated "
                     "remote code execution, or full host / domain compromise.", "CVSS ≥ 9.0"),
        ("high", "A serious weakness with a realistic exploitation path.", "CVSS 7.0–8.9"),
        ("medium", "A meaningful weakness, but harder to exploit or lower impact.", "CVSS 4.0–6.9"),
        ("low", "A minor issue or a hardening gap.", "CVSS < 4.0"),
    ]
    sev_rows = "".join(
        f'<div class="scorerow">{_sev_badge(s)}<span>{escape(meaning)}</span>'
        f'<span class="tag">{basis}</span></div>' for s, meaning, basis in sev)
    conf = [
        ("confirmed", "recce observed the condition directly with a non-intrusive "
                      "check — the evidence is shown on the finding."),
        ("likely", "strong indicators, but not positively proven."),
        ("potential", "inferred from a service's version or banner; not exploited or "
                      "confirmed. Verify before reporting."),
    ]
    conf_rows = "".join(
        f'<div class="scorerow">{_conf_badge(c)}<span>{escape(meaning)}</span></div>'
        for c, meaning in conf)
    return (
        '<section><h2>How findings are scored</h2><div class="dash">'
        '<div class="panel"><h3>Severity — how bad is it</h3>'
        '<p class="basis">CVE-based findings inherit the published CVSS score; '
        'observed misconfigurations are rated by their impact.</p>'
        f'<div class="scorelist">{sev_rows}</div></div>'
        '<div class="panel"><h3>Confidence — how sure are we</h3>'
        f'<div class="scorelist">{conf_rows}</div>'
        '<p class="basis">Nothing here is presented as fact without evidence — every '
        'finding below shows exactly what it was based on.</p></div></div></section>')


def _findings_table(hosts):
    rows = []
    for f in list_findings(hosts, min_severity="info"):
        aff = ", ".join(f["affected"][:6]) + ("…" if len(f["affected"]) > 6 else "")
        cve = ", ".join(f["cves"][:3])
        rows.append(
            f'<tr><td class="mono">{escape(f["id"])}</td><td>{_sev_badge(f["severity"])}</td>'
            f'<td>{_conf_badge(f["confidence"])}</td>'
            f'<td>{escape(f["title"])}</td><td class="mono">{escape(aff)}</td>'
            f'<td class="mono">{escape(cve)}</td></tr>')
    if not rows:
        return '<section><h2>Findings</h2><p class="muted">No findings recorded.</p></section>'
    return ('<section><h2>Findings</h2><table><thead><tr><th>ID</th><th>Severity</th>'
            '<th>Confidence</th><th>Finding</th><th>Affected</th><th>CVE</th></tr>'
            '</thead><tbody>' + "".join(rows) + "</tbody></table></section>")


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
                f'<h3>{_sev_badge(f.severity)} {_conf_badge(f.confidence)} '
                f'{escape(f.title)}</h3>',
                f'<div class="meta">{"".join(meta)}</div>',
                f'<div class="mono muted">Affected: {escape(aff)}</div>',
                f'<div class="basis">{_severity_basis(f)}</div>']
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
    out = ['<section><h2>Attack path <span class="tag">projected</span></h2>',
           '<div class="narr"><p>A <b>prioritised route</b> grounded in recce\'s '
           'confirmed findings: each step\'s precondition was directly observed by '
           'recce (e.g. the exposed service, the confirmed injection), and unverified '
           '"potential" version guesses are excluded. It has <b>not</b> been walked '
           'end-to-end — recce does not exploit, so every step below gives the exact '
           'command to run and how to validate it. Lateral-movement steps are options '
           'that become available once you hold a valid credential.</p></div>']
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


def _ipkey(ip):
    try:
        return tuple(int(o) for o in ip.split("."))
    except (ValueError, AttributeError):
        return (999, 999, 999, 999)


def _cov_cell(host, step, tracking):
    """One coverage cell: done / to-do / not-applicable, mirroring the workbook
    Checklist (operator tick wins, else the tool's auto/derived state)."""
    if not tr.step_applies(host, step):
        return '<td class="na">—</td>'
    key = tr.step_key(step, host.ip)
    done = tracking[key][0] if key in tracking else tr.step_auto(host, step)
    return '<td class="ok">&#10003;</td>' if done else '<td class="todo">&#9744;</td>'


def _progress_checklist(hosts, tracking):
    """A READ-ONLY mirror of the workbook Checklist, so a non-technical reader can see
    per-host progress in a browser. Editing still happens in the spreadsheet - that is
    the one place ticks persist back to recce's datastore."""
    up = [h for h in hosts if h.is_up]
    if not up:
        return ""
    tracking = tracking or {}
    steps = list(tr.STEP_COLUMNS.items())          # [(label, step)]
    by_subnet: dict[str, list] = {}
    for h in up:
        by_subnet.setdefault(h.subnet or "—", []).append(h)

    out = ['<section><h2>Assessment coverage</h2>',
           '<p class="legendkey">A read-only view of the tracking Checklist: '
           '&#10003; done · &#9744; to&nbsp;do · — not&nbsp;applicable. '
           'Update it in <b>enumeration.xlsx</b> — that is where ticks are saved.</p>']
    head = "".join(f'<th>{escape(lab)}</th>' for lab, _ in steps)
    for subnet in sorted(by_subnet, key=_ipkey):
        rows = sorted(by_subnet[subnet], key=lambda x: _ipkey(x.ip))
        reviewed = sum(1 for h in rows
                       if tracking.get(tr.host_key(h.ip), (False, ""))[0])
        body = []
        for h in rows:
            cells = "".join(_cov_cell(h, step, tracking) for _, step in steps)
            rev = ('<td class="ok">&#10003;</td>'
                   if tracking.get(tr.host_key(h.ip), (False, ""))[0]
                   else '<td class="todo">&#9744;</td>')
            name = escape(h.ip + (f" {h.hostname}" if h.hostname else ""))
            body.append(f'<tr><td class="mono">{name}</td>{cells}{rev}</tr>')
        out.append(f'<h3>{escape(subnet)} '
                   f'<span class="muted">— {reviewed}/{len(rows)} reviewed</span></h3>')
        out.append(f'<table class="cov"><thead><tr><th>Host</th>{head}'
                   f'<th>Reviewed</th></tr></thead><tbody>{"".join(body)}'
                   f'</tbody></table>')
    out.append('</section>')
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
               domains=None, credentials=None, generated: str = "",
               tracking=None) -> str:
    """Write a self-contained HTML report. Returns the path."""
    creds = cr.stack(hosts, credentials or [])
    title = title or "Penetration Test Report"
    body = "".join([
        f'<header><div class="wrap"><h1>{escape(title)}</h1>'
        f'<div class="sub">recce engagement report'
        + (f' · {escape(generated)}' if generated else "") + '</div></div></header>',
        '<div class="wrap">',
        _exec_summary(hosts, domains, creds),
        _dashboard(hosts),
        _scoring_legend(),
        _findings_table(hosts),
        _attack_path(hosts),
        _findings_detail(hosts),
        _progress_checklist(hosts, tracking),
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
