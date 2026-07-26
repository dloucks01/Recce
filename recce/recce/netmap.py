"""Architecture / network map from the enumeration.

Turns what recce OBSERVED — hosts, subnets, service roles, AD domains and trusts —
into a self-contained diagram (Mermaid + Graphviz DOT), the same airgap-safe way the
attack path is drawn. It is a *logical* map: recce enumerates each host independently
and does not trace physical routing, VLANs or firewall rules, so the only edges drawn
are relationships it actually saw (a host's subnet, a DC's domain, a domain trust).
Nothing is inferred that wasn't observed.
"""
from __future__ import annotations

import re

from .models import Host
from . import ad
from . import web
from . import db as dbmod
from . import smb

_MAIL_PORTS = {25, 465, 587, 110, 143, 993, 995}
_ROLE_ORDER = ["DC", "DB", "Web", "Mail", "File/SMB", "Workstation", "Host"]
_ROLE_CLASS = {"DC": "dc", "DB": "db", "Web": "web", "Mail": "mail",
               "File/SMB": "file", "Workstation": "ws", "Host": "host"}


def _ipkey(ip):
    try:
        return tuple(int(o) for o in ip.split("."))
    except (ValueError, AttributeError):
        return (999, 999, 999, 999)


def roles_for(host: Host) -> list[str]:
    """Every role tag that applies to a host, from its confirmed open services."""
    ports = host.open_ports
    tags: list[str] = []
    if "Domain Controller" in (host.roles or []):
        tags.append("DC")
    if dbmod.db_ports(host):
        tags.append("DB")
    if any(web.is_web(p) for p in ports):
        tags.append("Web")
    if any(p.portid in _MAIL_PORTS for p in ports):
        tags.append("Mail")
    if "DC" not in tags and any(smb.is_smb(p) for p in ports):
        tags.append("File/SMB")
    if not tags:
        osn = (host.os_name or "").lower()
        if any(w in osn for w in ("windows 10", "windows 11", "windows 7",
                                  "windows 8", "windows xp")):
            tags.append("Workstation")
        else:
            tags.append("Host")
    return tags


def primary_role(host: Host) -> str:
    tags = set(roles_for(host))
    for r in _ROLE_ORDER:
        if r in tags:
            return r
    return "Host"


def summary(hosts: list[Host], domains=None) -> list[str]:
    """A short, grounded description of the architecture, for the report/CLI."""
    up = [h for h in hosts if h.is_up]
    if not up:
        return ["No hosts enumerated yet."]
    subnets = sorted({h.subnet or "unknown" for h in up}, key=_ipkey)
    counts: dict[str, int] = {}
    for h in up:
        counts[primary_role(h)] = counts.get(primary_role(h), 0) + 1
    roles = ", ".join(f"{n}× {r}" for r, n in
                      sorted(counts.items(), key=lambda kv: _ROLE_ORDER.index(kv[0])))
    doms = domains or ad.derive_domains(up)
    lines = [f"{len(up)} host(s) across {len(subnets)} network segment(s): {roles}."]
    if doms:
        dparts = []
        for d in doms:
            dcs = ", ".join(d.dc_ips) if getattr(d, "dc_ips", None) else "no DC seen"
            dparts.append(f"{d.name} (DC: {dcs})")
        lines.append("AD domain(s): " + "; ".join(dparts) + ".")
    return lines


def _label(s: str, n: int = 26) -> str:
    s = re.sub(r"\s+", " ", (s or "").strip())
    # Mermaid node text: keep it quote/bracket-safe.
    s = s.replace('"', "'").replace("[", "(").replace("]", ")")
    return (s[: n - 1] + "…") if len(s) > n else s


def mermaid(hosts: list[Host], domains=None) -> str:
    """A Mermaid diagram: one subgraph per subnet (network segment), role-coloured
    host nodes, plus AD domain nodes with DC-of edges and trust edges. Paste into any
    Mermaid viewer / GitHub / mermaid.live."""
    up = [h for h in hosts if h.is_up]
    if not up:
        return 'flowchart TB\n  empty["No hosts enumerated yet"]\n'
    by_subnet: dict[str, list[Host]] = {}
    for h in up:
        by_subnet.setdefault(h.subnet or "unknown", []).append(h)

    out = ["flowchart TB"]
    nid: dict[str, str] = {}
    i = 0
    for si, subnet in enumerate(sorted(by_subnet, key=_ipkey)):
        rows = sorted(by_subnet[subnet], key=lambda x: _ipkey(x.ip))
        out.append(f'  subgraph seg{si}["{_label(subnet, 22)} '
                   f'({len(rows)} host{"s" if len(rows) != 1 else ""})"]')
        for h in rows:
            node = f"h{i}"
            nid[h.ip] = node
            i += 1
            parts = [_label(h.ip, 18)]
            if h.hostname:
                parts.append(_label(h.hostname, 20))
            parts.append(primary_role(h))
            if h.os_name:
                parts.append(_label(h.os_name, 22))
            out.append(f'    {node}["{"<br/>".join(parts)}"]:::{_ROLE_CLASS[primary_role(h)]}')
        out.append("  end")

    # AD domains: a node per domain, an edge from each in-scope DC to it, and trust
    # edges between domains (all observed, never inferred).
    doms = domains or ad.derive_domains(up)
    dom_node: dict[str, str] = {}
    for di, d in enumerate(doms or []):
        dn = f"dom{di}"
        dom_node[(d.name or "").lower()] = dn
        out.append(f'  {dn}(["AD domain<br/>{_label(d.name, 24)}"]):::domain')
        for ip in getattr(d, "dc_ips", []) or []:
            if ip in nid:
                out.append(f"  {nid[ip]} -->|DC of| {dn}")
    for d in doms or []:
        src = dom_node.get((d.name or "").lower())
        for t in getattr(d, "trusts", []) or []:
            tgt = dom_node.get((t.get("name") or "").lower())
            direction = t.get("direction", "")
            if src and tgt:
                lbl = f"trust {direction}".strip()
                out.append(f"  {src} -.->|{_label(lbl, 18)}| {tgt}")

    out += [
        "  classDef dc fill:#fbe3e3,stroke:#C00000,stroke-width:2px",
        "  classDef db fill:#e7eefb,stroke:#1f4e9c",
        "  classDef web fill:#e8f4ec,stroke:#2E7D32",
        "  classDef mail fill:#fbf3e0,stroke:#9C7A00",
        "  classDef file fill:#eef1f1,stroke:#5f6f6e",
        "  classDef ws fill:#f3eefb,stroke:#6b4fa0",
        "  classDef host fill:#ffffff,stroke:#8a9997",
        "  classDef domain fill:#fff6e6,stroke:#C15A11,stroke-width:2px",
    ]
    return "\n".join(out) + "\n"


# Role palette shared by the SVG renderer (fill, stroke).
_ROLE_COLOR = {
    "DC": ("#fbe3e3", "#C00000"), "DB": ("#e7eefb", "#1f4e9c"),
    "Web": ("#e8f4ec", "#2E7D32"), "Mail": ("#fbf3e0", "#9C7A00"),
    "File/SMB": ("#eef1f1", "#5f6f6e"), "Workstation": ("#f3eefb", "#6b4fa0"),
    "Host": ("#ffffff", "#8a9997"),
}
_DOMAIN_COLOR = ("#fff6e6", "#C15A11")


def _x(s, n=30):
    from html import escape as _e
    s = re.sub(r"\s+", " ", (s or "").strip())
    if len(s) > n:
        s = s[: n - 1] + "…"
    return _e(s)


def svg(hosts: list[Host], domains=None) -> str:
    """A directly-viewable inline SVG of the network map — renders in any browser
    with no tools or JavaScript (and prints to PDF). Subnet columns of role-coloured
    host cards, AD domain nodes below with edges to their DCs, and a legend. For a
    large estate (>50 live hosts) it aggregates each subnet to role counts instead of
    drawing every host, so it stays readable."""
    from html import escape as _e
    up = [h for h in hosts if h.is_up]
    if not up:
        return ('<svg viewBox="0 0 320 60" width="320" height="60" role="img" '
                'aria-label="Network map"><text x="12" y="34" font-size="14" '
                'fill="#5f6f6e">No hosts enumerated yet.</text></svg>')
    by_subnet: dict[str, list[Host]] = {}
    for h in up:
        by_subnet.setdefault(h.subnet or "unknown", []).append(h)
    subnets = sorted(by_subnet, key=_ipkey)
    doms = domains or ad.derive_domains(up)
    aggregate = len(up) > 50

    colW, cardW, cardH, cardGap, colGap = 210, 196, 50, 10, 26
    m, headerH = 18, 30
    x0 = m
    els, dc_anchor = [], {}          # dc_anchor[ip] = (x, y_bottom) of its card

    def card(x, y, fill, stroke, lines, w=cardW, h=cardH):
        out = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="7" '
               f'fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>']
        ty = y + 16
        for i, (txt, bold) in enumerate(lines):
            weight = "700" if bold else "400"
            col = "#1a2422" if i == 0 else "#3a4644"
            out.append(f'<text x="{x + 10}" y="{ty}" font-size="11.5" '
                       f'font-weight="{weight}" fill="{col}">{txt}</text>')
            ty += 14
        return "".join(out)

    max_rows = 0
    for ci, sub in enumerate(subnets):
        rows = sorted(by_subnet[sub], key=lambda z: _ipkey(z.ip))
        x = x0 + ci * (colW + colGap)
        els.append(f'<text x="{x}" y="{m + 18}" font-size="13" font-weight="700" '
                   f'fill="#115e59">{_x(sub, 24)} '
                   f'<tspan fill="#5f6f6e" font-weight="400">'
                   f'({len(rows)})</tspan></text>')
        y = m + headerH
        if aggregate:
            counts: dict[str, int] = {}
            for h in rows:
                counts[primary_role(h)] = counts.get(primary_role(h), 0) + 1
            for role in _ROLE_ORDER:
                if role not in counts:
                    continue
                fill, stroke = _ROLE_COLOR[role]
                els.append(card(x, y, fill, stroke,
                                [(f"{counts[role]}× {_e(role)}", True)], h=32))
                y += 32 + cardGap
            max_rows = max(max_rows, len(counts))
        else:
            for h in rows:
                role = primary_role(h)
                fill, stroke = _ROLE_COLOR[role]
                l1 = _x(h.ip, 22)
                l2 = _x((h.hostname + "  ") if h.hostname else "") + _e(role)
                l3 = _x(h.os_name, 30) if h.os_name else ""
                lines = [(l1, True), (l2, False)] + ([(l3, False)] if l3 else [])
                els.append(card(x, y, fill, stroke, lines))
                if "Domain Controller" in (h.roles or []):
                    dc_anchor[h.ip] = (x + cardW / 2, y + cardH)
                y += cardH + cardGap
            max_rows = max(max_rows, len(rows))

    row_h = (32 + cardGap) if aggregate else (cardH + cardGap)
    dom_y = m + headerH + max_rows * row_h + 24
    dom_anchor = {}
    for di, d in enumerate(doms or []):
        dx = x0 + di * (colW + colGap)
        fill, stroke = _DOMAIN_COLOR
        els.append(f'<rect x="{dx}" y="{dom_y}" width="{cardW}" height="34" rx="17" '
                   f'fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>')
        els.append(f'<text x="{dx + cardW / 2}" y="{dom_y + 21}" text-anchor="middle" '
                   f'font-size="12" font-weight="700" fill="#7a3a0a">AD: '
                   f'{_x(d.name, 22)}</text>')
        dom_anchor[(d.name or "").lower()] = (dx + cardW / 2, dom_y)
        for ip in getattr(d, "dc_ips", []) or []:
            if ip in dc_anchor:
                x1, y1 = dc_anchor[ip]
                els.insert(0, f'<path d="M{x1:.0f},{y1:.0f} L{dx + cardW / 2:.0f},'
                              f'{dom_y:.0f}" stroke="#C15A11" stroke-width="1.4" '
                              f'stroke-dasharray="4 3" fill="none"/>')

    # legend
    leg_y = dom_y + 52
    lx = x0
    els.append(f'<text x="{lx}" y="{leg_y}" font-size="11" fill="#5f6f6e">Role:</text>')
    lx += 42
    for role in _ROLE_ORDER:
        fill, stroke = _ROLE_COLOR[role]
        els.append(f'<rect x="{lx}" y="{leg_y - 10}" width="12" height="12" rx="2" '
                   f'fill="{fill}" stroke="{stroke}"/>')
        els.append(f'<text x="{lx + 17}" y="{leg_y}" font-size="11" '
                   f'fill="#3a4644">{_e(role)}</text>')
        lx += 30 + len(role) * 7

    width = max(x0 + len(subnets) * (colW + colGap), lx + 20,
                x0 + max(1, len(doms or [])) * (colW + colGap))
    height = leg_y + 20
    return (f'<svg viewBox="0 0 {int(width)} {int(height)}" width="{int(width)}" '
            f'height="{int(height)}" role="img" aria-label="Network architecture map" '
            f'font-family="-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif">'
            + "".join(els) + "</svg>")


# AD tier-0 palette (fill, stroke) — distinct from the network-map roles.
_AD_DOMAIN = ("#fff6e6", "#C15A11")     # domain object
_AD_GROUP = ("#fde7ef", "#a01050")      # high-value group (Domain Admins, ...)
_AD_DC = ("#fbe3e3", "#C00000")         # Domain Controller
_AD_USER = ("#e7eefb", "#1f4e9c")       # privileged user
_AD_COMPUTER = ("#eef1f1", "#5f6f6e")   # member computer
_AD_OTHER = ("#ffffff", "#8a9997")


def _ad_color(node: dict):
    if node.get("type") == "Domain":
        return _AD_DOMAIN
    if node.get("dc"):
        return _AD_DC
    if node.get("type") == "Group" and node.get("hv"):
        return _AD_GROUP
    if node.get("type") == "User":
        return _AD_USER
    if node.get("type") == "Computer":
        return _AD_COMPUTER
    return _AD_OTHER


def ad_svg(arch: dict) -> str:
    """A directly-viewable inline SVG of the *tier-0* Active Directory architecture
    that recce derived from a BloodHound/SharpHound collection: the domain(s) on
    top, the high-value groups and Domain Controllers below, and their privileged
    members at the bottom — with MemberOf / control (ACL, DCSync) edges and domain
    trust edges. Renders in any browser and prints to PDF; no tools, no JavaScript.
    `arch` is the dict from bloodhound.architecture()."""
    from html import escape as _e
    nodes = (arch or {}).get("nodes") or {}
    if not nodes:
        return ('<svg viewBox="0 0 360 60" width="360" height="60" role="img" '
                'aria-label="AD architecture"><text x="12" y="34" font-size="14" '
                'fill="#5f6f6e">No BloodHound tier-0 graph available.</text></svg>')
    edges = (arch or {}).get("edges") or []
    trusts = (arch or {}).get("trusts") or []

    tiers: dict[int, list[str]] = {0: [], 1: [], 2: []}
    for sid, n in nodes.items():
        t = n.get("tier", 1)
        tiers.setdefault(t if t in (0, 1, 2) else 2, []).append(sid)
    for t in tiers:
        tiers[t].sort(key=lambda s: (nodes[s].get("label") or s).upper())

    boxW, boxH, hGap, vGap, m = 156, 40, 18, 96, 22
    ncols = max(1, max(len(v) for v in tiers.values()))
    width = m * 2 + ncols * (boxW + hGap) - hGap
    row_y = {0: m + 24, 1: m + 24 + vGap, 2: m + 24 + 2 * vGap}

    pos: dict[str, tuple] = {}
    for t in (0, 1, 2):
        row = tiers.get(t) or []
        if not row:
            continue
        tw = len(row) * (boxW + hGap) - hGap
        startx = max(float(m), (width - tw) / 2)
        for i, sid in enumerate(row):
            pos[sid] = (startx + i * (boxW + hGap) + boxW / 2, row_y[t])

    def anchor(sid, toward_y):
        cx, cy = pos[sid]
        if toward_y < cy:
            return cx, cy - boxH / 2
        if toward_y > cy:
            return cx, cy + boxH / 2
        return cx, cy

    els: list[str] = []
    # Edges first, so the boxes sit on top of the lines.
    for src, label, dst in edges:
        if src not in pos or dst not in pos:
            continue
        x1, y1 = anchor(src, pos[dst][1])
        x2, y2 = anchor(dst, pos[src][1])
        control = label != "MemberOf"
        col = "#C00000" if control else "#9aa8a6"
        dash = ' stroke-dasharray="5 3"' if control else ""
        els.append(f'<path d="M{x1:.0f},{y1:.0f} L{x2:.0f},{y2:.0f}" stroke="{col}" '
                   f'stroke-width="1.4" fill="none"{dash}/>')
        if control:
            mx, my = (x1 + x2) / 2, (y1 + y2) / 2
            els.append(f'<text x="{mx:.0f}" y="{my:.0f}" font-size="9.5" '
                       f'fill="#C00000" text-anchor="middle">{_e(label)}</text>')

    # Trust edges between domain boxes (dashed, orange), matched by label text.
    label_pos: dict[str, tuple] = {}
    for sid in tiers.get(0, []):
        label_pos[(nodes[sid].get("label") or "").upper()] = pos[sid]
    for src_name, direction, dst_name in trusts:
        a = label_pos.get((src_name or "").upper())
        b = label_pos.get((dst_name or "").upper())
        if not a or not b:
            continue
        els.append(f'<path d="M{a[0]:.0f},{a[1] - boxH / 2:.0f} '
                   f'C{a[0]:.0f},{a[1] - boxH:.0f} {b[0]:.0f},{b[1] - boxH:.0f} '
                   f'{b[0]:.0f},{b[1] - boxH / 2:.0f}" stroke="#C15A11" '
                   f'stroke-width="1.3" stroke-dasharray="4 3" fill="none"/>')
        mx = (a[0] + b[0]) / 2
        els.append(f'<text x="{mx:.0f}" y="{a[1] - boxH - 2:.0f}" font-size="9.5" '
                   f'fill="#C15A11" text-anchor="middle">trust '
                   f'{_x(direction, 14)}</text>')

    def box(sid):
        n = nodes[sid]
        cx, cy = pos[sid]
        fill, stroke = _ad_color(n)
        x, y = cx - boxW / 2, cy - boxH / 2
        rx = boxH / 2 if n.get("type") == "Domain" else 7
        tag = "DC" if n.get("dc") else n.get("type", "")
        return (
            f'<rect x="{x:.0f}" y="{y:.0f}" width="{boxW}" height="{boxH}" rx="{rx:.0f}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="1.6"/>'
            f'<text x="{cx:.0f}" y="{cy - 2:.0f}" text-anchor="middle" font-size="11.5" '
            f'font-weight="700" fill="#1a2422">{_x(n.get("label") or sid, 22)}</text>'
            f'<text x="{cx:.0f}" y="{cy + 12:.0f}" text-anchor="middle" font-size="9.5" '
            f'fill="#5f6f6e">{_x(tag, 18)}</text>')

    for sid in pos:
        els.append(box(sid))

    # Legend.
    leg_y = row_y[2] + boxH / 2 + 30
    lx = m
    items = [("Domain", _AD_DOMAIN), ("HV group", _AD_GROUP), ("DC", _AD_DC),
             ("User", _AD_USER), ("Computer", _AD_COMPUTER)]
    for name, (fill, stroke) in items:
        els.append(f'<rect x="{lx}" y="{leg_y - 10:.0f}" width="12" height="12" rx="2" '
                   f'fill="{fill}" stroke="{stroke}"/>')
        els.append(f'<text x="{lx + 17}" y="{leg_y:.0f}" font-size="11" '
                   f'fill="#3a4644">{name}</text>')
        lx += 34 + len(name) * 7
    els.append(f'<text x="{m}" y="{leg_y + 18:.0f}" font-size="10.5" fill="#8a3030">'
               '— control edge (ACL / DCSync)</text>')
    els.append(f'<text x="{m + 220}" y="{leg_y + 18:.0f}" font-size="10.5" '
               f'fill="#9aa8a6">— MemberOf</text>')

    height = leg_y + 30
    if (arch or {}).get("truncated"):
        els.append(f'<text x="{m}" y="{height - 2:.0f}" font-size="10" fill="#5f6f6e">'
                   'Showing the top tier-0 objects (graph truncated for legibility).</text>')
        height += 16
    return (f'<svg viewBox="0 0 {int(width)} {int(height)}" width="{int(width)}" '
            f'height="{int(height)}" role="img" aria-label="AD tier-0 architecture" '
            f'font-family="-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif">'
            + "".join(els) + "</svg>")


def dot(hosts: list[Host], domains=None) -> str:
    """Graphviz DOT of the same map (render: dot -Tpng architecture.dot -o arch.png)."""
    up = [h for h in hosts if h.is_up]
    lines = ["digraph architecture {", "  rankdir=TB; node [shape=box, style=rounded];"]
    if not up:
        return lines[0] + '\n  empty [label="No hosts enumerated yet"];\n}\n'
    by_subnet: dict[str, list[Host]] = {}
    for h in up:
        by_subnet.setdefault(h.subnet or "unknown", []).append(h)
    nid: dict[str, str] = {}
    i = 0
    for si, subnet in enumerate(sorted(by_subnet, key=_ipkey)):
        lines.append(f'  subgraph cluster_{si} {{ label="{subnet}"; style=dashed;')
        for h in sorted(by_subnet[subnet], key=lambda x: _ipkey(x.ip)):
            node = f"h{i}"
            nid[h.ip] = node
            i += 1
            label = "\\n".join(
                [h.ip] + ([h.hostname] if h.hostname else [])
                + [primary_role(h)] + ([h.os_name] if h.os_name else []))
            lines.append(f'    {node} [label="{label}"];')
        lines.append("  }")
    for di, d in enumerate(domains or ad.derive_domains(up) or []):
        dn = f"dom{di}"
        lines.append(f'  {dn} [label="AD domain\\n{d.name}", shape=oval];')
        for ip in getattr(d, "dc_ips", []) or []:
            if ip in nid:
                lines.append(f'  {nid[ip]} -> {dn} [label="DC of"];')
    lines.append("}")
    return "\n".join(lines) + "\n"
