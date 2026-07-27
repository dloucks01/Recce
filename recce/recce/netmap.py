"""Architecture / network map from the enumeration.

Turns what recce OBSERVED — hosts, subnets, service roles, AD domains and trusts —
into a directly-viewable, self-contained **SVG** (renders in any browser, no tools or
JavaScript, prints to PDF — airgap-native). It is a *logical* map: recce enumerates each
host independently and does not trace physical routing, VLANs or firewall rules, so the
only edges drawn are relationships it actually saw (a host's subnet, a DC's domain, a
domain trust). Nothing is inferred that wasn't observed.
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


def _ipkey(ip):
    try:
        return tuple(int(o) for o in ip.split("."))
    except (ValueError, AttributeError):
        return (999, 999, 999, 999)


_CLIENT_OS = ("windows 10", "windows 11", "windows 7", "windows 8",
              "windows xp", "windows vista")


def roles_for(host: Host) -> list[str]:
    """Every role tag that applies to a host, from its confirmed open services."""
    ports = host.open_ports
    is_client = any(w in (host.os_name or "").lower() for w in _CLIENT_OS)
    tags: list[str] = []
    if "Domain Controller" in (host.roles or []):
        tags.append("DC")
    if dbmod.db_ports(host):
        tags.append("DB")
    if any(web.is_web(p) for p in ports):
        tags.append("Web")
    if any(p.portid in _MAIL_PORTS for p in ports):
        tags.append("Mail")
    # SMB on a *server* OS is a File/SMB role; on a client OS it is just ordinary
    # Windows workstation sharing (445 is open on every domain-joined workstation),
    # so a plain client reads as a Workstation, not a file server — otherwise every
    # workstation in the estate is mislabelled File/SMB.
    if "DC" not in tags and not is_client and any(smb.is_smb(p) for p in ports):
        tags.append("File/SMB")
    if not tags:
        tags.append("Workstation" if is_client else "Host")
    return tags


def primary_role(host: Host) -> str:
    tags = set(roles_for(host))
    for r in _ROLE_ORDER:
        if r in tags:
            return r
    return "Host"


# --- enrichment from SharpHound / other findings --------------------------------

def ad_dc_names(ad) -> set:
    """Short, upper-cased Domain Controller names from a BloodHound analysis blob
    (the tier-0 architecture). Used to *confirm* which enumerated hosts are DCs from
    AD ground-truth — a DC that only had 445 open still gets marked."""
    arch = (ad or {}).get("architecture") or {} if isinstance(ad, dict) else {}
    out = set()
    for n in (arch.get("nodes") or {}).values():
        if n.get("dc") and n.get("label"):
            out.add(str(n["label"]).split(".")[0].upper())
    return out


def _host_short(host: Host) -> str:
    hn = host.hostname or ""
    return hn.split(".")[0].upper() if hn else ""


def role_with_ad(host: Host, dc_names: set) -> str:
    """Primary role, but promoted to DC when SharpHound says this host is a DC."""
    if dc_names and _host_short(host) in dc_names:
        return "DC"
    return primary_role(host)


_SEV_ORDER = ["critical", "high", "medium", "low"]


def worst_severity(host: Host) -> str:
    """Highest severity among the host's *confirmed* vulns (excludes unverified
    'potential' version guesses), or '' if none. Grounds the map's risk overlay."""
    best = ""
    for v in getattr(host, "vulns", []) or []:
        if getattr(v, "confidence", "") == "potential":
            continue
        sev = (getattr(v, "severity", "") or "").lower()
        if sev in _SEV_ORDER and (best == "" or
                                  _SEV_ORDER.index(sev) < _SEV_ORDER.index(best)):
            best = sev
    return best


def has_access(host: Host) -> bool:
    return bool(getattr(host, "access_gained", False))


def real_hostname(host: Host) -> str:
    """The host's DNS name only when it ADDS information — '' when it's empty or just
    the IP re-punctuated (e.g. '10-0-10-10'), so a tile never prints the IP twice."""
    hn = (host.hostname or "").strip()
    if not hn or hn == host.ip:
        return ""
    if re.sub(r"\D", "", hn) == re.sub(r"\D", "", host.ip or "") and re.sub(r"\D", "", hn):
        return ""                                  # same digits as the IP -> IP-derived
    return hn


def os_short(host: Host) -> str:
    """A compact OS label for a tile (no accuracy %), '' if unknown."""
    return (host.os_name or "").strip()


def summary(hosts: list[Host], domains=None, ad_data=None) -> list[str]:
    """A short, grounded description of the architecture, for the report/CLI."""
    up = [h for h in hosts if h.is_up]
    if not up:
        return ["No hosts enumerated yet."]
    dc_names = ad_dc_names(ad_data)
    subnets = sorted({h.subnet or "unknown" for h in up}, key=_ipkey)
    counts: dict[str, int] = {}
    for h in up:
        r = role_with_ad(h, dc_names)
        counts[r] = counts.get(r, 0) + 1
    roles = ", ".join(f"{n}× {r}" for r, n in
                      sorted(counts.items(), key=lambda kv: _ROLE_ORDER.index(kv[0])))
    doms = domains or ad.derive_domains(up)
    lines = [f"{len(up)} host(s) across {len(subnets)} network segment(s): {roles}."]
    # Status overlay from findings: what we own and where the risk is.
    accessed = [h for h in up if has_access(h)]
    risky = [h for h in up if worst_severity(h) in ("critical", "high")]
    status = []
    if accessed:
        status.append(f"{len(accessed)} with confirmed access")
    if risky:
        status.append(f"{len(risky)} with critical/high findings")
    if status:
        lines.append("Status: " + ", ".join(status) + ".")
    if doms:
        dparts = []
        for d in doms:
            dcs = ", ".join(d.dc_ips) if getattr(d, "dc_ips", None) else "no DC seen"
            dparts.append(f"{d.name} (DC: {dcs})")
        lines.append("AD domain(s): " + "; ".join(dparts) + ".")
    if dc_names:
        confirmed = sorted({_host_short(h) for h in up if _host_short(h) in dc_names})
        if confirmed:
            lines.append("AD-confirmed Domain Controller(s) from BloodHound: "
                         + ", ".join(confirmed) + ".")
    return lines


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


_SEV_DOT = {"critical": "#C00000", "high": "#E8863D"}
_ACCESS_STROKE = "#2E7D32"        # green outline for a host we hold access to


def svg(hosts: list[Host], domains=None, ad_data=None, aggregate=None) -> str:
    """A directly-viewable inline SVG of the network map — renders in any browser
    with no tools or JavaScript (and prints to PDF). Subnet columns of role-coloured
    host cards, AD domain nodes below with edges to their DCs, and a legend. Enriched
    from other findings: hosts recce **gained access** to get a green outline + ✓, and
    each card carries a **risk dot** for its worst confirmed finding; SharpHound
    ground-truth **confirms Domain Controllers** (a DC that only had 445 open is still
    marked).

    `aggregate`: None (default) auto-picks — a large estate (>50 live hosts) collapses
    each subnet to role counts so it stays readable; True/False force the aggregated
    overview or the full per-host map regardless of size."""
    from html import escape as _e
    up = [h for h in hosts if h.is_up]
    if not up:
        return ('<svg viewBox="0 0 320 60" width="320" height="60" role="img" '
                'aria-label="Network map"><text x="12" y="34" font-size="14" '
                'fill="#5f6f6e">No hosts enumerated yet.</text></svg>')
    dc_names = ad_dc_names(ad_data)
    by_subnet: dict[str, list[Host]] = {}
    for h in up:
        by_subnet.setdefault(h.subnet or "unknown", []).append(h)
    subnets = sorted(by_subnet, key=_ipkey)
    doms = domains or ad.derive_domains(up)
    aggregate = (len(up) > 50) if aggregate is None else aggregate
    any_access = any(has_access(h) for h in up)
    any_risk = any(worst_severity(h) in _SEV_DOT for h in up)

    colW, cardW, cardH, cardGap, colGap = 210, 196, 80, 10, 26
    m, headerH = 18, 30
    x0 = m
    els, dc_anchor = [], {}          # dc_anchor[ip] = (x, y_bottom) of its card

    def card(x, y, fill, stroke, lines, w=cardW, h=cardH, sw=1.5):
        out = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="7" '
               f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>']
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
                   f'fill="#115e59">{_x(sub, 20)} '
                   f'<tspan fill="#5f6f6e" font-weight="400">'
                   f'({len(rows)})</tspan></text>')
        owned = sum(1 for h in rows if has_access(h))
        if owned:
            # Right-aligned at the column edge so it never overlaps the subnet label.
            els.append(f'<text x="{x + cardW}" y="{m + 18}" text-anchor="end" '
                       f'font-size="11" font-weight="700" fill="{_ACCESS_STROKE}">'
                       f'✓ {owned} owned</text>')
        y = m + headerH
        if aggregate:
            counts: dict[str, int] = {}
            for h in rows:
                counts[role_with_ad(h, dc_names)] = \
                    counts.get(role_with_ad(h, dc_names), 0) + 1
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
                role = role_with_ad(h, dc_names)
                fill, stroke = _ROLE_COLOR[role]
                accessed = has_access(h)
                cxm = x + cardW / 2
                # Vertical tile: device icon on top, then IP, then (real) hostname, then
                # role · OS. Access = a bold border in the role colour.
                els.append(f'<rect x="{x}" y="{y}" width="{cardW}" height="{cardH}" rx="7" '
                           f'fill="{fill}" stroke="{stroke}" '
                           f'stroke-width="{3 if accessed else 1.5}"/>')
                els.append(glyph(role_kind(role), cxm - 9, y + 7, 18, stroke))
                hn = real_hostname(h)
                osn = os_short(h)
                ty = y + 40
                els.append(f'<text x="{cxm:.0f}" y="{ty}" text-anchor="middle" '
                           f'font-size="12" font-weight="700" fill="#1a2422">'
                           f'{_x(h.ip, 22)}</text>')
                if hn:
                    ty += 15
                    els.append(f'<text x="{cxm:.0f}" y="{ty}" text-anchor="middle" '
                               f'font-size="10.5" fill="#1a2422">{_x(hn, 24)}</text>')
                ty += 15
                rl = role + (f" · {osn}" if osn else "")
                els.append(f'<text x="{cxm:.0f}" y="{ty}" text-anchor="middle" '
                           f'font-size="10" fill="#3a4644">{_x(rl, 30)}</text>')
                # Overlays (top-right, white-ringed): risk dot then a ✓ when owned.
                bx = x + cardW - 12
                sev = worst_severity(h)
                if sev in _SEV_DOT:
                    els.append(f'<circle cx="{bx:.0f}" cy="{y + 13}" r="5.5" '
                               f'fill="{_SEV_DOT[sev]}" stroke="#fff" stroke-width="1"/>')
                    bx -= 18
                if accessed:
                    els.append(f'<circle cx="{bx:.0f}" cy="{y + 13}" r="7.5" '
                               f'fill="{_ACCESS_STROKE}" stroke="#fff" stroke-width="1"/>')
                    els.append(f'<text x="{bx:.0f}" y="{y + 17}" text-anchor="middle" '
                               f'font-size="10" font-weight="700" fill="#fff">✓</text>')
                if role == "DC":
                    dc_anchor[h.ip] = (cxm, y + cardH)
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

    # Overlay keys (only shown when they apply, so the legend stays honest).
    leg2_y = leg_y + 20
    lx2 = x0
    if any_access:
        els.append(f'<circle cx="{lx2 + 6}" cy="{leg2_y - 4}" r="7" '
                   f'fill="{_ACCESS_STROKE}"/>')
        els.append(f'<text x="{lx2 + 6}" y="{leg2_y}" text-anchor="middle" '
                   f'font-size="10" font-weight="700" fill="#fff">✓</text>')
        els.append(f'<text x="{lx2 + 18}" y="{leg2_y}" font-size="11" '
                   f'fill="#3a4644">access confirmed (bold border + ✓)</text>')
        lx2 += 260
    if any_risk:
        els.append(f'<circle cx="{lx2 + 6}" cy="{leg2_y - 4}" r="5.5" fill="#C00000"/>')
        els.append(f'<text x="{lx2 + 16}" y="{leg2_y}" font-size="11" '
                   f'fill="#3a4644">critical</text>')
        lx2 += 82
        els.append(f'<circle cx="{lx2 + 6}" cy="{leg2_y - 4}" r="5.5" fill="#E8863D"/>')
        els.append(f'<text x="{lx2 + 16}" y="{leg2_y}" font-size="11" '
                   f'fill="#3a4644">high finding</text>')
        lx2 += 110

    width = max(x0 + len(subnets) * (colW + colGap), lx + 20, lx2 + 20,
                x0 + max(1, len(doms or [])) * (colW + colGap))
    height = (leg2_y if (any_access or any_risk) else leg_y) + 20
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


def ad_svg(arch: dict, owned_labels=None) -> str:
    """A directly-viewable inline SVG of the *tier-0* Active Directory architecture
    that recce derived from a BloodHound/SharpHound collection: the domain(s) on
    top, the high-value groups and Domain Controllers below, and their privileged
    members at the bottom — with MemberOf / control (ACL, DCSync) edges and domain
    trust edges. Renders in any browser and prints to PDF; no tools, no JavaScript.
    `arch` is the dict from bloodhound.architecture().

    Enriched like the network map: a tier-0 object recce **already holds** (its label
    is in `owned_labels` — usernames from captured credentials, or a DC we accessed)
    gets a bold border + ✓; a node that is the **direct target of a control edge**
    (DCSync = critical, other ACL = high) gets a risk dot."""
    from html import escape as _e
    owned = {str(x).upper() for x in (owned_labels or set())}
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
    # Domain trust arcs are drawn ABOVE the tier-0 row; reserve headroom when any
    # exist so the arc + "trust" label don't clip against the top of the viewBox.
    top_pad = 26 if trusts else 0
    y0 = m + 24 + top_pad
    row_y = {0: y0, 1: y0 + vGap, 2: y0 + 2 * vGap}

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

    # Per-node risk from incoming control edges: DCSync = critical, other ACL = high.
    # Only count edges whose target is actually drawn (in `pos`) so the risk legend
    # key never appears without a matching dot on the page.
    node_risk: dict[str, str] = {}
    for src, label, dst in edges:
        if label == "MemberOf" or dst not in pos:
            continue
        sev = "critical" if label == "DCSync" else "high"
        if node_risk.get(dst) != "critical":
            node_risk[dst] = sev
    any_owned = any((nodes[s].get("label") or "").upper() in owned for s in pos)
    any_risk = bool(node_risk)

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
        held = (n.get("label") or "").upper() in owned
        out = [
            f'<rect x="{x:.0f}" y="{y:.0f}" width="{boxW}" height="{boxH}" rx="{rx:.0f}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="{3 if held else 1.6}"/>'
            f'<text x="{cx:.0f}" y="{cy - 2:.0f}" text-anchor="middle" font-size="11.5" '
            f'font-weight="700" fill="#1a2422">{_x(n.get("label") or sid, 17)}</text>'
            f'<text x="{cx:.0f}" y="{cy + 12:.0f}" text-anchor="middle" font-size="9.5" '
            f'fill="#5f6f6e">{_x(tag, 18)}</text>']
        # Overlays (top-right): risk dot for the worst incoming control edge, then a
        # ✓ when recce already holds this principal.
        bx = x + boxW - 9
        sev = node_risk.get(sid)
        if sev in _SEV_DOT:
            out.append(f'<circle cx="{bx:.0f}" cy="{y + 9:.0f}" r="5.5" '
                       f'fill="{_SEV_DOT[sev]}" stroke="#fff" stroke-width="1"/>')
            bx -= 17
        if held:
            out.append(f'<circle cx="{bx:.0f}" cy="{y + 9:.0f}" r="7" '
                       f'fill="{_ACCESS_STROKE}" stroke="#fff" stroke-width="1"/>')
            out.append(f'<text x="{bx:.0f}" y="{y + 13:.0f}" text-anchor="middle" '
                       f'font-size="10" font-weight="700" fill="#fff">✓</text>')
        return "".join(out)

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
    # Overlay keys, only when they apply (keeps the legend honest).
    if any_owned or any_risk:
        oy = leg_y + 36
        ox = m
        if any_owned:
            els.append(f'<circle cx="{ox + 6}" cy="{oy - 4:.0f}" r="7" '
                       f'fill="{_ACCESS_STROKE}" stroke="#fff" stroke-width="1"/>')
            els.append(f'<text x="{ox + 6}" y="{oy:.0f}" text-anchor="middle" '
                       f'font-size="10" font-weight="700" fill="#fff">✓</text>')
            els.append(f'<text x="{ox + 18}" y="{oy:.0f}" font-size="10.5" '
                       f'fill="#3a4644">already held (bold border + ✓)</text>')
            ox += 240
        if any_risk:
            els.append(f'<circle cx="{ox + 6}" cy="{oy - 4:.0f}" r="5.5" fill="#C00000" '
                       'stroke="#fff" stroke-width="1"/>')
            els.append(f'<text x="{ox + 16}" y="{oy:.0f}" font-size="10.5" '
                       f'fill="#3a4644">directly seizable (DCSync=critical, ACL=high)'
                       '</text>')
        height += 24
    if (arch or {}).get("truncated"):
        els.append(f'<text x="{m}" y="{height - 2:.0f}" font-size="10" fill="#5f6f6e">'
                   'Showing the top tier-0 objects (graph truncated for legibility).</text>')
        height += 16
    return (f'<svg viewBox="0 0 {int(width)} {int(height)}" width="{int(width)}" '
            f'height="{int(height)}" role="img" aria-label="AD tier-0 architecture" '
            f'font-family="-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif">'
            + "".join(els) + "</svg>")


# --- tiered lateral / reachability view -----------------------------------------

# Role -> trust tier. Tier 0 = Domain Controllers, tier 1 = servers, tier 2 = clients.
_TIER_OF = {"DC": 0, "DB": 1, "Web": 1, "Mail": 1, "File/SMB": 1,
            "Workstation": 2, "Host": 2}
_TIER_LABEL = {0: "Tier 0 · Domain Controllers", 1: "Tier 1 · Servers",
               2: "Tier 2 · Workstations & hosts"}
# Remote-auth protocols an attacker pivots over once holding a credential/hash. This is
# the *credentialed pivot surface* recce can justify from open ports — NOT a claim that
# any two hosts can route to each other (recce never tests host-to-host reachability).
_REACH = [("SMB", (445, 139)), ("WinRM", (5985, 5986)), ("RDP", (3389,)),
          ("SSH", (22,)), ("MSSQL", (1433,))]


def reach_counts(hosts: list[Host]) -> list[tuple]:
    """[(proto, host-count)] for the remote-auth pivot surface, present protocols only."""
    up = [h for h in hosts if h.is_up]
    out = []
    for name, ports in _REACH:
        n = sum(1 for h in up if {p.portid for p in h.open_ports} & set(ports))
        if n:
            out.append((name, n))
    return out


def tiered_svg(hosts: list[Host], domains=None, ad_data=None) -> str:
    """A directly-viewable inline SVG of the estate as trust tiers — Domain Controllers
    (tier 0) above servers (tier 1) above workstations/hosts (tier 2) — with the
    credentialed lateral-movement surface overlaid.

    Honest by construction: recce enumerates each host independently and does NOT test
    which hosts can route to which. So the tiers are a *logical* grouping by role, the
    upward arrows show the direction an attacker escalates (client → server → DC), and
    the pivot legend lists the services that accept remote authentication (how you move
    once you hold a credential) — none of it asserts physical/firewall reachability."""
    from html import escape as _e
    up = [h for h in hosts if h.is_up]
    if not up:
        return ('<svg viewBox="0 0 340 60" width="340" height="60" role="img" '
                'aria-label="Tiered network map"><text x="12" y="34" font-size="14" '
                'fill="#5f6f6e">No hosts enumerated yet.</text></svg>')
    dc_names = ad_dc_names(ad_data)
    tiers: dict[int, dict[str, list]] = {0: {}, 1: {}, 2: {}}
    for h in up:
        role = role_with_ad(h, dc_names)
        t = _TIER_OF.get(role, 2)
        cell = tiers[t].setdefault(role, [0, 0])
        cell[0] += 1
        if has_access(h):
            cell[1] += 1
    doms = domains or ad.derive_domains(up)
    reach = reach_counts(up)
    footholds = sum(1 for h in up if has_access(h))

    W, m = 900, 18
    bandH, gap, top = 108, 52, 46
    chipW, chipH, chipGap = 138, 42, 12
    band_y = {t: top + t * (bandH + gap) for t in (0, 1, 2)}
    H = band_y[2] + bandH + 74               # room for the pivot legend + caption
    cx = W / 2
    els = [
        '<defs><marker id="tup" markerWidth="10" markerHeight="10" refX="5" refY="8" '
        'orient="auto"><path d="M5,0 L10,8 L0,8 Z" fill="#6b4fa0"/></marker></defs>',
        f'<rect x="0" y="0" width="{W}" height="{H}" fill="#ffffff"/>',
        f'<text x="{m}" y="26" font-size="15" font-weight="700" fill="#115e59">'
        'Tiered view — DC → servers → workstations</text>',
    ]

    # upward escalation arrows first (behind the bands), client -> server -> DC
    for t in (2, 1):
        y1 = band_y[t]
        y2 = band_y[t - 1] + bandH
        els.append(f'<line x1="{cx:.0f}" y1="{y1}" x2="{cx:.0f}" y2="{y2 + 4}" '
                   f'stroke="#b08cc0" stroke-width="2" stroke-dasharray="5 4" '
                   f'marker-end="url(#tup)"/>')
        els.append(f'<rect x="{cx + 8:.0f}" y="{(y1 + y2) / 2 - 9:.0f}" width="132" '
                   f'height="18" rx="9" fill="#f3eefb" stroke="#6b4fa0"/>')
        els.append(f'<text x="{cx + 74:.0f}" y="{(y1 + y2) / 2 + 4:.0f}" '
                   f'text-anchor="middle" font-size="10.5" fill="#6b4fa0">'
                   f'lateral / escalate</text>')

    for t in (0, 1, 2):
        y = band_y[t]
        pop = sum(c[0] for c in tiers[t].values())
        els.append(f'<rect x="{m}" y="{y}" width="{W - 2 * m}" height="{bandH}" rx="10" '
                   f'fill="#fafcfb" stroke="#e3e8e7"/>')
        els.append(f'<text x="{m + 14}" y="{y + 22}" font-size="12.5" font-weight="700" '
                   f'fill="#115e59">{_e(_TIER_LABEL[t])} '
                   f'<tspan fill="#5f6f6e" font-weight="400">({pop} host'
                   f'{"s" if pop != 1 else ""})</tspan></text>')
        if not tiers[t]:
            els.append(f'<text x="{m + 14}" y="{y + 64}" font-size="11.5" '
                       f'fill="#b7c0be">— none observed —</text>')
        cxp = m + 14
        for role in _ROLE_ORDER:
            if role not in tiers[t]:
                continue
            cnt, acc = tiers[t][role]
            fill, stroke = _ROLE_COLOR.get(role, ("#ffffff", "#8a9997"))
            cy = y + 34
            els.append(f'<rect x="{cxp}" y="{cy}" width="{chipW}" height="{chipH}" rx="8" '
                       f'fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>')
            els.append(glyph(role_kind(role), cxp + 8, cy + chipH / 2 - 8, 16, stroke))
            els.append(f'<text x="{cxp + 30}" y="{cy + 18}" font-size="12" '
                       f'font-weight="700" fill="#1a2422">{_e(role)} ×{cnt}</text>')
            sub = f"{acc} owned ✓" if acc else "&#8203;"
            els.append(f'<text x="{cxp + 30}" y="{cy + 33}" font-size="10.5" '
                       f'fill="#2E7D32">{sub}</text>')
            cxp += chipW + chipGap
        # AD domain pill in the tier-0 band, linked to it
        if t == 0 and doms:
            dn = ", ".join(d.name for d in doms if d.name)[:40] or "AD"
            dx = W - m - 210
            els.append(f'<rect x="{dx}" y="{y + 30}" width="196" height="46" rx="10" '
                       f'fill="{_DOMAIN_COLOR[0]}" stroke="{_DOMAIN_COLOR[1]}" '
                       f'stroke-width="2"/>')
            els.append(f'<text x="{dx + 12}" y="{y + 50}" font-size="11.5" '
                       f'font-weight="700" fill="#1a2422">AD domain</text>')
            els.append(f'<text x="{dx + 12}" y="{y + 67}" font-size="11" '
                       f'fill="#3a4644">{_e(dn)}</text>')

    # pivot legend
    ly = band_y[2] + bandH + 24
    parts = " · ".join(f"{p} ×{n}" for p, n in reach) or "none observed"
    els.append(f'<text x="{m}" y="{ly}" font-size="12" font-weight="700" '
               f'fill="#1a2422">Credentialed pivot surface: '
               f'<tspan font-weight="400">{_e(parts)}</tspan>'
               f'<tspan fill="#2E7D32">   ·   {footholds} foothold'
               f'{"s" if footholds != 1 else ""} held</tspan></text>')
    els.append(f'<text x="{m}" y="{ly + 20}" font-size="10.5" fill="#5f6f6e">'
               'Logical view: tiers group hosts by role and the arrows show the '
               'escalation direction. The pivot surface lists services that accept '
               'remote auth — recce does not test host-to-host network reachability.'
               '</text>')

    return (f'<svg viewBox="0 0 {W} {int(H)}" width="{W}" height="{int(H)}" role="img" '
            f'aria-label="Tiered network map" '
            f'font-family="system-ui,Segoe UI,Arial,sans-serif">'
            + "".join(els) + "</svg>")


# --- role glyphs (small inline-SVG computer icons) -------------------------------
# Three device classes, stroke-drawn so they read at ~18px and print cleanly:
#   dc          - a server tower with a star (the domain's authority)
#   server      - a rack unit with drive slots
#   workstation - a desktop monitor on a stand
def role_kind(role: str) -> str:
    if role == "DC":
        return "dc"
    if role in ("DB", "Web", "Mail", "File/SMB"):
        return "server"
    return "workstation"                      # Workstation, Host


def glyph(kind: str, x: float, y: float, s: float = 18, color: str = "#3a4644") -> str:
    """An inline-SVG device icon of size s at top-left (x, y). No fills that fight the
    card colour — thin strokes only, plus one accent for the DC star."""
    u = s / 18.0
    def P(*pts):
        return " ".join(f"{x + a * u:.1f},{y + b * u:.1f}" for a, b in pts)
    st = f'stroke="{color}" stroke-width="1.4" fill="none" ' \
         'stroke-linejoin="round" stroke-linecap="round"'
    if kind == "workstation":
        return (f'<g {st}>'
                f'<rect x="{x + 1 * u:.1f}" y="{y + 1 * u:.1f}" width="{16 * u:.1f}" '
                f'height="{11 * u:.1f}" rx="{1.5 * u:.1f}"/>'
                f'<line x1="{x + 6 * u:.1f}" y1="{y + 12 * u:.1f}" x2="{x + 6 * u:.1f}" '
                f'y2="{y + 15 * u:.1f}"/>'
                f'<line x1="{x + 12 * u:.1f}" y1="{y + 12 * u:.1f}" x2="{x + 12 * u:.1f}" '
                f'y2="{y + 15 * u:.1f}"/>'
                f'<line x1="{x + 4 * u:.1f}" y1="{y + 15.5 * u:.1f}" x2="{x + 14 * u:.1f}" '
                f'y2="{y + 15.5 * u:.1f}"/></g>')
    # dc + server share the tower body; dc adds a star accent
    body = (f'<rect x="{x + 3 * u:.1f}" y="{y + 1 * u:.1f}" width="{12 * u:.1f}" '
            f'height="{16 * u:.1f}" rx="{1.5 * u:.1f}"/>'
            f'<line x1="{x + 5.5 * u:.1f}" y1="{y + 4.5 * u:.1f}" x2="{x + 12.5 * u:.1f}" '
            f'y2="{y + 4.5 * u:.1f}"/>'
            f'<line x1="{x + 5.5 * u:.1f}" y1="{y + 7.5 * u:.1f}" x2="{x + 12.5 * u:.1f}" '
            f'y2="{y + 7.5 * u:.1f}"/>'
            f'<circle cx="{x + 6.2 * u:.1f}" cy="{y + 13 * u:.1f}" r="{1 * u:.1f}"/>')
    if kind == "dc":
        star = (f'<path d="M{x + 9 * u:.1f},{y + 9.5 * u:.1f} l{1.1 * u:.1f},{2.2 * u:.1f} '
                f'l{2.4 * u:.1f},{0.3 * u:.1f} l{-1.8 * u:.1f},{1.7 * u:.1f} '
                f'l{0.5 * u:.1f},{2.4 * u:.1f} l{-2.2 * u:.1f},{-1.2 * u:.1f} '
                f'l{-2.2 * u:.1f},{1.2 * u:.1f} l{0.5 * u:.1f},{-2.4 * u:.1f} '
                f'l{-1.8 * u:.1f},{-1.7 * u:.1f} l{2.4 * u:.1f},{-0.3 * u:.1f} z" '
                f'fill="{color}" stroke="none"/>')
        return f'<g {st}>{body}</g>{star}'
    return f'<g {st}>{body}</g>'


def glyph_legend(x: float, y: float, color: str = "#5f6f6e") -> str:
    """A one-row key for the three device glyphs, starting at (x, y)."""
    out, cx = [], x
    for kind, label in (("dc", "Domain Controller"), ("server", "Server"),
                        ("workstation", "Workstation / host")):
        out.append(glyph(kind, cx, y, 16, color))
        out.append(f'<text x="{cx + 22:.0f}" y="{y + 13:.0f}" font-size="10.5" '
                   f'fill="{color}">{label}</text>')
        cx += 40 + len(label) * 6.4
    return "".join(out)


# --- observed reachability (from on-target topology) -----------------------------

def adjacency(hosts: list[Host]) -> dict:
    """Host-to-host links OBSERVED from compromised hosts' own topology (folded in by
    `ingest`): ARP neighbours (the box demonstrably reached that L2 address) and live
    connection peers. This is ground truth, unlike the outside-in scan — recce only
    draws a link because a foothold actually contacted the other end.

    Returns {footholds:[ip], edges:[{src,dst,kind,label,dst_known}], pivots:{ip:[subnet]}}.
    `kind` is 'arp' (same-segment L2 contact) or 'conn' (a live/known connection)."""
    up = [h for h in hosts if h.is_up]
    ip_host = {h.ip: h for h in up}
    iface_ip = {}
    for h in up:
        for iface in (h.topology or {}).get("interfaces", []):
            if iface.get("ip"):
                iface_ip[iface["ip"]] = h.ip

    def resolve(ip):
        return ip_host.get(ip) and ip or iface_ip.get(ip) or (ip if ip in ip_host else "")

    footholds, edges, pivots = [], [], {}
    seen = set()
    for h in up:
        topo = h.topology or {}
        if not topo:
            continue
        footholds.append(h.ip)
        subs = sorted({i["subnet"] for i in topo.get("interfaces", []) if i.get("subnet")})
        if len(subs) > 1:
            pivots[h.ip] = subs
        for n in topo.get("neighbors", []):
            dst = resolve(n) or n
            if dst == h.ip:
                continue
            k = (h.ip, dst, "arp")
            if k in seen:
                continue
            seen.add(k)
            edges.append({"src": h.ip, "dst": dst, "kind": "arp", "label": "",
                          "dst_known": dst in ip_host})
        for p in topo.get("peers", []):
            dst = resolve(p["ip"]) or p["ip"]
            if dst == h.ip:
                continue
            k = (h.ip, dst, "conn")
            if k in seen:
                continue
            seen.add(k)
            edges.append({"src": h.ip, "dst": dst, "kind": "conn",
                          "label": str(p.get("port", "")), "dst_known": dst in ip_host})
    return {"footholds": footholds, "edges": edges, "pivots": pivots}


def reachability_svg(hosts: list[Host], ad_data=None, max_nodes: int = 60) -> str:
    """A directly-viewable inline SVG of OBSERVED host-to-host reachability, from the
    topology on-target enums brought back. Footholds (left) with solid edges to the
    ARP neighbours they reached and dashed edges to live connection peers (right).
    Pivots (dual-homed hosts bridging segments) are flagged. Renders with no tools."""
    from html import escape as _e
    adj = adjacency(hosts)
    if not adj["footholds"]:
        return ('<svg viewBox="0 0 560 60" width="560" height="60" role="img" '
                'aria-label="Observed reachability"><text x="12" y="34" font-size="13" '
                'fill="#5f6f6e">No on-target topology yet — run the enum NETWORK block '
                'and `recce ingest` its output.</text></svg>')
    up = {h.ip: h for h in hosts if h.is_up}
    dc_names = ad_dc_names(ad_data)

    def label(ip):
        h = up.get(ip)
        hn = h.hostname if h else ""
        return ip + (f"  {hn}" if hn else "")

    def kind_of(ip):
        h = up.get(ip)
        return role_kind(role_with_ad(h, dc_names)) if h else "workstation"

    foot = list(dict.fromkeys(adj["footholds"]))
    others, oseen = [], set(adj["footholds"])
    truncated = 0
    for e in adj["edges"]:
        if e["dst"] not in oseen:
            if len(others) >= max_nodes:
                truncated += 1
                continue
            oseen.add(e["dst"])
            others.append(e["dst"])
    drawn = {e for e in range(len(adj["edges"]))}

    cardW, cardH, vgap, m, colGap = 214, 76, 14, 18, 150
    top = 52
    rowsL, rowsR = len(foot), max(1, len(others))
    H = top + max(rowsL, rowsR) * (cardH + vgap) + 54
    W = m * 2 + cardW * 2 + colGap
    xL, xR = m, m + cardW + colGap
    posL = {ip: top + i * (cardH + vgap) for i, ip in enumerate(foot)}
    posR = {ip: top + i * (cardH + vgap) for i, ip in enumerate(others)}

    els = [
        '<defs><marker id="rar" markerWidth="9" markerHeight="9" refX="7" refY="3" '
        'orient="auto"><path d="M0,0 L7,3 L0,6 Z" fill="#5f6f6e"/></marker></defs>',
        f'<rect x="0" y="0" width="{W}" height="{int(H)}" fill="#ffffff"/>',
        f'<text x="{m}" y="26" font-size="15" font-weight="700" fill="#115e59">'
        'Observed reachability <tspan font-weight="400" fill="#5f6f6e">'
        '(from compromised hosts’ ARP + live connections)</tspan></text>',
        f'<text x="{xL}" y="{top - 12}" font-size="11" font-weight="700" '
        f'fill="#5f6f6e">FOOTHOLDS</text>',
        f'<text x="{xR}" y="{top - 12}" font-size="11" font-weight="700" '
        f'fill="#5f6f6e">REACHED</text>',
    ]

    # edges first (behind cards)
    for e in adj["edges"]:
        if e["src"] not in posL:
            continue
        y1 = posL[e["src"]] + cardH / 2
        if e["dst"] in posR:
            y2 = posR[e["dst"]] + cardH / 2
        elif e["dst"] in posL:
            y2 = posL[e["dst"]] + cardH / 2
        else:
            continue
        x1, x2 = xL + cardW, xR
        dash = 'stroke-dasharray="5 4" ' if e["kind"] == "conn" else ""
        col = "#1f4e9c" if e["kind"] == "conn" else "#5f6f6e"
        els.append(f'<path d="M{x1},{y1:.0f} C{x1 + 40},{y1:.0f} {x2 - 40},{y2:.0f} '
                   f'{x2 - 6},{y2:.0f}" fill="none" stroke="{col}" stroke-width="1.5" '
                   f'{dash}marker-end="url(#rar)"/>')

    def card(x, y, ip, foothold):
        h = up.get(ip)
        role = role_with_ad(h, dc_names) if h else ""
        fill, stroke = (_ROLE_COLOR.get(role, ("#ffffff", "#8a9997")) if h
                        else ("#f7faf9", "#b7c0be"))
        cxm = x + cardW / 2
        # Vertical tile: device icon on top, IP, then (real) hostname, then a note.
        out = [f'<rect x="{x}" y="{y}" width="{cardW}" height="{cardH}" rx="8" '
               f'fill="{fill}" stroke="{stroke}" stroke-width="{2 if foothold else 1.3}"/>']
        out.append(glyph(kind_of(ip), cxm - 9, y + 7, 18, stroke))
        ty = y + 38
        out.append(f'<text x="{cxm:.0f}" y="{ty}" text-anchor="middle" '
                   f'font-size="11.5" font-weight="700" fill="#1a2422">'
                   f'{_e(_x(ip, 22))}</text>')
        hn = real_hostname(h) if h else ""
        if hn:
            ty += 14
            out.append(f'<text x="{cxm:.0f}" y="{ty}" text-anchor="middle" '
                       f'font-size="10" fill="#1a2422">{_e(_x(hn, 26))}</text>')
        note = ""
        if ip in adj["pivots"]:
            note = "PIVOT · " + ", ".join(adj["pivots"][ip][:2])
        elif not h:
            note = "(not in scan)"
        elif role:
            note = role
        if note:
            col = "#C15A11" if (ip in adj["pivots"] or not h) else "#3a4644"
            ty += 14
            out.append(f'<text x="{cxm:.0f}" y="{ty}" text-anchor="middle" '
                       f'font-size="10" fill="{col}">{_e(_x(note, 28))}</text>')
        return "".join(out)

    for ip in foot:
        els.append(card(xL, posL[ip], ip, True))
    for ip in others:
        els.append(card(xR, posR[ip], ip, False))

    ly = H - 30
    els.append(glyph_legend(m, ly - 10))
    els.append(f'<line x1="{xR}" y1="{ly + 2:.0f}" x2="{xR + 22}" y2="{ly + 2:.0f}" '
               f'stroke="#5f6f6e" stroke-width="1.5"/>'
               f'<text x="{xR + 28}" y="{ly + 6:.0f}" font-size="10.5" fill="#5f6f6e">'
               f'ARP (same segment)</text>'
               f'<line x1="{xR + 150}" y1="{ly + 2:.0f}" x2="{xR + 172}" y2="{ly + 2:.0f}" '
               f'stroke="#1f4e9c" stroke-width="1.5" stroke-dasharray="5 4"/>'
               f'<text x="{xR + 178}" y="{ly + 6:.0f}" font-size="10.5" fill="#5f6f6e">'
               f'live connection</text>')
    if truncated:
        els.append(f'<text x="{m}" y="{H - 8:.0f}" font-size="10" fill="#5f6f6e">'
                   f'+{truncated} more reached host(s) not shown (capped for legibility).'
                   '</text>')
    return (f'<svg viewBox="0 0 {W} {int(H)}" width="{W}" height="{int(H)}" role="img" '
            f'aria-label="Observed reachability" '
            f'font-family="system-ui,Segoe UI,Arial,sans-serif">' + "".join(els) + "</svg>")
