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
