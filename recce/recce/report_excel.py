"""Excel workbook generation and update - standard-library only (see xlsx.py).

Airgapped-friendly: no openpyxl. Two entry points:

  build_workbook(...)   - write a fresh workbook.
  update_workbook(...)  - regenerate the workbook while preserving the operator's
                          checkboxes and notes AND the existing row order, with
                          rows for new IPs/services appended at the bottom. This
                          gives an in-place feel (reviewed rows stay put, new
                          systems show up below) without a heavyweight editor.

Every tracked sheet carries a hidden "Key" column (stable per-item id), a
checkbox column and a Notes column. Read-back resolves both inline strings (what
we write) and shared strings (what Excel writes when the operator saves).
"""

from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable

from . import ad
from . import db as dbmod
from . import privesc as pe
from . import tracking as tr
from . import xlsx
from .exploitref import proven_exploit_ref
from .models import Domain, Host

CHECKBOX_HEADERS = {"Reviewed", "Checked", "Triaged"}
CHECKLIST_TITLE = "Checklist"
Tracking = dict  # {key: (reviewed_bool, notes_str)}

# Per-port tri-state work status (Services sheet): a tester marks each open port
# not-started / in-progress / done. Symbol-prefixed so the cell reads at a glance.
STATUS_TODO = "☐ Not started"
STATUS_WIP = "◐ In progress"
STATUS_DONE = "☑ Done"
STATUS_VALUES = [STATUS_TODO, STATUS_WIP, STATUS_DONE]
STATUS_HEADERS = {"Status"}

_SEV_STYLE = {
    "critical": "sev_critical", "high": "sev_high", "medium": "sev_medium",
    "low": "sev_low", "info": "sev_info",
}

# Columns holding machine data render in a monospace font (like the HTML
# previews), so IPs, ports, versions, CVEs and IDs line up and read as data.
# ("IP" is handled separately - it also gets the teal accent colour.)
MONO_COLS = {
    "Port", "Proto", "Version", "CVE / refs", "CWE", "Scope", "CPE",
    "Extra info", "RID", "EDB-ID", "CVEs", "Hosts (ip:port)", "Open ports",
    "# Vulns", "# Hosts", "Script", "Path", "SPN", "Command (fill in your values)",
    "Enum command",
}


@dataclass
class SheetSpec:
    title: str
    cols: list[tuple[str, str, int]]   # (header, role, width); role: checkbox|data|notes|key
    rows: list[dict]                   # {"key": str, "data": {header: value}}
    styler: Callable | None = None     # data_dict -> {header: style_name}
    skip_if_empty: bool = False
    group_by: str | None = None        # header to group rows under collapsible host bands


# Tab colours group the sheets into visual bands in Excel's tab bar, by role:
#   guide/summary (grey-blue) · working (blue) · findings (red) · inventory
#   (green) · raw evidence (grey). Titles not listed get no colour.
_TAB_GUIDE, _TAB_WORK = "FF8497B0", "FF0E7C75"
_TAB_FIND, _TAB_INV, _TAB_RAW = "FFC00000", "FF548235", "FF7F7F7F"
TAB_COLORS = {
    "Start Here": _TAB_GUIDE, "Runbook": _TAB_GUIDE, "Overview": _TAB_GUIDE,
    "Checklist": _TAB_WORK, "Services": _TAB_WORK,
    "Vulnerabilities": _TAB_FIND, "Exploits": _TAB_FIND,
    "AD Quick Wins": _TAB_FIND, "Priv-Esc": _TAB_FIND,
    "Exploitation": _TAB_FIND,
    "Services by Product": _TAB_INV, "Databases": _TAB_INV,
    "Active Directory": _TAB_INV, "Users & Accounts": _TAB_INV,
    "Raw NSE": _TAB_RAW,
}


def _ip_sort_key(ip: str):
    try:
        return tuple(int(o) for o in ip.split("."))
    except ValueError:
        return (999, ip)


# --- stylers (return {header: style_name} for special cells) ---------------------

def _subnet_sort_key(subnet: str):
    try:
        net = subnet.split("/")[0]
        return (0,) + tuple(int(o) for o in net.split("."))
    except ValueError:
        return (1, subnet)


# Per-step column widths on the Checklist (headers come from tr.STEP_COLUMNS).
_STEP_WIDTHS = {"Enumerated": 11, "Vuln-scan": 11, "Web": 7, "AD": 6, "DB": 6,
                "Access": 8, "Priv-esc": 10, "Creds": 8, "Lateral": 8}

# How many leading identity columns to freeze per sheet (in addition to the
# header row), so the host IP stays on-screen while scrolling through the wide
# right-hand columns. 0 (default) freezes only the header row.
_FREEZE_COLS = {"Checklist": 3, "Services": 2, "Vulnerabilities": 3}


def _spec_checklist(hosts: list[Host]) -> SheetSpec:
    """One row per IP, grouped by subnet, with a checkbox for each workflow step.

    Rows are sorted by subnet then IP, so every subnet's hosts sit together (and
    you can filter to one subnet). Auto steps (Enumerated/Vuln-scan/Web/DB) turn
    green when the tool finishes them; manual steps (AD review, Access/Priv-esc/
    Creds/Lateral) are operator sign-offs you tick as you go. Steps that don't
    apply to a host show "—" instead of a box (no Web box without a web server,
    no AD box off a DC, no DB box without a database), so a checked box always
    means real work was done. The Reviewed checkbox is your per-host sign-off.
    The long tail of services (SMB, remote access, mail, SNMP...) is tracked
    per-port on the Services tab rather than as columns here.
    """
    step_cols = [(h, "check", _STEP_WIDTHS.get(h, 9)) for h in tr.STEP_COLUMNS]
    cols = [
        ("Reviewed", "checkbox", 9), ("Subnet", "data", 16), ("IP", "data", 15),
        ("Hostname", "data", 22), ("OS", "data", 20), ("Hops", "data", 6),
        ("Roles", "data", 22), ("Open ports", "data", 28), ("# Vulns", "data", 8),
        ("AV / EDR", "data", 26),
        *step_cols,
        ("Notes", "notes", 28), ("Key", "key", 4),
    ]
    rows = []
    for h in sorted(hosts, key=lambda x: (_subnet_sort_key(x.subnet), _ip_sort_key(x.ip))):
        checks = {header: (tr.step_key(step, h.ip), tr.step_auto(h, step),
                           tr.step_applies(h, step))
                  for header, step in tr.STEP_COLUMNS.items()}
        open_ports = ", ".join(str(p.portid) for p in sorted(h.open_ports, key=lambda p: p.portid))
        rows.append({"key": tr.host_key(h.ip), "checks": checks, "data": {
            "Subnet": h.subnet, "IP": h.ip, "Hostname": h.hostname, "OS": h.os_guess,
            "Hops": (str(h.distance) if h.distance else ""),
            "Roles": ", ".join(h.roles), "Open ports": open_ports,
            "# Vulns": len(h.vulns), "AV / EDR": "; ".join(h.defenses)}})
    return SheetSpec(CHECKLIST_TITLE, cols, rows, _styler_checklist)


def _styler_checklist(d: dict) -> dict:
    return {"Roles": "boldred"} if "Domain Controller" in str(d.get("Roles", "")) else {}


def _styler_vulns(d: dict) -> dict:
    out = {"Details": "wrap"}
    sev = str(d.get("Severity", "")).lower()
    if sev in _SEV_STYLE:
        out["Severity"] = _SEV_STYLE[sev]
    return out


def _styler_quickwins(d: dict) -> dict:
    fills = {
        "Domain Controller": "sev_high", "NTLM relay target": "sev_high",
        "SMBv1 / MS17-010": "sev_critical", "Kerberoastable": "sev_medium",
        "AS-REP roastable": "sev_high", "Delegation": "sev_medium",
        "Privileged account": "sev_low",
    }
    cat = d.get("Category", "")
    return {"Category": fills[cat]} if cat in fills else {}


def _styler_accounts(d: dict) -> dict:
    out = {}
    if d.get("Roastable"):
        out["Roastable"] = "sev_high"
    if d.get("Delegation"):
        out["Delegation"] = "sev_medium"
    return out


# --- tracked-sheet specs --------------------------------------------------------

def _spec_services(hosts: list[Host]) -> SheetSpec:
    """One row per open port, grouped by IP. Each port has its own tri-state work
    Status (not started / in progress / done) and a Notes cell, so a tester can
    track exactly which ports they've looked at, are working, or haven't touched."""
    from . import serviceenum as se
    cols = [
        ("Status", "status", 15), ("IP", "data", 16),
        ("Hostname", "data", 24), ("Port", "data", 7), ("Proto", "data", 6),
        ("Service", "data", 16), ("Product", "data", 22), ("Version", "data", 16),
        ("Extra info", "data", 24), ("CPE", "data", 28),
        ("Enum command", "data", 42), ("Notes", "notes", 28),
        ("Key", "key", 4),
    ]
    rows = []
    for h in sorted(hosts, key=lambda x: _ip_sort_key(x.ip)):
        for p in sorted(h.open_ports, key=lambda p: p.portid):
            script = se.script_for(p.service, p.portid)
            enum_cmd = f"{se.DRIVER} {script} {h.ip} {p.portid}" if script else ""
            rows.append({"key": tr.svc_key(h.ip, p.protocol, p.portid),
                         "group": h.ip, "data": {
                "IP": h.ip, "Hostname": h.hostname, "Port": p.portid,
                "Proto": p.protocol, "Service": p.service,
                "Product": p.product, "Version": p.version, "Extra info": p.extrainfo,
                "CPE": ", ".join(p.cpe), "Enum command": enum_cmd}})
    return SheetSpec("Services", cols, rows, group_by="IP")


def _spec_services_by_product(hosts: list[Host]) -> SheetSpec:
    cols = [
        ("Checked", "checkbox", 9), ("Product", "data", 26), ("Version", "data", 18),
        ("Service", "data", 16), ("# Hosts", "data", 8), ("Hosts (ip:port)", "data", 80),
        ("Notes", "notes", 28), ("Key", "key", 4),
    ]
    groups: dict[str, list[tuple[str, int, str]]] = defaultdict(list)
    display: dict[str, tuple[str, str, str]] = {}
    for h in hosts:
        for p in h.open_ports:
            key = p.product_version_key
            groups[key].append((h.ip, p.portid, h.hostname))
            display.setdefault(key, (p.product or p.service or "unknown", p.version, p.service))
    rows = []
    for key in sorted(groups, key=lambda k: (-len(groups[k]), k)):
        product, version, service = display[key]
        entries = sorted(groups[key], key=lambda t: _ip_sort_key(t[0]))
        rows.append({"key": tr.prod_key(key), "data": {
            "Product": product, "Version": version, "Service": service,
            "# Hosts": len(entries),
            "Hosts (ip:port)": ", ".join(f"{ip}:{port}" for ip, port, _ in entries)}})
    return SheetSpec("Services by Product", cols, rows)


def _spec_vulns(hosts: list[Host]) -> SheetSpec:
    cols = [
        ("Triaged", "checkbox", 9), ("Severity", "data", 10), ("IP", "data", 16),
        ("Hostname", "data", 20), ("Port", "data", 6), ("Finding", "data", 44),
        ("Source", "data", 11), ("Conf.", "data", 10), ("CVE / refs", "data", 22),
        ("CWE", "data", 16), ("Proven exploit", "data", 52),
        ("Remediation", "data", 44), ("Details", "data", 50),
        ("Notes", "notes", 26), ("Key", "key", 4),
    ]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows = []
    ordered = [(h, v) for h in hosts for v in h.vulns]
    ordered.sort(key=lambda hv: (order.get(hv[1].severity, 9), _ip_sort_key(hv[0].ip)))
    for h, v in ordered:
        out = v.output if len(v.output) < 700 else v.output[:700] + " ..."
        rows.append({"key": tr.vuln_key(v.ip, v.port, f"{v.script_id}:{v.title[:40]}"),
                     "data": {
            "Severity": v.severity.upper(), "IP": h.ip, "Hostname": h.hostname,
            "Port": v.port if v.port else "", "Finding": v.title or v.script_id,
            "Source": v.source, "Conf.": v.confidence, "CVE / refs": ", ".join(v.ids),
            "CWE": ", ".join(v.cwes), "Proven exploit": _proven_exploit_for(h, v),
            "Remediation": v.remediation, "Details": out}})
    return SheetSpec("Vulnerabilities", cols, rows, _styler_vulns)


def _proven_exploit_for(host: Host, v) -> str:
    """The verifiable, proven exploit for a vuln - same rule as the Word write-ups:
    a searchsploit/EDB match on this port, or a curated known exploit, and never
    for an unconfirmed advisory (confidence 'potential'). Empty string otherwise."""
    if v.confidence == "potential":
        return ""
    edb = [e for e in host.exploits if e.port == v.port and e.edb_id]
    if edb:
        return "searchsploit: " + ", ".join(f"EDB-{e.edb_id}" for e in edb[:4])
    return proven_exploit_ref(v.ids, f"{v.title} {v.script_id}") or ""


def _spec_exploits(hosts: list[Host]) -> SheetSpec:
    cols = [
        ("Checked", "checkbox", 9), ("IP", "data", 16), ("Hostname", "data", 22),
        ("Port", "data", 6), ("Product", "data", 20), ("Version", "data", 16),
        ("EDB-ID", "data", 9), ("Type", "data", 12), ("Title", "data", 60),
        ("CVEs", "data", 24), ("Path", "data", 40), ("Notes", "notes", 28),
        ("Key", "key", 4),
    ]
    rows = []
    for h in sorted(hosts, key=lambda x: _ip_sort_key(x.ip)):
        for e in h.exploits:
            rows.append({"key": tr.exploit_key(e.ip, e.port, e.edb_id), "data": {
                "IP": e.ip, "Hostname": h.hostname, "Port": e.port or "",
                "Product": e.product, "Version": e.version, "EDB-ID": e.edb_id,
                "Type": e.type, "Title": e.title, "CVEs": ", ".join(e.cves),
                "Path": e.path}})
    return SheetSpec("Exploits", cols, rows, skip_if_empty=True)


def _clip(text: str, limit: int = 2000) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[:limit] + " ...[truncated]"


def _styler_raw(d: dict) -> dict:
    return {"Output": "wrap_mono"}       # raw evidence in monospace, wrapped


def _spec_raw_nse(hosts: list[Host]) -> SheetSpec:
    """All raw NSE script output, verbatim, in one place. The Scope column says
    whether a script ran against the whole host ("host": smb-os-discovery,
    smb2-time, nbstat, ldap-rootdse...) or a single open port (the port number:
    ftp-anon on 21, ssl-cert on 443...). This is the unparsed evidence behind the
    parsed sheets - filter Scope to `host` for host-wide facts, or to a port to
    read that service's output. Grouped by host and collapsible."""
    cols = [
        ("Checked", "checkbox", 9), ("IP", "data", 16), ("Hostname", "data", 22),
        ("Scope", "data", 8), ("Script", "data", 28), ("Output", "data", 94),
        ("Notes", "notes", 26), ("Key", "key", 4),
    ]
    rows = []
    for h in sorted(hosts, key=lambda x: _ip_sort_key(x.ip)):
        for s in h.host_scripts:                     # host-wide scripts first
            if not (s.output or "").strip():
                continue
            rows.append({"key": f"raw:{h.ip}:host:{s.id}", "group": h.ip, "data": {
                "IP": h.ip, "Hostname": h.hostname, "Scope": "host",
                "Script": s.id, "Output": _clip(s.output)}})
        for p in sorted(h.open_ports, key=lambda p: p.portid):
            for s in p.scripts:                      # then per-port scripts
                if not (s.output or "").strip():
                    continue
                rows.append({"key": f"raw:{h.ip}:{p.portid}:{s.id}", "group": h.ip,
                             "data": {
                    "IP": h.ip, "Hostname": h.hostname, "Scope": str(p.portid),
                    "Script": s.id, "Output": _clip(s.output)}})
    return SheetSpec("Raw NSE", cols, rows, _styler_raw, skip_if_empty=True,
                     group_by="IP")


def _styler_databases(d: dict) -> dict:
    return {"Auth": "sev_high"} if d.get("Auth") else {}


def _spec_databases(hosts: list[Host]) -> SheetSpec:
    # Convention: state box, then IP + Hostname lead every host-centric sheet
    # (Vuln-scan status moved next to Engine/Version rather than before the IP).
    cols = [
        ("Checked", "checkbox", 9), ("IP", "data", 16), ("Hostname", "data", 22),
        ("Port", "data", 6), ("Engine", "data", 12), ("Version", "data", 22),
        ("Vuln-scan", "data", 11), ("Auth", "data", 16), ("Databases", "data", 34),
        ("Users", "data", 30), ("Findings", "data", 40), ("Notes", "notes", 26),
        ("Key", "key", 4),
    ]
    rows = []
    for inst in dbmod.db_instances(hosts):
        rows.append({"key": f"db:{inst['ip']}:{inst['port']}", "data": {
            "Vuln-scan": "scanned" if inst["vuln_scanned"] else "pending",
            "IP": inst["ip"], "Hostname": inst["hostname"], "Port": inst["port"],
            "Engine": inst["engine"], "Version": inst["version"],
            "Auth": inst["auth"], "Databases": inst["databases"],
            "Users": inst["users"], "Findings": inst["findings"]}})
    return SheetSpec("Databases", cols, rows, _styler_databases, skip_if_empty=True)


def _styler_privesc(d: dict) -> dict:
    return {"Category": "sev_medium"} if d.get("Category") == "finding" else {}


def _spec_privesc(hosts: list[Host]) -> SheetSpec:
    cols = [
        ("Checked", "checkbox", 9), ("IP", "data", 16), ("Hostname", "data", 20),
        ("OS", "data", 22), ("Category", "data", 10), ("Vector", "data", 30),
        ("How-to / command", "data", 55), ("Ref / note", "data", 40),
        ("Notes", "notes", 26), ("Key", "key", 4),
    ]
    rows = []
    for r in pe.all_rows(hosts):
        rows.append({"key": r["key"], "data": {
            "IP": r["ip"], "Hostname": r["hostname"], "OS": r["os"],
            "Category": r["category"], "Vector": r["vector"],
            "How-to / command": r["howto"], "Ref / note": r["note"]}})
    return SheetSpec("Priv-Esc", cols, rows, _styler_privesc, skip_if_empty=True)


def _spec_exploitation(hosts: list[Host]) -> SheetSpec:
    """The finding -> run-this bridge for every CONFIRMED finding: remote exploits
    (Metasploit modules, params filled in), remote tool actions (impacket / netexec
    / GTFOBins), and post-shell priv-esc - each mapped to the exact EXISTING public
    tool, the command with the finding's values filled in, the prerequisite, and how
    to validate. References vetted tools - it does not generate exploit code. Empty
    (sheet skipped) until there are confirmed findings. `exploitplan` writes the
    same actions out as runnable .rc / .sh artifacts."""
    from . import exploitplan as xp
    _KIND = {"remote-msf": "remote (msf)", "remote-tool": "remote (tool)",
             "post-shell": "post-shell"}
    defenses = {h.ip: "; ".join(h.defenses) for h in hosts if h.defenses}
    cols = [
        ("Done", "checkbox", 9), ("IP", "data", 15), ("Hostname", "data", 15),
        ("Type", "data", 13), ("Finding", "data", 28), ("Existing tool", "data", 28),
        ("Command (fill in your values)", "data", 58),
        ("Prerequisite", "data", 28), ("Validate", "data", 22),
        ("Defenses (host)", "data", 26), ("Notes", "notes", 20), ("Key", "key", 4),
    ]
    rows = [{"key": a["key"], "data": {
        "IP": a["ip"], "Hostname": a["hostname"],
        "Type": _KIND.get(a["kind"], a["kind"]), "Finding": a["finding"],
        "Existing tool": a["tool"], "Command (fill in your values)": a["cmd"],
        "Prerequisite": a["prereq"], "Validate": a["validate"],
        "Defenses (host)": defenses.get(a["ip"], "")}}
        for a in xp.all_actions(hosts)]
    return SheetSpec("Exploitation", cols, rows, skip_if_empty=True)


def _spec_quick_wins(hosts: list[Host]) -> SheetSpec:
    cols = [
        ("Checked", "checkbox", 9), ("Category", "data", 20), ("Target", "data", 34),
        ("Detail", "data", 40), ("Why it matters", "data", 55), ("Notes", "notes", 28),
        ("Key", "key", 4),
    ]
    rows = [{"key": w["key"], "data": {
        "Category": w["category"], "Target": w["target"], "Detail": w["detail"],
        "Why it matters": w["why"]}} for w in ad.quick_wins(hosts)]
    return SheetSpec("AD Quick Wins", cols, rows, _styler_quickwins, skip_if_empty=True)


def _spec_accounts(hosts: list[Host]) -> SheetSpec:
    cols = [
        ("Checked", "checkbox", 9), ("Kind", "data", 9), ("Domain", "data", 14),
        ("Name", "data", 22), ("RID", "data", 7), ("Enabled", "data", 8),
        ("AdminCount", "data", 10), ("Roastable", "data", 18), ("Delegation", "data", 13),
        ("SPN", "data", 40), ("Member of", "data", 30), ("Description", "data", 30),
        ("OS", "data", 22), ("Source", "data", 14), ("IP", "data", 15),
        ("Notes", "notes", 28), ("Key", "key", 4),
    ]
    kind_order = {"user": 0, "group": 1, "computer": 2, "spn": 3, "share": 4,
                  "domain": 5, "trust": 6}
    rows = []
    for h, a in sorted(((h, a) for h in hosts for a in h.accounts),
                       key=lambda ha: (kind_order.get(ha[1].kind, 9), ha[1].domain,
                                       ha[1].name.lower())):
        at = a.attrs
        roastable = []
        if at.get("spn"):
            roastable.append("kerberoast")
        if at.get("asrep_roastable") == "yes":
            roastable.append("AS-REP")
        rows.append({"key": tr.acct_key(a.source, a.kind, a.domain, a.name), "data": {
            "Kind": a.kind, "Domain": a.domain, "Name": a.name, "RID": a.rid,
            "Enabled": at.get("enabled", ""), "AdminCount": at.get("admincount", ""),
            "Roastable": ", ".join(roastable), "Delegation": at.get("delegation", ""),
            "SPN": at.get("spn", "") or at.get("members", ""),
            "Member of": at.get("memberof", ""), "Description": at.get("description", ""),
            "OS": at.get("os", ""), "Source": a.source, "IP": h.ip}})
    return SheetSpec("Users & Accounts", cols, rows, _styler_accounts, skip_if_empty=True)


# --- writing a tracked sheet (with stable ordering) ------------------------------

def _ordered_keys(spec_rows: list[dict], order: list[str] | None) -> list[str]:
    """Row keys in final order: existing rows keep their saved position, new
    items append at the bottom. Shared by the sheet writer and the Overview's
    Checklist-row deep-link computation so the two always agree."""
    rows_by_key = {r["key"]: r for r in spec_rows}
    ordered: list[str] = []
    seen: set[str] = set()
    for k in (order or []):
        if k in rows_by_key and k not in seen:
            ordered.append(k)
            seen.add(k)
    for k in rows_by_key:
        if k not in seen:
            ordered.append(k)
            seen.add(k)
    return ordered


def _write_spec(sheet, spec: SheetSpec, tracking: Tracking,
                order: list[str] | None = None,
                statuses: dict | None = None) -> None:
    statuses = statuses or {}
    sheet.write([(h, "header") for h, _, _ in spec.cols])

    rows_by_key = {r["key"]: r for r in spec.rows}
    ordered_keys = _ordered_keys(spec.rows, order)

    # Optional collapsible grouping: reorder keys into per-host bands (stable by
    # first appearance), so each host's rows sit under a header the tester can
    # collapse. `items` is a flat sequence of ("hdr", groupval) / ("row", key).
    grouped = bool(spec.group_by)
    ip_col = next((i for i, (h, _, _) in enumerate(spec.cols, 1) if h == "IP"), 1)
    noun = {"Services": "ports", "Raw NSE": "scripts"}.get(spec.title, "rows")
    if grouped:
        buckets: dict[str, list[str]] = {}
        for k in ordered_keys:
            buckets.setdefault(rows_by_key[k].get("group", ""), []).append(k)
        items: list[tuple[str, str]] = []
        for gv, keys in buckets.items():
            items.append(("hdr", gv))
            items += [("row", k) for k in keys]
    else:
        items = [("row", k) for k in ordered_keys]

    # Excel row numbers (1-based, header is row 1) where a "check" column holds a
    # real checkbox rather than an N/A dash - used to scope validation/formatting.
    active_check_rows: dict[int, list[int]] = {}
    data_rows: list[int] = []            # detail (non-group-header) row numbers
    excel_row = 1
    for kind, key in items:
        excel_row += 1
        if kind == "hdr":
            # A collapsible section band: IP + hostname + count in the IP column,
            # the rest blank but styled, so a whole host folds into one row.
            grp_rows = buckets[key]
            hostname = rows_by_key[grp_rows[0]]["data"].get("Hostname", "")
            label = f"{key}   ·   {hostname}   ·   {len(grp_rows)} {noun}".replace(
                "·      ·", "·")
            hdr_cells = []
            for ci, (_h, _role, _w) in enumerate(spec.cols, start=1):
                hdr_cells.append((label if ci == ip_col else "", "group"))
            sheet.write(hdr_cells, outline=0)
            continue
        data_rows.append(excel_row)
        row = rows_by_key[key]
        data = row["data"]
        checks = row.get("checks", {})   # {header: (stepkey, auto_default, applies)}
        rev, note = tracking.get(key, (False, ""))
        styles = spec.styler(data) if spec.styler else {}
        band = (excel_row % 2 == 0)      # zebra-stripe even data rows
        data_style = "cell_band" if band else "cell"
        center_style = "center_band" if band else "center"
        cells = []
        for ci, (header, role, _w) in enumerate(spec.cols, start=1):
            if role == "checkbox":
                cells.append((xlsx.CHECK_ON if rev else xlsx.CHECK_OFF, center_style))
            elif role == "check":
                stepkey, auto, applies = checks.get(header, ("", False, True))
                if not applies:
                    cells.append((tr.STEP_NA, center_style))  # not relevant here
                    continue
                shown = tracking[stepkey][0] if stepkey in tracking else auto
                cells.append((xlsx.CHECK_ON if shown else xlsx.CHECK_OFF, center_style))
                active_check_rows.setdefault(ci, []).append(excel_row)
            elif role == "status":
                # Explicit tri-state wins; otherwise fall back to the reviewed
                # flag (a port already marked done shows Done, else Not started).
                cells.append((statuses.get(key)
                              or (STATUS_DONE if rev else STATUS_TODO), data_style))
            elif role == "notes":
                cells.append((note, data_style))
            elif role == "key":
                cells.append((key, data_style))
            else:
                val = data.get(header, "")
                st = styles.get(header)
                if st:                        # styler-assigned accent (severity/wrap)
                    if st == "wrap":
                        st = "wrap_band" if band else "wrap"
                    elif st == "wrap_mono":
                        st = "wrap_band_mono" if band else "wrap_mono"
                    cells.append((val, st))
                elif header == "IP":          # teal monospace accent
                    cells.append((val, "ip_band" if band else "ip"))
                elif header in MONO_COLS:      # machine data -> monospace
                    cells.append((val, "cell_band_mono" if band else "cell_mono"))
                else:
                    cells.append((val, data_style))
        sheet.write(cells, outline=(1 if grouped else 0))

    ncols = len(spec.cols)
    sheet.freeze_header = True
    sheet.hide_gridlines = True          # our hairline rules read cleaner than gridlines
    sheet.header_height = 22
    sheet.tab_color = TAB_COLORS.get(spec.title)
    # Freeze the identity columns so the IP stays visible when scrolling right.
    sheet.freeze_cols = _FREEZE_COLS.get(spec.title, 0)
    sheet.autofilter_cols = ncols
    for i, (_h, role, w) in enumerate(spec.cols, start=1):
        sheet.set_col(i, w, hidden=(role == "key"))
    last = sheet.nrows

    def _rowset_sqref(col: int) -> str | None:
        # On grouped sheets, scope validation/formatting to the DATA rows only, so
        # the collapsible group-header rows never sprout a stray dropdown arrow.
        if not grouped:
            return None
        letter = xlsx.col_letter(col)
        return " ".join(f"{letter}{r}" for r in data_rows) or None

    # Checkbox / check columns get the ☑/☐ dropdown + green-when-checked. For
    # per-step "check" columns, restrict it to the cells that actually hold a box
    # so N/A dashes don't trip Excel's list-validation error.
    for i, (h, role, _w) in enumerate(spec.cols, 1):
        if role == "check":
            active = active_check_rows.get(i, [])
            if not active:
                continue
            letter = xlsx.col_letter(i)
            sqref = " ".join(f"{letter}{r}" for r in active)
            sheet.dropdown(i, 2, last, sqref=sqref)
            sheet.green_when_true(i, 2, last, sqref=sqref)
        elif role == "status":
            sq = _rowset_sqref(i)
            sheet.dropdown(i, 2, last, sqref=sq, values=STATUS_VALUES)
            sheet.highlight_when_equal(i, 2, last, STATUS_DONE, dxf_id=0, sqref=sq)
            sheet.highlight_when_equal(i, 2, last, STATUS_WIP, dxf_id=1, sqref=sq)
        elif h in CHECKBOX_HEADERS:
            sq = _rowset_sqref(i)
            sheet.dropdown(i, 2, last, sqref=sq)
            sheet.green_when_true(i, 2, last, sqref=sq)


# --- computed (non-tracked) sheets ----------------------------------------------

def _build_guide(wb, meta: dict) -> None:
    """A friendly 'Start Here' sheet so the workbook explains itself."""
    sh = wb.add_sheet("Start Here")
    sh.write([("recce - engagement tracker", "title")])
    sh.write([(meta.get("subtitle", ""), "sub")])
    sh.write([""])
    sh.write([("Scans fill this workbook in; you check things off as you go. "
               "Your ticks and notes are saved and survive re-scans.", "bold")])
    sh.write([""])

    sh.write([("How to use it", "title")])
    for line in [
        "1. Go to the CHECKLIST tab - one row per IP, a checkbox for each step.",
        "2. Auto steps (Enumerated / Vuln-scan / Web / DB) turn green when the tool "
        "finishes them. Manual sign-offs (AD, and the kill-chain Access / Priv-esc "
        "/ Creds / Lateral) start unchecked - you tick them as you go.",
        "3. Steps that don't apply to a host show '—' instead of a box (e.g. no AD "
        "box off a non-DC). SMB/remote/mail/SNMP are tracked on the SERVICES tab.",
        "4. You can tick/untick any box by hand - your choice sticks (untick to "
        "flag 'redo'). Tick 'Reviewed' when you're personally done with a host.",
        "5. The boxes are ☑ / ☐ dropdowns: click the cell and pick ☑ to check it.",
        "6. Use the SERVICES tab to track each open PORT: set its Status dropdown "
        "to Not started / In progress / Done and jot findings in Notes.",
        "7. Filter a step column to ☐ (or Services Status to 'Not started') to see "
        "exactly what still needs work.",
        "8. The OVERVIEW tab and the `status` command show overall progress.",
    ]:
        sh.write([line])
    sh.write([""])

    sh.write([("What each tab is", "title")])
    sh.write([("Tab", "header"), ("What it shows", "header")])
    for tab, desc in [
        ("Runbook", "Step-by-step: exactly what to type for each phase + the options "
                    "that matter, plus a troubleshooting table. Start here if you "
                    "just want the commands."),
        ("Overview", "Totals, review progress, and live-hosts-per-subnet coverage."),
        ("Checklist", "THE working tab: one row per IP (grouped by subnet) with a "
                      "checkbox for each phase + host detail + Reviewed + Notes."),
        ("Services", "The other working tab: every open port with a per-port Status "
                     "(not started / in progress / done) and Notes - track each "
                     "port you work (incl. SMB, remote access, mail, SNMP)."),
        ("Vulnerabilities", "Findings by severity: CVE + remediation (offline engine)."),
        ("Exploits", "searchsploit matches (EDB-ID, type, CVEs, local path)."),
        ("Services by Product", "Who runs the same service+version (mass-patch pivot)."),
        ("Databases", "DB inventory: engine, version, auth, databases, users."),
        ("Active Directory", "Domains, DCs, password policy, trusts."),
        ("AD Quick Wins", "Prioritised AD attack paths (DC, relay, roast, deleg)."),
        ("Users & Accounts", "AD/SMB users, groups, computers, shares."),
        ("Priv-Esc", "Per-host escalation findings + a Windows/Linux playbook."),
        ("Exploitation", "Each confirmed priv-esc finding mapped to the exact "
                         "existing tool + command (your values filled in) + how "
                         "to validate. References vetted tools, not new exploits."),
        ("Raw NSE", "All raw NSE script output, verbatim (Scope = host or port) - "
                    "the evidence behind the parsed sheets; grouped by host."),
    ]:
        sh.write([tab, desc])
    sh.write([""])

    sh.write([("Commands (run these to fill the workbook)", "title")])
    sh.write([("Command", "header"), ("What it does", "header")])
    for cmd, desc in [
        ("doctor", "Check this box can run everything (env + tools + self-scan)."),
        ("enum <targets>", "Phase 1: discover hosts, scan ports, ID services (fast)."),
        ("vulns [targets]", "Phase 2: vuln-scan open ports (safe; --aggressive for more)."),
        ("db [targets]", "Database enumeration + vuln scan."),
        ("privesc [targets]", "Priv-esc playbook (+ --scan for remote checks)."),
        ("credenum -u U -p P -d DOM", "Authenticated enum (netexec/impacket/ssh) "
                                      "- shares, roasting, local admin, hashes."),
        ("writeups", "Generate a Word (.docx) write-up per finding - finish each "
                     "in Word (screenshots auto-added for web when a browser is present)."),
        ("status / report", "Show progress / rebuild this workbook from the datastore."),
    ]:
        sh.write([cmd, desc])
    sh.write([""])
    sh.write([("Targets = a single IP, several IPs, a range (10.0.0.10-40), a "
               "whole subnet (10.0.0.0/24), or @file.", "sub")])
    sh.set_col(1, 24)
    sh.set_col(2, 78)


def _build_runbook(wb, meta: dict) -> None:
    """A step-by-step 'Runbook' sheet: exactly what to type, phase by phase,
    with the options that matter for each phase. The tester can work top-to-
    bottom without leaving the workbook."""
    sh = wb.add_sheet("Runbook")
    sh.hide_gridlines = True

    def section(title, blurb=""):
        sh.write([""])
        sh.write([(title, "title")])
        if blurb:
            sh.write([(blurb, "sub")])
        sh.write([("Type this", "header"), ("What it does / options", "header")])

    def cmd(c, desc):
        sh.write([(c, "cell_mono"), (desc, "wrap")])

    sh.write([("recce - tester runbook", "title")])
    sh.write([(meta.get("subtitle", "") or "Work top-to-bottom. Each phase writes "
               "into this workbook; your ticks and notes survive re-scans.", "sub")])
    sh.write([("Prefix every command with `python3 -m recce` (or use the bundled "
               "`./bin/recce` wrapper). `-o DIR` is the engagement folder that holds "
               "the workbook + datastore; keep it the same across all phases.", "bold")])

    section("Targets - the one thing every scan phase takes",
            "Give enum/vulns/scan any of these forms (space-separated to mix):")
    cmd("10.0.0.5", "a single host")
    cmd("10.0.0.5 10.0.0.9 10.0.0.20", "several hosts")
    cmd("10.0.0.10-40", "a range (last octet 10 through 40)")
    cmd("10.0.0.0/24", "a whole subnet")
    cmd("@scope.txt", "read targets from a file (one per line; # comments ok)")
    cmd("--exclude 10.0.0.1,10.0.0.0/28", "carve out-of-scope hosts back out")

    section("0. Pre-flight - prove the box can do the work")
    cmd("doctor", "Check env + required/optional tools + run a localhost self-scan. "
                  "Run this first; it tells you loudly what's missing.")

    section("1. Enumerate - discover hosts, ports, services (fast, safe)",
            "Already have an nmap scan? Use `import` instead of `enum` (no scanning).")
    cmd("import scan.xml [more...] -o eng",
        "Import EXISTING nmap scans - XML (-oX, richest), grepable (-oG), or normal "
        "(-oN); multiple files/dirs/globs; masscan XML too. Appends + merges (never "
        "duplicates). Runs the same offline enrichment as enum; ticks Enumerated.")
    cmd("enum <targets> -o eng --title \"Client X\"",
        "Host discovery + full TCP + service/version/OS + deep service NSE. "
        "Fills Checklist, Services, Raw NSE.")
    cmd("  --profile quick|standard|thorough",
        "How hard to look (standard is the default; quick skips deep enum for speed).")
    cmd("  --workers N", "How many hosts to scan at once (default 6).")
    cmd("  --host-timeout MIN", "Give up on a slow host after MIN minutes and move on.")

    section("2. Vulns - vuln-scan the open ports you found")
    cmd("vulns -o eng", "Curated detection NSE + version-matched offline vuln DB + "
                        "HTTP/TLS probes. Fills Vulnerabilities, Exploits.")
    cmd("  --fast", "Top-signal detection scripts only - much quicker on a /24 when "
                    "you just want the high-value hits. Shows live per-host progress + ETA.")
    cmd("  --aggressive", "Add nmap `vulners` + broader scripts (slower, noisier, "
                          "more coverage). Opposite end from --fast.")
    cmd("  [targets]", "Optional: limit to specific hosts/ports (default = everything "
                       "enum found).")

    section("3. Databases (optional) - deep DB enumeration")
    cmd("db -o eng", "Enumerate + vuln-scan discovered database services. Fills Databases.")

    section("4. Priv-esc playbook - per-host escalation guidance")
    cmd("privesc -o eng", "Build the Priv-Esc sheet from what's already known.")
    cmd("  --scan", "Also run remote priv-esc NSE checks against the hosts.")
    cmd("ingest loot.txt -o eng",
        "Fold findings from an on-target run of recce-enum.sh / recce-enum.ps1 "
        "(the [!] lines) into the Priv-Esc sheet. Point it at the saved -o/-OutFile.")

    section("5. Credentialed enum - authenticated power moves",
            "Two accounts are supported: a normal user does the enumeration; an "
            "optional privileged account runs the admin-only checks.")
    cmd("credenum -u user -p pass -d corp.local -o eng",
        "Authenticated SMB/LDAP enum with the user account: shares, roasting, "
        "delegation, local-admin reach. Fills Users & Accounts, AD sheets.")
    cmd("  --admin-user adm --admin-pass P [--admin-domain D]",
        "Privileged account: confirms local-admin reach and dumps secrets "
        "(secretsdump). Each result is labelled by which account produced it.")
    cmd("  --ldap-enum / --ldap-anon / --ldap-ssl / --dc-ip IP",
        "Credentialed LDAP of the DC / anonymous bind / LDAPS / target a specific DC.")

    section("6. Report - turn findings into deliverables")
    cmd("writeups -o eng", "One Word (.docx) write-up per finding (web screenshots "
                           "auto-added when a browser is present). Finish each in Word.")
    cmd("report -o eng", "Rebuild this workbook + reports from the datastore "
                         "(preserves your ticks and notes).")
    cmd("status -o eng", "Print live review-coverage without rebuilding anything.")

    section("On-target - run these ON a compromised host (read-only)",
            "Copy the script from recce/local/ to the target, self-test, then run "
            "and save the output; bring it back and `ingest` it (phase 4).")
    cmd("./recce-enum.sh -t", "Linux: self-test (parse-check + what will run). Safe first step.")
    cmd("./recce-enum.sh -o loot.txt", "Linux: full read-only sweep, saved to loot.txt.")
    cmd("powershell -ep bypass -File recce-enum.ps1 -SelfTest",
        "Windows: self-test only (no enumeration).")
    cmd("powershell -ep bypass -File recce-enum.ps1 -OutFile loot.txt",
        "Windows: full read-only sweep, saved to loot.txt.")

    # --- troubleshooting ---------------------------------------------------------
    sh.write([""])
    sh.write([("If something goes wrong", "title")])
    sh.write([("Run `doctor` first - it reports what's missing and self-tests the "
               "pipeline. Re-running any phase is safe (idempotent - never "
               "duplicates rows).", "sub")])
    sh.write([("Symptom", "header"), ("Fix", "header")])

    def fix(symptom, action):
        sh.write([(symptom, "wrap"), (action, "wrap")])

    fix("nmap not found", "Install nmap - the only hard requirement. Everything "
                          "else is optional and degrades cleanly.")
    fix("'Not running as root' / weak scan",
        "Run with sudo. Under sudo use `sudo ./bin/recce ...` so PATH/PYTHONPATH "
        "survive (SYN scan, OS detection and UDP need root).")
    fix("Discovery finds no hosts",
        "A firewall is dropping pings. Re-run `enum` with --no-discovery (-Pn: "
        "treat every target as up).")
    fix("Scans too slow",
        "--fast (masscan), --workers N, `vulns --fast` (top-signal + progress/ETA), "
        "--profile quick, --top-ports N, --host-timeout MIN.")
    fix("Crashed or interrupted",
        "Nothing is lost. Re-run with --resume, or `report -o eng` to rebuild from "
        "saved data. Set RECCE_DEBUG=1 for the full traceback.")
    fix("'No open ports match' on vulns",
        "Run `enum` first; --unscanned finds nothing once everything is scanned; "
        "widen or drop --only.")
    fix("No findings (but you expected some)",
        "Improve service ID on enum (--version-all / --version-intensity 9), then "
        "try `vulns --aggressive` for the full intrusive NSE category.")
    fix("credenum: no tools / auth table",
        "Install netexec + impacket (or ssh). In the table: FAIL = credential "
        "rejected (check user/pass/DOMAIN); ERR = unreachable/tool error; '-' = "
        "not attempted (a missing tool is never shown as FAIL).")
    fix("Workbook won't update / locked",
        "Close it in Excel/LibreOffice before a scan or `report` - an open file is "
        "locked. Your ticks and notes are read back on the next run.")
    fix("Web screenshots missing in write-ups",
        "Install firefox/chromium, or point RECCE_BROWSER at a browser; or use "
        "`writeups --no-screenshots` and add them in Word.")
    fix("Full guide",
        "See TROUBLESHOOTING.md in the project, or run `recce <command> -h` for "
        "every option.")

    sh.set_col(1, 46)
    sh.set_col(2, 82)


def _bar(pct: int) -> str:
    filled = round(pct / 10)
    return "▓" * filled + "░" * (10 - filled)


def _build_overview(wb, hosts: list[Host], meta: dict, domains: list[Domain],
                    tracking: Tracking, scope: dict, issues: list | None = None,
                    nav: list[str] | None = None,
                    host_rows: dict | None = None) -> None:
    """One summary tab: engagement totals, review progress, and (prominently)
    live-hosts-per-subnet coverage. Doubles as a navigation hub - the jump bar
    and several totals are clickable links to the matching sheet."""
    sh = wb.add_sheet("Overview")
    nav = nav or []
    open_ports = [p for h in hosts for p in h.open_ports]
    win = sum(1 for h in hosts if "windows" in (h.os_family or h.os_name).lower())
    lin = sum(1 for h in hosts if "linux" in (h.os_family or h.os_name).lower())
    crit = sum(1 for h in hosts for v in h.vulns if v.severity in ("critical", "high"))

    sh.write([("Engagement Overview", "title")])
    sh.write([(meta.get("subtitle", ""), "sub")])
    sh.write([""])

    # --- Navigation hub: a clickable jump bar to every populated sheet ---
    if nav:
        sh.write([("Jump to", "header")])
        link_row = sh.nrows + 1
        sh.write([(t, "link") for t in nav])
        for ci, title in enumerate(nav, start=1):
            sh.link_to(link_row, ci, title)
        sh.write([""])

    # --- Scan issues (front and centre so nothing failed silently) ---
    issues = issues or []
    if issues:
        errs = sum(1 for i in issues if i.get("level") == "error")
        warns = len(issues) - errs
        sh.write([(f"⚠ SCAN ISSUES: {errs} error(s), {warns} incomplete - "
                   f"review before trusting coverage (full log: recce.log)",
                   "boldred")])
        sh.write([("When", "bold"), ("Host", "bold"), ("Phase", "bold"),
                  ("Level", "bold"), ("What happened", "bold")])
        for i in issues[:40]:
            lvl = i.get("level", "warning")
            sh.write([i.get("ts", ""), i.get("ip", ""), i.get("phase", ""),
                      (lvl.upper(), "sev_high" if lvl == "error" else "sev_medium"),
                      i.get("message", "")])
        if len(issues) > 40:
            sh.write([("", None), (f"... and {len(issues) - 40} more (see recce.log)",
                                   "sub")])
        sh.set_col(5, 70)
        sh.write([""])

    # --- Totals (several labels link straight to the relevant sheet) ---
    sh.write([("Totals", "header"), ("", "header")])
    nav_set = set(nav)
    proven = sum(1 for h in hosts for v in h.vulns if _proven_exploit_for(h, v))
    _links = {
        "Live hosts": "Checklist", "Open service ports": "Services",
        "Vuln findings": "Vulnerabilities", "High / Critical findings": "Vulnerabilities",
        "Findings with a proven exploit": "Vulnerabilities",
        "Candidate exploits": "Exploits", "Domains / DCs": "Active Directory",
        "NTLM relay targets": "AD Quick Wins",
        "Kerberoastable / AS-REP": "AD Quick Wins",
    }
    for label, val in [
        ("Live hosts", len(hosts)),
        ("Windows / Linux", f"{win} / {lin}"),
        ("Open service ports", len(open_ports)),
        ("Vuln findings", sum(len(h.vulns) for h in hosts)),
        ("High / Critical findings", crit),
        ("Findings with a proven exploit", proven),
        ("Candidate exploits", sum(len(h.exploits) for h in hosts)),
        ("Domains / DCs", f"{len(domains or ad.derive_domains(hosts))} / "
                          f"{len(ad.domain_controllers(hosts))}"),
        ("NTLM relay targets", len(ad.relay_targets(hosts))),
        ("Kerberoastable / AS-REP", f"{len(ad.kerberoastable(hosts))} / "
                                    f"{len(ad.asrep_roastable(hosts))}"),
        ("Hosts with AV / EDR seen", sum(1 for h in hosts if h.defenses)),
    ]:
        target = _links.get(label)
        if target in nav_set:
            r = sh.nrows + 1
            sh.write([(label, "link"), val])
            sh.link_to(r, 1, target)
        else:
            sh.write([(label, "bold"), val])
    sh.write([""])

    # --- Credentialed access matrix (only when credenum has run) ---
    cred_hosts = [h for h in hosts if getattr(h, "cred_enumerated", False)]
    if cred_hosts:
        def _has(h, needle):
            return any(needle in v.title for v in h.vulns)
        sh.write([("Credentialed access matrix (per account)", "header"),
                  ("", "header"), ("", "header"), ("", "header"), ("", "header")])
        sh.write([("Host", "bold"), ("User acct", "bold"),
                  ("User = admin", "bold"), ("Priv acct = admin", "bold"),
                  ("Hashes dumped", "bold")])
        for h in sorted(cred_hosts, key=lambda x: _ip_sort_key(x.ip)):
            user_admin = _has(h, "Local admin confirmed - user account")
            priv_admin = _has(h, "Local admin confirmed - privileged account")
            dumped = _has(h, "Credential hashes dumped")
            yes, no = ("✓", "done"), "—"
            name = f"{h.ip}" + (f" ({h.hostname})" if h.hostname else "")
            sh.write([name, "✓",
                      yes if user_admin else no,
                      yes if priv_admin else no,
                      yes if dumped else no])
        sh.write([("✓ = access confirmed via netexec (Pwn3d!) / secretsdump; "
                   "a User=admin tick means the low-priv account is over-privileged.",
                   "sub")])
        sh.write([""])

    # --- Review progress ---
    sh.write([("Review progress (what you've ticked off)", "header"),
              ("", "header"), ("", "header"), ("", "header")])
    cov = tr.compute_coverage(hosts, tracking)
    labels = {"hosts": "Hosts", "services": "Services", "vulns": "Vulnerabilities",
              "exploits": "Exploits", "quick_wins": "AD Quick Wins",
              "accounts": "Users & Accounts"}
    o = cov["overall"]
    sh.write([("OVERALL", "bold"), (f"{o['done']}/{o['total']}", "bold"),
              (f"{o['pct']}%", "bold"), (_bar(o["pct"]), "bold")])
    for cat in tr.COVERAGE_CATEGORIES:
        c = cov[cat]
        sh.write([labels.get(cat, cat), f"{c['done']}/{c['total']}",
                  f"{c['pct']}%", _bar(c["pct"])])
    sh.write([""])

    # --- Coverage by subnet (live hosts + auto phase completion) ---
    # Only the tool-completed surfaces belong here; AD review and the kill-chain
    # markers are manual sign-offs, tracked per host on the Checklist.
    sh.write([("Coverage by subnet - live hosts and phase completion", "header"),
              ("", "header"), ("", "header"), ("", "header"), ("", "header"),
              ("", "header"), ("", "header"), ("", "header")])
    sh.write([("Subnet", "bold"), ("In range", "bold"), ("Live hosts", "bold"),
              ("Enumerated", "bold"), ("Vuln-scanned", "bold"), ("Web", "bold"),
              ("DB", "bold"), ("# Vulns", "bold")])
    agg: dict[str, list] = defaultdict(list)
    for h in hosts:
        agg[h.subnet or "unknown"].append(h)

    def cell(done, total):
        # Denominator counts only hosts the step applies to, so "x/y" reflects
        # real coverage of that surface (blank when the surface is absent).
        if not total:
            return ""
        return (f"{done}/{total}", "done") if done == total else \
               (f"{done}/{total}", "sev_medium") if done else f"{done}/{total}"

    def phase(hs, step):
        applic = [h for h in hs if tr.step_applies(h, step)]
        return cell(sum(1 for h in applic if tr.step_auto(h, step)), len(applic))

    for sn in sorted(set(agg) | set(scope or {}), key=_subnet_sort_key):
        hs = agg.get(sn, [])
        sh.write([sn, (scope or {}).get(sn, ""), len(hs),
                  phase(hs, "enum"), phase(hs, "vuln"), phase(hs, "web"),
                  phase(hs, "db"), sum(len(h.vulns) for h in hs)])
    for col, w in {1: 26, 2: 10, 3: 11, 4: 12, 5: 13, 6: 8, 7: 8, 8: 8}.items():
        sh.set_col(col, w)
    sh.write([""])

    # --- Host index: click an IP to jump straight to its Checklist row ---
    host_rows = host_rows or {}
    if host_rows:
        sh.write([("Host index - click an IP to jump to its Checklist row",
                   "header"), ("", "header"), ("", "header"), ("", "header"),
                  ("", "header")])
        sh.write([("IP", "bold"), ("Hostname", "bold"), ("OS", "bold"),
                  ("Open ports", "bold"), ("# Vulns", "bold")])
        by_ip = {h.ip: h for h in hosts}
        # List in Checklist row order (host_rows maps ip -> that sheet's row).
        for ip, crow in sorted(host_rows.items(), key=lambda kv: kv[1]):
            h = by_ip.get(ip)
            if h is None:
                continue
            r = sh.nrows + 1
            sh.write([(ip, "link"), h.hostname, h.os_guess,
                      len(h.open_ports), len(h.vulns)])
            sh.link_to(r, 1, CHECKLIST_TITLE, cell=f"A{crow}")


def _build_active_directory(wb, hosts: list[Host], domains: list[Domain]) -> None:
    if not domains and not ad.domain_controllers(hosts):
        return
    sh = wb.add_sheet("Active Directory")
    sh.write([("Active Directory Overview", "title")])
    sh.write([""])
    for dom in domains or ad.derive_domains(hosts):
        sh.write([(f"Domain: {dom.name}", "boldred")])
        facts = [
            ("NetBIOS", dom.netbios),
            ("Forest / functional level", f"{dom.forest} / {dom.functional_level}".strip(" /")),
            ("Naming context", dom.naming_context),
            ("Domain Controllers", ", ".join(dom.dc_ips)),
            ("Machine account quota", dom.machine_account_quota),
            ("Anonymous LDAP bind", "YES" if dom.anonymous_bind else "no"),
            ("Sources", ", ".join(dom.sources)),
        ]
        if dom.password_policy:
            facts.append(("Password policy",
                          "; ".join(f"{k}={v}" for k, v in dom.password_policy.items())))
        for label, val in facts:
            if not val and val != "no":
                continue
            style = None
            if label == "Anonymous LDAP bind" and dom.anonymous_bind:
                style = "sev_high"
            elif label == "Machine account quota" and str(val) not in ("0", ""):
                style = "sev_low"
            sh.write([(label, "bold"), (val, style) if style else val])
        if dom.trusts:
            sh.write([("Trusts", "bold")])
            for t in dom.trusts:
                sh.write(["", f"{t.get('name')} ({t.get('direction')}, type {t.get('type')})"])
        sh.write([""])
    sh.set_col(1, 26)
    sh.set_col(2, 70)


# --- public entry points --------------------------------------------------------

def _ordered_specs(hosts: list[Host], scope: dict | None = None):
    """Specs in final left-to-right order, following the engagement flow:
    orient -> track -> find -> exploit -> pivot -> AD -> post-exploitation.

    Active Directory (a computed sheet) is inserted between Databases and AD
    Quick Wins by build_workbook, giving the final tab order:

        Start Here, Overview, Checklist, Services, Vulnerabilities, Exploits,
        Services by Product, Databases, Active Directory, AD Quick Wins,
        Users & Accounts, Priv-Esc, Raw NSE.

    Rationale for the pairings you flip between:
      * Checklist <-> Services  - host <-> its open ports (the working pair).
      * Services <-> Vulnerabilities <-> Exploits - port -> finding -> exploit.
      * Vulnerabilities -> Services by Product - "who else runs this?" pivot.
      * Active Directory <-> AD Quick Wins <-> Users & Accounts - the AD cluster.
      * Priv-Esc last - post-exploitation, reached after a foothold.
    """
    return [_spec_checklist(hosts), _spec_services(hosts), _spec_vulns(hosts),
            _spec_exploits(hosts), _spec_services_by_product(hosts),
            _spec_databases(hosts)], \
           [_spec_quick_wins(hosts), _spec_accounts(hosts), _spec_privesc(hosts),
            _spec_exploitation(hosts), _spec_raw_nse(hosts)]


def build_workbook(hosts: list[Host], out_path: str, meta: dict | None = None,
                   domains: list[Domain] | None = None,
                   tracking: Tracking | None = None,
                   order_map: dict | None = None,
                   scope: dict | None = None,
                   statuses: dict | None = None,
                   issues: list | None = None) -> str:
    meta = meta or {}
    domains = domains or []
    tracking = tracking or {}
    order_map = order_map or {}
    statuses = statuses or {}
    wb = xlsx.Workbook()
    pre, post = _ordered_specs(hosts, scope)
    # Which sheets will actually exist (skip_if_empty ones may not), in tab order,
    # so the Overview's jump bar only links to sheets that are really there.
    ad_present = bool(domains or ad.domain_controllers(hosts))
    nav = [s.title for s in pre if not (s.skip_if_empty and not s.rows)]
    if ad_present:
        nav.append("Active Directory")
    nav += [s.title for s in post if not (s.skip_if_empty and not s.rows)]

    # Pre-compute each host's Checklist row (header is row 1, data from row 2) so
    # the Overview can deep-link an IP straight to it. Uses the SAME ordering the
    # Checklist writer will use, so the links land on the right rows.
    checklist_spec = next((s for s in pre if s.title == CHECKLIST_TITLE), None)
    host_rows: dict[str, int] = {}
    if checklist_spec:
        ck_keys = _ordered_keys(checklist_spec.rows, order_map.get(CHECKLIST_TITLE))
        key_ip = {r["key"]: r["data"]["IP"] for r in checklist_spec.rows}
        host_rows = {key_ip[k]: 2 + i for i, k in enumerate(ck_keys) if k in key_ip}

    _build_guide(wb, meta)
    _build_runbook(wb, meta)
    _build_overview(wb, hosts, meta, domains, tracking, scope, issues or [], nav,
                    host_rows)
    for spec in pre:
        if spec.skip_if_empty and not spec.rows:
            continue
        _write_spec(wb.add_sheet(spec.title), spec, tracking,
                    order_map.get(spec.title), statuses)
    _build_active_directory(wb, hosts, domains)
    for spec in post:
        if spec.skip_if_empty and not spec.rows:
            continue
        _write_spec(wb.add_sheet(spec.title), spec, tracking,
                    order_map.get(spec.title), statuses)
    # Colour the computed (non-spec) sheets' tabs too, so the whole tab bar is
    # grouped into role bands.
    for sh in wb.sheets:
        if sh.tab_color is None:
            sh.tab_color = TAB_COLORS.get(sh.title)
    wb.save(out_path)
    return out_path


def update_workbook(path: str, hosts: list[Host], meta: dict | None = None,
                    domains: list[Domain] | None = None,
                    tracking: Tracking | None = None,
                    scope: dict | None = None,
                    statuses: dict | None = None,
                    issues: list | None = None) -> str:
    """Regenerate preserving existing row order (new rows appended) + tracking.

    The tool re-lays-out the sheet each time; the operator's checkboxes, notes and
    row order are preserved via read-back. (Manual cell formatting the operator
    adds is not preserved - track via the checkbox/Notes columns.)
    """
    order_map = read_key_order(path) if os.path.exists(path) else {}
    return build_workbook(hosts, path, meta, domains, tracking, order_map, scope,
                          statuses, issues)


def read_key_order(path: str) -> dict[str, list[str]]:
    """{sheet_title: [keys in current row order]} from an existing workbook."""
    order: dict[str, list[str]] = {}
    try:
        sheets = xlsx.read_sheets(path)
    except Exception:
        return order
    for title, rows in sheets.items():
        if not rows:
            continue
        header = rows[0]
        if "Key" not in header:
            continue
        kidx = header.index("Key")
        order[title] = [r[kidx] for r in rows[1:] if len(r) > kidx and r[kidx]]
    return order


def read_workbook_edits(path: str) -> tuple[Tracking, dict]:
    """Parse operator edits once. Returns ({key: (reviewed, notes)}, {key: status})
    where `status` holds the per-port tri-state from any Status column."""
    result: Tracking = {}
    statuses: dict = {}
    try:
        sheets = xlsx.read_sheets(path)
    except Exception:
        return result, statuses
    def as_bool(v) -> bool:
        s = str(v).strip()
        return s == xlsx.CHECK_ON or s.upper() in ("TRUE", "1", "X", "YES", "DONE")

    for title, rows in sheets.items():
        if not rows:
            continue
        header = rows[0]
        # Per-host step checkboxes live only on the Checklist (other sheets have
        # a same-named "Vuln-scan" text column that must NOT be read as steps).
        if title == CHECKLIST_TITLE and "IP" in header:
            ipc = header.index("IP")
            step_cols = [(header.index(h), s) for h, s in tr.STEP_COLUMNS.items()
                         if h in header]
            for r in rows[1:]:
                if len(r) <= ipc or not r[ipc]:
                    continue
                ip = str(r[ipc])
                for ci, step in step_cols:
                    if ci >= len(r):
                        continue
                    cell = str(r[ci]).strip()
                    if not cell or cell == tr.STEP_NA:
                        continue   # N/A step - not a real checkbox, never an override
                    result[tr.step_key(step, ip)] = (as_bool(r[ci]), "")

        if "Key" not in header:
            continue
        kidx = header.index("Key")
        cbidx = next((i for i, h in enumerate(header) if h in CHECKBOX_HEADERS), None)
        stidx = next((i for i, h in enumerate(header) if h in STATUS_HEADERS), None)
        nidx = header.index("Notes") if "Notes" in header else None
        for r in rows[1:]:
            if len(r) <= kidx or not r[kidx]:
                continue
            key = str(r[kidx])
            note = r[nidx] if (nidx is not None and nidx < len(r)) else ""
            status = ""
            if stidx is not None and stidx < len(r):
                status = str(r[stidx]).strip()
            # reviewed comes from a real checkbox, or from a tri-state Status == Done.
            if cbidx is not None and cbidx < len(r):
                reviewed = as_bool(r[cbidx])
            elif status:
                reviewed = status == STATUS_DONE
            else:
                reviewed = False
            if status:
                statuses[key] = status
            # A key can appear on more than one sheet (e.g. Checklist + Hosts both
            # carry host:<ip>). Combine: reviewed if ticked anywhere; keep a note.
            prev = result.get(key)
            if prev:
                result[key] = (prev[0] or reviewed, prev[1] or note)
            else:
                result[key] = (reviewed, note)
    return result, statuses


def read_workbook_tracking(path: str) -> Tracking:
    """{key: (reviewed_bool, notes)} for every row carrying a Key value."""
    return read_workbook_edits(path)[0]
