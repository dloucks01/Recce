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


@dataclass
class SheetSpec:
    title: str
    cols: list[tuple[str, str, int]]   # (header, role, width); role: checkbox|data|notes|key
    rows: list[dict]                   # {"key": str, "data": {header: value}}
    styler: Callable | None = None     # data_dict -> {header: style_name}
    skip_if_empty: bool = False


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
        ("Hostname", "data", 22), ("OS", "data", 20), ("Roles", "data", 22),
        ("Open ports", "data", 30), ("# Vulns", "data", 8),
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
            "Roles": ", ".join(h.roles), "Open ports": open_ports,
            "# Vulns": len(h.vulns)}})
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
    cols = [
        ("Status", "status", 15), ("IP", "data", 16),
        ("Hostname", "data", 24), ("Port", "data", 7), ("Proto", "data", 6),
        ("Service", "data", 16), ("Product", "data", 22), ("Version", "data", 16),
        ("Extra info", "data", 24), ("CPE", "data", 30), ("Notes", "notes", 30),
        ("Key", "key", 4),
    ]
    rows = []
    for h in sorted(hosts, key=lambda x: _ip_sort_key(x.ip)):
        for p in sorted(h.open_ports, key=lambda p: p.portid):
            rows.append({"key": tr.svc_key(h.ip, p.protocol, p.portid), "data": {
                "IP": h.ip, "Hostname": h.hostname, "Port": p.portid,
                "Proto": p.protocol, "Service": p.service,
                "Product": p.product, "Version": p.version, "Extra info": p.extrainfo,
                "CPE": ", ".join(p.cpe)}})
    return SheetSpec("Services", cols, rows)


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
        ("CWE", "data", 16), ("Remediation", "data", 44), ("Details", "data", 50),
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
            "CWE": ", ".join(v.cwes),
            "Remediation": v.remediation, "Details": out}})
    return SheetSpec("Vulnerabilities", cols, rows, _styler_vulns)


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


def _styler_databases(d: dict) -> dict:
    return {"Auth": "sev_high"} if d.get("Auth") else {}


def _spec_databases(hosts: list[Host]) -> SheetSpec:
    cols = [
        ("Checked", "checkbox", 9), ("Vuln-scan", "data", 11), ("IP", "data", 16),
        ("Hostname", "data", 22), ("Port", "data", 6), ("Engine", "data", 12),
        ("Version", "data", 22), ("Auth", "data", 16), ("Databases", "data", 34),
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

def _write_spec(sheet, spec: SheetSpec, tracking: Tracking,
                order: list[str] | None = None,
                statuses: dict | None = None) -> None:
    statuses = statuses or {}
    sheet.write([(h, "header") for h, _, _ in spec.cols])

    rows_by_key = {r["key"]: r for r in spec.rows}
    ordered_keys: list[str] = []
    seen: set[str] = set()
    for k in (order or []):        # existing rows keep their position
        if k in rows_by_key and k not in seen:
            ordered_keys.append(k)
            seen.add(k)
    for k in rows_by_key:          # new items appended at the bottom
        if k not in seen:
            ordered_keys.append(k)
            seen.add(k)

    # Excel row numbers (1-based, header is row 1) where a "check" column holds a
    # real checkbox rather than an N/A dash - used to scope validation/formatting.
    active_check_rows: dict[int, list[int]] = {}
    excel_row = 1
    for key in ordered_keys:
        excel_row += 1
        row = rows_by_key[key]
        data = row["data"]
        checks = row.get("checks", {})   # {header: (stepkey, auto_default, applies)}
        rev, note = tracking.get(key, (False, ""))
        styles = spec.styler(data) if spec.styler else {}
        cells = []
        for ci, (header, role, _w) in enumerate(spec.cols, start=1):
            if role == "checkbox":
                cells.append(xlsx.CHECK_ON if rev else xlsx.CHECK_OFF)
            elif role == "check":
                stepkey, auto, applies = checks.get(header, ("", False, True))
                if not applies:
                    cells.append(tr.STEP_NA)     # not relevant to this host
                    continue
                shown = tracking[stepkey][0] if stepkey in tracking else auto
                cells.append(xlsx.CHECK_ON if shown else xlsx.CHECK_OFF)
                active_check_rows.setdefault(ci, []).append(excel_row)
            elif role == "status":
                # Explicit tri-state wins; otherwise fall back to the reviewed
                # flag (a port already marked done shows Done, else Not started).
                cells.append(statuses.get(key)
                             or (STATUS_DONE if rev else STATUS_TODO))
            elif role == "notes":
                cells.append(note)
            elif role == "key":
                cells.append(key)
            else:
                val = data.get(header, "")
                st = styles.get(header)
                cells.append((val, st) if st else val)
        sheet.write(cells)

    ncols = len(spec.cols)
    sheet.freeze_header = True
    sheet.autofilter_cols = ncols
    for i, (_h, role, w) in enumerate(spec.cols, start=1):
        sheet.set_col(i, w, hidden=(role == "key"))
    last = sheet.nrows
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
            sheet.dropdown(i, 2, last, values=STATUS_VALUES)
            sheet.highlight_when_equal(i, 2, last, STATUS_DONE, dxf_id=0)  # green
            sheet.highlight_when_equal(i, 2, last, STATUS_WIP, dxf_id=1)   # amber
        elif h in CHECKBOX_HEADERS:
            sheet.dropdown(i, 2, last)
            sheet.green_when_true(i, 2, last)


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
        ("status / report", "Show progress / rebuild this workbook from the datastore."),
    ]:
        sh.write([cmd, desc])
    sh.write([""])
    sh.write([("Targets = a single IP, several IPs, a range (10.0.0.10-40), a "
               "whole subnet (10.0.0.0/24), or @file.", "sub")])
    sh.set_col(1, 24)
    sh.set_col(2, 78)


def _bar(pct: int) -> str:
    filled = round(pct / 10)
    return "▓" * filled + "░" * (10 - filled)


def _build_overview(wb, hosts: list[Host], meta: dict, domains: list[Domain],
                    tracking: Tracking, scope: dict, issues: list | None = None) -> None:
    """One summary tab: engagement totals, review progress, and (prominently)
    live-hosts-per-subnet coverage. Replaces the old Dashboard/Coverage/Subnets."""
    sh = wb.add_sheet("Overview")
    open_ports = [p for h in hosts for p in h.open_ports]
    win = sum(1 for h in hosts if "windows" in (h.os_family or h.os_name).lower())
    lin = sum(1 for h in hosts if "linux" in (h.os_family or h.os_name).lower())
    crit = sum(1 for h in hosts for v in h.vulns if v.severity in ("critical", "high"))

    sh.write([("Engagement Overview", "title")])
    sh.write([(meta.get("subtitle", ""), "sub")])
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

    # --- Totals ---
    sh.write([("Totals", "header"), ("", "header")])
    for label, val in [
        ("Live hosts", len(hosts)),
        ("Windows / Linux", f"{win} / {lin}"),
        ("Open service ports", len(open_ports)),
        ("Vuln findings", sum(len(h.vulns) for h in hosts)),
        ("High / Critical findings", crit),
        ("Candidate exploits", sum(len(h.exploits) for h in hosts)),
        ("Domains / DCs", f"{len(domains or ad.derive_domains(hosts))} / "
                          f"{len(ad.domain_controllers(hosts))}"),
        ("NTLM relay targets", len(ad.relay_targets(hosts))),
        ("Kerberoastable / AS-REP", f"{len(ad.kerberoastable(hosts))} / "
                                    f"{len(ad.asrep_roastable(hosts))}"),
    ]:
        sh.write([(label, "bold"), val])
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
        Users & Accounts, Priv-Esc.

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
           [_spec_quick_wins(hosts), _spec_accounts(hosts), _spec_privesc(hosts)]


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
    _build_guide(wb, meta)
    _build_overview(wb, hosts, meta, domains, tracking, scope, issues or [])
    pre, post = _ordered_specs(hosts, scope)
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


def read_workbook_status(path: str) -> dict:
    """{key: status_str} for rows whose sheet has a tri-state Status column."""
    return read_workbook_edits(path)[1]
