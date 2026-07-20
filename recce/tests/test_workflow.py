"""High-fidelity integration tests: the whole workflow end-to-end, with a hard
focus on correctness of the spreadsheet - that the RIGHT fields land on the RIGHT
IP row, that per-IP tracking never bleeds across hosts, and that re-scans/updates
preserve everything.

These drive the real parser -> store -> workbook writer -> read-back -> report
paths (no nmap needed) against the bundled sample scan, whose four hosts each
have a distinct fingerprint:

    10.0.10.10  dc01.corp.local  Windows Server 2019  88,389,445,3389  ms17-010
    10.0.10.25  ws01.corp.local  Windows 10 21H2      135,445,3389     (no vulns)
    10.0.20.5   web01            Linux 5.4            22,80,443        4 vulns
    10.0.20.6   web02            Linux 5.4            22,80,21,3306    ftp-anon
"""

import contextlib
import io
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recce import ad, parser, xlsx
from recce import tracking as tr
from recce.models import Host, Port, Vuln
from recce.report_excel import (build_workbook, read_key_order,
                                 read_workbook_edits, read_workbook_tracking,
                                 update_workbook, STATUS_WIP, STATUS_TODO)
from recce.store import Store
from recce.targets import _subnet_of

SAMPLE = os.path.join(os.path.dirname(parser.__file__), "sample_scan.xml")

# Ground-truth facts, keyed by IP, for cross-checking the spreadsheet.
FACTS = {
    "10.0.10.10": {"host": "dc01.corp.local", "os": "Windows Server 2019",
                   "ports": [88, 389, 445, 3389], "nvulns": 1},
    "10.0.10.25": {"host": "ws01.corp.local", "os": "Windows 10",
                   "ports": [135, 445, 3389], "nvulns": 0},
    "10.0.20.5": {"host": "web01", "os": "Linux",
                  "ports": [22, 80, 443], "nvulns": 4},
    "10.0.20.6": {"host": "web02", "os": "Linux",
                  "ports": [21, 22, 80, 3306], "nvulns": 1},
}


def sample_hosts():
    hosts = parser.parse_nmap_xml(SAMPLE)
    for h in hosts:
        h.subnet = _subnet_of(h.ip)
        h.enumerated = True
    ad.analyze_hosts(hosts)
    return hosts


def rows_by_ip(sheets, title):
    """Return (header, {ip: [row-as-dict, ...]}) for a sheet with an IP column."""
    rows = sheets[title]
    hdr = rows[0]
    ipc = hdr.index("IP")
    out: dict = {}
    for r in rows[1:]:
        if len(r) > ipc and r[ipc]:
            out.setdefault(str(r[ipc]), []).append(dict(zip(hdr, r)))
    return hdr, out


class ChecklistPerIpFidelityTest(unittest.TestCase):
    """Every host's Checklist row carries ITS OWN facts - no cross-IP bleed."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.out = os.path.join(self.d, "wb.xlsx")
        build_workbook(sample_hosts(), self.out)
        self.sheets = xlsx.read_sheets(self.out)

    def test_each_ip_row_has_its_own_identity(self):
        _hdr, by_ip = rows_by_ip(self.sheets, "Checklist")
        self.assertEqual(set(by_ip), set(FACTS))
        for ip, facts in FACTS.items():
            self.assertEqual(len(by_ip[ip]), 1, f"{ip} should be exactly one row")
            row = by_ip[ip][0]
            self.assertEqual(row["Hostname"], facts["host"])
            self.assertIn(facts["os"].split()[0], row["OS"])
            self.assertEqual(str(row["# Vulns"]), str(facts["nvulns"]))
            # Open-ports cell lists exactly this host's ports, in order.
            self.assertEqual(row["Open ports"],
                             ", ".join(str(p) for p in facts["ports"]))

    def test_dc_role_only_on_the_dc_row(self):
        _hdr, by_ip = rows_by_ip(self.sheets, "Checklist")
        self.assertIn("Domain Controller", by_ip["10.0.10.10"][0]["Roles"])
        for ip in ("10.0.20.5", "10.0.20.6"):
            self.assertNotIn("Domain Controller", by_ip[ip][0]["Roles"] or "")

    def test_surface_steps_match_host_type(self):
        _hdr, by_ip = rows_by_ip(self.sheets, "Checklist")
        # DC: AD applies (☐, manual), Web/DB do not (—).
        dc = by_ip["10.0.10.10"][0]
        self.assertEqual(dc["AD"], xlsx.CHECK_OFF)
        self.assertEqual(dc["Web"], tr.STEP_NA)
        self.assertEqual(dc["DB"], tr.STEP_NA)
        # web01: Web applies, AD does not, DB does not.
        web = by_ip["10.0.20.5"][0]
        self.assertEqual(web["Web"], xlsx.CHECK_OFF)
        self.assertEqual(web["AD"], tr.STEP_NA)
        self.assertEqual(web["DB"], tr.STEP_NA)
        # web02: has MySQL -> DB applies.
        self.assertEqual(by_ip["10.0.20.6"][0]["DB"], xlsx.CHECK_OFF)


class ServicesPerIpFidelityTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.out = os.path.join(self.d, "wb.xlsx")
        build_workbook(sample_hosts(), self.out)
        self.sheets = xlsx.read_sheets(self.out)

    def test_every_service_row_maps_port_to_correct_ip(self):
        hdr, by_ip = rows_by_ip(self.sheets, "Services")
        for ip, facts in FACTS.items():
            got = sorted(int(r["Port"]) for r in by_ip.get(ip, []))
            self.assertEqual(got, sorted(facts["ports"]),
                             f"{ip} services should be exactly its own ports")
        # The FTP service (21) exists on web02 ONLY.
        ftp_rows = [r for rs in by_ip.values() for r in rs if str(r["Port"]) == "21"]
        self.assertEqual(len(ftp_rows), 1)
        self.assertEqual(ftp_rows[0]["IP"], "10.0.20.6")
        self.assertIn("ftp", ftp_rows[0]["Service"].lower())

    def test_hostname_column_matches_the_row_ip(self):
        _hdr, by_ip = rows_by_ip(self.sheets, "Services")
        for ip, rows in by_ip.items():
            for r in rows:
                self.assertEqual(r["Hostname"], FACTS[ip]["host"])


class VulnerabilitiesPerIpFidelityTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.out = os.path.join(self.d, "wb.xlsx")
        build_workbook(sample_hosts(), self.out)
        self.sheets = xlsx.read_sheets(self.out)

    def test_findings_attributed_to_correct_ip(self):
        _hdr, by_ip = rows_by_ip(self.sheets, "Vulnerabilities")
        # ms17-010 is on the DC only.
        dc_finds = " ".join(r["Finding"] for r in by_ip.get("10.0.10.10", []))
        self.assertIn("ms17-010", dc_finds)
        # ...and NOT attributed to any other host.
        for ip in ("10.0.20.5", "10.0.20.6", "10.0.10.25"):
            self.assertNotIn("ms17-010",
                             " ".join(r["Finding"] for r in by_ip.get(ip, [])))
        # ftp-anon is web02 only.
        self.assertIn("FTP", " ".join(r["Finding"] for r in by_ip.get("10.0.20.6", [])))
        # ws01 has no findings at all.
        self.assertEqual(by_ip.get("10.0.10.25", []), [])

    def test_vuln_row_counts_match_per_host(self):
        _hdr, by_ip = rows_by_ip(self.sheets, "Vulnerabilities")
        for ip, facts in FACTS.items():
            self.assertEqual(len(by_ip.get(ip, [])), facts["nvulns"], ip)


class TrackingIsolationTest(unittest.TestCase):
    """Ticking a box for one IP must never touch another IP's tracking."""

    def test_reviewing_one_host_isolates_to_that_key(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(os.path.join(d, "s.sqlite"))
            for h in sample_hosts():
                store.upsert_host(h)
            store.set_reviewed(tr.host_key("10.0.20.5"), True, notes="looked at web01")
            got = store.get_tracking()
            self.assertTrue(got[tr.host_key("10.0.20.5")][0])
            for ip in ("10.0.10.10", "10.0.10.25", "10.0.20.6"):
                self.assertNotIn(tr.host_key(ip), got)
            store.close()

    def test_step_and_status_keys_are_per_ip(self):
        # Distinct hosts, same open port -> distinct svc/step keys, no collision.
        a = tr.svc_key("10.0.20.5", "tcp", 80)
        b = tr.svc_key("10.0.20.6", "tcp", 80)
        self.assertNotEqual(a, b)
        self.assertNotEqual(tr.step_key("vuln", "10.0.20.5"),
                            tr.step_key("vuln", "10.0.20.6"))
        self.assertNotEqual(tr.vuln_key("10.0.20.5", 80, "http-x"),
                            tr.vuln_key("10.0.20.6", 80, "http-x"))

    def test_workbook_reviewed_readback_targets_the_edited_ip(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            hosts = sample_hosts()
            # Operator ticks Reviewed for web02 (10.0.20.6) only.
            build_workbook(hosts, out,
                           tracking={tr.host_key("10.0.20.6"): (True, "done")})
            back = read_workbook_tracking(out)
            self.assertTrue(back[tr.host_key("10.0.20.6")][0])
            for ip in ("10.0.10.10", "10.0.10.25", "10.0.20.5"):
                self.assertFalse(back.get(tr.host_key(ip), (False, ""))[0])

    def test_per_port_status_isolates_to_one_service_row(self):
        # Every service row carries a Status (default "Not started"); only the one
        # we set should read back as In-progress - no other row is elevated.
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            k = tr.svc_key("10.0.20.6", "tcp", 21)
            build_workbook(sample_hosts(), out, statuses={k: STATUS_WIP})
            _edits, statuses = read_workbook_edits(out)
            self.assertEqual(statuses.get(k), STATUS_WIP)
            others = {kk: v for kk, v in statuses.items() if kk != k}
            self.assertTrue(others, "other service rows should still be present")
            self.assertTrue(all(v == STATUS_TODO for v in others.values()),
                            "no other port should be marked in-progress/done")


class MergeRescanFidelityTest(unittest.TestCase):
    """Re-scanning a host merges into the right IP and leaves others untouched."""

    def test_rescan_merges_ports_flags_vulns_without_touching_other_hosts(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(os.path.join(d, "s.sqlite"))
            a1 = Host(ip="10.0.0.5", subnet="10.0.0.0/24", enumerated=True,
                      hostnames=["a"], ports=[Port(portid=80, service="http")])
            b = Host(ip="10.0.0.9", subnet="10.0.0.0/24", enumerated=True,
                     hostnames=["b"], ports=[Port(portid=22, service="ssh")])
            store.upsert_host(a1)
            store.upsert_host(b)
            # Re-scan A: new port + a vuln + db flag; same vuln twice to test dedup.
            v = Vuln(ip="10.0.0.5", port=443, protocol="tcp", script_id="ssl-x",
                     title="weak tls", severity="medium")
            a2 = Host(ip="10.0.0.5", subnet="10.0.0.0/24", db_scanned=True,
                      ports=[Port(portid=443, service="https")], vulns=[v, v])
            store.upsert_host(a2)

            A = store.get_host("10.0.0.5")
            self.assertEqual(sorted(p.portid for p in A.ports), [80, 443])
            self.assertTrue(A.enumerated)          # preserved from first scan
            self.assertTrue(A.db_scanned)           # merged from rescan
            self.assertEqual(len(A.vulns), 1)       # deduped
            # B is completely untouched.
            B = store.get_host("10.0.0.9")
            self.assertEqual([p.portid for p in B.ports], [22])
            self.assertEqual(B.vulns, [])
            store.close()

    def test_regenerate_preserves_row_order_and_appends_new_host(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            hosts = sample_hosts()
            build_workbook(hosts, out)
            order_before = read_key_order(out)["Checklist"]
            # A new host is discovered on a later scan.
            newh = Host(ip="10.0.20.99", subnet="10.0.20.0/24", enumerated=True,
                        hostnames=["new"], ports=[Port(portid=8080, service="http")])
            update_workbook(out, hosts + [newh])
            order_after = read_key_order(out)["Checklist"]
            # Existing rows keep their exact positions; the new one is appended.
            self.assertEqual(order_after[:len(order_before)], order_before)
            self.assertEqual(order_after[-1], tr.host_key("10.0.20.99"))


class CoverageMathFidelityTest(unittest.TestCase):
    def test_marking_one_host_counts_once_in_the_right_subnet(self):
        hosts = sample_hosts()
        tracking = {tr.host_key("10.0.10.10"): (True, "")}
        cov = tr.compute_coverage(hosts, tracking)
        self.assertEqual(cov["hosts"]["total"], 4)
        self.assertEqual(cov["hosts"]["done"], 1)
        sc = tr.subnet_coverage(hosts, tracking)
        self.assertEqual(sc["10.0.10.0/24"]["done"], 1)   # the DC's subnet
        self.assertEqual(sc["10.0.10.0/24"]["total"], 2)
        self.assertEqual(sc["10.0.20.0/24"]["done"], 0)   # other subnet unaffected

    def test_service_coverage_counts_all_open_ports(self):
        hosts = sample_hosts()
        keys = tr.item_keys(hosts)
        total_ports = sum(len(h.open_ports) for h in hosts)
        self.assertEqual(len(keys["services"]), total_ports)
        # Mark exactly one service done -> coverage done == 1.
        k = tr.svc_key("10.0.20.6", "tcp", 21)
        cov = tr.compute_coverage(hosts, {k: (True, "")})
        self.assertEqual(cov["services"]["done"], 1)


class WriteupPerIpFidelityTest(unittest.TestCase):
    def test_grouped_finding_lists_only_the_affected_ip(self):
        from recce.report_docx import group_findings
        findings = group_findings(sample_hosts())
        ms17 = next(f for f in findings if "ms17-010" in f.title.lower())
        self.assertEqual(sorted({a[0] for a in ms17.affected}), ["10.0.10.10"])
        ftp = next(f for f in findings if "ftp" in f.title.lower())
        self.assertEqual(sorted({a[0] for a in ftp.affected}), ["10.0.20.6"])

    def test_shared_finding_across_hosts_lists_all_affected(self):
        # Two hosts with the same finding title -> one write-up, both IPs.
        from recce.report_docx import group_findings
        hosts = [
            Host(ip="10.0.0.1", ports=[Port(portid=443, service="https")],
                 vulns=[Vuln(ip="10.0.0.1", port=443, protocol="tcp",
                             script_id="ssl", title="Weak TLS", severity="medium")]),
            Host(ip="10.0.0.2", ports=[Port(portid=443, service="https")],
                 vulns=[Vuln(ip="10.0.0.2", port=443, protocol="tcp",
                             script_id="ssl", title="Weak TLS", severity="medium")]),
        ]
        f = group_findings(hosts)[0]
        self.assertEqual(sorted({a[0] for a in f.affected}),
                         ["10.0.0.1", "10.0.0.2"])

    def test_generated_docx_contains_correct_ip_only(self):
        from recce.report_docx import build_writeups
        import zipfile
        import xml.etree.ElementTree as ET
        W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "w")
            build_writeups(sample_hosts(), out)
            fn = next(p for p in os.listdir(out) if "ms17" in p)
            root = ET.fromstring(zipfile.ZipFile(os.path.join(out, fn))
                                 .read("word/document.xml"))
            text = "\n".join("".join(t.text or "" for t in p.iter(f"{W}t"))
                             for p in root.iter(f"{W}p"))
            self.assertIn("10.0.10.10", text)          # the affected host
            self.assertNotIn("10.0.20.5", text)         # not an unrelated host


class FullCliRoundTripTest(unittest.TestCase):
    """Drive the real cli report/import functions, as the commands do."""

    def test_report_then_operator_edit_then_import_persists_per_ip(self):
        from recce import cli
        with tempfile.TemporaryDirectory() as d:
            paths = cli._open_paths(d)
            store = Store(paths["db"])
            store.set_meta("engagement", "roundtrip")
            for h in sample_hosts():
                store.upsert_host(h)
            # 1. Generate all reports from the datastore (like `report`).
            cli._generate_reports(store, paths, "roundtrip", quiet=True)
            self.assertTrue(os.path.exists(paths["xlsx"]))
            # 2. Operator edits the workbook: tick Reviewed for web01 only.
            build_workbook(store.all_hosts(), paths["xlsx"],
                           tracking={tr.host_key("10.0.20.5"): (True, "reviewed")},
                           order_map=read_key_order(paths["xlsx"]))
            # 3. Import edits back (like the start of any command).
            cli._import_excel_tracking(store, paths)
            got = store.get_tracking()
            self.assertTrue(got[tr.host_key("10.0.20.5")][0])
            self.assertEqual(got[tr.host_key("10.0.20.5")][1], "reviewed")
            # No other host got reviewed.
            for ip in ("10.0.10.10", "10.0.10.25", "10.0.20.6"):
                self.assertFalse(got.get(tr.host_key(ip), (False, ""))[0])
            # 4. Regenerate -> the tick survives and stays on the right IP.
            cli._generate_reports(store, paths, "roundtrip", quiet=True)
            back = read_workbook_tracking(paths["xlsx"])
            self.assertTrue(back[tr.host_key("10.0.20.5")][0])
            store.close()

    def test_manual_step_override_survives_regeneration(self):
        from recce import cli
        with tempfile.TemporaryDirectory() as d:
            paths = cli._open_paths(d)
            store = Store(paths["db"])
            for h in sample_hosts():
                store.upsert_host(h)
            cli._generate_reports(store, paths, "t", quiet=True)
            # Operator ticks the manual 'Access' box for the DC only.
            key = tr.step_key("access", "10.0.10.10")
            build_workbook(store.all_hosts(), paths["xlsx"],
                           tracking={key: (True, "")},
                           order_map=read_key_order(paths["xlsx"]))
            cli._import_excel_tracking(store, paths)
            self.assertTrue(store.get_tracking()[key][0])
            # Regenerate and confirm it is still checked on the DC row only.
            cli._generate_reports(store, paths, "t", quiet=True)
            sheets = xlsx.read_sheets(paths["xlsx"])
            _hdr, by_ip = rows_by_ip(sheets, "Checklist")
            self.assertEqual(by_ip["10.0.10.10"][0]["Access"], xlsx.CHECK_ON)
            self.assertEqual(by_ip["10.0.20.5"][0]["Access"], xlsx.CHECK_OFF)
            store.close()


class WorkbookStructureTest(unittest.TestCase):
    def test_all_sheets_present_and_key_column_hidden_consistent(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            build_workbook(sample_hosts(), out)
            sheets = xlsx.read_sheets(out)
        # Always present.
        for name in ("Start Here", "Overview", "Checklist", "Services",
                     "Vulnerabilities", "Services by Product"):
            self.assertIn(name, sheets)
        # Present because the sample has this data (Exploits is skip-if-empty and
        # absent here since searchsploit didn't run).
        for name in ("Databases", "Active Directory", "AD Quick Wins",
                     "Users & Accounts", "Priv-Esc"):
            self.assertIn(name, sheets)
        self.assertNotIn("Exploits", sheets)   # no exploit data -> sheet omitted
        # Tracked sheets carry a Key column so read-back can find every row.
        for name in ("Checklist", "Services", "Vulnerabilities"):
            self.assertIn("Key", sheets[name][0])

    def test_openpyxl_can_open_the_workbook(self):
        try:
            from openpyxl import load_workbook
        except ImportError:
            self.skipTest("openpyxl not installed")
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            build_workbook(sample_hosts(), out)
            wb = load_workbook(out)
            self.assertIn("Checklist", wb.sheetnames)

    def test_styling_freeze_gridlines_and_severity_contrast(self):
        """The polish pass: identity columns frozen, gridlines off, and critical
        severity is solid with white text (openpyxl reads the applied styles)."""
        try:
            from openpyxl import load_workbook
        except ImportError:
            self.skipTest("openpyxl not installed")
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            build_workbook(sample_hosts(), out)
            wb = load_workbook(out)
        self.assertEqual(wb["Checklist"].freeze_panes, "D2")   # header + 3 id cols
        self.assertEqual(wb["Services"].freeze_panes, "C2")
        self.assertFalse(wb["Checklist"].sheet_view.showGridLines)
        vs = wb["Vulnerabilities"]
        hdr = [c.value for c in vs[1]]
        sev_i = hdr.index("Severity") + 1
        crit = next(vs.cell(row=r, column=sev_i)
                    for r in range(2, vs.max_row + 1)
                    if vs.cell(row=r, column=sev_i).value == "CRITICAL")
        self.assertEqual(crit.fill.fgColor.rgb, "FFC00000")     # solid red
        self.assertEqual(crit.font.color.rgb, "FFFFFFFF")       # white text
        self.assertTrue(crit.font.bold)

    def test_raw_script_sheets_split_host_and_port_level(self):
        from recce.models import Host, Port, Script
        hosts = [
            Host(ip="10.0.0.5", hostnames=["a"], ports=[Port(portid=445,
                 service="microsoft-ds", scripts=[Script(id="smb2-security-mode",
                 output="Message signing enabled but not required")])],
                 host_scripts=[Script(id="smb-os-discovery", output="OS: Windows")]),
            Host(ip="10.0.0.6", ports=[Port(portid=21, service="ftp",
                 scripts=[Script(id="ftp-anon", output="Anonymous FTP login allowed")])]),
        ]
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            build_workbook(hosts, out)
            sheets = xlsx.read_sheets(out)
        self.assertIn("Host Scripts", sheets)
        self.assertIn("Scan Output", sheets)

        # Host-level script lands ONLY on Host Scripts, on the right IP.
        _h, host_by_ip = rows_by_ip(sheets, "Host Scripts")
        hblob = " ".join(v for row in host_by_ip["10.0.0.5"] for v in row.values())
        self.assertIn("smb-os-discovery", hblob)
        self.assertIn("OS: Windows", hblob)
        self.assertEqual(set(host_by_ip), {"10.0.0.5"})       # only host w/ host scripts
        # Host Scripts sheet has no Port column (host-wide, not per-port).
        self.assertNotIn("Port", sheets["Host Scripts"][0])

        # Port-level scripts land on Scan Output, and NOT the host-level one.
        _h2, port_by_ip = rows_by_ip(sheets, "Scan Output")
        pblob = " ".join(v for row in port_by_ip["10.0.0.5"] for v in row.values())
        self.assertIn("smb2-security-mode", pblob)
        self.assertNotIn("smb-os-discovery", pblob)           # host script not here
        pblob6 = " ".join(v for row in port_by_ip["10.0.0.6"] for v in row.values())
        self.assertIn("Anonymous FTP login allowed", pblob6)
        self.assertNotIn("ftp-anon", pblob)                   # no cross-host bleed


class ScannerCommandTest(unittest.TestCase):
    """Verify the actual nmap command assembled for each phase (mock _run)."""

    def _capture(self, fn, *a, **k):
        import recce.scanner as s
        calls = []
        orig = s._run
        s._run = lambda cmd, timeout=None: (calls.append((cmd, timeout))
                                            or s.RunOutcome(returncode=0))
        try:
            fn(*a, **k)
        finally:
            s._run = orig
        return calls

    def test_full_port_scan_flags(self):
        import recce.scanner as s
        with tempfile.TemporaryDirectory() as d:
            calls = self._capture(s.full_port_scan, "1.2.3.4",
                                  os.path.join(d, "p.xml"), s.PROFILES["standard"])
        cmd = calls[0][0]
        self.assertIn("-p-", cmd)                 # full sweep by default
        self.assertIn("--host-timeout", cmd)
        self.assertIn("--max-retries", cmd)
        self.assertIn("1.2.3.4", cmd)
        self.assertIsNotNone(calls[0][1])         # subprocess timeout set

    def test_enum_scan_flags(self):
        import recce.scanner as s
        with tempfile.TemporaryDirectory() as d:
            calls = self._capture(s.enum_scan, "1.2.3.4", [80, 445],
                                  os.path.join(d, "e.xml"), s.PROFILES["standard"])
        cmd = calls[0][0]
        j = " ".join(cmd)
        self.assertIn("-sV", cmd)
        self.assertIn("--version-intensity", cmd)     # standard = intensity gate
        self.assertIn("--host-timeout", cmd)
        self.assertIn("smb-os-discovery", j)          # AD enrichment scripts
        self.assertIn("80,445", j)                    # exactly the ports given

    def test_vuln_scan_safe_vs_aggressive(self):
        import recce.scanner as s
        with tempfile.TemporaryDirectory() as d:
            safe = self._capture(s.vuln_scan, "1.2.3.4", [80],
                                 os.path.join(d, "v.xml"), s.PROFILES["standard"])
            agg = self._capture(s.vuln_scan, "1.2.3.4", [80],
                                os.path.join(d, "v.xml"), s.PROFILES["standard"],
                                aggressive=True)
        self.assertIn("vuln and safe", " ".join(safe[0][0]))
        self.assertIn("--version-light", safe[0][0])   # not a full re-scan
        self.assertIn("vuln or vulners", " ".join(agg[0][0]))

    def test_version_all_profile_uses_version_all(self):
        import recce.scanner as s
        with tempfile.TemporaryDirectory() as d:
            calls = self._capture(s.enum_scan, "1.2.3.4", [80],
                                  os.path.join(d, "e.xml"), s.PROFILES["thorough"])
        self.assertIn("--version-all", calls[0][0])

    def test_no_ports_writes_empty_xml_and_no_scan(self):
        import recce.scanner as s
        with tempfile.TemporaryDirectory() as d:
            xmlp = os.path.join(d, "e.xml")
            calls = self._capture(s.enum_scan, "1.2.3.4", [], xmlp,
                                  s.PROFILES["standard"])
            self.assertEqual(calls, [])                # nothing scanned
            self.assertTrue(os.path.exists(xmlp))      # but a parseable stub exists
            self.assertEqual(parser.parse_nmap_xml(xmlp), [])


class MarkdownCsvFidelityTest(unittest.TestCase):
    def test_markdown_attributes_findings_to_correct_host(self):
        from recce.report_markdown import build_markdown
        with tempfile.TemporaryDirectory() as d:
            md = os.path.join(d, "r.md")
            build_markdown(sample_hosts(), md, title="Eng", domains=[])
            with open(md) as fh:
                text = fh.read()
        self.assertIn("Eng", text)
        self.assertIn("10.0.10.10", text)
        # The DC's finding is present and tied to the DC's IP line.
        dc_line = next(ln for ln in text.splitlines()
                       if "ms17-010" in ln)
        self.assertIn("10.0.10.10", dc_line)

    def test_csv_one_row_per_open_port_with_correct_ip(self):
        import csv as csvmod
        from recce.report_markdown import build_csv
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.csv")
            build_csv(sample_hosts(), p)
            with open(p) as fh:
                rows = list(csvmod.reader(fh))
        hdr, data = rows[0], rows[1:]
        self.assertEqual(len(data), sum(len(FACTS[ip]["ports"]) for ip in FACTS))
        ipc, portc = hdr.index("ip"), hdr.index("port")
        # The FTP port row (21) belongs to web02.
        ftp = [r for r in data if r[portc] == "21"]
        self.assertEqual(len(ftp), 1)
        self.assertEqual(ftp[0][ipc], "10.0.20.6")
        # Every row's port genuinely belongs to that row's IP.
        for r in data:
            self.assertIn(int(r[portc]), FACTS[r[ipc]]["ports"])


def _nmap_xml(ip, ports):
    """Build a minimal, parseable nmap XML for a host with the given ports.

    ports: list of dicts {port, service, product?, version?, scripts?:[(id,out)]}.
    """
    body = [f'<host><status state="up"/>'
            f'<address addr="{ip}" addrtype="ipv4"/><ports>']
    for p in ports:
        body.append(f'<port protocol="tcp" portid="{p["port"]}">'
                    f'<state state="open"/>')
        svc = f'<service name="{p.get("service", "")}"'
        if p.get("product"):
            svc += f' product="{p["product"]}"'
        if p.get("version"):
            svc += f' version="{p["version"]}"'
        body.append(svc + '/>')
        for sid, out in p.get("scripts", []):
            body.append(f'<script id="{sid}" output="{out}"/>')
        body.append('</port>')
    body.append('</ports></host>')
    return '<?xml version="1.0"?><nmaprun start="1">' + "".join(body) + '</nmaprun>'


def _fake_scan(out, ip, ports):
    """Write a canned nmap XML and return the (path, issue) tuple a scan fn does."""
    with open(out, "w") as fh:
        fh.write(_nmap_xml(ip, ports))
    return out, None


class ModelSerializationTest(unittest.TestCase):
    """Host/Domain survive the exact JSON round-trip the store uses (no field loss)."""

    def _rich_host(self):
        from recce.models import Account, Exploit, Script
        return Host(
            ip="10.0.0.5", subnet="10.0.0.0/24", hostnames=["h1", "h1.corp"],
            os_name="Linux 5.4", os_family="Linux", os_accuracy=95,
            roles=["Domain Controller"], ntlm={"domain": "CORP"},
            smb_signing="not required", enumerated=True, db_scanned=True,
            privesc_checked=True, cred_enumerated=True, notes="a note",
            ports=[Port(portid=445, service="microsoft-ds", product="Samba",
                        version="4.13", vuln_scanned=True,
                        scripts=[Script(id="smb-os", output="x", elements={"k": "v"})])],
            vulns=[Vuln(ip="10.0.0.5", port=445, protocol="tcp", script_id="v",
                        title="t", severity="high", ids=["CVE-2020-1"],
                        cwes=["CWE-78"], source="version-db", confidence="likely")],
            accounts=[Account(ip="10.0.0.5", source="smb", kind="user", name="a",
                              domain="CORP", rid="500", attrs={"spn": "x"})],
            exploits=[Exploit(ip="10.0.0.5", port=445, edb_id="123",
                              title="e", cves=["CVE-2020-1"])],
            host_scripts=[Script(id="hs", output="o")])

    def test_host_json_roundtrip_via_store_encoding(self):
        import json
        h = self._rich_host()
        h2 = Host.from_json(json.loads(json.dumps(h.to_json())))
        # Scalars + all progress flags.
        for f in ("ip", "subnet", "os_name", "os_family", "smb_signing", "notes",
                  "enumerated", "db_scanned", "privesc_checked", "cred_enumerated"):
            self.assertEqual(getattr(h2, f), getattr(h, f), f)
        self.assertEqual(h2.hostnames, h.hostnames)
        self.assertEqual(h2.roles, h.roles)
        self.assertEqual(h2.ntlm, h.ntlm)
        # Nested structures.
        self.assertEqual(h2.ports[0].scripts[0].elements, {"k": "v"})
        self.assertTrue(h2.ports[0].vuln_scanned)
        self.assertEqual(h2.vulns[0].cwes, ["CWE-78"])       # newest field survives
        self.assertEqual(h2.vulns[0].ids, ["CVE-2020-1"])
        self.assertEqual(h2.accounts[0].attrs, {"spn": "x"})
        self.assertEqual(h2.exploits[0].edb_id, "123")
        self.assertEqual(h2.host_scripts[0].id, "hs")

    def test_domain_json_roundtrip(self):
        from recce.models import Domain
        import json
        d = Domain(name="corp.local", netbios="CORP", dc_ips=["10.0.10.10"],
                   anonymous_bind=True, password_policy={"min": 7},
                   trusts=[{"name": "x"}], sources=["nse"])
        d2 = Domain.from_json(json.loads(json.dumps(d.to_json())))
        self.assertEqual(d2.name, "corp.local")
        self.assertEqual(d2.dc_ips, ["10.0.10.10"])
        self.assertTrue(d2.anonymous_bind)
        self.assertEqual(d2.password_policy, {"min": 7})


class PhaseWorkerTest(unittest.TestCase):
    """The real enum/vuln/db/privesc workers, with scanner mocked (no nmap)."""

    def _paths(self, d):
        from recce import cli
        return cli._open_paths(d)

    def test_enum_worker_folds_ports_flags_and_runs_vulndb(self):
        from recce import cli
        import recce.scanner as s
        orig = s.enum_scan
        s.enum_scan = lambda ip, ports, out, profile, creds=None: _fake_scan(
            out, ip, [{"port": 21, "service": "ftp", "product": "vsftpd",
                       "version": "2.3.4"}])
        try:
            with tempfile.TemporaryDirectory() as d:
                paths = self._paths(d)
                host, issues = cli._enum_worker(
                    "10.0.0.5", s.PROFILES["standard"], paths, None,
                    {"10.0.0.5": [21]}, {"10.0.0.5": "10.0.0.0/24"})
        finally:
            s.enum_scan = orig
        self.assertTrue(host.enumerated)
        self.assertEqual([p.portid for p in host.open_ports], [21])
        self.assertEqual(host.subnet, "10.0.0.0/24")
        # vulndb ran inside the worker and flagged the vsftpd backdoor.
        self.assertTrue(any("vsftpd 2.3.4 backdoor" in v.title for v in host.vulns))
        self.assertEqual(issues, [])

    def test_vuln_worker_merges_findings_and_marks_ports(self):
        from recce import cli
        import recce.scanner as s
        orig = s.vuln_scan
        s.vuln_scan = lambda ip, ports, out, profile, creds=None, aggressive=False: \
            _fake_scan(out, ip, [{"port": 80, "service": "http", "scripts": [
                ("http-vuln-x", "VULNERABLE: demo issue State: VULNERABLE")]}])
        try:
            with tempfile.TemporaryDirectory() as d:
                paths = self._paths(d)
                host = Host(ip="10.0.0.5", ports=[Port(portid=80, service="http",
                            state="open")])
                host, issues = cli._vuln_worker(
                    host, [80], s.PROFILES["standard"], paths, None,
                    aggressive=False, use_ss=False, use_probes=False)
        finally:
            s.vuln_scan = orig
        self.assertTrue(host.ports[0].vuln_scanned)          # port marked done
        self.assertTrue(any("http-vuln-x" in (v.script_id or "") for v in host.vulns))
        self.assertEqual(issues, [])

    def test_db_worker_sets_db_scanned(self):
        from recce import cli
        import recce.scanner as s
        orig = s.nse_scan
        s.nse_scan = lambda ip, ports, out, profile, scripts, creds=None: _fake_scan(
            out, ip, [{"port": 3306, "service": "mysql"}])
        try:
            with tempfile.TemporaryDirectory() as d:
                paths = self._paths(d)
                host = Host(ip="10.0.0.5", ports=[Port(portid=3306, service="mysql",
                            state="open")])
                host, issues = cli._db_worker(host, [3306], s.PROFILES["standard"],
                                              paths, None, aggressive=False,
                                              use_ss=False)
        finally:
            s.nse_scan = orig
        self.assertTrue(host.db_scanned)
        self.assertTrue(host.ports[0].vuln_scanned)
        self.assertEqual(issues, [])

    def test_privesc_worker_returns_host_and_issues(self):
        from recce import cli
        import recce.scanner as s
        orig = s.nse_scan
        s.nse_scan = lambda ip, ports, out, profile, scripts, creds=None: _fake_scan(
            out, ip, [{"port": 445, "service": "microsoft-ds"}])
        try:
            with tempfile.TemporaryDirectory() as d:
                paths = self._paths(d)
                host = Host(ip="10.0.0.9", os_family="Windows",
                            ports=[Port(portid=445, service="microsoft-ds",
                                        state="open")])
                host, issues = cli._privesc_worker(host, s.PROFILES["standard"],
                                                   paths, None, aggressive=False)
        finally:
            s.nse_scan = orig
        self.assertEqual(host.ip, "10.0.0.9")
        self.assertIsInstance(issues, list)


class EnvironmentAndTargetsTest(unittest.TestCase):
    def test_check_environment_requires_nmap_and_warns(self):
        import recce.scanner as s
        from recce.scanner import ScanProfile, ScannerError
        oh, orr = s._have, s._is_root
        try:
            s._have = lambda t: False        # nothing installed
            s._is_root = lambda: False
            with self.assertRaises(ScannerError):
                s.check_environment(ScanProfile())      # nmap missing -> raise
            s._have = lambda t: t == "nmap"             # only nmap present
            warns = s.check_environment(ScanProfile())
            self.assertTrue(any("root" in w.lower() for w in warns))
            # masscan requested but absent -> warn + fall back to nmap.
            prof = ScanProfile(scanner="masscan")
            warns = s.check_environment(prof)
            self.assertEqual(prof.scanner, "nmap")
            self.assertTrue(any("masscan" in w.lower() for w in warns))
        finally:
            s._have, s._is_root = oh, orr

    def test_load_targets_from_file_with_comments_and_cidr(self):
        from recce.targets import load_targets
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "scope.txt")
            with open(f, "w") as fh:
                fh.write("10.0.0.1\n# a comment\n10.0.0.2   # trailing\n"
                         "10.0.1.0/30\n\n")
            hosts, sm = load_targets(["@" + f])
        self.assertIn("10.0.0.1", hosts)
        self.assertIn("10.0.0.2", hosts)
        self.assertIn("10.0.1.1", hosts)                 # expanded from the CIDR
        self.assertEqual(sm["10.0.1.1"], "10.0.1.0/30")  # CIDR line -> subnet label

    def test_missing_target_file_raises(self):
        from recce.targets import load_targets
        with self.assertRaises(FileNotFoundError):
            load_targets(["@/no/such/file.txt"])


class TargetingFormE2ETest(unittest.TestCase):
    """Drive the REAL `vulns` command end-to-end (parser -> selection -> workers ->
    store) and prove each targeting form selects EXACTLY the right stored hosts.

    This locks in the core promise that every phase works on a single IP, several
    IPs, a dash range, a whole subnet, an @file, or 'everything' - using the same
    CLI grammar, with no cross-host bleed. The scanner is mocked so no nmap runs;
    the selection layer under test is entirely real.

    Seeded scope (from the bundled sample): 10.0.10.10, 10.0.10.25 (10.0.10.0/24)
    and 10.0.20.5, 10.0.20.6 (10.0.20.0/24).
    """

    ALL = {"10.0.10.10", "10.0.10.25", "10.0.20.5", "10.0.20.6"}

    def _run_vulns(self, targets):
        """Run `vulns <targets>` against a freshly seeded store; return the set of
        IPs that actually got vuln-scanned (i.e. the hosts the phase selected)."""
        from recce import cli
        import recce.scanner as s

        d = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        paths = cli._open_paths(d)
        seed = Store(paths["db"])
        seed.set_meta("engagement", "e2e")
        for h in sample_hosts():
            seed.upsert_host(h)
        seed.close()

        def fake_vuln(ip, portids, out, profile, creds=None, aggressive=False):
            # Echo the requested ports back as an open-port XML the worker parses.
            return _fake_scan(out, ip, [{"port": p, "service": "tcp"}
                                        for p in portids])

        oc, ov, ou = s.check_environment, s.vuln_scan, s.udp_scan
        s.check_environment = lambda profile: []          # no nmap/root needed
        s.vuln_scan = fake_vuln
        s.udp_scan = lambda ip, out, profile: _fake_scan(out, ip, [])
        argv = ["vulns", *targets, "-o", d, "--yes",
                "--no-searchsploit", "--no-probes", "--workers", "1"]
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                rc = cli.main(argv)
        finally:
            s.check_environment, s.vuln_scan, s.udp_scan = oc, ov, ou
        self.assertEqual(rc, 0)

        store = Store(paths["db"])
        try:
            scanned = {h.ip for h in store.all_hosts()
                       if any(p.vuln_scanned for p in h.open_ports)}
            # Every seeded host must still be present (selection never drops rows).
            self.assertEqual({h.ip for h in store.all_hosts()}, self.ALL)
        finally:
            store.close()
        return scanned

    def test_single_ip(self):
        self.assertEqual(self._run_vulns(["10.0.10.10"]), {"10.0.10.10"})

    def test_several_ips(self):
        self.assertEqual(self._run_vulns(["10.0.10.10", "10.0.20.6"]),
                         {"10.0.10.10", "10.0.20.6"})

    def test_dash_range(self):
        # .10-.25 covers both 10.0.10.x hosts and nothing in 10.0.20.x.
        self.assertEqual(self._run_vulns(["10.0.10.10-25"]),
                         {"10.0.10.10", "10.0.10.25"})

    def test_range_excludes_outside(self):
        # A range that stops before .25 must NOT pick it up.
        self.assertEqual(self._run_vulns(["10.0.10.1-15"]), {"10.0.10.10"})

    def test_whole_subnet(self):
        self.assertEqual(self._run_vulns(["10.0.20.0/24"]),
                         {"10.0.20.5", "10.0.20.6"})

    def test_mixed_single_and_subnet(self):
        self.assertEqual(self._run_vulns(["10.0.10.25", "10.0.20.0/24"]),
                         {"10.0.10.25", "10.0.20.5", "10.0.20.6"})

    def test_at_file(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        f = os.path.join(d, "scope.txt")
        with open(f, "w") as fh:
            fh.write("10.0.10.10\n"
                     "10.0.20.0/24   # the linux subnet\n")
        self.assertEqual(self._run_vulns(["@" + f]),
                         {"10.0.10.10", "10.0.20.5", "10.0.20.6"})

    def test_empty_targets_selects_everything(self):
        self.assertEqual(self._run_vulns([]), self.ALL)


class EntryPointTest(unittest.TestCase):
    def test_module_entrypoint_runs(self):
        import subprocess
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = dict(os.environ, PYTHONPATH=root)
        r = subprocess.run([sys.executable, "-m", "recce", "--version"],
                           capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(r.returncode, 0)
        self.assertIn("recce", (r.stdout + r.stderr).lower())


if __name__ == "__main__":
    unittest.main()
