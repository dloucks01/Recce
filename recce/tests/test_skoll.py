"""Sköll-Fieldkit bridge: export (recce -> Sköll) and import (Sköll -> recce).

Covers the round-trip contract: recce synthesizes an nmap-greppable + a rich bridge
JSON + a plan Sköll consumes, and folds a Sköll findings.json (raw or the enriched
recce_findings.json) back into confirmed Vulns that reach the workbook + report.
No network, no tools - pure data transforms, so it runs airgapped like the tool.
"""
import json
import os
import re
import shutil
import tempfile
import unittest

from recce import cli
from recce import skoll
from recce.models import Host, Port, Vuln
from recce.store import Store


def _win_host():
    h = Host(ip="10.0.10.10", subnet="10.0.10.0/24", enumerated=True,
             hostnames=["dc01.corp.local"], os_name="Windows Server 2019",
             os_accuracy=96, roles=["Domain Controller"], smb_signing="required")
    h.ports = [Port(portid=445, state="open", service="microsoft-ds",
                    product="Microsoft Windows Server 2019"),
               Port(portid=88, state="open", service="kerberos-sec"),
               Port(portid=3389, state="open", service="ms-wbt-server")]
    h.vulns = [Vuln(ip="10.0.10.10", port=445, protocol="tcp",
                    script_id="smb-vuln-ms17-010", state="finding",
                    title="smb-vuln-ms17-010", severity="critical",
                    confidence="confirmed", source="nse", ids=["CVE-2017-0143"])]
    return h


def _web_host():
    h = Host(ip="10.0.20.5", subnet="10.0.20.0/24", enumerated=True,
             hostnames=["web01"], os_name="Linux 5.4", os_accuracy=94)
    h.ports = [Port(portid=80, state="open", service="http", product="Apache httpd",
                    version="2.4.41"),
               Port(portid=443, state="open", service="https", product="Apache httpd",
                    version="2.4.41")]
    # same weakness confirmed on two ports -> must collapse to one bridge finding
    h.vulns = [Vuln(ip="10.0.20.5", port=80, protocol="tcp", script_id="vulners",
                    state="finding", title="Apache httpd multiple vulns",
                    severity="high", confidence="confirmed", source="version-db",
                    ids=["CVE-2022-22720"]),
               Vuln(ip="10.0.20.5", port=443, protocol="tcp", script_id="vulners",
                    state="finding", title="Apache httpd multiple vulns",
                    severity="high", confidence="confirmed", source="version-db",
                    ids=["CVE-2023-25690"]),
               Vuln(ip="10.0.20.5", port=80, protocol="tcp", script_id="http-methods",
                    state="finding", title="Risky HTTP methods",
                    severity="low", confidence="potential", source="nse")]
    return h


class ExportTest(unittest.TestCase):

    def test_gnmap_is_valid_greppable_sweep_can_parse(self):
        gn = skoll.build_gnmap([_win_host(), _web_host()])
        # Re-parse with the exact regexes sweep.py triage uses.
        hosts = {}
        for line in gn.splitlines():
            m = re.search(r"Host:\s+(\S+)\s+\(([^)]*)\)", line)
            if not m or "Ports:" not in line:
                continue
            ports = {int(p) for p in re.findall(r"(\d+)/open/", line)}
            hosts[m.group(1)] = (m.group(2), ports)
        self.assertIn("10.0.10.10", hosts)
        self.assertEqual(hosts["10.0.10.10"][0], "dc01.corp.local")
        self.assertEqual(hosts["10.0.10.10"][1], {445, 88, 3389})
        self.assertEqual(hosts["10.0.20.5"][1], {80, 443})

    def test_bridge_has_ports_and_confirmed_findings(self):
        b = skoll.build_bridge([_win_host(), _web_host()], engagement="Eng")
        self.assertEqual(b["_recce_bridge"], skoll.BRIDGE_VERSION)
        by_ip = {h["ip"]: h for h in b["hosts"]}
        dc = by_ip["10.0.10.10"]
        self.assertEqual(dc["findings"][0]["severity"], "critical")
        self.assertIn("CVE-2017-0143", dc["findings"][0]["cves"])
        # a 445 open port suggests the smb generator
        self.assertTrue(any("gen_smb" in r["module"] for r in dc["suggested"]))

    def test_bridge_collapses_same_finding_across_ports(self):
        b = skoll.build_bridge([_web_host()])
        web = b["hosts"][0]
        apache = [f for f in web["findings"] if f["title"] == "Apache httpd multiple vulns"]
        self.assertEqual(len(apache), 1)                       # deduped by title
        self.assertEqual(set(apache[0]["ports"]), {80, 443})   # ports unioned
        self.assertEqual(set(apache[0]["cves"]), {"CVE-2022-22720", "CVE-2023-25690"})
        # the 'potential' finding is excluded (only confirmed reach Sköll)
        self.assertFalse(any(f["title"] == "Risky HTTP methods" for f in web["findings"]))

    def test_plan_md_ranks_and_names_generators(self):
        b = skoll.build_bridge([_win_host(), _web_host()], engagement="Eng")
        md = skoll.build_plan_md(b)
        self.assertIn("Sköll attack plan", md)
        self.assertIn("dc01.corp.local", md)
        self.assertIn("gen_smb", md)
        self.assertIn("CVE-2017-0143", md)


class ImportTest(unittest.TestCase):

    def test_parse_affected_host(self):
        self.assertEqual(skoll.parse_affected_host("10.0.0.5 (WIN-SQL01)"),
                         ("10.0.0.5", "WIN-SQL01"))
        self.assertEqual(skoll.parse_affected_host("10.0.0.6 (web01, Ubuntu 22.04)"),
                         ("10.0.0.6", "web01"))
        self.assertEqual(skoll.parse_affected_host("justahost")[0], "")

    def test_raw_findings_json_folds_with_fallback_severity(self):
        data = {"findings": [{
            "title": "Passwordless sudo on find", "vector_type": "gtfobins_sudo",
            "affected_host": "10.0.0.6 (web01)", "severity": "High",
            "evidence": "find -exec spawned a root shell",
            "steps": [{"cmd": "sudo -l", "output": "(root) NOPASSWD: /usr/bin/find"}],
            "references": "CVE-2020-0000",
        }]}
        hosts = skoll.findings_to_hosts(data)
        self.assertIn("10.0.0.6", hosts)
        v = hosts["10.0.0.6"]["vulns"][0]
        self.assertEqual(v.severity, "high")             # lowercased for recce
        self.assertEqual(v.source, "skoll")
        self.assertEqual(v.confidence, "confirmed")
        self.assertIn("CVE-2020-0000", v.ids)
        self.assertIn("sudo -l", v.output)               # PoC step captured

    def test_enriched_recce_block_wins(self):
        data = {"_recce_import": 1, "findings": [{
            "title": "Unquoted service path", "vector_type": "unquoted_service",
            "affected_host": "ignored", "steps": [{"cmd": "sc", "output": "x"}],
            "_recce": {"ip": "10.0.0.5", "hostname": "WIN-SQL01", "port": None,
                       "severity": "high", "cwes": ["CWE-428"],
                       "remediation": "Quote the ImagePath.", "ids": ["CVE-1"]},
        }]}
        hosts = skoll.findings_to_hosts(data)
        v = hosts["10.0.0.5"]["vulns"][0]
        self.assertEqual(hosts["10.0.0.5"]["hostname"], "WIN-SQL01")
        self.assertEqual(v.cwes, ["CWE-428"])
        self.assertEqual(v.remediation, "Quote the ImagePath.")


class RoundTripCliTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.eng = os.path.join(self.dir, "eng")
        paths = cli._open_paths(self.eng)
        store = Store(paths["db"])
        store.upsert_host(_win_host())
        store.upsert_host(_web_host())
        store.close()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _args(self, **kw):
        import argparse
        ns = argparse.Namespace(output_dir=self.eng, title="T", targets=[],
                                host=[], subnet=[])
        for k, v in kw.items():
            setattr(ns, k, v)
        return ns

    def test_export_writes_seed_files(self):
        rc = cli.cmd_skoll_export(self._args())
        self.assertEqual(rc, 0)
        sk = os.path.join(self.eng, "skoll")
        for name in ("ports.gnmap", "smb-null.txt", "recce-bridge.json", "SKOLL.md"):
            self.assertTrue(os.path.exists(os.path.join(sk, name)), name)
        bridge = json.load(open(os.path.join(sk, "recce-bridge.json")))
        self.assertEqual(len(bridge["hosts"]), 2)

    def test_import_lands_in_store_and_marks_access(self):
        ff = os.path.join(self.dir, "recce_findings.json")
        json.dump({"source": "skoll", "findings": [{
            "title": "vsftpd 2.3.4 backdoor", "vector_type": "exposed_service_cve",
            "affected_host": "10.0.20.5 (web01)",
            "steps": [{"cmd": "nc host 21", "output": "230 Login successful"}],
            "_recce": {"ip": "10.0.20.5", "hostname": "web01", "port": 21,
                       "severity": "critical", "cwes": ["CWE-78"],
                       "remediation": "Reinstall vsftpd from a trusted source.",
                       "ids": ["CVE-2011-2523"]},
        }]}, open(ff, "w"))
        rc = cli.cmd_skoll_import(self._args(findings=ff))
        self.assertEqual(rc, 0)
        store = Store(cli._open_paths(self.eng)["db"])
        h = store.get_host("10.0.20.5")
        store.close()
        self.assertTrue(h.access_gained)
        skolls = [v for v in h.vulns if v.source == "skoll"]
        self.assertEqual(len(skolls), 1)
        self.assertEqual(skolls[0].severity, "critical")
        self.assertEqual(skolls[0].port, 21)
        self.assertIn("CVE-2011-2523", skolls[0].ids)

    def test_import_is_idempotent(self):
        ff = os.path.join(self.dir, "f.json")
        json.dump({"findings": [{
            "title": "dup", "vector_type": "gtfobins_sudo",
            "affected_host": "10.0.20.5 (web01)",
            "steps": [{"cmd": "sudo -l", "output": "ok"}],
        }]}, open(ff, "w"))
        cli.cmd_skoll_import(self._args(findings=ff))
        cli.cmd_skoll_import(self._args(findings=ff))
        store = Store(cli._open_paths(self.eng)["db"])
        h = store.get_host("10.0.20.5")
        store.close()
        self.assertEqual(sum(1 for v in h.vulns if v.title == "dup"), 1)


if __name__ == "__main__":
    unittest.main()
