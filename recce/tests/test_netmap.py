"""Architecture / network map built from the enumeration."""
import os
import tempfile
import unittest

from recce import netmap
from recce.models import Host, Port
from recce.models import Domain


def _h(ip, subnet="10.0.10.0/24", ports=(), roles=(), os_name="", hostname="",
       access=False, vulns=()):
    from recce.models import Vuln
    return Host(ip=ip, subnet=subnet, state="up", up_reason="syn-ack",
                hostnames=[hostname] if hostname else [], os_name=os_name,
                roles=list(roles), access_gained=access,
                vulns=[Vuln(ip=ip, port=None, protocol="tcp", script_id="v",
                            title="v", severity=sev, source="nse",
                            confidence=conf) for sev, conf in vulns],
                ports=[Port(portid=p, protocol="tcp", state="open", service=s)
                       for p, s in ports])


class RoleTest(unittest.TestCase):

    def test_role_classification(self):
        dc = _h("10.0.10.10", ports=[(389, "ldap"), (445, "microsoft-ds")],
                roles=["Domain Controller"])
        self.assertEqual(netmap.primary_role(dc), "DC")           # DC beats File/SMB
        web = _h("10.0.20.5", ports=[(80, "http"), (443, "https")])
        self.assertEqual(netmap.primary_role(web), "Web")
        dbh = _h("10.0.20.6", ports=[(3306, "mysql")])
        self.assertEqual(netmap.primary_role(dbh), "DB")
        fileh = _h("10.0.10.9", ports=[(445, "microsoft-ds")])
        self.assertEqual(netmap.primary_role(fileh), "File/SMB")
        ws = _h("10.0.10.50", ports=[(3389, "ms-wbt-server")],
                os_name="Microsoft Windows 10 21H2")
        self.assertEqual(netmap.primary_role(ws), "Workstation")
        bare = _h("10.0.10.60", ports=[(23, "telnet")])
        self.assertEqual(netmap.primary_role(bare), "Host")


class MermaidTest(unittest.TestCase):

    def _hosts(self):
        return [
            _h("10.0.10.10", ports=[(389, "ldap"), (445, "microsoft-ds")],
               roles=["Domain Controller"], hostname="dc01", os_name="Windows Server 2019"),
            _h("10.0.20.5", subnet="10.0.20.0/24", ports=[(80, "http")],
               hostname="web01", os_name="Linux 5.4"),
        ]

    def test_mermaid_has_segments_roles_and_domain_edges(self):
        doms = [Domain(name="corp.local", dc_ips=["10.0.10.10"])]
        mm = netmap.mermaid(self._hosts(), doms)
        self.assertTrue(mm.startswith("flowchart TB"))
        self.assertIn('subgraph seg0["10.0.10.0/24', mm)
        self.assertIn('subgraph seg1["10.0.20.0/24', mm)
        self.assertIn(":::dc", mm)                     # DC node styled
        self.assertIn(":::web", mm)
        self.assertIn("AD domain", mm)
        self.assertIn("-->|DC of|", mm)                # DC edge to its domain
        self.assertIn("classDef dc", mm)               # legend/colours present

    def test_trust_edges_only_when_observed(self):
        # A trust to another in-scope domain draws an edge; nothing invented.
        doms = [Domain(name="corp.local", dc_ips=["10.0.10.10"],
                       trusts=[{"name": "child.corp.local", "direction": "Bidirectional"}]),
                Domain(name="child.corp.local", dc_ips=[])]
        mm = netmap.mermaid(self._hosts(), doms)
        self.assertIn("-.->", mm)                       # a trust edge
        self.assertIn("trust", mm)

    def test_empty_is_graceful(self):
        self.assertIn("No hosts enumerated", netmap.mermaid([]))
        self.assertIn("No hosts enumerated", netmap.dot([]))
        self.assertIn("No hosts", netmap.svg([]))

    def test_svg_renders_directly_and_is_self_contained(self):
        import xml.dom.minidom as md
        doms = [Domain(name="corp.local", dc_ips=["10.0.10.10"])]
        s = netmap.svg(self._hosts(), doms)
        self.assertTrue(s.startswith("<svg"))
        md.parseString(s)                              # well-formed XML (renders anywhere)
        self.assertNotIn("xmlns", s)                   # inline, self-contained
        self.assertNotIn("http://", s)
        self.assertIn("#C00000", s)                    # DC role colour
        self.assertIn("<path", s)                      # DC -> domain edge
        self.assertIn("10.0.10.10", s)

    def test_svg_aggregates_large_estate(self):
        many = [_h(f"10.0.0.{i}", ports=[(80, "http")]) for i in range(1, 60)]
        s = netmap.svg(many)
        import xml.dom.minidom as md
        md.parseString(s)
        self.assertIn("×", s)                          # "N× Web" aggregate labels

    def test_dot_renders(self):
        d = netmap.dot(self._hosts(), [Domain(name="corp.local", dc_ips=["10.0.10.10"])])
        self.assertIn("digraph architecture", d)
        self.assertIn("cluster_", d)
        self.assertIn("DC of", d)

    def test_summary_is_grounded(self):
        lines = netmap.summary(self._hosts(),
                               [Domain(name="corp.local", dc_ips=["10.0.10.10"])])
        joined = " ".join(lines)
        self.assertIn("2 host(s)", joined)
        self.assertIn("2 network segment(s)", joined)
        self.assertIn("corp.local", joined)

    def test_label_is_mermaid_safe(self):
        # Quotes/brackets in a hostname must not break the node syntax.
        h = _h("10.0.0.1", hostname='we"ird[name]', ports=[(80, "http")])
        mm = netmap.mermaid([h])
        self.assertNotIn('"we"ird', mm)                # inner quote neutralised


class NetworkMapEnrichmentTest(unittest.TestCase):
    """The network map is enriched from SharpHound + other findings: DCs confirmed
    from AD ground-truth, an access overlay, and a per-host risk dot."""

    def _ad(self):
        return {"architecture": {"nodes": {
            "S-1-5-21-1-1-1-1000": {"type": "Computer", "label": "DC01.CORP.LOCAL",
                                    "dc": True, "hv": True, "tier": 1}},
            "edges": [], "trusts": [], "truncated": False}}

    def test_dc_confirmed_from_sharphound(self):
        # A host with only 445 open and no DC role — SharpHound says it's a DC.
        dc = _h("10.0.10.10", ports=[(445, "microsoft-ds")], hostname="dc01.corp.local")
        self.assertEqual(netmap.primary_role(dc), "File/SMB")     # ports alone
        self.assertEqual(netmap.role_with_ad(dc, netmap.ad_dc_names(self._ad())), "DC")
        s = netmap.svg([dc], None, self._ad())
        import xml.dom.minidom as md
        md.parseString(s)
        self.assertIn("#C00000", s)                               # DC role colour

    def test_access_and_risk_overlay(self):
        owned = _h("10.0.20.6", subnet="10.0.20.0/24", ports=[(21, "ftp")],
                   hostname="web02", access=True, vulns=[("critical", "confirmed")])
        s = netmap.svg([owned])
        import xml.dom.minidom as md
        md.parseString(s)
        self.assertIn("#2E7D32", s)                     # green access outline/badge
        self.assertIn("✓", s)                           # access check mark
        self.assertIn("#C00000", s)                     # critical risk dot
        self.assertIn("access confirmed", s)            # legend key present

    def test_potential_vuln_not_counted_as_risk(self):
        # An unverified 'potential' finding must NOT light the risk dot.
        h = _h("10.0.0.9", ports=[(80, "http")], vulns=[("high", "potential")])
        self.assertEqual(netmap.worst_severity(h), "")
        s = netmap.svg([h])
        self.assertNotIn("access confirmed", s)         # no access, no overlay legend

    def test_summary_reports_access_and_confirmed_dc(self):
        hosts = [_h("10.0.10.10", ports=[(445, "microsoft-ds")], hostname="dc01"),
                 _h("10.0.20.6", subnet="10.0.20.0/24", ports=[(21, "ftp")],
                    hostname="web02", access=True, vulns=[("critical", "confirmed")])]
        lines = " ".join(netmap.summary(hosts, None, self._ad()))
        self.assertIn("1 with confirmed access", lines)
        self.assertIn("1 with critical/high findings", lines)
        self.assertIn("AD-confirmed Domain Controller", lines)


class AdArchitectureSvgTest(unittest.TestCase):

    def _arch(self):
        B = "S-1-5-21-9-9-9"
        return {
            "nodes": {
                B: {"type": "Domain", "label": "CORP.LOCAL", "domain": "",
                    "hv": True, "dc": False, "tier": 0},
                "S-1-5-21-7-7-7": {"type": "Domain", "label": "CHILD.CORP.LOCAL",
                                   "domain": "", "hv": True, "dc": False, "tier": 0},
                f"{B}-512": {"type": "Group", "label": "DOMAIN ADMINS", "domain": "CORP.LOCAL",
                             "hv": True, "dc": False, "tier": 1},
                f"{B}-1000": {"type": "Computer", "label": "DC01", "domain": "CORP.LOCAL",
                              "hv": True, "dc": True, "tier": 1},
                f"{B}-1105": {"type": "Group", "label": "HELPDESK", "domain": "CORP.LOCAL",
                              "hv": False, "dc": False, "tier": 2},
                f"{B}-1001": {"type": "User", "label": "BOB", "domain": "CORP.LOCAL",
                              "hv": False, "dc": False, "tier": 2},
            },
            "edges": [[f"{B}-1105", "MemberOf", f"{B}-512"],
                      [f"{B}-1001", "GenericAll", f"{B}-1105"],
                      [f"{B}-1001", "DCSync", B]],
            "trusts": [["CORP.LOCAL", "Bidirectional", "CHILD.CORP.LOCAL"]],
            "truncated": False,
        }

    def test_ad_svg_renders_and_is_self_contained(self):
        import xml.dom.minidom as md
        s = netmap.ad_svg(self._arch())
        self.assertTrue(s.startswith("<svg"))
        md.parseString(s)                              # well-formed XML (renders anywhere)
        self.assertNotIn("xmlns", s)                   # inline, self-contained
        self.assertNotIn("http://", s)
        self.assertIn("DOMAIN ADMINS", s)              # a high-value group
        self.assertIn("CORP.LOCAL", s)                 # the domain
        self.assertIn("DC01", s)                       # the Domain Controller
        self.assertIn("#C00000", s)                    # DC / control-edge colour
        self.assertIn("GenericAll", s)                 # a control edge is labelled
        self.assertIn("DCSync", s)
        self.assertIn("trust", s)                      # domain trust edge label
        self.assertIn("<path", s)

    def test_ad_svg_empty_is_graceful(self):
        s = netmap.ad_svg({})
        self.assertIn("No BloodHound", s)
        self.assertTrue(s.startswith("<svg"))

    def test_ad_svg_access_and_risk_overlay(self):
        import xml.dom.minidom as md
        arch = self._arch()
        # We hold ADMINISTRATOR-equivalent principal BOB; a DCSync edge targets the
        # domain (critical) — both overlays should appear, grounded in the data.
        s = netmap.ad_svg(arch, owned_labels={"BOB"})
        md.parseString(s)
        self.assertIn("✓", s)                          # held principal marked
        self.assertIn("already held", s)               # access legend key
        self.assertIn("directly seizable", s)          # risk legend key
        self.assertIn("#C00000", s)                    # critical (DCSync target) dot
        # No owned set → no access legend key (stays honest).
        self.assertNotIn("already held", netmap.ad_svg(arch))

    def test_ad_svg_truncation_note(self):
        arch = self._arch()
        arch["truncated"] = True
        self.assertIn("truncated", netmap.ad_svg(arch).lower())


class ReportEmbedTest(unittest.TestCase):

    def test_network_map_in_assets_page(self):
        from recce import report_html
        hosts = [_h("10.0.10.10", ports=[(445, "microsoft-ds")],
                    roles=["Domain Controller"], hostname="dc01")]
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "assets.html")
            report_html.build_assets_html(
                hosts, p, title="Map",
                domains=[Domain(name="corp.local", dc_ips=["10.0.10.10"])])
            with open(p, encoding="utf-8") as fh:
                html = fh.read()
        self.assertIn("Network map", html)
        self.assertIn("<svg", html)                    # renders directly, no tools
        self.assertIn("logical", html)                 # honest caveat
        self.assertNotIn("xmlns", html)                # inline SVG stays self-contained
        for bad in ("src=", "<link", "<script"):
            self.assertNotIn(bad, html)


if __name__ == "__main__":
    unittest.main()
