"""Normalized data model for enumeration results.

Everything the scanners and parsers produce is coerced into these dataclasses so
the reporting layer never has to care which tool produced the data.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Script:
    """Output of a single NSE script run against a host or port."""

    id: str
    output: str = ""
    # Structured <elem>/<table> data when nmap provides it.
    elements: dict[str, Any] = field(default_factory=dict)


@dataclass
class Port:
    portid: int
    protocol: str = "tcp"
    state: str = "open"
    reason: str = ""
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    ostype: str = ""
    cpe: list[str] = field(default_factory=list)
    scripts: list[Script] = field(default_factory=list)
    vuln_scanned: bool = False   # tool progress: a vuln pass has run on this port

    @property
    def service_banner(self) -> str:
        """Human-friendly 'product version (extrainfo)' string."""
        parts = [p for p in (self.product, self.version) if p]
        banner = " ".join(parts)
        if self.extrainfo:
            banner = f"{banner} ({self.extrainfo})" if banner else self.extrainfo
        return banner

    @property
    def product_version_key(self) -> str:
        """Stable grouping key: 'product|version' (falls back to service name)."""
        prod = self.product or self.service or "unknown"
        return f"{prod}|{self.version}".strip("|")


@dataclass
class Vuln:
    ip: str
    port: int | None
    protocol: str
    script_id: str
    state: str = ""          # e.g. VULNERABLE, LIKELY VULNERABLE
    title: str = ""
    output: str = ""
    severity: str = "info"   # critical/high/medium/low/info (best-effort)
    ids: list[str] = field(default_factory=list)  # CVE / BID references
    source: str = "nse"      # nse | version-db | config
    remediation: str = ""    # how to fix (offline knowledge base)
    confidence: str = ""     # confirmed | likely | potential

    @property
    def key(self) -> str:
        # Include the title so multiple findings on one port (e.g. several
        # version-db matches) don't collide and get deduped away.
        return f"{self.ip}:{self.port}:{self.script_id}:{self.title[:60]}"


@dataclass
class Exploit:
    """A candidate exploit for a service, from an offline DB (searchsploit)."""

    ip: str
    port: int | None
    product: str = ""
    version: str = ""
    edb_id: str = ""
    title: str = ""
    type: str = ""       # remote / local / webapps / dos
    path: str = ""       # local path in exploitdb
    date: str = ""
    cves: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.ip}:{self.port}:{self.edb_id}"


@dataclass
class Account:
    """A user / account / share / domain fact discovered during AD enrichment."""

    ip: str
    source: str          # smb-enum-users, ldap, netexec, ...
    kind: str = "user"   # user / group / share / domain / computer / spn / trust
    name: str = ""
    domain: str = ""
    rid: str = ""
    detail: str = ""
    # Flexible AD attributes: uac flags, spn, memberof, description, os,
    # enabled, admincount, kerberoastable, asrep_roastable, delegation, ...
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class Domain:
    """Domain-level facts assembled from NSE output and/or LDAP enumeration."""

    name: str = ""                 # DNS domain, e.g. corp.local
    netbios: str = ""              # e.g. CORP
    forest: str = ""
    dc_ips: list[str] = field(default_factory=list)
    functional_level: str = ""
    naming_context: str = ""
    machine_account_quota: str = ""
    anonymous_bind: bool = False
    password_policy: dict[str, Any] = field(default_factory=dict)
    trusts: list[dict[str, Any]] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Domain":
        return cls(**data)


@dataclass
class Host:
    ip: str
    subnet: str = ""
    state: str = "up"
    hostnames: list[str] = field(default_factory=list)
    mac: str = ""
    vendor: str = ""
    os_name: str = ""
    os_family: str = ""
    os_accuracy: int = 0
    distance: int = 0
    ports: list[Port] = field(default_factory=list)
    vulns: list[Vuln] = field(default_factory=list)
    accounts: list[Account] = field(default_factory=list)
    exploits: list["Exploit"] = field(default_factory=list)
    host_scripts: list[Script] = field(default_factory=list)  # host-level NSE output
    roles: list[str] = field(default_factory=list)   # e.g. Domain Controller
    ntlm: dict[str, Any] = field(default_factory=dict)  # domain/fqdn/os from NTLM
    smb_signing: str = ""                            # required / not required / unknown
    enumerated: bool = False       # tool progress: service enumeration has run
    db_scanned: bool = False       # the `db` phase ran against this host
    privesc_checked: bool = False  # the `privesc` phase ran against this host
    last_scanned: str = ""
    reviewed: bool = False
    notes: str = ""

    @property
    def hostname(self) -> str:
        return self.hostnames[0] if self.hostnames else ""

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def status(self) -> str:
        """Auto tool-progress status (distinct from the human Reviewed flag)."""
        if not self.enumerated:
            return "discovered"
        op = self.open_ports
        if not op:
            return "enumerated (no open ports)"
        scanned = sum(1 for p in op if p.vuln_scanned)
        if scanned == 0:
            return "enumerated"
        if scanned == len(op):
            return "vuln-scanned"
        return f"vuln-scanned {scanned}/{len(op)}"

    @property
    def vuln_step(self) -> str:
        """Checklist cell for the vuln-scan step: done / N/M / pending / n/a."""
        op = self.open_ports
        if not op:
            return "n/a"
        scanned = sum(1 for p in op if p.vuln_scanned)
        if scanned == 0:
            return "pending"
        if scanned == len(op):
            return "done"
        return f"{scanned}/{len(op)}"

    @property
    def os_guess(self) -> str:
        if self.os_name:
            return f"{self.os_name} ({self.os_accuracy}%)" if self.os_accuracy else self.os_name
        return ""

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Host":
        ports = [
            Port(**{**p, "scripts": [Script(**s) for s in p.get("scripts", [])]})
            for p in data.get("ports", [])
        ]
        vulns = [Vuln(**v) for v in data.get("vulns", [])]
        accounts = [Account(**a) for a in data.get("accounts", [])]
        exploits = [Exploit(**e) for e in data.get("exploits", [])]
        host_scripts = [Script(**s) for s in data.get("host_scripts", [])]
        core = {
            k: v
            for k, v in data.items()
            if k not in ("ports", "vulns", "accounts", "exploits", "host_scripts")
        }
        return cls(ports=ports, vulns=vulns, accounts=accounts, exploits=exploits,
                   host_scripts=host_scripts, **core)
