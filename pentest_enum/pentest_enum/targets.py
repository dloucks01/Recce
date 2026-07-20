"""Target parsing and subnet expansion.

Accepts CIDRs, ranges, single IPs, hostnames, and @files (one target per line).
Keeps a mapping of each host back to the subnet it belongs to so the report can
group by subnet.
"""

from __future__ import annotations

import ipaddress
import os


def _expand_token(token: str) -> list[str]:
    token = token.strip()
    if not token or token.startswith("#"):
        return []
    # CIDR (e.g. 10.0.0.0/24) -> all usable hosts.
    if "/" in token:
        net = ipaddress.ip_network(token, strict=False)
        if net.num_addresses <= 2:
            return [str(h) for h in net]  # /31, /32
        return [str(h) for h in net.hosts()]
    # Dash range in last octet: 10.0.0.10-40
    if "-" in token and token.count(".") == 3:
        base, _, tail = token.rpartition(".")
        lo_s, _, hi_s = tail.partition("-")
        lo, hi = int(lo_s), int(hi_s)
        return [f"{base}.{o}" for o in range(lo, hi + 1)]
    return [token]  # single IP or hostname


def _subnet_of(ip: str) -> str:
    """Best-effort /24 label for grouping (falls back to the raw value)."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    except ValueError:
        return "unresolved"


def load_targets(tokens: list[str]) -> tuple[list[str], dict[str, str]]:
    """Return (ordered unique hosts, {host: subnet_label}).

    A token beginning with '@' is treated as a path to a target file.
    """
    hosts: list[str] = []
    seen: set[str] = set()
    subnet_map: dict[str, str] = {}

    def add(raw_token: str, subnet_hint: str = "") -> None:
        for host in _expand_token(raw_token):
            if host in seen:
                continue
            seen.add(host)
            hosts.append(host)
            subnet_map[host] = subnet_hint or _subnet_of(host)

    for token in tokens:
        if token.startswith("@"):
            path = token[1:]
            if not os.path.exists(path):
                raise FileNotFoundError(f"Target file not found: {path}")
            with open(path) as fh:
                for line in fh:
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    # If the file line is itself a CIDR, use it as the subnet label.
                    hint = line if "/" in line else ""
                    add(line, hint)
        else:
            hint = token if "/" in token else ""
            add(token, hint)

    return hosts, subnet_map


def ip_matcher(tokens: list[str]):
    """Build a predicate(ip)->bool from IP / range / CIDR / @file tokens.

    Used by the post-enum phases (vulns/db/privesc) to select stored hosts by a
    single IP, several IPs, or whole subnets. Empty tokens => match everything.
    """
    flat: list[str] = []
    for t in tokens or []:
        t = t.strip()
        if not t:
            continue
        if t.startswith("@") and os.path.exists(t[1:]):
            with open(t[1:]) as fh:
                flat += [ln.split("#", 1)[0].strip() for ln in fh if ln.strip()]
        else:
            flat.append(t)
    if not flat:
        return lambda ip: True

    nets: list = []
    ips: set[str] = set()
    for t in flat:
        if "/" in t:
            try:
                nets.append(ipaddress.ip_network(t, strict=False))
            except ValueError:
                pass
        elif "-" in t and t.count(".") == 3:
            ips.update(_expand_token(t))
        else:
            ips.add(t)

    def match(ip: str) -> bool:
        if ip in ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in nets)

    return match


def apply_exclusions(hosts: list[str], excludes: list[str]) -> list[str]:
    """Remove any hosts covered by the exclusion tokens."""
    if not excludes:
        return hosts
    excluded: set[str] = set()
    for token in excludes:
        excluded.update(_expand_token(token))
    return [h for h in hosts if h not in excluded]
