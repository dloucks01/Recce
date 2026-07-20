"""Coverage-tracking primitives shared by the store, reports and CLI.

Every trackable item (host, service, vuln, AD quick-win, account, subnet) has a
stable string key. The same key is:
  - written into a hidden "Key" column in each workbook sheet,
  - read back from an operator-edited workbook,
  - stored in the datastore's `tracking` table,
  - used to compute live coverage percentages.

Keeping the key logic in one place guarantees generation, read-back and coverage
never drift apart.
"""

from __future__ import annotations

from typing import Any

# Categories that count toward coverage %, in display order.
COVERAGE_CATEGORIES = ["hosts", "services", "vulns", "exploits", "quick_wins", "accounts"]

# Per-host workflow steps shown as checkboxes on the Checklist: header -> step id.
STEP_COLUMNS = {"Enumerated": "enum", "Vuln-scan": "vuln", "DB": "db",
                "Priv-esc": "privesc"}


def step_key(step: str, ip: str) -> str:
    return f"step:{step}:{ip}"


def step_auto(host, step: str) -> bool:
    """Tool-completion state for a step (the checkbox's default value).

    A step is 'done' when the tool has completed it, or when it is not applicable
    (a host with no open ports needs no vuln scan; a host with no DB needs no DB
    scan). The operator can still override any of these on the sheet.
    """
    if step == "enum":
        return host.enumerated
    if step == "vuln":
        op = host.open_ports
        return host.enumerated and (not op or all(p.vuln_scanned for p in op))
    if step == "db":
        from . import db as dbmod
        return host.enumerated and (not dbmod.db_ports(host) or host.db_scanned)
    if step == "privesc":
        return host.privesc_checked
    return False


def host_key(ip: str) -> str:
    return f"host:{ip}"


def svc_key(ip: str, proto: str, port: int) -> str:
    return f"svc:{ip}:{proto}:{port}"


def vuln_key(ip: str, port: Any, script_id: str) -> str:
    return f"vuln:{ip}:{port or 0}:{script_id}"


def exploit_key(ip: str, port: Any, edb_id: str) -> str:
    return f"exploit:{ip}:{port or 0}:{edb_id}"


def acct_key(source: str, kind: str, domain: str, name: str) -> str:
    return f"acct:{source}:{kind}:{domain}:{name}"


def prod_key(product_version_key: str) -> str:
    return f"prod:{product_version_key}"


def subnet_key(subnet: str) -> str:
    return f"subnet:{subnet}"


def item_keys(hosts: list) -> dict[str, list[str]]:
    """All trackable keys grouped by category (order-stable, deduplicated)."""
    from . import ad

    out: dict[str, list[str]] = {c: [] for c in COVERAGE_CATEGORIES}
    subnets: set[str] = set()
    seen: set[str] = set()

    def push(cat: str, key: str) -> None:
        if key not in seen:
            seen.add(key)
            out[cat].append(key)

    for h in hosts:
        push("hosts", host_key(h.ip))
        subnets.add(h.subnet or "unknown")
        for p in h.open_ports:
            push("services", svc_key(h.ip, p.protocol, p.portid))
        for v in h.vulns:
            push("vulns", vuln_key(v.ip, v.port, v.script_id))
        for e in h.exploits:
            push("exploits", exploit_key(e.ip, e.port, e.edb_id))
        for a in h.accounts:
            push("accounts", acct_key(a.source, a.kind, a.domain, a.name))

    for qw in ad.quick_wins(hosts):
        push("quick_wins", qw["key"])

    out["subnets"] = [subnet_key(s) for s in sorted(subnets)]
    return out


def compute_coverage(hosts: list, tracking: dict[str, tuple]) -> dict[str, dict]:
    """Return {category: {total, done, pct}} plus an 'overall' roll-up."""
    keys = item_keys(hosts)
    cov: dict[str, dict] = {}
    grand_total = grand_done = 0
    for cat in COVERAGE_CATEGORIES:
        ks = keys.get(cat, [])
        total = len(ks)
        done = sum(1 for k in ks if tracking.get(k, (False, ""))[0])
        cov[cat] = {"total": total, "done": done,
                    "pct": (100 * done // total if total else 100)}
        grand_total += total
        grand_done += done
    cov["overall"] = {"total": grand_total, "done": grand_done,
                      "pct": (100 * grand_done // grand_total if grand_total else 100)}
    return cov


def subnet_coverage(hosts: list, tracking: dict[str, tuple]) -> dict[str, dict]:
    """Per-subnet host-review coverage."""
    agg: dict[str, dict] = {}
    for h in hosts:
        s = h.subnet or "unknown"
        a = agg.setdefault(s, {"total": 0, "done": 0})
        a["total"] += 1
        if tracking.get(host_key(h.ip), (False, ""))[0]:
            a["done"] += 1
    for s, a in agg.items():
        a["pct"] = 100 * a["done"] // a["total"] if a["total"] else 0
    return agg
