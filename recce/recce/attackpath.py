"""Attack-path synthesis - the "so what".

Chains recce's CONFIRMED findings into a prioritised path an attacker would walk:
foothold -> privilege escalation -> credential access -> lateral movement -> (in
AD) domain dominance. Grounded entirely in what recce already found; every step
names the specific host and the EXISTING tool. No new scanning, no exploit code -
it reuses the exploitation actions and orders them into stages.
"""
from __future__ import annotations

import re

from .models import Host
from . import exploitplan as xp

STAGE_ORDER = ["Initial Access", "Privilege Escalation", "Credential Access",
               "Lateral Movement", "Domain Dominance"]

# playbook (post-shell) id -> attack stage. Escalation vs. credential-theft.
_PLAY_STAGE = {
    "win-seimpersonate": "Privilege Escalation",
    "win-alwaysinstallelevated": "Privilege Escalation",
    "win-unquoted": "Privilege Escalation",
    "win-writable-service": "Privilege Escalation",
    "win-sebackup": "Credential Access",
    "win-gpp-cpassword": "Credential Access",
    "win-stored-cred": "Credential Access",
    "lin-sudo": "Privilege Escalation",
    "lin-suid": "Privilege Escalation",
    "lin-writable-passwd": "Privilege Escalation",
    "lin-readable-shadow": "Credential Access",
    "lin-docker": "Privilege Escalation",
    "lin-lxd": "Privilege Escalation",
    "lin-pwnkit": "Privilege Escalation",
    "lin-dirtypipe": "Privilege Escalation",
    "lin-writable-cron": "Privilege Escalation",
    "lin-ld-preload": "Privilege Escalation",
}


def _step(stage, ip, hostname, title, tool, cmd, why, key):
    return {"stage": stage, "ip": ip, "hostname": hostname, "title": title,
            "tool": tool, "cmd": cmd, "why": why, "key": key}


def _stage_for_action(a: dict) -> str:
    kind = a["kind"]
    text = (a["finding"] or "").lower()
    if kind == "remote-msf":
        return "Initial Access"
    if kind == "remote-tool":
        if any(k in text for k in ("as-rep", "kerberoast", "relay", "ntlm")):
            return "Domain Dominance"
        return "Initial Access"
    if kind == "post-shell":
        pid = a["key"].split(":")[-1]
        return _PLAY_STAGE.get(pid, "Privilege Escalation")
    return "Privilege Escalation"


def _lateral_summary(hosts: list[Host]) -> list[dict]:
    """Scope-level lateral-movement options from the remote-access surface (used
    once you hold a credential/hash), rather than one row per host."""
    def with_port(*ports):
        return [h.ip for h in hosts
                if set(ports) & {p.portid for p in h.open_ports}]
    out = []
    smb = with_port(445, 139)
    if smb:
        out.append(_step("Lateral Movement", ", ".join(smb[:6]), "",
                         f"SMB exec / password spray ({len(smb)} host(s))",
                         "netexec / impacket (existing)",
                         "netexec smb <subnet> -u <user> -p <pass> --shares   ; "
                         "impacket-psexec <user>@<ip>  (or -hashes :<nthash> for PtH)",
                         "Reuse a captured credential/hash to authenticate and execute "
                         "across the SMB estate.", "path:lateral:smb"))
    winrm = with_port(5985, 5986)
    if winrm:
        out.append(_step("Lateral Movement", ", ".join(winrm[:6]), "",
                         f"WinRM remote shell ({len(winrm)} host(s))",
                         "evil-winrm / netexec (existing)",
                         "evil-winrm -i <ip> -u <user> -p <pass>   (or -H <nthash>)",
                         "WinRM gives a full remote PowerShell with valid creds or a "
                         "hash.", "path:lateral:winrm"))
    rdp = with_port(3389)
    if rdp:
        out.append(_step("Lateral Movement", ", ".join(rdp[:6]), "",
                         f"RDP session ({len(rdp)} host(s))", "xfreerdp (existing)",
                         "xfreerdp /v:<ip> /u:<user> /p:<pass> +clipboard",
                         "RDP is a login/pivot vector once you hold creds.",
                         "path:lateral:rdp"))
    ssh = with_port(22)
    if ssh:
        out.append(_step("Lateral Movement", ", ".join(ssh[:6]), "",
                         f"SSH access ({len(ssh)} host(s))", "ssh / sshpass (existing)",
                         "ssh <user>@<ip>   (spray a recovered key/password)",
                         "Reuse recovered SSH keys/passwords - reuse is common.",
                         "path:lateral:ssh"))
    return out


def build(hosts: list[Host]) -> list[dict]:
    """Ordered attack-path steps (by stage), grounded in confirmed findings."""
    steps: list[dict] = []
    seen: set[str] = set()
    for a in xp.all_actions(hosts):
        stage = _stage_for_action(a)
        if a["key"] in seen:
            continue
        seen.add(a["key"])
        steps.append(_step(stage, a["ip"], a["hostname"], a["finding"],
                           a["tool"], a["cmd"], a["validate"], a["key"]))
    steps.extend(_lateral_summary(hosts))
    steps.sort(key=lambda s: STAGE_ORDER.index(s["stage"]))
    return steps


def _label(s: str, n: int = 40) -> str:
    s = re.sub(r"\s+", " ", (s or "").strip())
    return (s[: n - 1] + "…") if len(s) > n else s


def mermaid(hosts: list[Host], steps: list[dict] | None = None) -> str:
    """A Mermaid flowchart of the attack path: stage subgraphs left-to-right, one
    node per step (host + finding), with dashed same-host edges showing a box being
    walked through the stages. Paste into any Mermaid viewer / GitHub / mermaid.live."""
    steps = steps if steps is not None else build(hosts)
    used = [st for st in STAGE_ORDER if any(s["stage"] == st for s in steps)]
    if not steps:
        return "flowchart LR\n  empty[\"No confirmed attack path yet\"]\n"
    out = ["flowchart LR"]
    nid: dict[str, str] = {}
    per_host_stage: dict[tuple, str] = {}
    i = 0
    for si, st in enumerate(used):
        out.append(f'  subgraph S{si}["{st}"]')
        for s in [x for x in steps if x["stage"] == st]:
            node = f"n{i}"
            nid[s["key"]] = node
            host = s["ip"] + (f" ({s['hostname']})" if s["hostname"] else "")
            out.append(f'    {node}["{_label(host, 28)}<br/>{_label(s["title"])}"]')
            per_host_stage[(s["ip"], st)] = node
            i += 1
        out.append("  end")
    # Stage-to-stage flow.
    for a, b in zip(range(len(used)), range(1, len(used))):
        out.append(f"  S{a} --> S{b}")
    # Same-host continuity across consecutive stages (dashed).
    for h in {s["ip"] for s in steps}:
        chain = [per_host_stage[(h, st)] for st in used if (h, st) in per_host_stage]
        for a, b in zip(chain, chain[1:]):
            out.append(f"  {a} -. same host .-> {b}")
    return "\n".join(out) + "\n"


def dot(hosts: list[Host], steps: list[dict] | None = None) -> str:
    """Graphviz DOT of the attack path (render: dot -Tpng attack_path.dot -o path.png)."""
    steps = steps if steps is not None else build(hosts)
    used = [st for st in STAGE_ORDER if any(s["stage"] == st for s in steps)]
    lines = ['digraph attack_path {', '  rankdir=LR; node [shape=box, style=rounded];']
    if not steps:
        return "".join([lines[0], "\n  empty [label=\"No confirmed attack path yet\"];\n}\n"])
    nid: dict[str, str] = {}
    i = 0
    for si, st in enumerate(used):
        lines.append(f'  subgraph cluster_{si} {{ label="{st}"; style=dashed;')
        for s in [x for x in steps if x["stage"] == st]:
            node = f"n{i}"
            nid[s["key"]] = node
            host = s["ip"] + (f" ({s['hostname']})" if s["hostname"] else "")
            lines.append(f'    {node} [label="{_label(host, 28)}\\n{_label(s["title"])}"];')
            i += 1
        lines.append("  }")
    # Same-host continuity edges.
    per: dict[tuple, str] = {}
    for s in steps:
        per[(s["ip"], s["stage"])] = nid[s["key"]]
    for h in {s["ip"] for s in steps}:
        chain = [per[(h, st)] for st in used if (h, st) in per]
        for a, b in zip(chain, chain[1:]):
            lines.append(f'  {a} -> {b};')
    lines.append("}")
    return "\n".join(lines) + "\n"


def narrative(hosts: list[Host], steps: list[dict] | None = None) -> list[str]:
    """A short, grounded summary of the likely path (for the CLI + report)."""
    steps = steps if steps is not None else build(hosts)
    by_stage = {st: [s for s in steps if s["stage"] == st] for st in STAGE_ORDER}
    used = [st for st in STAGE_ORDER if by_stage[st]]
    lines = [f"{len(steps)} attack step(s) across {len(used)} stage(s): "
             f"{', '.join(used)}." if steps else "No confirmed attack path yet - "
             "run vulns / ingest to confirm findings."]
    if not steps:
        return lines
    dc = [h for h in hosts if "Domain Controller" in (h.roles or [])]
    ia = by_stage["Initial Access"]
    if ia:
        chain = [f"foothold via {ia[0]['title']} on {ia[0]['ip']}"]
        if by_stage["Privilege Escalation"]:
            chain.append("escalate locally to SYSTEM/root")
        if by_stage["Credential Access"]:
            chain.append("harvest credentials/hashes")
        if by_stage["Lateral Movement"]:
            chain.append("reuse them to move laterally")
        if dc and by_stage["Domain Dominance"]:
            chain.append(f"pivot to domain compromise ({dc[0].ip})")
        lines.append("Likely path: " + " -> ".join(chain) + ".")
    elif dc and by_stage["Domain Dominance"]:
        lines.append(f"AD attack surface on the DC ({dc[0].ip}): "
                     + "; ".join(s["title"] for s in by_stage["Domain Dominance"][:3]) + ".")
    return lines
