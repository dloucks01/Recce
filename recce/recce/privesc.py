"""Privilege-escalation guidance for Windows and Linux hosts.

A network scanner can't run local privesc checks itself, so this module does two
useful things offline:

  1. Surfaces privesc-relevant signals we DID observe remotely (missing patches
     with public exploits, SMB signing off, unauthenticated services, kernel/
     service versions with known local exploits).
  2. Emits a per-host, OS-specific privesc *playbook* - the exact checks/commands
     to run once you have a foothold - so the operator has a prioritised checklist
     instead of a blank page.

Both feed the Priv-Esc report sheet. Optional remote NSE checks (smb-vuln-*) can
be run by the `privesc` command; the playbook needs no scanning.
"""

from __future__ import annotations

from .models import Host

# OS-specific local checklists. (vector, command / how-to, note)
WINDOWS_VECTORS = [
    ("System info & patches", "systeminfo ; wmic qfe list",
     "Feed to a local exploit suggester (WES-NG / Sherlock) offline."),
    ("Automated enum", "recce-enum.ps1 (bundled) / winPEAS.exe / PowerUp.ps1",
     "Run recce/local/recce-enum.ps1 on the host: read-only deep sweep of "
     "privileges, services, tasks, creds, autoruns, patches."),
    ("Service perms / unquoted paths", "PowerUp: Get-ServiceUnquoted, "
     "Get-ModifiableServiceFile, Get-ModifiableService",
     "Writable service binary or unquoted path -> SYSTEM."),
    ("AlwaysInstallElevated", "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\"
     "Windows\\Installer /v AlwaysInstallElevated",
     "If 1 (both HKLM+HKCU) -> install a malicious MSI as SYSTEM."),
    ("Token privileges (whoami /priv)", "whoami /priv",
     "SeImpersonate or SeAssignPrimaryToken held? Typical for IIS/MSSQL/service "
     "accounts (NT SERVICE\\*, NETWORK/LOCAL SERVICE). If yes -> Potato to SYSTEM "
     "(see the Potato rows)."),
    ("Potato -> SYSTEM (patched Win10/11 & Server 2016-2022)",
     "GodPotato -cmd \"cmd /c whoami\"  |  PrintSpoofer64.exe -i -c cmd  |  "
     "SharpEfsPotato.exe -p C:\\Windows\\System32\\cmd.exe -a whoami",
     "Still work on fully-patched builds because they abuse SeImpersonate (not a "
     "patchable bug): GodPotato / SigmaPotato (DCOM/RPC, most reliable), "
     "PrintSpoofer (spooler named pipe), EfsPotato / SharpEfsPotato (MS-EFSR), "
     "JuicyPotatoNG (CLSID). RottenPotato & classic JuicyPotato are dead on "
     "current builds."),
    ("Potato: network / DCOM variants",
     "RoguePotato.exe -r <redirector-ip> -e cmd -l 9999  ;  DCOMPotato",
     "RoguePotato when the OXID resolver (tcp/135) can reach a redirector you "
     "control; DCOMPotato targets specific DCOM services still abusable when "
     "patched."),
    ("LocalPotato (CVE-2023-21746)", "LocalPotato.exe  (local NTLM reflection)",
     "Local NTLM EoP -> arbitrary file write as SYSTEM; chain a DLL/service "
     "hijack for code exec if the host isn't fully mitigated."),
    ("Stored credentials", "cmdkey /list ; reg query HKLM /f password /t "
     "REG_SZ /s ; type unattend.xml / sysprep.inf",
     "Look for saved/plaintext creds and autologon."),
    ("Scheduled tasks", "schtasks /query /fo LIST /v",
     "Writable task binary run by a privileged account."),
    ("DLL hijacking / PATH", "PowerUp: Find-PathDLLHijack",
     "Writable dir on a service's DLL search path."),
]

LINUX_VECTORS = [
    ("Kernel & distro", "uname -a ; cat /etc/os-release",
     "Map kernel/distro to local exploits offline (linux-exploit-suggester)."),
    ("Automated enum", "recce-enum.sh (bundled) / linPEAS.sh / LinEnum.sh",
     "Run recce/local/recce-enum.sh on the host: read-only deep sweep of sudo, "
     "SUID/caps, cron, writable services, creds, kernel LPE (PwnKit/DirtyPipe)."),
    ("Sudo rights", "sudo -l",
     "NOPASSWD entries + GTFOBins -> root; check sudo version (CVE-2021-3156)."),
    ("SUID/SGID binaries", "find / -perm -4000 -type f 2>/dev/null",
     "Unusual SUID + GTFOBins -> root."),
    ("Capabilities", "getcap -r / 2>/dev/null",
     "cap_setuid / cap_dac_read_search on a binary -> root."),
    ("Cron jobs", "cat /etc/crontab ; ls -la /etc/cron.*",
     "World-writable script run as root."),
    ("Writable sensitive files", "ls -la /etc/passwd /etc/shadow ; find / "
     "-writable -type f 2>/dev/null | grep -vE '^/proc|^/sys'",
     "Writable /etc/passwd or a root-run script."),
    ("NFS no_root_squash", "cat /etc/exports ; showmount -e <host>",
     "no_root_squash export -> drop a SUID root binary from a client."),
    ("Docker / group perms", "id ; docker ps 2>/dev/null",
     "Membership in docker/lxd/disk group -> root."),
]

# Remotely-observable findings that indicate a privesc/lateral path, with the
# port/hint that raises them.
_PRIVESC_VULN_HINTS = [
    ("ms17-010", "MS17-010 EternalBlue - unauth SMB RCE as SYSTEM"),
    ("ms08-067", "MS08-067 - unauth SMB RCE as SYSTEM"),
    ("cve-2020-1472", "ZeroLogon - domain takeover"),
    ("smb-vuln", "SMB vulnerability - potential RCE/priv path"),
    ("printnightmare", "PrintNightmare - spooler RCE/LPE"),
    ("cve-2019-0708", "BlueKeep - unauth RDP RCE"),
]


# Remotely-runnable privesc/lateral-relevant NSE (safe detection by default).
_NSE_SAFE = [
    "smb-vuln-ms17-010", "smb-security-mode", "smb2-security-mode",
    "smb-enum-shares", "rdp-ntlm-info", "rdp-enum-encryption",
    "smb-vuln-cve-2017-7494", "http-vuln-cve2017-5638",
]
_NSE_AGGR = [
    "smb-vuln-ms08-067", "smb-vuln-cve2009-3103", "rdp-vuln-ms12-020",
    "smb-vuln-regsvc-dos",
]


def nse_scripts(aggressive: bool) -> list[str]:
    return _NSE_SAFE + (_NSE_AGGR if aggressive else [])


def remote_findings(host: Host) -> list[dict]:
    """Privesc/lateral signals observed over the network for this host."""
    out: list[dict] = []

    def add(signal, detail, refs=""):
        out.append({"signal": signal, "detail": detail, "refs": refs})

    for v in host.vulns:
        low = f"{v.script_id} {v.title}".lower()
        for hint, desc in _PRIVESC_VULN_HINTS:
            if hint in low:
                add(desc, f"{v.script_id} on port {v.port or '-'}",
                    ", ".join(v.ids))
                break

    if host.smb_signing == "not required":
        add("SMB signing not required",
            "Relay captured/coerced auth (ntlmrelayx) to this host", "")

    # Services whose account usually holds SeImpersonate -> a Potato lands SYSTEM
    # if you get code exec here (webshell, xp_cmdshell, deserialization...).
    for p in host.open_ports:
        svc, prod = (p.service or "").lower(), (p.product or "").lower()
        if "microsoft-iis" in prod or ("http" in svc and "iis" in prod):
            add("IIS service - AppPool identity likely holds SeImpersonate",
                f"port {p.portid}: RCE as the AppPool -> Potato (GodPotato/"
                f"PrintSpoofer) -> SYSTEM")
            break
    for p in host.open_ports:
        if p.portid == 1433 or "ms-sql" in (p.service or "").lower():
            add("MSSQL service - service account likely holds SeImpersonate",
                f"port {p.portid}: code exec (xp_cmdshell) -> Potato (GodPotato/"
                f"PrintSpoofer) -> SYSTEM")
            break

    # Local-exploit candidates from searchsploit on service versions.
    for e in host.exploits:
        if e.type.lower() in ("local", "remote"):
            add(f"Exploit: {e.title}",
                f"{e.product} {e.version} on port {e.port or '-'} (EDB {e.edb_id})",
                ", ".join(e.cves))
    return out


def _os_kind(host: Host) -> str:
    blob = (host.os_family or host.os_name).lower()
    if "windows" in blob:
        return "windows"
    if "linux" in blob or "unix" in blob:
        return "linux"
    # Fall back to service hints.
    for p in host.open_ports:
        s = (p.service or "").lower()
        if s in ("microsoft-ds", "ms-wbt-server", "msrpc"):
            return "windows"
        if s == "ssh":
            return "linux"
    return "unknown"


def plan(host: Host) -> list[dict]:
    """Per-host privesc rows: on-target findings + remote findings, then the
    OS playbook."""
    rows: list[dict] = []
    # On-target enum findings (ingested from recce-enum.sh/.ps1) come first - they
    # are confirmed local observations, the strongest signal on the sheet.
    for f in getattr(host, "local_findings", []) or []:
        sect = f.get("section", "")
        rows.append({"category": f.get("category", "local"),
                     "vector": f.get("vector", ""),
                     "howto": f"on-target finding ({sect})" if sect else "on-target finding",
                     "note": f"via {f.get('source', 'recce-enum')}"})
    for f in remote_findings(host):
        rows.append({"category": "finding", "vector": f["signal"],
                     "howto": f["detail"], "note": f["refs"]})
    kind = _os_kind(host)
    vectors = []
    if kind in ("windows", "unknown"):
        vectors += [("windows", v) for v in WINDOWS_VECTORS]
    if kind in ("linux", "unknown"):
        vectors += [("linux", v) for v in LINUX_VECTORS]
    for os_kind, (vector, howto, note) in vectors:
        rows.append({"category": os_kind, "vector": vector, "howto": howto,
                     "note": note})
    return rows


def all_rows(hosts: list[Host]) -> list[dict]:
    """Flatten per-host plans for the report (with host context + a stable key)."""
    out = []
    for h in hosts:
        for r in plan(h):
            out.append({**r, "ip": h.ip, "hostname": h.hostname,
                        "os": h.os_family or h.os_name,
                        "key": f"privesc:{h.ip}:{r['category']}:{r['vector']}"})
    return out
