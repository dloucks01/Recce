"""Deep LDAP / Active Directory enumeration (stdlib only).

Modelled on recce/smb.py and recce/ftp.py. A hand-rolled BER/ASN.1 LDAP client on
a raw socket - no python-ldap, no ldap3 - so it runs on a stock airgapped Kali.

Credential-free, read-only. Against a Directory port (389/636/3268/3269) recce:

  * attempts an **anonymous simple bind** (name "", password "") - RFC 4513 - to see
    whether the server hands out an anonymous session at all;
  * reads the **RootDSE** (base "", scope base, filter (objectClass=*)): naming
    contexts, the domain/forest DNS names, the DC's dnsHostName, the domain/forest
    **functional level**, and the supported SASL mechanisms - the crown jewel of
    anonymous LDAP recon and readable on virtually every DC;
  * tries to **read the base naming-context object anonymously** - if attributes come
    back, the directory leaks objects to an unauthenticated client (a real misconfig,
    not the default AD posture);
  * flags **cleartext LDAP** when a simple bind is accepted on 389 with no LDAPS/StartTLS
    - a credential-sniffing and NTLM-relay surface.

Every positive becomes a finding that folds into the main severity totals, the
Vulnerabilities sheet, the write-ups, the prove engine, and a dedicated **LDAP**
workbook tab. Airgapped-safe; degrades cleanly when the port doesn't speak LDAP.
"""
from __future__ import annotations

import socket

from .models import Host, Port

_DEFAULT_PORT = 389
_LDAPS = 636
_GC, _GCS = 3268, 3269          # Global Catalog (plain / TLS)
_TIMEOUT = 6.0
_TLS_PORTS = (_LDAPS, _GCS)

# RootDSE attributes worth pulling (all readable pre-auth on a normal DC).
_ROOTDSE_ATTRS = [
    "defaultNamingContext", "rootDomainNamingContext", "namingContexts",
    "configurationNamingContext", "schemaNamingContext", "dnsHostName",
    "serverName", "ldapServiceName", "domainFunctionality", "forestFunctionality",
    "domainControllerFunctionality", "supportedLDAPVersion",
    "supportedSASLMechanisms", "supportedControl", "supportedCapabilities",
    "isGlobalCatalogReady", "currentTime",
]

# msDS-Behavior-Version -> Windows Server release (domain/forest/DC functional level).
_FUNC_LEVEL = {"0": "2000", "1": "2003 interim", "2": "2003", "3": "2008",
               "4": "2008 R2", "5": "2012", "6": "2012 R2", "7": "2016"}


def is_ldap(port: Port) -> bool:
    if port.state != "open":
        return False
    if port.portid in (_DEFAULT_PORT, _LDAPS, _GC, _GCS):
        return True
    return "ldap" in f"{port.service} {port.product}".lower()


def _is_tls_port(port: int) -> bool:
    return port in _TLS_PORTS


# --- BER / ASN.1 encoding (just what LDAP needs) --------------------------------

def _ber_len(n: int) -> bytes:
    """Definite-form length: short form < 128, else long form (0x80|count + bytes)."""
    if n < 0x80:
        return bytes([n])
    body = []
    while n:
        body.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(body)]) + bytes(body)


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _int(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b"\x00")
    body = []
    while n:
        body.insert(0, n & 0xFF)
        n >>= 8
    if body[0] & 0x80:              # keep it positive
        body.insert(0, 0)
    return _tlv(0x02, bytes(body))


def _octet(s) -> bytes:
    return _tlv(0x04, s.encode() if isinstance(s, str) else s)


def _enum(n: int) -> bytes:
    return _tlv(0x0A, bytes([n]))


def _boolean(b: bool) -> bytes:
    return _tlv(0x01, b"\xff" if b else b"\x00")


def build_bind_request(msgid: int = 1, dn: str = "", password: str = "") -> bytes:
    """LDAPMessage{ msgid, [APPLICATION 0] BindRequest{ version 3, name, simple pw } }.
    Empty name + empty password = an anonymous bind (RFC 4513)."""
    simple = _tlv(0x80, password.encode())          # authentication CHOICE simple [0]
    bindreq = _tlv(0x60, _int(3) + _octet(dn) + simple)  # [APPLICATION 0] constructed
    return _tlv(0x30, _int(msgid) + bindreq)


def build_search_request(msgid: int, base: str, scope: int,
                         attributes: list[str]) -> bytes:
    """LDAPMessage{ msgid, [APPLICATION 3] SearchRequest{...} } with the present
    filter (objectClass=*). scope: 0 base / 1 one-level / 2 subtree."""
    filt = _tlv(0x87, b"objectClass")               # present filter [7] "objectClass"
    attrs = _tlv(0x30, b"".join(_octet(a) for a in attributes))
    body = (_octet(base) + _enum(scope) + _enum(0)  # derefAliases = neverDerefAliases
            + _int(0) + _int(0) + _boolean(False)   # sizeLimit, timeLimit, typesOnly
            + filt + attrs)
    searchreq = _tlv(0x63, body)                    # [APPLICATION 3] constructed
    return _tlv(0x30, _int(msgid) + searchreq)


# --- BER decoding ---------------------------------------------------------------

def _read_len(data: bytes, i: int) -> tuple[int, int]:
    first = data[i]
    i += 1
    if first < 0x80:
        return first, i
    n = 0
    for _ in range(first & 0x7F):
        n = (n << 8) | data[i]
        i += 1
    return n, i


def _parse_tlv(data: bytes, i: int) -> tuple[int, bytes, int]:
    """Return (tag, value_bytes, next_index) for the TLV at `i`."""
    tag = data[i]
    length, j = _read_len(data, i + 1)
    return tag, data[j:j + length], j + length


def result_code(msg: bytes):
    """resultCode from a response LDAPMessage (bind/search-done), or None."""
    try:
        _, body, _ = _parse_tlv(msg, 0)             # outer SEQUENCE
        _, _msgid, i = _parse_tlv(body, 0)          # messageID
        _, op, _ = _parse_tlv(body, i)              # protocolOp (a *Response)
        _, rc, _ = _parse_tlv(op, 0)                # resultCode ENUMERATED
        return rc[0] if rc else None
    except (IndexError, ValueError):
        return None


def _op_tag(msg: bytes):
    """The protocolOp application tag of a response LDAPMessage (0x61 bindResponse,
    0x64 searchResEntry, 0x65 searchResDone), or None."""
    try:
        _, body, _ = _parse_tlv(msg, 0)
        _, _msgid, i = _parse_tlv(body, 0)
        return body[i]
    except (IndexError, ValueError):
        return None


def parse_search_entry(msg: bytes) -> tuple[str, dict]:
    """(objectName, {attr: [values]}) from a searchResEntry LDAPMessage."""
    _, body, _ = _parse_tlv(msg, 0)
    _, _msgid, i = _parse_tlv(body, 0)
    _, op, _ = _parse_tlv(body, i)                  # [APPLICATION 4] value
    _, objname, k = _parse_tlv(op, 0)               # objectName
    obj = objname.decode("utf-8", "replace")
    _, attrseq, _ = _parse_tlv(op, k)               # PartialAttributeList SEQUENCE
    attrs: dict[str, list[str]] = {}
    j = 0
    while j < len(attrseq):
        _, one, j = _parse_tlv(attrseq, j)          # SEQUENCE{ type, vals }
        _, atype, m = _parse_tlv(one, 0)
        name = atype.decode("utf-8", "replace")
        _, vset, _ = _parse_tlv(one, m)             # SET OF values
        vals, n = [], 0
        while n < len(vset):
            _, v, n = _parse_tlv(vset, n)
            vals.append(v.decode("utf-8", "replace"))
        attrs[name] = vals
    return obj, attrs


# --- socket I/O -----------------------------------------------------------------

def _recvn(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _read_message(sock, timeout: float) -> bytes | None:
    """Read exactly one LDAPMessage (a top-level SEQUENCE) off the socket."""
    sock.settimeout(timeout)
    try:
        first = _recvn(sock, 2)
        if len(first) < 2 or first[0] != 0x30:
            return None
        if first[1] < 0x80:
            return first + _recvn(sock, first[1])
        nbytes = first[1] & 0x7F
        lenb = _recvn(sock, nbytes)
        if len(lenb) < nbytes:
            return None
        length = int.from_bytes(lenb, "big")
        if length > 8 * 1024 * 1024:                # sanity cap
            return None
        return first + lenb + _recvn(sock, length)
    except OSError:
        return None


def _read_search(sock, timeout: float, cap: int = 64) -> list[dict]:
    """Collect searchResEntry attribute dicts until searchResDone / cap / EOF."""
    entries = []
    for _ in range(cap):
        msg = _read_message(sock, timeout)
        if msg is None:
            break
        op = _op_tag(msg)
        if op == 0x64:                              # searchResEntry
            try:
                _obj, attrs = parse_search_entry(msg)
                entries.append(attrs)
            except (IndexError, ValueError):
                continue
        elif op == 0x65:                            # searchResDone
            break
    return entries


# --- credential-free probe ------------------------------------------------------

def _dn_to_domain(dn: str) -> str:
    parts = [p[3:] for p in dn.split(",") if p.strip().upper().startswith("DC=")]
    return ".".join(parts)


def _first(d: dict, key: str, default: str = "") -> str:
    v = d.get(key)
    return v[0] if v else default


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict | None:
    """Anonymous bind + RootDSE + anonymous naming-context read. No credentials.
    Returns None if the port didn't answer LDAP. Never writes to the directory."""
    if _is_tls_port(port):
        return _probe_tls(ip, port, timeout)
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            return _run_probe(s, ip, port, timeout)
    except OSError:
        return None


def _probe_tls(ip: str, port: int, timeout: float) -> dict | None:
    """LDAPS (636/3269): wrap the socket in TLS (unverified - we're reaching an
    exposed/self-signed DC), then run the same LDAP probe."""
    import ssl
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    try:
        ctx = ssl._create_unverified_context()
        with ctx.wrap_socket(raw, server_hostname=ip) as s:
            return _run_probe(s, ip, port, timeout)
    except (OSError, ssl.SSLError, ValueError):
        try:
            raw.close()
        except OSError:
            pass
        return None


def _run_probe(s, ip: str, port: int, timeout: float) -> dict | None:
    # 1. anonymous simple bind.
    s.sendall(build_bind_request(1, "", ""))
    bind_resp = _read_message(s, timeout)
    if bind_resp is None:
        return None                                 # didn't speak LDAP
    anon_bind = result_code(bind_resp) == 0

    # 2. RootDSE (base "", scope base). Readable even when the bind was refused on
    #    some servers, so always try it.
    s.sendall(build_search_request(2, "", 0, _ROOTDSE_ATTRS))
    root_entries = _read_search(s, timeout)
    rootdse = root_entries[0] if root_entries else {}

    default_nc = _first(rootdse, "defaultNamingContext")
    naming = default_nc or _first(rootdse, "namingContexts")
    domain = _dn_to_domain(default_nc or naming)
    forest = _dn_to_domain(_first(rootdse, "rootDomainNamingContext")) or domain

    # 3. anonymous directory read: read the naming-context base object. If attributes
    #    come back, an unauthenticated client can read directory objects.
    anon_read, sample = False, {}
    if anon_bind and naming:
        s.sendall(build_search_request(3, naming, 0,
                                       ["objectClass", "objectSid", "ms-DS-MachineAccountQuota"]))
        nc = _read_search(s, timeout)
        if nc and nc[0]:
            anon_read = True
            sample = {k: v for k, v in nc[0].items()}

    def _lvl(key: str) -> str:
        return _FUNC_LEVEL.get(_first(rootdse, key), _first(rootdse, key))

    return {
        "ip": ip, "port": port, "tls": _is_tls_port(port),
        "anon_bind": anon_bind, "anon_read": anon_read,
        "domain": domain, "forest": forest,
        "dc_dns": _first(rootdse, "dnsHostName"),
        "server_name": _first(rootdse, "serverName"),
        "naming_context": naming,
        "domain_level": _lvl("domainFunctionality"),
        "forest_level": _lvl("forestFunctionality"),
        "dc_level": _lvl("domainControllerFunctionality"),
        "sasl": rootdse.get("supportedSASLMechanisms") or [],
        "is_gc": _first(rootdse, "isGlobalCatalogReady").upper() == "TRUE",
        "rootdse_ok": bool(rootdse),
        "sample_attrs": sample,
    }


def ldap_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_ldap(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product or "", "version": p.version or ""})
    return out


# --- narratives -----------------------------------------------------------------

_NARRATIVE = {
    "ldap_anon_bind": (
        "The directory accepted an anonymous simple bind (empty username and password), "
        "handing out an unauthenticated LDAP session. Even when object ACLs restrict "
        "what that session can read, it is a foothold for reconnaissance and, combined "
        "with an anonymous read, leaks users, groups and policy. Disable anonymous binds "
        "unless a specific application requires them."),
    "ldap_anon_read": (
        "An unauthenticated client can READ directory objects: recce bound anonymously "
        "and the naming context returned attributes. That typically exposes the full "
        "user and group population, service-principal names (kerberoast targets), the "
        "machine-account quota, and descriptions that frequently contain passwords - all "
        "without a single credential. This is a serious misconfiguration on a domain "
        "directory (the default AD posture denies it)."),
    "ldap_rootdse": (
        "The RootDSE is world-readable (by design), but it fingerprints the directory "
        "pre-authentication: the domain and forest DNS names, the domain controller's "
        "FQDN, the domain/forest functional level (hence the minimum DC OS - a low level "
        "flags legacy, unsupported controllers), and the offered SASL mechanisms. It is "
        "the first pivot for an AD attack and confirms a reachable, unauthenticated DC."),
    "ldap_cleartext": (
        "This directory answers on cleartext 389 and accepts a simple bind, so a real "
        "credentialed bind here transmits the username and password in the clear - "
        "anyone sniffing the segment captures them verbatim. The same missing transport "
        "protection is what lets an attacker relay coerced NTLM authentication to LDAP "
        "(ntlmrelayx) to create machine accounts or grant DCSync. Require LDAPS/StartTLS "
        "and enforce LDAP signing + channel binding."),
}


def narrative_for(kind: str) -> str:
    return _NARRATIVE.get(kind, "")


TESTING_NARRATIVE = [
    ("1. Credential-free probe (stdlib BER/ASN.1 client)",
     "recce speaks LDAP directly on a raw socket - no python-ldap. It sends an anonymous "
     "simple bind, then a base-scoped RootDSE search, then tries to read the naming "
     "context anonymously. LDAPS (636/3269) is wrapped in TLS first."),
    ("2. Vulnerability identification",
     "Anonymous bind accepted -> unauthenticated session. Naming context readable "
     "anonymously -> directory disclosure (users/SPNs/quota). Cleartext 389 -> "
     "credential-sniffing + LDAP-relay surface. RootDSE -> domain/forest/DC + functional "
     "level (legacy DC flag). Each folds into the totals and the prove engine adjudicates."),
    ("3. RootDSE recon",
     "The domain and forest DNS names, DC FQDN, functional level and SASL mechanisms are "
     "captured pre-auth and pre-filled into the follow-on ldapsearch / netexec commands."),
    ("4. Runbook",
     "The exact anonymous and credentialed enumeration commands (ldapsearch, nxc ldap "
     "--users/--groups/--kerberoasting, bloodhound-python) are staged per DC."),
]


# --- findings -------------------------------------------------------------------

def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind=""):
    return {"category": "ldap", "severity": sev, "title": title, "target": target,
            "detail": detail, "tool": tool, "command": cmd, "remediation": rem,
            "cwes": list(cwes), "kind": kind, "narrative": _NARRATIVE.get(kind, "")}


def _rootdse_summary(pr: dict) -> str:
    bits = []
    if pr.get("domain"):
        bits.append(f"domain {pr['domain']}")
    if pr.get("forest") and pr["forest"] != pr.get("domain"):
        bits.append(f"forest {pr['forest']}")
    if pr.get("dc_dns"):
        bits.append(f"DC {pr['dc_dns']}")
    if pr.get("dc_level"):
        bits.append(f"functional level Server {pr['dc_level']}")
    if pr.get("is_gc"):
        bits.append("Global Catalog")
    return ", ".join(bits)


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_ldap(p):
                continue
            tgt = f"{h.ip}:{p.portid}"
            pr = probes.get((h.ip, p.portid)) or {}
            if not pr:
                continue
            summary = _rootdse_summary(pr)
            if pr.get("anon_read"):
                out.append(_finding(
                    "high", "Anonymous LDAP directory read", tgt,
                    "recce bound anonymously and the naming context "
                    f"({pr.get('naming_context', '')}) returned attributes - an "
                    "unauthenticated client can read directory objects. "
                    + (f"Directory: {summary}." if summary else ""),
                    "ldapsearch / netexec",
                    f"ldapsearch -x -H ldap://{h.ip}:{p.portid} -b '{pr.get('naming_context', '')}' "
                    "'(objectClass=user)' sAMAccountName servicePrincipalName description",
                    "Deny anonymous read on the directory (dsHeuristics / anonymous ACLs); "
                    "require authentication for all reads.",
                    ["CWE-306", "CWE-200"], kind="ldap_anon_read"))
            if pr.get("anon_bind"):
                out.append(_finding(
                    "medium", "Anonymous LDAP bind allowed", tgt,
                    "The server accepted a simple bind with an empty username and "
                    "password (anonymous session). "
                    + (f"Directory: {summary}." if summary else ""),
                    "ldapsearch / netexec",
                    f"ldapsearch -x -H ldap://{h.ip}:{p.portid} -s base -b '' "
                    "'(objectClass=*)'   # anonymous RootDSE, then try -b the naming context",
                    "Disable anonymous LDAP binds unless a specific application needs them.",
                    ["CWE-287", "CWE-306"], kind="ldap_anon_bind"))
                if not pr.get("tls") and p.portid == _DEFAULT_PORT:
                    out.append(_finding(
                        "medium", "LDAP over cleartext (no TLS on 389)", tgt,
                        "A simple bind is accepted on cleartext 389, so credentialed "
                        "binds transmit the password in the clear (sniffable) and the "
                        "missing transport protection is an NTLM->LDAP relay surface.",
                        "wireshark / ntlmrelayx",
                        "ntlmrelayx.py -t ldap://<ip> --escalate-user <user>   # relay coerced auth",
                        "Require LDAPS/StartTLS; enforce LDAP signing and channel binding "
                        "(LdapEnforceChannelBinding).",
                        ["CWE-319", "CWE-522"], kind="ldap_cleartext"))
            if pr.get("rootdse_ok") and summary:
                out.append(_finding(
                    "info", "LDAP RootDSE information disclosure", tgt,
                    f"Pre-authentication RootDSE read exposes: {summary}. Supported SASL: "
                    + (", ".join(pr.get("sasl") or []) or "n/a") + ".",
                    "ldapsearch",
                    f"ldapsearch -x -H ldap{'s' if pr.get('tls') else ''}://{h.ip}:{p.portid} "
                    "-s base -b '' '(objectClass=*)' '*' +",
                    "Expected for a DC; ensure a low functional level isn't flagging a "
                    "legacy/unsupported controller.",
                    ["CWE-200"], kind="ldap_rootdse"))
    return out


# --- runbooks -------------------------------------------------------------------

def _fill(text: str, ip: str, port: int, base: str, creds: dict | None) -> str:
    creds = creds or {}
    return (text.replace("<ip>", ip).replace("<port>", str(port))
            .replace("<base>", base or "<base>")
            .replace("<user>", creds.get("user") or "<user>")
            .replace("<pass>", creds.get("secret") or "<pass>")
            .replace("<domain>", creds.get("domain") or "<domain>"))


def credfree_runbook(ip: str, port: int, base: str = "") -> list[dict]:
    scheme = "ldaps" if port in _TLS_PORTS else "ldap"
    steps = [
        ("recon", "nmap NSE", "nmap -p<port> --script ldap-rootdse,ldap-search <ip>",
         "RootDSE + any anonymously-readable objects."),
        ("recon", "ldapsearch", f"ldapsearch -x -H {scheme}://<ip>:<port> -s base -b '' "
         "'(objectClass=*)' '*' +", "Read the RootDSE (domain/forest/DC/functional level)."),
        ("enumerate", "ldapsearch", f"ldapsearch -x -H {scheme}://<ip>:<port> -b '<base>' "
         "'(objectClass=user)' sAMAccountName servicePrincipalName description memberOf",
         "Anonymously enumerate users/SPNs/descriptions if reads are allowed."),
        ("enumerate", "netexec", "nxc ldap <ip> -u '' -p '' --users --groups",
         "Null-session user/group enumeration via netexec."),
    ]
    return [{"phase": ph, "tool": t, "command": _fill(c, ip, port, base, None), "why": w}
            for ph, t, c, w in steps]


def cred_runbook(ip: str, port: int, base: str, creds: dict | None) -> list[dict]:
    steps = [
        ("enumerate", "netexec", "nxc ldap <ip> -u <user> -p <pass> -d <domain> "
         "--users --groups --kerberoasting kerb.txt --asreproast asrep.txt",
         "Full authenticated AD enumeration + roastable accounts in one pass."),
        ("collect", "bloodhound", "bloodhound-python -u <user> -p <pass> -d <domain> "
         "-dc <ip> -c All --zip", "Collect the graph for attack-path analysis."),
        ("loot", "ldapsearch", "ldapsearch -x -H ldap://<ip>:<port> -D '<user>@<domain>' "
         "-w '<pass>' -b '<base>' '(objectClass=user)' description",
         "Hunt credentials stashed in description / info attributes."),
    ]
    return [{"phase": ph, "tool": t, "command": _fill(c, ip, port, base, creds), "why": w}
            for ph, t, c, w in steps]


# --- proof screenshot -----------------------------------------------------------

def proof_html(command, output, banner: str = "") -> str:
    from . import mssql
    return mssql.proof_html(command, output, prompt="ldap> ", banner=banner)


# --- top-level analyze ----------------------------------------------------------

def findings_to_vulns(fs: list[dict]) -> dict:
    """LDAP findings -> {ip: [Vuln]} (source='ldap')."""
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "ldap", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None,
            active: bool = True) -> dict:
    """Full LDAP analysis. Returns {targets, findings, runbooks, probes, stats}."""
    targets = ldap_targets(hosts)
    probes: dict = {}
    if active:
        for t in targets:
            pr = probe(t["ip"], t["port"])
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["domain"] = pr.get("domain", "")
                t["dc_dns"] = pr.get("dc_dns", "")
                t["anon_bind"] = pr.get("anon_bind", False)
                t["anon_read"] = pr.get("anon_read", False)
                t["dc_level"] = pr.get("dc_level", "")
                t["naming_context"] = pr.get("naming_context", "")
    fs = findings(hosts, probes)
    runbooks = []
    for t in targets:
        base = t.get("naming_context", "")
        runbooks.append({"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                         "credfree": credfree_runbook(t["ip"], t["port"], base),
                         "credentialed": cred_runbook(t["ip"], t["port"], base, creds)})
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs)}}
