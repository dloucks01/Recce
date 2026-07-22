"""Service-detection enrichment - fill the gaps nmap's -sV leaves behind.

nmap is the primary identifier; when it returns a concrete name we keep it. But
plenty of ports come back `unknown`/`tcpwrapped` or blank - especially Windows
RPC/ephemeral services (5040 CDPSvc, 5357 wsdapi, 47001 winrm-http, dynamic
MSRPC) and anything nmap ships no signature for. This module recovers those in
three escalating, airgapped-safe layers:

  1. servicefp mining   - nmap already collected the service's raw response but
     couldn't match it; we keyword-match those bytes ourselves. Zero new traffic.
  2. curated port map    - a well-known port with no name gets an *inferred* label
     from the port number (how nmap-services / IANA lists work). Zero new traffic.
  3. active banner grab  - a stdlib connect-and-read (plus a few protocol nudges:
     HTTP HEAD, Redis PING, RDP X.224) fingerprints ports the first two missed.
     Only touches the target, no external deps - runs on a stock airgapped Kali.

Every label we set records its provenance in Port.detect_source (nmap / inferred
/ banner) so the sheet can show *how confident* an ID is, and an unmatched port
becomes an actionable to-do (suggest_id_command) instead of a dead "unknown".
"""

from __future__ import annotations

import re
import socket

from .models import Host, Port

# --- layer 2: curated port -> (service, human description) ----------------------
# Deliberately scoped to the gaps nmap habitually leaves blank/unknown - mostly
# Windows RPC/ephemeral and a few app ports. NOT a full nmap-services clone; it
# only fills a label when nmap gave us nothing usable.
PORT_NAMES: dict[int, tuple[str, str]] = {
    135: ("msrpc", "Microsoft RPC Endpoint Mapper"),
    593: ("ncacn_http", "MS RPC over HTTP (ncacn_http)"),
    2179: ("vmrdp", "Hyper-V VMConnect (RDP over VMBus)"),
    3389: ("ms-wbt-server", "Remote Desktop (RDP)"),
    5040: ("cdpsvc", "Windows Connected Devices Platform Service (CDPSvc)"),
    5353: ("mdns", "Multicast DNS / Bonjour"),
    5355: ("llmnr", "Link-Local Multicast Name Resolution"),
    5357: ("wsdapi", "Microsoft Web Services on Devices (WSDAPI)"),
    5985: ("wsman", "WinRM / WS-Management (HTTP)"),
    5986: ("wsmans", "WinRM / WS-Management (HTTPS)"),
    47001: ("winrm-http", "WinRM listener (HTTP.sys)"),
    9389: ("adws", "Active Directory Web Services"),
    5722: ("dfsr", "DFS Replication RPC"),
    464: ("kpasswd", "Kerberos password change"),
    49152: ("msrpc", "Dynamic MSRPC (ephemeral)"),
    102: ("iso-tsap", "Siemens S7 / ISO-TSAP"),
    623: ("ipmi", "IPMI / BMC (out-of-band mgmt)"),
    1900: ("upnp", "UPnP SSDP"),
    2049: ("nfs", "Network File System"),
    111: ("rpcbind", "ONC RPC portmapper"),
    873: ("rsync", "rsync daemon"),
    2375: ("docker", "Docker API (plaintext)"),
    2376: ("docker-s", "Docker API (TLS)"),
    6443: ("kube-apiserver", "Kubernetes API server"),
    9100: ("jetdirect", "Printer / HP JetDirect (raw)"),
    11211: ("memcached", "Memcached"),
    27017: ("mongodb", "MongoDB"),
    5432: ("postgresql", "PostgreSQL"),
    1521: ("oracle-tns", "Oracle TNS listener"),
}

# Dynamic MSRPC range (Windows ephemeral high ports) - anything here with no name
# is almost always an RPC endpoint the mapper (135) hands out.
_MSRPC_DYNAMIC = range(49152, 65536)


# --- layers 1 & 3: byte-signature matching --------------------------------------
# (compiled pattern, service name, description). Matched against the servicefp
# nmap kept AND against any banner we grab ourselves. Bytes are decoded latin-1
# so a text regex can scan them without choking on non-UTF-8.
_SIGNATURES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"^SSH-\d"), "ssh", "SSH"),
    (re.compile(r"^RFB \d{3}\."), "vnc", "VNC (RFB)"),
    (re.compile(r"^\+PONG"), "redis", "Redis"),
    (re.compile(r"-ERR .*unknown command|NOAUTH .*Authentication"), "redis", "Redis"),
    (re.compile(r"^220.*\b(FTP|FileZilla|vsFTPd|ProFTPD|Pure-FTPd)\b", re.I), "ftp", "FTP"),
    (re.compile(r"^220.*\b(SMTP|ESMTP|Postfix|Exim|Sendmail)\b", re.I), "smtp", "SMTP"),
    (re.compile(r"^\+OK"), "pop3", "POP3"),
    (re.compile(r"^\* OK.*IMAP", re.I), "imap", "IMAP"),
    (re.compile(r"^HTTP/\d"), "http", "HTTP"),
    (re.compile(r"^\x16\x03[\x00-\x04]"), "ssl", "TLS/SSL"),
    (re.compile(r"^\x03\x00\x00"), "ms-wbt-server", "RDP (X.224)"),
    (re.compile(r"mysql_native_password|^.\x00\x00\x00\x0a\d"), "mysql", "MySQL"),
    (re.compile(r"^\*\x03|MongoDB", re.I), "mongodb", "MongoDB"),
    (re.compile(r"^RTSP/\d"), "rtsp", "RTSP"),
    (re.compile(r"^AMQP\x00"), "amqp", "AMQP / RabbitMQ"),
    (re.compile(r"^\x00\x00\x00.\xffSMB|\xfeSMB"), "smb", "SMB"),
]


def _match_signature(data: str) -> tuple[str, str] | None:
    for pat, name, desc in _SIGNATURES:
        if pat.search(data):
            return name, desc
    return None


# --- active banner grab (layer 3) -----------------------------------------------

_BANNER_TIMEOUT = 4.0
_READ = 512

# Ports where the service stays silent until spoken to - send a tiny, protocol-
# appropriate nudge so we actually get bytes back. Everything else we just read
# (FTP/SMTP/SSH/POP/IMAP/VNC announce themselves on connect).
_NUDGE = {
    80: b"HEAD / HTTP/1.0\r\n\r\n", 8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\n\r\n", 8888: b"HEAD / HTTP/1.0\r\n\r\n",
    5000: b"HEAD / HTTP/1.0\r\n\r\n", 3000: b"HEAD / HTTP/1.0\r\n\r\n",
    6379: b"PING\r\n", 11211: b"version\r\n",
}
# RDP: an X.224 Connection Request. Cheap, and the response starts 0x03 0x00.
_RDP_CR = bytes.fromhex("0300000b06e00000000000")


def grab_banner(ip: str, port: Port, timeout: float = _BANNER_TIMEOUT) -> str:
    """Connect, (optionally nudge), read up to 512 bytes. Returns the raw bytes
    decoded latin-1 (lossless), or "" on any failure. Never raises."""
    pid = port.portid
    nudge = _NUDGE.get(pid)
    if pid == 3389:
        nudge = _RDP_CR
    try:
        with socket.create_connection((ip, pid), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(_READ)          # many services greet on connect
            except (socket.timeout, OSError):
                data = b""
            if not data and nudge:
                try:
                    s.sendall(nudge)
                    data = s.recv(_READ)
                except OSError:
                    data = b""
            return data.decode("latin-1", "replace") if data else ""
    except OSError:
        return ""


# --- orchestration --------------------------------------------------------------

def _needs_id(port: Port) -> bool:
    """True when nmap left this port without a real service name."""
    return (not port.service) or port.service in ("unknown", "tcpwrapped")


def infer_port_name(port: Port) -> tuple[str, str] | None:
    """Layers 1+2 (no network): mine nmap's kept servicefp, else the curated port
    map. Returns (service, description) or None."""
    if port.servicefp:
        hit = _match_signature(port.servicefp)
        if hit:
            return hit
    if port.portid in PORT_NAMES:
        return PORT_NAMES[port.portid]
    if port.portid in _MSRPC_DYNAMIC:
        return ("msrpc", "Dynamic MSRPC endpoint (ephemeral)")
    return None


def enrich_port(ip: str, port: Port, active: bool = True) -> bool:
    """Fill a missing service label for one port. Passive layers first (free),
    then an active banner grab if `active`. Returns True if a label was set or
    upgraded. nmap-sourced names are never overwritten."""
    if port.detect_source == "nmap":
        return False
    changed = False
    hit = infer_port_name(port)
    if hit and _needs_id(port):
        port.service = hit[0]
        port.extrainfo = port.extrainfo or hit[1]
        port.detect_source = "inferred"        # a good guess; a banner confirms it
        changed = True
    if not active:
        return changed
    banner = grab_banner(ip, port)
    if banner:
        port.banner = banner[:200]
        sig = _match_signature(banner)
        if sig:
            port.service = sig[0]
            port.extrainfo = port.extrainfo or sig[1]
            port.detect_source = "banner"      # strongest of our own evidence
            changed = True
    return changed


def enrich_host(host: Host, active: bool = True) -> int:
    """Enrich every open port on a host that nmap didn't concretely identify.
    Returns the number of ports we set/upgraded a label for."""
    n = 0
    for port in host.open_ports:
        if port.detect_source == "nmap":
            continue
        if enrich_port(host.ip, port, active=active):
            n += 1
    return n


def still_unknown_ports(host: Host) -> list[int]:
    """Open ports we STILL couldn't name after the passive + active layers - the
    candidates for a second-opinion nmap re-probe."""
    return [p.portid for p in host.open_ports if _needs_id(p)]


def apply_reprobe(host: Host, parsed_hosts: list) -> int:
    """Fold a second-opinion nmap `-sV --version-all` re-probe back in: upgrade any
    port nmap has now concretely named (its answer is authoritative, so it wins
    over our inferred/banner guesses). Returns the number of ports upgraded."""
    idx = {(p.protocol, p.portid): p for p in host.ports}
    upgraded = 0
    for ph in parsed_hosts:
        if ph.ip != host.ip:
            continue
        for rp in ph.ports:
            cur = idx.get((rp.protocol, rp.portid))
            if cur is None:
                continue
            if rp.service and rp.service not in ("unknown", "tcpwrapped"):
                cur.service = rp.service
                cur.product = rp.product or cur.product
                cur.version = rp.version or cur.version
                cur.extrainfo = rp.extrainfo or cur.extrainfo
                if rp.cpe:
                    cur.cpe = rp.cpe
                cur.detect_source = "nmap"
                upgraded += 1
    return upgraded


def suggest_id_command(ip: str, port: Port) -> str:
    """The next command a tester should run to positively ID a still-unknown port
    - so 'unknown' is an actionable to-do, not a shrug."""
    p = port.portid
    if _needs_id(port):
        return f"nmap -sV --version-all -p {p} {ip}   # or: amap -A {ip} {p}"
    return ""
