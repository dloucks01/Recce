"""Well-formed protocol wire captures, shared by the high-fidelity test batches.

Each builder returns the exact bytes a real server puts on the wire for the happy
path. They are constructed with each module's own encoders, so a fixture and the
decoder it feeds can never silently drift apart. Two consumers use them:

  * test_fuzz_decoders.py - as *seeds* to truncate, bit-flip and splice, checking
    that every decoder survives hostile mutations of a real message.
  * test_wire_vectors.py  - as *golden* input, asserting the exact parsed output so
    a decoder that starts mis-reading a real server's fields is caught.

Keeping them here (not inline in one test) means both batches exercise byte-for-byte
the same "real" message, so a fuzz failure and a golden failure are comparable.
"""
import struct

from recce import snmp as S
from recce import mongodb as M
from recce import ldap as L
from recce import ntlm as N
from recce import smb as SMB


# --- SNMP -----------------------------------------------------------------------

def snmp_get_response() -> bytes:
    """A GetResponse: community 'public', request-id 42, one sysDescr varbind."""
    varbind = S._tlv(0x30, S.encode_oid("1.3.6.1.2.1.1.1.0")
                     + S._octet("Linux recce 6.1.0"))
    pdu = S._tlv(0xA2, S._int(42) + S._int(0) + S._int(0) + S._tlv(0x30, varbind))
    return S._tlv(0x30, S._int(1) + S._octet("public") + pdu)


# --- MongoDB / BSON -------------------------------------------------------------

def _bson_e_double(name, v):
    return b"\x01" + M._cstr(name) + struct.pack("<d", v)


def _bson_e_bool(name, v):
    return b"\x08" + M._cstr(name) + bytes([1 if v else 0])


def _bson_e_doc(name, doc):
    return b"\x03" + M._cstr(name) + doc


def _bson_e_array(name, docs):
    inner = M.bson_doc(*[_bson_e_doc(str(i), d) for i, d in enumerate(docs)])
    return b"\x04" + M._cstr(name) + inner


def mongodb_hello_doc() -> bytes:
    """The BSON body of a hello/isMaster reply from an unauthed primary."""
    return M.bson_doc(_bson_e_bool("isWritablePrimary", True),
                      M._e_int32("maxWireVersion", 17),
                      M._e_str("setName", "rs0"),
                      _bson_e_double("ok", 1.0))


def mongodb_listdbs_doc() -> bytes:
    """A listDatabases reply carrying a nested array of sub-documents (exercises the
    embedded-document and array code paths of bson_parse)."""
    dbs = _bson_e_array("databases", [
        M.bson_doc(M._e_str("name", "admin"), _bson_e_double("sizeOnDisk", 4096.0)),
        M.bson_doc(M._e_str("name", "config"), _bson_e_double("sizeOnDisk", 8192.0)),
    ])
    return M.bson_doc(dbs, _bson_e_double("totalSize", 12288.0),
                      _bson_e_double("ok", 1.0))


# --- LDAP -----------------------------------------------------------------------

def ldap_search_entry() -> bytes:
    """A searchResEntry LDAPMessage with one multi-valued attribute."""
    def tlv(t, v):
        return bytes([t]) + L._ber_len(len(v)) + v
    vals = tlv(0x31, L._octet("dc01.corp.local") + L._octet("dc01"))
    attr = tlv(0x30, L._octet("dnsHostName") + vals)
    op = tlv(0x64, L._octet("CN=DC01,OU=Domain Controllers,DC=corp,DC=local")
             + tlv(0x30, attr))
    return tlv(0x30, L._int(2) + op)


# --- NTLM -----------------------------------------------------------------------

# Real AV-pair TargetInfo block from the MS-NLMP worked example (NetBIOS domain
# "Domain", NetBIOS server "Server", terminated by an MsvAvEOL pair).
_NTLM_TARGET_INFO = bytes.fromhex(
    "02000c0044006f006d00610069006e00"
    "01000c00530065007200760065007200"
    "00000000")


def ntlm_type2() -> bytes:
    """A CHALLENGE_MESSAGE (type 2) with a server challenge and TargetInfo payload."""
    challenge = bytes.fromhex("0123456789abcdef")
    flags = N._SEAL_FLAGS
    ti = _NTLM_TARGET_INFO
    ti_off = 56                                       # after the 8-byte Version field
    header = (N._SIG                                  # 0:8   signature
              + struct.pack("<I", 2)                  # 8:12  message type
              + struct.pack("<HHI", 0, 0, 0)          # 12:20 TargetName fields (empty)
              + struct.pack("<I", flags)              # 20:24 NegotiateFlags
              + challenge                             # 24:32 ServerChallenge
              + b"\x00" * 8                           # 32:40 Reserved
              + struct.pack("<HHI", len(ti), len(ti), ti_off)   # 40:48 TargetInfo fields
              + b"\x00" * 8)                          # 48:56 Version
    return header + ti


# --- SMB ------------------------------------------------------------------------

def smb2_negotiate_response() -> bytes:
    """An SMB2 NEGOTIATE OK selecting dialect 3.1.1, signing enabled but not required."""
    hdr = SMB._smb2_header(0x0000, flags=0x00000001)
    body = (struct.pack("<H", 65) + struct.pack("<H", 0x01)
            + struct.pack("<H", 0x0311) + struct.pack("<H", 0) + b"\x11" * 16
            + struct.pack("<I", 7) + struct.pack("<I", 0x800000) * 3)
    return struct.pack(">I", len(hdr + body)) + hdr + body


def smb1_negotiate_response() -> bytes:
    """An SMBv1 NEGOTIATE answer that selects a dialect (SMBv1 enabled)."""
    hdr = (b"\xffSMB" + b"\x72" + b"\x00\x00\x00\x00" + b"\x98" + b"\x01\x28"
           + b"\x00\x00" + b"\x00" * 8 + b"\x00\x00" + b"\x00\x00" + b"\x2f\x4b"
           + b"\x00\x08" + b"\xc5\x5e")
    body = struct.pack("<B", 17) + struct.pack("<H", 5) + b"\x00" * 30
    return struct.pack(">I", len(hdr + body)) + hdr + body


# --- nmap XML -------------------------------------------------------------------

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV 10.0.0.5">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="dc01.corp.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds" product="Samba smbd" version="4.15" ostype="Linux"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.24" tunnel="ssl"/>
        <script id="ssl-cert" output="Subject: CN=dc01.corp.local"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.x" accuracy="95"/></os>
  </host>
</nmaprun>
"""


ALL_BYTE_VECTORS = {
    "snmp_get_response": snmp_get_response,
    "mongodb_hello_doc": mongodb_hello_doc,
    "mongodb_listdbs_doc": mongodb_listdbs_doc,
    "ldap_search_entry": ldap_search_entry,
    "ntlm_type2": ntlm_type2,
    "smb2_negotiate_response": smb2_negotiate_response,
    "smb1_negotiate_response": smb1_negotiate_response,
}
