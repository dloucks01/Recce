"""SQLite-backed datastore.

Hosts are stored as JSON blobs keyed by IP so a re-scan simply upserts. This
makes multi-subnet engagements resumable: interrupt at any point, and the next
run merges new findings into the existing store instead of starting over.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing

from .models import Domain, Host

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    ip       TEXT PRIMARY KEY,
    subnet   TEXT,
    data     TEXT NOT NULL,
    updated  TEXT
);
CREATE TABLE IF NOT EXISTS domains (
    name TEXT PRIMARY KEY,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scope (
    subnet TEXT PRIMARY KEY,
    size   INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tracking (
    key      TEXT PRIMARY KEY,
    reviewed INTEGER DEFAULT 0,
    notes    TEXT DEFAULT '',
    status   TEXT DEFAULT '',
    updated  TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS issues (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT DEFAULT '',
    ip      TEXT DEFAULT '',
    phase   TEXT DEFAULT '',
    level   TEXT DEFAULT 'warning',
    message TEXT DEFAULT ''
);
"""


class Store:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.executescript(_SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after a datastore was first created."""
        with closing(self.conn.cursor()) as cur:
            cols = {r[1] for r in cur.execute("PRAGMA table_info(tracking)").fetchall()}
            if "status" not in cols:
                cur.execute("ALTER TABLE tracking ADD COLUMN status TEXT DEFAULT ''")

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- merge semantics --------------------------------------------------------

    def _merge(self, old: Host, new: Host) -> Host:
        """Combine two scans of the same host, preferring the richer data."""
        merged = old
        # Ports: index by (proto, portid); newer non-empty fields win.
        port_index = {(p.protocol, p.portid): p for p in old.ports}
        for np in new.ports:
            key = (np.protocol, np.portid)
            if key in port_index:
                op = port_index[key]
                op.state = np.state or op.state
                op.service = np.service or op.service
                op.product = np.product or op.product
                op.version = np.version or op.version
                op.extrainfo = np.extrainfo or op.extrainfo
                op.tunnel = np.tunnel or op.tunnel
                op.cpe = np.cpe or op.cpe
                op.vuln_scanned = op.vuln_scanned or np.vuln_scanned
                if np.scripts:
                    seen = {s.id for s in op.scripts}
                    op.scripts.extend(s for s in np.scripts if s.id not in seen)
            else:
                port_index[key] = np
        merged.ports = list(port_index.values())

        # Scalar enrichment: fill blanks, upgrade OS accuracy.
        merged.hostnames = list(dict.fromkeys(old.hostnames + new.hostnames))
        merged.mac = merged.mac or new.mac
        merged.vendor = merged.vendor or new.vendor
        if new.os_accuracy >= old.os_accuracy and new.os_name:
            merged.os_name, merged.os_accuracy, merged.os_family = (
                new.os_name, new.os_accuracy, new.os_family)
        merged.state = new.state or old.state
        merged.distance = new.distance or old.distance
        merged.enumerated = old.enumerated or new.enumerated
        merged.db_scanned = old.db_scanned or new.db_scanned
        merged.privesc_checked = old.privesc_checked or new.privesc_checked
        merged.cred_enumerated = old.cred_enumerated or new.cred_enumerated
        merged.last_scanned = new.last_scanned or old.last_scanned
        merged.subnet = new.subnet or old.subnet

        # Host-level scripts: dedup by id.
        hs_seen = {s.id for s in old.host_scripts}
        merged.host_scripts.extend(s for s in new.host_scripts if s.id not in hs_seen)
        # Ingested on-target findings: dedup by (category, vector).
        lf_seen = {(f.get("category"), f.get("vector")) for f in old.local_findings}
        for f in new.local_findings:
            k = (f.get("category"), f.get("vector"))
            if k not in lf_seen:
                lf_seen.add(k)
                merged.local_findings.append(f)
        # Roles / ntlm / signing enrichment.
        merged.roles = sorted(set(old.roles) | set(new.roles))
        merged.ntlm = {**new.ntlm, **old.ntlm}
        if new.smb_signing and new.smb_signing != "unknown":
            merged.smb_signing = new.smb_signing

        # Vulns / exploits / accounts: dedup by natural key, accumulating the
        # seen-set so duplicates WITHIN one scan are collapsed too, not just
        # old-vs-new.
        vseen = {v.key for v in old.vulns}
        for nv in new.vulns:
            if nv.key not in vseen:
                vseen.add(nv.key)
                merged.vulns.append(nv)
        eseen = {e.key for e in old.exploits}
        for ne in new.exploits:
            if ne.key not in eseen:
                eseen.add(ne.key)
                merged.exploits.append(ne)
        aseen = {(a.source, a.kind, a.name, a.domain, a.rid) for a in old.accounts}
        for a in new.accounts:
            k = (a.source, a.kind, a.name, a.domain, a.rid)
            if k not in aseen:
                merged.accounts.append(a)
                aseen.add(k)
        return merged

    def upsert_host(self, host: Host) -> None:
        existing = self.get_host(host.ip)
        if existing:
            host = self._merge(existing, host)
        with closing(self.conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO hosts(ip, subnet, data, updated) VALUES(?,?,?,?) "
                "ON CONFLICT(ip) DO UPDATE SET subnet=excluded.subnet, "
                "data=excluded.data, updated=excluded.updated",
                (host.ip, host.subnet, json.dumps(host.to_json()), host.last_scanned),
            )
        self.conn.commit()

    def get_host(self, ip: str) -> Host | None:
        with closing(self.conn.cursor()) as cur:
            row = cur.execute("SELECT data FROM hosts WHERE ip=?", (ip,)).fetchone()
        return Host.from_json(json.loads(row[0])) if row else None

    def all_hosts(self) -> list[Host]:
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute("SELECT data FROM hosts ORDER BY ip").fetchall()
        return [Host.from_json(json.loads(r[0])) for r in rows]

    def scanned_ips(self) -> set[str]:
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute("SELECT ip FROM hosts").fetchall()
        return {r[0] for r in rows}

    # --- domains ----------------------------------------------------------------

    def upsert_domain(self, domain: Domain) -> None:
        from .ad import merge_domain
        existing = self.get_domain(domain.name)
        if existing:
            domain = merge_domain(existing, domain)
        with closing(self.conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO domains(name, data) VALUES(?,?) "
                "ON CONFLICT(name) DO UPDATE SET data=excluded.data",
                (domain.name.lower(), json.dumps(domain.to_json())),
            )
        self.conn.commit()

    def get_domain(self, name: str) -> Domain | None:
        with closing(self.conn.cursor()) as cur:
            row = cur.execute("SELECT data FROM domains WHERE name=?",
                              (name.lower(),)).fetchone()
        return Domain.from_json(json.loads(row[0])) if row else None

    def all_domains(self) -> list[Domain]:
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute("SELECT data FROM domains ORDER BY name").fetchall()
        return [Domain.from_json(json.loads(r[0])) for r in rows]

    # --- coverage tracking ------------------------------------------------------

    def set_reviewed(self, key: str, reviewed: bool, notes: str | None = None,
                     when: str = "") -> None:
        with closing(self.conn.cursor()) as cur:
            row = cur.execute("SELECT notes FROM tracking WHERE key=?", (key,)).fetchone()
            keep_notes = row[0] if (row and notes is None) else (notes or "")
            cur.execute(
                "INSERT INTO tracking(key, reviewed, notes, updated) VALUES(?,?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET reviewed=excluded.reviewed, "
                "notes=excluded.notes, updated=excluded.updated",
                (key, 1 if reviewed else 0, keep_notes, when),
            )
        self.conn.commit()

    def bulk_set_tracking(self, items: dict[str, tuple], when: str = "") -> int:
        """items: {key: (reviewed_bool, notes)}. Returns number of rows written."""
        n = 0
        with closing(self.conn.cursor()) as cur:
            for key, (reviewed, notes) in items.items():
                cur.execute(
                    "INSERT INTO tracking(key, reviewed, notes, updated) VALUES(?,?,?,?) "
                    "ON CONFLICT(key) DO UPDATE SET reviewed=excluded.reviewed, "
                    "notes=excluded.notes, updated=excluded.updated",
                    (key, 1 if reviewed else 0, notes or "", when),
                )
                n += 1
        self.conn.commit()
        return n

    # --- scope (every subnet in the engagement, so none is missed) --------------

    def set_scope(self, subnet: str, size: int) -> None:
        with closing(self.conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO scope(subnet, size) VALUES(?,?) "
                "ON CONFLICT(subnet) DO UPDATE SET size=max(scope.size, excluded.size)",
                (subnet, size),
            )
        self.conn.commit()

    def get_scope(self) -> dict[str, int]:
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute("SELECT subnet, size FROM scope").fetchall()
        return {r[0]: r[1] for r in rows}

    def delete_tracking(self, key: str) -> None:
        with closing(self.conn.cursor()) as cur:
            cur.execute("DELETE FROM tracking WHERE key=?", (key,))
        self.conn.commit()

    def get_tracking(self) -> dict[str, tuple]:
        """Return {key: (reviewed_bool, notes)}."""
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute("SELECT key, reviewed, notes FROM tracking").fetchall()
        return {r[0]: (bool(r[1]), r[2] or "") for r in rows}

    def bulk_set_status(self, items: dict[str, tuple], when: str = "") -> int:
        """items: {key: (status_str, reviewed_bool, notes)}. Persists a per-item
        tri-state status (e.g. a per-port 'in progress') alongside the reviewed
        flag so coverage still works (reviewed True == the port is done)."""
        n = 0
        with closing(self.conn.cursor()) as cur:
            for key, (status, reviewed, notes) in items.items():
                cur.execute(
                    "INSERT INTO tracking(key, reviewed, notes, status, updated) "
                    "VALUES(?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET "
                    "reviewed=excluded.reviewed, notes=excluded.notes, "
                    "status=excluded.status, updated=excluded.updated",
                    (key, 1 if reviewed else 0, notes or "", status or "", when),
                )
                n += 1
        self.conn.commit()
        return n

    def get_statuses(self) -> dict[str, str]:
        """Return {key: status_str} for rows that carry a non-empty status."""
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute(
                "SELECT key, status FROM tracking WHERE status != ''").fetchall()
        return {r[0]: r[1] for r in rows}

    # --- scan issues (errors / incomplete scans, surfaced to the operator) ------

    def add_issue(self, ip: str, phase: str, level: str, message: str,
                  ts: str = "") -> None:
        with closing(self.conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO issues(ts, ip, phase, level, message) VALUES(?,?,?,?,?)",
                (ts, ip, phase, level, message),
            )
        self.conn.commit()

    def clear_issues(self, ip: str, phase: str) -> None:
        """Drop prior issues for one host+phase so re-running a phase replaces its
        issues instead of appending duplicates (which inflate the Overview count)."""
        with closing(self.conn.cursor()) as cur:
            cur.execute("DELETE FROM issues WHERE ip=? AND phase=?", (ip, phase))
        self.conn.commit()

    def get_issues(self) -> list[dict]:
        """All logged scan issues, newest first."""
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute(
                "SELECT ts, ip, phase, level, message FROM issues "
                "ORDER BY id DESC").fetchall()
        return [{"ts": r[0], "ip": r[1], "phase": r[2], "level": r[3],
                 "message": r[4]} for r in rows]

    def count_issues(self) -> dict[str, int]:
        """{'error': n, 'warning': m, 'total': t}."""
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute(
                "SELECT level, COUNT(*) FROM issues GROUP BY level").fetchall()
        out = {r[0]: r[1] for r in rows}
        out["total"] = sum(out.values())
        return out

    def set_meta(self, key: str, value: str) -> None:
        with closing(self.conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO meta(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
        self.conn.commit()

    def get_meta(self, key: str) -> str | None:
        with closing(self.conn.cursor()) as cur:
            row = cur.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None
