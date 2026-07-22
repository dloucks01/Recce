"""Command-line entrypoint for recce.

Subcommands (see `recce -h` for the full, authoritative list):
  Scan/enumerate  enum, scan, vulns, db, privesc, credenum, services
  Import/ingest   import (nmap -oX/-oG/-oN), ingest (on-target loot)
  Post-exploit    exploitplan, attackpath, creds
  Report/track    report, status, review, writeups, writeup
  Utility         demo (bundled sample, no network), doctor (self-test)
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import ad
from . import exploits
from . import parser as np
from . import scanner
from . import tracking as tr
from .models import Host
from .report_excel import read_workbook_edits, update_workbook
from .report_markdown import build_csv, build_markdown
from .store import Store, StoreError
from .targets import apply_exclusions, ip_matcher, load_targets

BANNER = r"""
  ____  _____ ____ ____ _____
 |  _ \| ____/ ___/ ___| ____|
 | |_) |  _|| |  | |   |  _|
 |  _ <| |__| |__| |___| |___
 |_| \_\_____\____\____|_____|
   recon & coverage tracker for airgapped pentests
"""



def _fmt_dur(seconds: float) -> str:
    """Compact human duration: 45s / 3m20s / 1h04m."""
    s = int(round(seconds))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m{s % 60:02d}s"
    return f"{s // 3600}h{(s % 3600) // 60:02d}m"


def _progress(done: int, total: int, start: float) -> str:
    """A '· 42% · ETA 3m20s' suffix from elapsed time and completion ratio."""
    if total <= 0:
        return ""
    pct = int(done * 100 / total)
    elapsed = time.monotonic() - start
    if done and done < total:
        eta = elapsed / done * (total - done)
        return f" · {pct}% · ETA {_fmt_dur(eta)}"
    if done >= total:
        return f" · 100% · {_fmt_dur(elapsed)} total"
    return f" · {pct}%"


def _summarize_failures(phase: str, errs: list, total: int) -> None:
    """Loud end-of-phase failure summary so a bad host can't scroll past unseen.
    `errs` is a list of (ip, message); prints nothing when everything went fine."""
    if not errs:
        print(f"[+] {phase}: {total}/{total} host(s) OK, no errors.")
        return
    hosts = len({ip for ip, _ in errs})
    print("\n" + "!" * 64)
    print(f"[x] {phase}: {hosts} host(s) had errors ({len(errs)} issue(s)) - "
          f"{total - hosts}/{total} clean:")
    for ip, msg in errs:
        print(f"      {ip:<16} {msg}")
    print("!" * 64)


def _ports_for_host(xml_path: str, ip: str) -> list[int]:
    for h in np.parse_nmap_xml(xml_path):
        if h.ip == ip:
            return [p.portid for p in h.ports]
    return []


def _open_store(db_path: str):
    """Open the datastore, turning a corrupt/unreadable DB (StoreError) into a
    clean actionable message + None instead of a traceback. Used by the commands
    that open an existing engagement directly (report/status/writeups/...)."""
    try:
        return Store(db_path)
    except StoreError as e:
        print(f"[x] {e}")
        return None


def _open_paths(out_dir: str) -> dict[str, str]:
    raw = os.path.join(out_dir, "raw")
    os.makedirs(raw, exist_ok=True)
    return {
        "raw": raw,
        "db": os.path.join(out_dir, "results.sqlite"),
        "xlsx": os.path.join(out_dir, "enumeration.xlsx"),
        "md": os.path.join(out_dir, "enumeration.md"),
        "csv": os.path.join(out_dir, "services.csv"),
        "html": os.path.join(out_dir, "report.html"),
        "log": os.path.join(out_dir, "recce.log"),
    }


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _record_issues(store: Store, paths: dict, ip: str, issues: list) -> None:
    """Persist scan issues (errors / incomplete scans) to the datastore + the
    plain-text run log, and echo errors to the console so they're seen live."""
    if not issues:
        return
    # Clear this host's prior issues for each phase we're about to (re)write, so a
    # re-run replaces its own issues instead of stacking duplicates.
    for phase in {iss.get("phase", "") for iss in issues if isinstance(iss, dict)}:
        store.clear_issues(ip, phase)
    for iss in issues:
        phase = iss.get("phase", "") if isinstance(iss, dict) else ""
        level = iss.get("level", "warning") if isinstance(iss, dict) else "warning"
        message = iss.get("message", "") if isinstance(iss, dict) else str(iss)
        store.add_issue(ip, phase, level, message, ts=_now())
        try:
            with open(paths["log"], "a") as fh:
                fh.write(f"{_now()} [{level.upper()}] {ip} {message}\n")
        except OSError:
            pass
        marker = "[!]" if level == "error" else "[~]"
        print(f"    {marker} {ip}: {message}")


def _persist_host(store: Store, paths: dict, ip: str, phase: str, host,
                  clear_step: str | None = None) -> bool:
    """Persist one host's results, isolating a datastore failure to that host so
    a single problematic host can never abort the rest of the phase (the store
    already retries locks via busy_timeout; this catches a lock that outlasts it
    or any serialization edge). Returns True if the host was stored."""
    try:
        store.upsert_host(host)
        if clear_step:
            store.delete_tracking(tr.step_key(clear_step, ip))  # re-run clears override
        return True
    except Exception as e:  # noqa: BLE001
        _record_issues(store, paths, ip,
                       [{"phase": phase, "level": "error",
                         "message": f"could not persist results: {e}"}])
        return False


def _resolve_domains(store: Store, hosts: list) -> list:
    domains = {d.name.lower(): d for d in ad.derive_domains(hosts)}
    for d in store.all_domains():
        key = d.name.lower()
        domains[key] = ad.merge_domain(domains[key], d) if key in domains else d
    return list(domains.values())


def _reconcile_steps(store: Store, step_edits: dict) -> None:
    """Turn Checklist step-checkbox values into overrides: record one only when it
    differs from the tool's current auto-completion; otherwise clear it so the box
    follows the tool. (This is what makes 'auto-default, manual wins' work.)"""
    for key, (shown, _note) in step_edits.items():
        try:
            _, step, ip = key.split(":", 2)
        except ValueError:
            continue
        host = store.get_host(ip)
        # A step that no longer applies to the host carries no override.
        if host and not tr.step_applies(host, step):
            store.delete_tracking(key)
            continue
        auto = tr.step_auto(host, step) if host else False
        if shown == auto:
            store.delete_tracking(key)     # follow the tool
        else:
            store.set_reviewed(key, shown)  # persist the manual override


def _import_excel_tracking(store: Store, paths: dict[str, str],
                           reconcile_steps: bool = True) -> None:
    """Pull operator checkbox/notes edits from the workbook into the datastore.

    The datastore is authoritative; call this BEFORE any mutation or regenerate so
    manual edits are captured but never clobbered by a stale rebuild. Step
    checkboxes are reconciled against tool auto-state only in operator-driven
    commands (`reconcile_steps=True`); mid-scan refreshes skip them, because the
    workbook can lag the tool's fresh progress and would look like manual edits."""
    if not os.path.exists(paths["xlsx"]):
        return
    edits, statuses = read_workbook_edits(paths["xlsx"])
    if not edits:
        return
    step_edits = {k: v for k, v in edits.items() if k.startswith("step:")}
    plain: dict = {}
    status_items: dict = {}
    for k, (rev, note) in edits.items():
        if k.startswith("step:"):
            continue
        if k in statuses:
            # Per-port tri-state: persist the status + derived reviewed + notes.
            status_items[k] = (statuses[k], rev, note)
        else:
            plain[k] = (rev, note)
    if plain:
        store.bulk_set_tracking(plain)
    if status_items:
        store.bulk_set_status(status_items)
    if reconcile_steps and step_edits:
        _reconcile_steps(store, step_edits)


def _safe_refresh(store: Store, paths: dict[str, str], title: str) -> bool:
    """Refresh reports mid-scan without losing operator edits.

    Re-imports the operator's saved checkboxes/notes from the workbook FIRST (so
    editing Excel while the scan runs is safe), then regenerates. If the workbook
    is open/locked and can't be written, leaves it and returns False - the edits
    are already captured in the datastore, so nothing is lost.
    """
    _import_excel_tracking(store, paths, reconcile_steps=False)
    try:
        _generate_reports(store, paths, title, quiet=True)
        return True
    except Exception:  # noqa: BLE001
        # A locked workbook (OSError) OR any report-builder bug must NOT abort the
        # scan phase mid-run - the data is safe in the datastore, and the final
        # report (or a later `report` command) will regenerate it.
        return False


def _generate_reports(store: Store, paths: dict[str, str], title: str,
                      quiet: bool = False) -> None:
    """Regenerate all reports from the datastore (the source of truth)."""
    hosts = store.all_hosts()
    tracking = store.get_tracking()
    domains = _resolve_domains(store, hosts)
    update_workbook(paths["xlsx"], hosts, meta={"subtitle": title},
                    domains=domains, tracking=tracking, scope=store.get_scope(),
                    statuses=store.get_statuses(), issues=store.get_issues(),
                    credentials=store.all_credentials())
    build_markdown(hosts, paths["md"], title=title, domains=domains)
    build_csv(hosts, paths["csv"])
    from .report_html import build_html
    build_html(hosts, paths["html"], title=title, domains=domains,
               credentials=store.all_credentials(), generated=_now())
    if not quiet:
        cov = tr.compute_coverage(hosts, tracking)["overall"]
        print(f"[+] Reports written ({cov['done']}/{cov['total']} items reviewed, "
              f"{cov['pct']}%):\n    {paths['xlsx']}\n    {paths['md']}\n    {paths['csv']}"
              f"\n    {paths['html']}")
        counts = store.count_issues()
        if counts.get("total"):
            print(f"[!] {counts['total']} scan issue(s) logged "
                  f"({counts.get('error', 0)} error, {counts.get('warning', 0)} "
                  f"incomplete) - see the Overview tab or {paths['log']}")


# --- scan command ----------------------------------------------------------------

def _apply_profile_overrides(profile, args) -> None:
    g = lambda name, default=None: getattr(args, name, default)  # noqa: E731
    if g("all_ports"):
        profile.all_ports = True
    if g("top_ports"):
        profile.all_ports = False
        profile.top_ports = args.top_ports
    if g("no_ad"):
        profile.ad_enrich = False
    if g("no_os"):
        profile.os_detect = False
    if g("min_rate"):
        profile.min_rate = args.min_rate
    if g("max_retries") is not None:
        profile.max_retries = args.max_retries
    if g("no_verify"):
        profile.verify = False
    if g("verify_all"):
        profile.verify_all = True
    if g("reliable"):
        profile.reliable = True
    if g("udp_top"):
        profile.udp_top = args.udp_top
    if g("masscan") or g("fast"):
        profile.scanner = "masscan"
    if g("offline"):
        profile.offline = True
    if g("host_timeout") is not None:
        profile.host_timeout = args.host_timeout
    if g("version_all"):
        profile.version_all = True
    if g("version_intensity") is not None:
        profile.version_intensity = args.version_intensity
    profile.ping_discovery = not g("no_discovery", False)
    profile.assume_up = not profile.ping_discovery   # -Pn: fail-fast on dead IPs


def _creds_of(args) -> dict | None:
    return {"username": args.username, "password": args.password,
            "domain": args.domain} if getattr(args, "username", None) else None


def _admin_creds_of(args) -> dict | None:
    """The optional privileged/superuser account (domain defaults to -d)."""
    if not getattr(args, "admin_username", None):
        return None
    return {"username": args.admin_username, "password": args.admin_password,
            "domain": getattr(args, "admin_domain", None) or getattr(args, "domain", None)}


class _Refresher:
    """Throttled interim report refresh: regenerate after every N hosts OR at
    least every `interval` seconds, whichever comes first. Results are already
    persisted to SQLite per host, so this only controls how often the *sheet* is
    rebuilt - findings are durable even if a refresh is skipped or the run dies.
    """

    def __init__(self, args, interval: float = 20.0):
        self.every = getattr(args, "refresh_every", 0) or 0
        self.interval = interval
        self.count = 0
        self.last = time.monotonic()

    def tick(self, store, paths, title) -> None:
        self.count += 1
        now = time.monotonic()
        due = (self.every and self.count % self.every == 0) or \
              (now - self.last >= self.interval)
        if not due:
            return
        if _safe_refresh(store, paths, title):
            self.last = now
            print(f"    ~ report refreshed ({self.count} host(s) so far).")
        else:
            print("    ~ report open/locked - kept your edits, will retry.")


def _final_report(store, paths, title) -> None:
    """Always-try final report (guarded); results survive even if the file is
    locked, since they're in the datastore."""
    try:
        _import_excel_tracking(store, paths, reconcile_steps=False)
        _generate_reports(store, paths, title)
    except Exception as e:  # noqa: BLE001
        # Runs in every command's `finally`, so a locked workbook OR any
        # report-builder bug must not turn completed scan work into a crash.
        detail = "open/locked" if isinstance(e, OSError) else f"{type(e).__name__}: {e}"
        print(f"[!] Could not write the workbook ({detail}). Your data is saved "
              "in the datastore - close the file and run `report` to rebuild it.")


# --- phase 1+2a: discovery + light service enumeration --------------------------

def _mkissue(scan_issue, phase: str) -> dict:
    return {"phase": phase, "level": scan_issue.level,
            "message": scan_issue.message}


def _enum_worker(ip, profile, paths, creds, port_map, subnet_map):
    """Returns (host|None, issues)."""
    issues: list[dict] = []
    truncated = False
    if port_map is not None:
        open_ports = port_map.get(ip, [])
    else:
        fp_xml = os.path.join(paths["raw"], f"{ip}_ports.xml")
        _, iss = scanner.full_port_scan(ip, fp_xml, profile)
        if iss:
            issues.append(_mkissue(iss, "port-sweep"))
            truncated = iss.kind == "host-timeout"
        open_ports = _ports_for_host(fp_xml, ip)
        # Completeness safeguard: a host that came back with ZERO ports may be
        # genuinely empty - or the fast pass dropped every probe. Confirm it with
        # an independent congestion-adaptive re-scan before we trust "no ports"
        # (everything downstream keys off this). Gated so dead -Pn IPs on a clean
        # network aren't all re-scanned: verify discovered-live hosts always, and
        # -Pn hosts only with --verify-all.
        if (not open_ports and profile.verify and not truncated
                and (profile.ping_discovery or profile.verify_all)):
            vx = os.path.join(paths["raw"], f"{ip}_verify.xml")
            _, viss = scanner.verify_port_scan(ip, vx, profile)
            vports = _ports_for_host(vx, ip)
            if viss and viss.kind == "host-timeout":
                truncated = True
            if vports:
                open_ports = vports
                issues.append(_mkissue(scanner.ScanIssue(
                    "warning", f"port-sweep: fast pass found 0 ports but a "
                    f"verification re-scan found {len(vports)} - the first sweep "
                    "under-reported (network likely lossy); used the re-scan"),
                    "port-sweep"))

    enum_xml = os.path.join(paths["raw"], f"{ip}_enum.xml")
    _, iss = scanner.enum_scan(ip, open_ports, enum_xml, profile, creds=creds)
    if iss:
        issues.append(_mkissue(iss, "enum"))
    host = _fold_host(ip, np.parse_nmap_xml(enum_xml), subnet_map)
    host.enumerated = True
    host.incomplete_scan = truncated
    ad.identify_roles(host)
    ad.parse_signing_and_ntlm(host)
    from . import vulndb
    vulndb.assess_host_inplace(host)   # offline version->CVE findings, immediately
    return host, issues


def _discover(args, profile, store, paths):
    try:
        hosts, subnet_map = load_targets(args.targets)
    except (ValueError, OSError) as e:
        # Bad CIDR/range (ValueError) or a missing/unreadable @file (OSError) - the
        # literal first thing a tester types. Fail with a clear message, not a crash.
        print(f"[x] Invalid targets: {e}\n    Fix the IP / range / CIDR / @file "
              "and re-run.")
        return None, [], None
    hosts = apply_exclusions(hosts, args.exclude or [])
    if not hosts:
        print("[x] No targets after expansion/exclusion.")
        return None, [], None
    # Record the full scope so the report accounts for every subnet, even those
    # that turn out to have no live hosts.
    sizes: dict[str, int] = {}
    for ip in hosts:
        sizes[subnet_map[ip]] = sizes.get(subnet_map[ip], 0) + 1
    for subnet, size in sizes.items():
        store.set_scope(subnet, size)
    print(f"[+] {len(hosts)} target host(s) across {len(sizes)} subnet(s).")

    fast_mode = getattr(args, "fast", False) or profile.scanner == "masscan"
    port_map = None
    if fast_mode:
        print("[*] Fast mode: network-wide masscan sweep ...")
        sweep_xml = os.path.join(paths["raw"], "masscan_sweep.xml")
        port_map = scanner.masscan_sweep(hosts, sweep_xml, profile)
        if port_map:
            live_ips = sorted(port_map, key=_ip_key)
            print(f"[+] masscan found {len(live_ips)} host(s) with open ports.")
        else:
            print("[!] masscan unavailable/empty; falling back to nmap.")
            port_map, fast_mode = None, False

    if not fast_mode:
        if profile.ping_discovery:
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
                tf.write("\n".join(hosts))
                targets_file = tf.name
            disc_xml = os.path.join(paths["raw"], "discovery.xml")
            print("[*] Discovery: host sweep ...")
            _, iss = scanner.discover_hosts(targets_file, disc_xml)
            if iss:
                _record_issues(store, paths, "(discovery)", [_mkissue(iss, "discovery")])
            live_ips = [h.ip for h in np.parse_nmap_xml(disc_xml)]
            os.unlink(targets_file)
            print(f"[+] {len(live_ips)} of {len(hosts)} target(s) responded to discovery.")
            if not live_ips:
                # Zero responses almost always means the network blocks ping/probes,
                # not that nothing is there. Don't hand back an empty engagement -
                # fall back to -Pn (scan every target as up) automatically.
                print("\n" + "!" * 64)
                print("[!] 0 hosts answered host discovery - the network is likely "
                      "blocking ping/probes.")
                print("    Falling back to -Pn (scanning all targets as up) so you "
                      "don't miss firewalled hosts.")
                print(f"    Per-host cap {profile.host_timeout}m + fail-fast keep it "
                      "moving; for a large scope, --fast (masscan) sweeps in seconds.")
                print("!" * 64)
                profile.assume_up = True          # dead IPs get scanned -> fail fast
                live_ips = hosts
            elif len(live_ips) < len(hosts):
                missed = len(hosts) - len(live_ips)
                print(f"    ({missed} didn't answer. If you expect more live hosts, "
                      "re-run with -Pn - firewalled hosts often block ping.)")
        else:
            live_ips = hosts
            print(f"[*] -Pn: skipping discovery, scanning all {len(hosts)} target(s) "
                  "as up.")
            print(f"    Each host is capped at {profile.host_timeout}m (--host-timeout) "
                  "and dead IPs are abandoned fast; --fast (masscan) is quickest on a "
                  "big scope.")

    if getattr(args, "resume", False):
        done = store.scanned_ips()
        live_ips = [ip for ip in live_ips if ip not in done]
        print(f"[+] Resume: {len(live_ips)} host(s) remaining.")
    return subnet_map, live_ips, port_map


def _phase_enum(store, paths, args, profile, subnet_map, live_ips, port_map) -> None:
    creds = _creds_of(args)
    workers = max(1, args.workers)
    print(f"[*] Enumerating {len(live_ips)} host(s) with {workers} worker(s) "
          f"(ports + services) ...")
    completed = 0
    refresher = _Refresher(args)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_enum_worker, ip, profile, paths, creds, port_map,
                             subnet_map): ip for ip in live_ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                host, issues = fut.result()
            except Exception as e:  # noqa: BLE001
                _record_issues(store, paths, ip,
                               [{"phase": "enum", "level": "error",
                                 "message": f"enum crashed: {e}"}])
                continue
            _record_issues(store, paths, ip, issues)
            if host is None:
                continue
            if not _persist_host(store, paths, ip, "enum", host, clear_step="enum"):
                continue   # one host's persist failure never aborts the rest
            completed += 1
            extra = f" - {', '.join(host.roles)}" if host.roles else ""
            print(f"    [{completed}/{len(live_ips)}] {ip}: "
                  f"{len(host.open_ports)} open port(s){extra}")
            refresher.tick(store, paths, args.title)


# --- phase 2b: vulnerability scanning (per open port) ---------------------------

def _merge_vuln_results(host: Host, parsed_list) -> None:
    """Fold vuln-phase results (vulns, accounts, port scripts) into a host."""
    port_index = {(p.protocol, p.portid): p for p in host.ports}
    for ph in parsed_list:
        if ph.ip != host.ip:
            continue
        vseen = {v.key for v in host.vulns}
        host.vulns.extend(v for v in ph.vulns if v.key not in vseen)
        aseen = {(a.source, a.kind, a.name, a.domain, a.rid) for a in host.accounts}
        for a in ph.accounts:
            if (a.source, a.kind, a.name, a.domain, a.rid) not in aseen:
                host.accounts.append(a)
        hs = {s.id for s in host.host_scripts}
        host.host_scripts.extend(s for s in ph.host_scripts if s.id not in hs)
        for np_ in ph.ports:
            op = port_index.get((np_.protocol, np_.portid))
            if op:
                seen = {s.id for s in op.scripts}
                op.scripts.extend(s for s in np_.scripts if s.id not in seen)
                op.product = op.product or np_.product
                op.version = op.version or np_.version


def _vuln_worker(host, portids, profile, paths, creds, aggressive, use_ss,
                 use_probes=True, fast=False):
    """Returns (host, issues)."""
    ip = host.ip
    issues: list[dict] = []
    if portids:
        vx = os.path.join(paths["raw"], f"{ip}_vuln.xml")
        _, iss = scanner.vuln_scan(ip, portids, vx, profile, creds=creds,
                                   aggressive=aggressive, fast=fast)
        if iss:
            issues.append(_mkissue(iss, "vuln-scan"))
        _merge_vuln_results(host, np.parse_nmap_xml(vx))
    if profile.udp_top:
        ux = os.path.join(paths["raw"], f"{ip}_udp.xml")
        _, iss = scanner.udp_scan(ip, ux, profile)
        if iss:
            issues.append(_mkissue(iss, "udp"))
        _merge_vuln_results(host, np.parse_nmap_xml(ux))
    pset = set(portids)
    for p in host.ports:
        if p.portid in pset:
            p.vuln_scanned = True
    ad.identify_roles(host)
    ad.parse_signing_and_ntlm(host)
    from . import vulndb
    vulndb.assess_host_inplace(host)   # offline version->CVE findings
    if use_probes:
        from . import probes
        probes.probe_host(host)        # stdlib HTTP-header + TLS analysis
    if use_ss:
        exploits.enrich_hosts([host])
    return host, issues


def _selected_hosts(hosts, args):
    """Filter stored hosts by IP / range / CIDR selection (targets/--host/--subnet)."""
    tokens = ((getattr(args, "targets", None) or [])
              + (getattr(args, "host", None) or [])
              + (getattr(args, "subnet", None) or []))
    match = ip_matcher(tokens)
    return [h for h in hosts if match(h.ip)]


def _vuln_targets(hosts, args):
    """Return [(host, [portids])] after target selection + --only/--unscanned."""
    only = [o.lower() for o in (getattr(args, "only", None) or [])]
    out = []
    for h in _selected_hosts(hosts, args):
        ports = h.open_ports
        if getattr(args, "unscanned", False):
            ports = [p for p in ports if not p.vuln_scanned]
        if only:
            ports = [p for p in ports
                     if any(k in (p.service or "").lower() or k == str(p.portid)
                            for k in only)]
        if ports:
            out.append((h, [p.portid for p in ports]))
    return out


def _phase_vulns(store, paths, args, profile) -> None:
    creds = _creds_of(args)
    aggressive = getattr(args, "aggressive", False)
    fast = getattr(args, "fast", False) and not aggressive
    use_ss = not getattr(args, "no_searchsploit", False) and exploits.available()
    use_probes = not getattr(args, "no_probes", False)
    if not getattr(args, "no_searchsploit", False) and not exploits.available():
        print("[!] searchsploit not found; skipping exploit mapping "
              "(apt install exploitdb).")
    if profile.offline:
        print("[*] Offline: vulners disabled; using local vuln scripts + searchsploit.")
    if aggressive:
        mode = "AGGRESSIVE (intrusive vuln category)"
    elif fast:
        mode = "FAST (top-signal detection scripts only)"
    else:
        mode = "safe (vuln+safe detection only)"
    print(f"[*] Vuln-scan mode: {mode}"
          f"{' + searchsploit' if use_ss else ''}"
          f"{' + http/tls probes' if use_probes else ''}.")

    targets = _vuln_targets(store.all_hosts(), args)
    if not targets:
        print("[!] No open ports match the vuln-scan filters.")
        return
    workers = max(1, args.workers)
    total_ports = sum(len(p) for _, p in targets)
    total = len(targets)
    print(f"[*] Vuln-scanning {total} host(s) / {total_ports} port(s) "
          f"with {workers} worker(s) ...")
    completed = 0
    errs: list[tuple[str, str]] = []   # (ip, message) for a loud end-of-phase summary
    start = time.monotonic()
    refresher = _Refresher(args)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_vuln_worker, h, ports, profile, paths, creds,
                             aggressive, use_ss, use_probes, fast): h.ip
                   for h, ports in targets}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                host, issues = fut.result()
            except Exception as e:  # noqa: BLE001
                _record_issues(store, paths, ip,
                               [{"phase": "vuln-scan", "level": "error",
                                 "message": f"vuln-scan crashed: {e}"}])
                completed += 1
                errs.append((ip, f"crashed: {e}"))
                print(f"    [{completed}/{total}] {ip}: FAILED (crashed)"
                      f"{_progress(completed, total, start)}")
                continue
            _record_issues(store, paths, ip, issues)
            errs.extend((ip, i["message"]) for i in issues
                        if i.get("level") == "error")
            if not _persist_host(store, paths, ip, "vuln-scan", host, clear_step="vuln"):
                completed += 1
                continue
            completed += 1
            bits = []
            if host.vulns:
                bits.append(f"{len(host.vulns)} finding(s)")
            if host.exploits:
                bits.append(f"{len(host.exploits)} exploit(s)")
            b = f" [{', '.join(bits)}]" if bits else ""
            print(f"    [{completed}/{total}] {ip}: vuln-scanned{b}"
                  f"{_progress(completed, total, start)}")
            refresher.tick(store, paths, args.title)
    _summarize_failures("vuln-scan", errs, total)


# --- phase: database enumeration / vuln scan ------------------------------------

def _db_worker(host, portids, profile, paths, creds, aggressive, use_ss):
    """Returns (host, issues)."""
    from . import db as dbmod
    issues: list[dict] = []
    vx = os.path.join(paths["raw"], f"{host.ip}_db.xml")
    _, iss = scanner.nse_scan(host.ip, portids, vx, profile,
                              dbmod.script_selection(aggressive), creds=creds)
    if iss:
        issues.append(_mkissue(iss, "db"))
    _merge_vuln_results(host, np.parse_nmap_xml(vx))
    pset = set(portids)
    for p in host.ports:
        if p.portid in pset:
            p.vuln_scanned = True
    host.db_scanned = True
    if use_ss:
        exploits.enrich_hosts([host])
    return host, issues


def _phase_db(store, paths, args, profile) -> None:
    from . import db as dbmod
    creds = _creds_of(args)
    aggressive = getattr(args, "aggressive", False)
    use_ss = not getattr(args, "no_searchsploit", False) and exploits.available()
    targets = [(h, [p.portid for p in dbmod.db_ports(h)])
               for h in _selected_hosts(store.all_hosts(), args)]
    targets = [(h, ports) for h, ports in targets if ports]
    if not targets:
        print("[!] No database services found in scope.")
        return
    mode = "AGGRESSIVE (brute/xp_cmdshell)" if aggressive else "safe (info + empty-pw)"
    print(f"[*] DB-scanning {len(targets)} host(s) [{mode}] ...")
    refresher = _Refresher(args)
    completed = 0
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futures = {ex.submit(_db_worker, h, ports, profile, paths, creds,
                             aggressive, use_ss): h.ip for h, ports in targets}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                host, issues = fut.result()
            except Exception as e:  # noqa: BLE001
                _record_issues(store, paths, ip,
                               [{"phase": "db", "level": "error",
                                 "message": f"db-scan crashed: {e}"}])
                continue
            _record_issues(store, paths, ip, issues)
            if not _persist_host(store, paths, ip, "db", host, clear_step="db"):
                continue
            completed += 1
            print(f"    [{completed}/{len(targets)}] {ip}: db-scanned")
            refresher.tick(store, paths, args.title)


# --- phase: privilege-escalation --------------------------------------------------

def _privesc_worker(host, profile, paths, creds, aggressive):
    """Returns (host, issues)."""
    from . import privesc as pe
    issues: list[dict] = []
    ports = [p.portid for p in host.open_ports
             if p.portid in (139, 445, 3389, 135) or "http" in (p.service or "")]
    if ports:
        vx = os.path.join(paths["raw"], f"{host.ip}_privesc.xml")
        _, iss = scanner.nse_scan(host.ip, ports, vx, profile,
                                  pe.nse_scripts(aggressive), creds=creds)
        if iss:
            issues.append(_mkissue(iss, "privesc"))
        _merge_vuln_results(host, np.parse_nmap_xml(vx))
        ad.identify_roles(host)
        ad.parse_signing_and_ntlm(host)
    return host, issues


def _phase_privesc(store, paths, args, profile) -> None:
    creds = _creds_of(args)
    aggressive = getattr(args, "aggressive", False)
    targets = _selected_hosts(store.all_hosts(), args)
    if not targets:
        print("[!] No hosts in scope.")
        return
    print(f"[*] Priv-esc checks on {len(targets)} host(s) "
          f"[{'aggressive' if aggressive else 'safe'} NSE] ...")
    refresher = _Refresher(args)
    completed = 0
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futures = {ex.submit(_privesc_worker, h, profile, paths, creds,
                             aggressive): h.ip for h in targets}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                host, issues = fut.result()
            except Exception as e:  # noqa: BLE001
                _record_issues(store, paths, ip,
                               [{"phase": "privesc", "level": "error",
                                 "message": f"privesc crashed: {e}"}])
                continue
            _record_issues(store, paths, ip, issues)
            if not _persist_host(store, paths, ip, "privesc", host):
                continue
            completed += 1
            refresher.tick(store, paths, args.title)


# --- phase: credentialed enumeration (netexec / impacket / ssh) ------------------

def _ssh_creds_of(args) -> dict | None:
    user = getattr(args, "ssh_user", None)
    if not user:
        return None
    return {"username": user, "password": getattr(args, "ssh_pass", None),
            "key": getattr(args, "ssh_key", None)}


def _credenum_worker(host, creds, ssh_creds, aggressive, admin_creds=None):
    """Returns (host, issues, auth)."""
    from . import credenum
    issues, auth = credenum.enrich_host(host, creds, ssh_creds, aggressive=aggressive,
                                        admin_creds=admin_creds)
    return host, issues, auth


def _auth_cell(st: dict | None) -> str:
    """Format one account's per-host auth outcome for the summary table. A cell
    is only recorded when the tool actually ran, so an unrecorded/absent cell
    shows '-' (never FAIL) - a missing tool is not an auth failure."""
    if not st or not st.get("tried"):
        return "-"
    if st.get("error"):
        return "ERR"          # tool ran but errored (unreachable/timeout)
    if not st.get("auth"):
        return "FAIL"         # credentials rejected
    return "OK (admin)" if st.get("admin") else "OK"


def _print_auth_table(auth_rows: list) -> None:
    """Per-host authentication success/fail table. Only shows the columns that
    were actually attempted; flags rejected credentials loudly at the end."""
    if not auth_rows:
        return
    cols = [("user", "USER ACCT"), ("admin", "PRIV ACCT"), ("ssh", "SSH")]
    used = [(k, hd) for k, hd in cols if any(a.get(k) for _, a in auth_rows)]
    if not used:
        return
    print("\n[*] Authentication summary (per host):")
    header = f"      {'HOST':<16}" + "".join(f"{hd:<13}" for _, hd in used)
    print(header)
    print("      " + "-" * (len(header) - 6))
    fails = errs = 0
    for ip, a in sorted(auth_rows, key=lambda r: _ip_key(r[0])):
        cells = ""
        for k, _ in used:
            val = _auth_cell(a.get(k))
            fails += val == "FAIL"
            errs += val == "ERR"
            cells += f"{val:<13}"
        print(f"      {ip:<16}{cells}")
    if fails:
        print(f"[!] {fails} credential(s) were REJECTED (FAIL) - check the "
              "username/password/domain for those rows.")
    if errs:
        print(f"[!] {errs} attempt(s) ERRORED (ERR) - host unreachable, timed "
              "out, or the tool failed; not necessarily a credential problem.")


def _phase_credenum(store, paths, args) -> None:
    from . import credenum
    creds = _creds_of(args)
    admin_creds = _admin_creds_of(args)
    ssh_creds = _ssh_creds_of(args)
    aggressive = getattr(args, "aggressive", False)
    if not creds and not ssh_creds and not admin_creds:
        print("\n" + "!" * 64)
        print("[x] credenum needs credentials but none were given.")
        print("    Provide --username/--password (+--domain) for SMB/AD, and/or "
              "--ssh-user for Linux hosts.")
        print("!" * 64)
        return
    tools = credenum.available_tools()
    have = [k for k, v in tools.items() if v]
    print(f"[*] Credentialed enum tools present: {', '.join(have) or 'NONE'}.")
    if not have:
        print("\n" + "!" * 64)
        print("[x] No credentialed-enum tools found (netexec/impacket/ssh).")
        print("    Install netexec + impacket, or ensure ssh is on PATH, then re-run.")
        print("!" * 64)
        return
    targets = _selected_hosts(store.all_hosts(), args)
    if not targets:
        print("[!] No hosts in scope.")
        return
    accts = []
    if creds:
        accts.append(f"user '{creds['username']}'")
    if admin_creds:
        accts.append(f"privileged '{admin_creds['username']}' (admin checks + secretsdump)")
    mode = (" with " + " + ".join(accts)) if accts else ""
    if aggressive and not admin_creds:
        mode += " + secretsdump (aggressive)"
    total = len(targets)
    print(f"[*] Credentialed enum on {total} host(s){mode} ...")
    refresher = _Refresher(args)
    completed = 0
    start = time.monotonic()
    errs: list[tuple[str, str]] = []
    auth_rows: list[tuple[str, dict]] = []   # (ip, auth) for the success/fail table
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futures = {ex.submit(_credenum_worker, h, creds, ssh_creds, aggressive,
                             admin_creds): h.ip
                   for h in targets}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                host, issues, auth = fut.result()
            except Exception as e:  # noqa: BLE001
                _record_issues(store, paths, ip,
                               [{"phase": "credenum", "level": "error",
                                 "message": f"credenum crashed: {e}"}])
                completed += 1
                errs.append((ip, f"crashed: {e}"))
                print(f"    [{completed}/{total}] {ip}: FAILED (crashed)"
                      f"{_progress(completed, total, start)}")
                continue
            _record_issues(store, paths, ip, issues)
            errs.extend((ip, i["message"]) for i in issues
                        if i.get("level") == "error")
            if auth:
                auth_rows.append((ip, auth))
            if not _persist_host(store, paths, ip, "credenum", host):
                completed += 1
                continue
            completed += 1
            n_acct = sum(1 for a in host.accounts
                         if a.source in ("netexec", "impacket", "secretsdump"))
            print(f"    [{completed}/{total}] {ip}: cred-enum done"
                  + (f" ({n_acct} account/loot rows)" if n_acct else "")
                  + _progress(completed, total, start))
            refresher.tick(store, paths, args.title)
    _print_auth_table(auth_rows)
    _summarize_failures("credenum", errs, total)


def _setup_scan(args, need_targets=True):
    """Shared setup: profile, env check, store. Returns (profile, paths, store)."""
    profile = scanner.PROFILES[args.profile]
    _apply_profile_overrides(profile, args)
    try:
        for w in scanner.check_environment(profile):
            print(f"[!] {w}")
    except scanner.ScannerError as e:
        print(f"[x] {e}")
        return None, None, None
    try:
        paths = _open_paths(args.output_dir)
    except OSError as e:
        print(f"[x] Cannot use output dir '{args.output_dir}': {e}")
        return None, None, None
    try:
        store = Store(paths["db"])
    except StoreError as e:
        print(f"[x] {e}")
        return None, None, None
    _import_excel_tracking(store, paths)
    return profile, paths, store


def cmd_enum(args: argparse.Namespace) -> int:
    print(BANNER)
    profile, paths, store = _setup_scan(args)
    if store is None:
        return 1
    store.set_meta("engagement", args.title)
    subnet_map, live_ips, port_map = _discover(args, profile, store, paths)
    if subnet_map is None:   # _discover already printed the specific reason
        store.close()
        return 1
    try:
        _phase_enum(store, paths, args, profile, subnet_map, live_ips, port_map)
        if args.ldap_enum or args.ldap_anon:
            _run_ldap_enum(store, args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted - saving results collected so far ...")
    finally:
        _final_report(store, paths, args.title)
        store.close()
    print(f"\n[+] Enumeration done -> {paths['xlsx']}")
    print(f"    Next:  recce vulns -o {args.output_dir}     "
          "# vuln-scan the open ports it found")
    print(f"    or:    recce services -o {args.output_dir}  "
          "# the exact per-service enum command for each open port")
    return 0


def cmd_vulns(args: argparse.Namespace) -> int:
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum` first.")
        return 1
    profile, paths, store = _setup_scan(args)
    if store is None:
        return 1
    title = store.get_meta("engagement") or args.title
    try:
        _phase_vulns(store, paths, args, profile)
        if args.ldap_enum or args.ldap_anon:
            _run_ldap_enum(store, args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted - saving results collected so far ...")
    finally:
        _final_report(store, paths, title)
        store.close()
    print("\n[+] Vuln scan done -> open the Vulnerabilities / Exploitation tabs.")
    print(f"    Next:  recce status -o {args.output_dir}      # what's left, and the "
          "suggested next step")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Convenience: run enum then vulns in one shot."""
    print(BANNER)
    profile, paths, store = _setup_scan(args)
    if store is None:
        return 1
    store.set_meta("engagement", args.title)
    subnet_map, live_ips, port_map = _discover(args, profile, store, paths)
    if subnet_map is None:   # _discover already printed the specific reason
        store.close()
        return 1
    try:
        _phase_enum(store, paths, args, profile, subnet_map, live_ips, port_map)
        _phase_vulns(store, paths, args, profile)
        if args.ldap_enum or args.ldap_anon:
            _run_ldap_enum(store, args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted - saving results collected so far ...")
    finally:
        _final_report(store, paths, args.title)
        store.close()
    print("\n[+] Done.")
    return 0


def cmd_db(args: argparse.Namespace) -> int:
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum` first.")
        return 1
    profile, paths, store = _setup_scan(args)
    if store is None:
        return 1
    title = store.get_meta("engagement") or args.title
    try:
        _phase_db(store, paths, args, profile)
    except KeyboardInterrupt:
        print("\n[!] Interrupted - saving results collected so far ...")
    finally:
        _final_report(store, paths, title)
        store.close()
    print("\n[+] Database scan done.")
    return 0


def cmd_privesc(args: argparse.Namespace) -> int:
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum` first.")
        return 1
    profile, paths, store = _setup_scan(args)
    if store is None:
        return 1
    title = store.get_meta("engagement") or args.title
    try:
        if args.scan:
            _phase_privesc(store, paths, args, profile)
        else:
            print("[*] Generating priv-esc playbook from existing data "
                  "(use --scan to also run remote privesc NSE checks).")
        # Mark the priv-esc step complete for the hosts we addressed.
        for h in _selected_hosts(store.all_hosts(), args):
            if not h.privesc_checked:
                h.privesc_checked = True
                store.upsert_host(h)
            store.delete_tracking(tr.step_key("privesc", h.ip))  # re-run clears override
    except KeyboardInterrupt:
        print("\n[!] Interrupted - saving results collected so far ...")
    finally:
        _final_report(store, paths, title)
        store.close()
    print("\n[+] Priv-esc sheet updated.")
    return 0


def cmd_credenum(args: argparse.Namespace) -> int:
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum` first.")
        return 1
    _, paths, store = _setup_scan(args, need_targets=False)
    if store is None:
        return 1
    title = store.get_meta("engagement") or args.title
    try:
        _phase_credenum(store, paths, args)
        # Note: the manual 'Creds' checklist box is the operator's own sign-off,
        # so credenum records findings but never ticks it automatically.
    except KeyboardInterrupt:
        print("\n[!] Interrupted - saving results collected so far ...")
    finally:
        _final_report(store, paths, title)
        store.close()
    print("\n[+] Credentialed enum complete - see Users & Accounts / Vulnerabilities.")
    return 0


def cmd_writeups(args: argparse.Namespace) -> int:
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`vulns` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)   # honour any Excel edits first
    hosts = _selected_hosts(store.all_hosts(), args)
    out_dir = os.path.join(args.output_dir, "writeups")
    from .report_docx import build_writeups
    from . import screenshot

    shots: dict = {}
    if not args.no_screenshots and not screenshot.available():
        print("[!] No headless browser found; skipping auto-screenshots (add them "
              "by hand in Word). Install firefox or chromium to enable them.")
    elif not args.no_screenshots:
        web_hosts = [h for h in hosts
                     if any(screenshot._web_url(p) for p in h.open_ports)]
        if web_hosts:
            print(f"[*] Capturing web screenshots for {len(web_hosts)} host(s) "
                  f"(headless browser) ...")
            for h in web_hosts:
                grabbed = screenshot.capture_for_host(h)
                if grabbed:
                    shots[h.ip] = grabbed
                    print(f"    [+] {h.ip}: {len(grabbed)} screenshot(s)")
    summary = build_writeups(hosts, out_dir, min_severity=args.min_severity,
                             include_potential=args.include_potential,
                             screenshots=shots, overwrite=args.overwrite)
    title = store.get_meta("engagement") or args.title
    combined_path = None
    if not args.no_combined:
        from .report_docx import build_combined
        combined_path = os.path.join(out_dir, "findings_report.docx")
        build_combined(hosts, combined_path, title=f"{title} - Findings Report",
                       min_severity=args.min_severity,
                       include_potential=args.include_potential, screenshots=shots)
    store.close()
    scope = "all" if args.include_potential else "real"
    print(f"\n[+] Finding write-ups: {len(summary['written'])} generated, "
          f"{len(summary['skipped'])} kept (already edited), "
          f"{summary['total']} {scope} finding(s) total.")
    print(f"    -> {out_dir}/  (open each .docx in Word to finish it)")
    if combined_path:
        print(f"[+] Combined report (summary table + all findings): {combined_path}")
    if summary.get("dropped_potential"):
        print(f"    ({summary['dropped_potential']} low-confidence 'potential' "
              f"finding(s) skipped; add --include-potential to write them up too)")
    if summary["skipped"]:
        print("    (use --overwrite to regenerate the kept ones - loses edits)")
    return 0


def cmd_writeup(args: argparse.Namespace) -> int:
    """Write up a SINGLE finding, pre-filled with looted/obtained evidence. With
    no selector, list the findings so the tester can pick one."""
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`vulns`/`import` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = store.all_hosts()
    from .report_docx import list_findings, build_one_writeup

    if not args.selector:
        findings = list_findings(hosts, min_severity="info")
        if not findings:
            print("[!] No findings yet. Run `vulns` (or `import`/`ingest`) first.")
            store.close()
            return 0
        print(f"Findings ({len(findings)}) - pick one:  recce writeup <id|CVE|IP|word> "
              f"-o {args.output_dir}\n")
        for row in findings:
            tag = "" if row["real"] else "  (potential)"
            aff = ", ".join(row["affected"][:4]) + ("..." if len(row["affected"]) > 4 else "")
            cve = f"  {row['cves'][0]}" if row["cves"] else ""
            print(f"  {row['id']}  {row['severity'].upper():<8} {row['title']}{cve}")
            print(f"          affected: {aff}{tag}")
        store.close()
        return 0

    out_dir = os.path.join(args.output_dir, "writeups")
    shots: dict = {}
    if not args.no_screenshots:
        from . import screenshot
        if screenshot.available():
            res = _match_one_host(hosts, args.selector)
            for h in res:
                grabbed = screenshot.capture_for_host(h)
                if grabbed:
                    shots[h.ip] = grabbed
    result = build_one_writeup(hosts, out_dir, args.selector,
                               screenshots=shots, overwrite=args.overwrite)
    store.close()
    if result["written"]:
        m = result["matched"][0]
        print(f"[+] Wrote {m['id']} ({m['severity'].upper()}): {m['title']}")
        print(f"    -> {result['written']}")
        if result.get("looted"):
            print(f"    pre-filled with {result['looted']} looted/obtained item(s) "
                  f"for the affected host(s).")
        if not result.get("real", True):
            print("    note: this is a low-confidence 'potential' (version-inferred) finding.")
        print("    Open it in Word to finish the narrative, impact, and screenshots.")
        return 0
    # No single match: help the tester narrow it.
    if result["reason"] == "exists":
        print(f"[!] Write-up already exists: {result['path']}")
        print("    Use --overwrite to regenerate it (loses any edits).")
        return 0
    cand = result["matched"]
    if not cand:
        print(f"[x] No finding matches '{args.selector}'. "
              f"Run `recce writeup -o {args.output_dir}` to list them.")
        return 1
    print(f"[!] '{args.selector}' matches {len(cand)} findings - be more specific:")
    for m in cand:
        print(f"    {m['id']}  {m['severity'].upper():<8} {m['title']}  "
              f"[{', '.join(m['affected'][:3])}]")
    return 1


def _match_one_host(hosts, selector):
    """Best-effort: the host(s) an IP/IP:port selector points at (for screenshots)."""
    sel = (selector or "").split(":")[0].strip()
    return [h for h in hosts if h.ip == sel] if sel else []


def cmd_services(args: argparse.Namespace) -> int:
    """Print the exact per-service enumeration command to run for every open port
    recce found - the bridge from the datastore to recce/scripts/. Answers 'what
    do I type next?' for each service."""
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    hosts = _selected_hosts(store.all_hosts(), args)
    store.close()
    from . import serviceenum

    print("Per-service enumeration - run these against the open ports recce found.")
    print("Safe by default (banners, versions, anon/null checks, TLS, NSE 'safe');")
    print("add -a to a command for the intrusive checks (brute / nikto / dir-bust).\n")
    total = 0
    unmapped: list[tuple[str, int, str]] = []
    for h in hosts:
        cmds = serviceenum.commands_for_host(h)
        um = serviceenum.unmapped_ports(h)
        if not cmds and not um:
            continue
        label = h.ip + (f"  ({h.hostname})" if h.hostname else "")
        roles = f"   [{', '.join(h.roles)}]" if h.roles else ""
        print(f"{label}{roles}")
        for port, svc, _script, cmd in cmds:
            print(f"  {port:<6}{svc:<14}{cmd}" + ("  -a" if args.aggressive else ""))
            total += 1
        for port, svc in um:
            unmapped.append((h.ip, port, svc))
        print()
    if total == 0:
        print("No enumerable open ports yet. Run `enum` (or `import`) first.")
        return 0
    print(f"{total} service command(s) across {len({h.ip for h in hosts})} host(s).")
    raw_glob = os.path.join(args.output_dir, "raw", "*.xml")
    print("Or sweep every open port in one go from recce's own scans:")
    print(f"  {serviceenum.DRIVER} from-nmap {raw_glob}"
          + ("  -a" if args.aggressive else ""))
    if unmapped:
        print(f"\n{len(unmapped)} open port(s) have no dedicated script - "
              f"enumerate manually:")
        for ip, port, svc in unmapped[:15]:
            print(f"  {ip}:{port} ({svc or '?'})  ->  nmap -sV --script vuln -p {port} {ip}")
        if len(unmapped) > 15:
            print(f"  ... and {len(unmapped) - 15} more")
    return 0


def cmd_exploitplan(args: argparse.Namespace) -> int:
    """Generate a per-finding exploitation PLAN: ready-to-run artifacts that drive
    EXISTING published tools/modules with the discovered parameters filled in.
    Confirmed findings only; safe by default (msf launch lines commented)."""
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`vulns`/`import` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)
    store.close()
    from . import exploitplan

    summary = exploitplan.build_plan(hosts, args.output_dir, lhost=args.lhost,
                                     lport=args.lport, run=args.run)
    if not summary["plans"]:
        print("[!] No confirmed findings map to a published exploit/tool yet.")
        print("    Plans cover CONFIRMED findings only (not 'potential' version "
              "guesses). Run `vulns` for deeper detection, or `ingest` on-target loot.")
        return 0
    print(f"[+] Exploitation plan -> {summary['dir']}/")
    print(f"    {summary['host_scripts']} per-host plan script(s), "
          f"{summary['rc_files']} Metasploit resource (.rc) file(s), "
          f"{summary['actions']} action(s) across {len(summary['plans'])} host(s).")
    print("    Each artifact configures an EXISTING published tool/module with the")
    print("    target's own parameters. recce authors no exploit code.")
    if args.lhost == "<LHOST>":
        print("    ! Set your callback with --lhost <IP> (payloads currently show "
              "<LHOST>).")
    if args.run:
        print("    ! --run: Metasploit launch lines are ARMED. Rules of engagement only.")
    else:
        print("    Safe mode: .rc files run `check` only; edit them (or use --run) "
              "to launch.")
    print(f"    Review:  cat {summary['dir']}/README.txt")
    return 0


def cmd_attackpath(args: argparse.Namespace) -> int:
    """Chain the confirmed findings into a prioritised attack path (foothold ->
    priv-esc -> creds -> lateral -> domain), grounded in what recce found."""
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`vulns`/`import` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    hosts = _selected_hosts(store.all_hosts(), args)
    store.close()
    from . import attackpath as ap

    steps = ap.build(hosts)
    for line in ap.narrative(hosts, steps):
        print(line)
    if not steps:
        return 0
    print()
    cur = None
    for s in steps:
        if s["stage"] != cur:
            cur = s["stage"]
            print(f"== {cur} ==")
        tgt = s["ip"] + (f" ({s['hostname']})" if s["hostname"] else "")
        print(f"  [{tgt}] {s['title']}")
        print(f"       {s['tool']}:  {s['cmd']}")
    print("\n  Full table on the Attack Path sheet; runnable artifacts via "
          "`recce exploitplan`.")
    return 0


def _parse_cred_spec(spec: str):
    """Parse 'user:secret', 'DOMAIN\\user:secret', or 'domain/user:secret'."""
    from .models import Credential
    idpart, secret = (spec.split(":", 1) + [""])[:2] if ":" in spec else (spec, "")
    domain = ""
    if "\\" in idpart:
        domain, user = idpart.split("\\", 1)
    elif "/" in idpart:
        domain, user = idpart.split("/", 1)
    else:
        user = idpart
    kind = "nthash" if re.fullmatch(r"[0-9a-fA-F]{32}", secret or "") else \
        ("password" if secret else "blank")
    return Credential(username=user, secret=secret, kind=kind, domain=domain,
                      source="manual")


def cmd_creds(args: argparse.Namespace) -> int:
    """Stack credentials (auto-harvested + manually captured) and build a spray
    plan across the discovered SMB/WinRM/LDAP/MSSQL/RDP/SSH surface."""
    from . import credentials as cr
    from .models import Credential
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`import` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1

    # ADD captured credentials.
    added = False
    to_add = []
    for spec in (args.add or []):
        to_add.append(_parse_cred_spec(spec))
    if args.user:
        kind = "nthash" if args.hash else ("password" if getattr(args, "password", None) else "blank")
        to_add.append(Credential(username=args.user, secret=(args.hash or args.password or ""),
                                 kind=kind, domain=args.domain or "", source="manual"))
    if to_add:
        n = sum(1 for c in to_add if store.add_credential(c))
        print(f"[+] Added {n} credential(s)"
              + (f" ({len(to_add) - n} already stacked)" if n < len(to_add) else "") + ".")
        added = True

    hosts = _selected_hosts(store.all_hosts(), args)
    stored = store.all_credentials()
    stacked = cr.stack(hosts, stored)

    # PLAN: write files + print the spray commands.
    if args.plan:
        if not stacked:
            print("[!] No credentials to spray yet. Add one:  "
                  "recce creds --add 'CORP\\alice:Passw0rd!'")
            store.close()
            return 0
        summary = cr.build_spray(stacked, hosts, args.output_dir)
        print(f"[+] Spray plan for {len(stacked)} credential(s) -> files in "
              f"{summary['dir']}/")
        if summary["files"]:
            print("    " + ", ".join(sorted(summary["files"])))
        print()
        for line in summary["commands"] or ["  (no sprayable services in scope yet)"]:
            print("  " + line if not line.startswith("#") else "\n  " + line)
        print("\n  ! Check the account-lockout policy first. '--continue-on-success' "
              "keeps going after a hit;")
        print("    the paired (user<->pass) list avoids a cartesian brute. Rules of "
              "engagement only.")
        store.close()
        return 0

    # ADD then regenerate the workbook so the Credentials sheet reflects it.
    if added:
        title = store.get_meta("engagement") or getattr(args, "title", "") or "Recce Engagement"
        _generate_reports(store, paths, title, quiet=True)

    # LIST (default).
    if not stacked:
        print("No credentials stacked yet.")
        print("  Capture then add:  recce creds --add 'CORP\\alice:Passw0rd!'  "
              "(or --user alice --hash <nt> --domain CORP)")
        print("  Then:              recce creds --plan   # netexec/impacket spray plan")
        store.close()
        return 0
    print(f"Stacked credentials ({len(stacked)}):")
    for c in stacked:
        sec = c.secret or "(blank)"
        if c.kind == "nthash" and len(sec) > 16:
            sec = sec[:13] + "..."
        origin = f" @{c.origin_ip}" if c.origin_ip else ""
        print(f"  {c.label:<26} {c.kind:<8} {sec:<20} [{c.source}{origin}]")
    print("\n  recce creds --plan   # build the spray plan (writes users/passwords/"
          "hashes + commands)")
    store.close()
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Check that this box can run the tool, and optionally prove it with a
    real localhost self-scan. Run this on any system before an engagement."""
    import platform
    import shutil

    print(BANNER)
    print("Environment")
    print(f"  Python           {sys.version.split()[0]}  ({platform.python_implementation()})")
    print(f"  Platform         {platform.system()} {platform.release()}")
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    print(f"  Root / privileges {'yes' if is_root else 'NO'}"
          + ("" if is_root else "  -> falls back to TCP connect scan; no SYN/OS/UDP"))
    py_ok = sys.version_info >= (3, 9)
    if not py_ok:
        print("  ! Python 3.9+ recommended.")

    print("\nTools (which capabilities are available)")
    tools = [
        ("nmap", True, "core scanning / service+OS detection / NSE vuln+AD+DB"),
        ("masscan", False, "--fast network-wide sweep"),
        ("searchsploit", False, "offline exploit mapping (Exploits sheet)"),
        ("ldap", False, "credentialed AD LDAP enum (ldapsearch or the ldap3 package)"),
        ("netexec", False, "credentialed SMB/AD enum (credenum phase)"),
        ("ssh", False, "credentialed Linux local checks (credenum phase)"),
        ("browser", False, "auto web screenshots in write-ups (firefox/chromium)"),
    ]
    nmap_ok = False
    presence: dict[str, bool] = {}   # reused for the summary, so it can't disagree
    for name, required, desc in tools:
        present = shutil.which(name) is not None
        if name == "searchsploit":
            from . import exploits
            present = exploits.available()               # mirror the runtime gate
        if name == "ldap":
            from . import ad
            present = ad.ldap_available()                # ldapsearch OR ldap3 package
            if present:
                backend = "ldapsearch" if shutil.which("ldapsearch") else "ldap3 package"
                desc = f"credentialed AD LDAP enum (using {backend})"
        if name == "netexec":
            from . import credenum
            present = credenum.smb_tool() is not None   # nxc / crackmapexec too
        if name == "browser":
            from . import screenshot
            present = screenshot.available()             # firefox / chrome variants
            found = screenshot.browser_tool()
            if found:
                desc = f"auto web screenshots in write-ups (using {found})"
        if name == "nmap":
            nmap_ok = present
        presence[name] = present
        mark = "OK  " if present else ("MISSING (required)" if required else "-   (optional)")
        print(f"  {name:<15} {mark:<20} {desc}")
    from . import credenum as _ce
    if _ce.impacket_tool("GetUserSPNs"):
        print(f"  {'impacket':<15} {'OK  ':<20} Kerberoast / AS-REP / secretsdump")
    import importlib.util
    if importlib.util.find_spec("openpyxl") is not None:
        print("  openpyxl        OK   (not required; stdlib xlsx is built in)")

    # Optional real self-scan to prove the pipeline end-to-end on THIS box.
    scan_ok = None
    if nmap_ok and not args.no_self_scan:
        print("\nSelf-scan (real nmap against 127.0.0.1, top 100 ports) ...")
        scan_ok = _self_scan()
        print("  " + ("PASS - scanned, parsed, and wrote a workbook."
                      if scan_ok else "FAIL - see error above."))

    print("\nSummary")
    if not nmap_ok:
        print("  NOT READY - install nmap (the only hard requirement).")
        verdict = 1
    elif scan_ok is False:
        print("  NOT READY - nmap is present but the self-scan failed (see above).")
        verdict = 1
    else:
        degraded = [n for n, req, _ in tools if not req and not presence.get(n)]
        print("  READY." + (f"  Optional tools missing: {', '.join(degraded)}."
                            if degraded else "  All tools present."))
        verdict = 0
    return verdict


def _self_scan() -> bool:
    import tempfile
    try:
        from . import scanner
        profile = scanner.PROFILES["quick"]
        with tempfile.TemporaryDirectory() as d:
            fp = os.path.join(d, "p.xml")
            scanner.full_port_scan("127.0.0.1", fp, profile)
            ports = _ports_for_host(fp, "127.0.0.1")
            deep = os.path.join(d, "e.xml")
            scanner.enum_scan("127.0.0.1", ports or [80], deep, profile)  # (xml, issue)
            host = _fold_host("127.0.0.1", np.parse_nmap_xml(deep), {"127.0.0.1": "local"})
            host.enumerated = True
            from .report_excel import build_workbook, read_workbook_tracking
            out = os.path.join(d, "wb.xlsx")
            build_workbook([host], out)
            read_workbook_tracking(out)  # prove read-back parses too
            print(f"  found {len(host.open_ports)} open port(s) on 127.0.0.1; "
                  f"report + read-back OK.")
        return True
    except Exception as e:  # noqa: BLE001
        print(f"  error: {e}")
        return False


def _run_ldap_enum(store: Store, args: argparse.Namespace) -> None:
    if not ad.ldap_available():
        print("[!] --ldap-enum requested but no LDAP client found; skipping. "
              "Install ldap-utils (ldapsearch) for airgapped use, or ldap3.")
        return
    all_hosts = store.all_hosts()
    dc_ips = [args.dc_ip] if args.dc_ip else [h.ip for h in ad.domain_controllers(all_hosts)]
    if not dc_ips:
        print("[!] No Domain Controllers found for LDAP enumeration "
              "(use --dc-ip to target one directly).")
        return
    for dc_ip in dc_ips:
        anon = args.ldap_anon and not args.username
        label = "anonymous" if anon else f"as {args.domain}\\{args.username}"
        print(f"[*] LDAP enumeration of {dc_ip} ({label}) ...")
        try:
            domain, accounts = ad.ldap_enumerate(
                dc_ip, domain=args.domain or "", username=args.username or "",
                password=args.password or "", use_ssl=args.ldap_ssl, anonymous=anon)
        except Exception as e:  # noqa: BLE001
            print(f"[!] LDAP enumeration failed for {dc_ip}: {e}")
            continue
        host = store.get_host(dc_ip)
        if host is not None:
            existing = {(a.source, a.kind, a.name) for a in host.accounts}
            host.accounts.extend(a for a in accounts
                                 if (a.source, a.kind, a.name) not in existing)
            store.upsert_host(host)
        store.upsert_domain(domain)
        n_users = sum(1 for a in accounts if a.kind == "user")
        n_spn = sum(1 for a in accounts if a.attrs.get("spn"))
        n_asrep = sum(1 for a in accounts if a.attrs.get("asrep_roastable") == "yes")
        print(f"    +{len(accounts)} objects ({n_users} users, {n_spn} with SPN, "
              f"{n_asrep} AS-REP roastable) for domain {domain.name or '?'}.")


def _ip_key(ip: str):
    try:
        return tuple(int(o) for o in ip.split("."))
    except ValueError:
        return (999, ip)


def _fold_host(ip, parsed_list, subnet_map):
    base = Host(ip=ip, subnet=subnet_map.get(ip, ""))
    for h in parsed_list:
        if h.ip != ip:
            continue
        base.hostnames = list(dict.fromkeys(base.hostnames + h.hostnames))
        base.mac = base.mac or h.mac
        base.vendor = base.vendor or h.vendor
        if h.os_accuracy >= base.os_accuracy and h.os_name:
            base.os_name, base.os_accuracy, base.os_family = h.os_name, h.os_accuracy, h.os_family
        base.distance = base.distance or h.distance
        base.last_scanned = h.last_scanned or base.last_scanned
        base.ports.extend(h.ports)
        base.vulns.extend(h.vulns)
        base.accounts.extend(h.accounts)
        base.exploits.extend(h.exploits)
        base.host_scripts.extend(h.host_scripts)
    base.subnet = subnet_map.get(ip, base.subnet)
    return base


# --- report / status / review ---------------------------------------------------

def _resolve_ingest_host(store, parsed, args):
    """Pick (or create) the Host that on-target loot belongs to.

    Priority: an explicit --host, else an IP parsed from the loot that already
    exists, else a synthetic host keyed by the loot's hostname/filename so the
    findings still land somewhere on the Priv-Esc sheet."""
    hosts = {h.ip: h for h in store.all_hosts()}
    hn = parsed.get("hostname", "")
    if getattr(args, "host", None):
        ip = args.host
        host = hosts.get(ip) or Host(ip=ip)
        # Record the loot's hostname so a later no --host ingest of the same box
        # matches this entry instead of synthesizing a second local:<host> one.
        if hn and hn not in host.hostnames:
            host.hostnames.append(hn)
        _tag_host_os(host, parsed)
        return host, (ip in hosts)
    # No --host: try the hostname against known hostnames, else synthesize.
    if hn:
        for h in hosts.values():
            if hn.lower() in [x.lower() for x in h.hostnames] or \
               hn.lower() == (h.hostname or "").lower():
                _tag_host_os(h, parsed)
                return h, True
    key = hn or os.path.splitext(os.path.basename(args.loot))[0]
    host = hosts.get(f"local:{key}") or Host(ip=f"local:{key}")
    if hn and hn not in host.hostnames:
        host.hostnames.append(hn)
    _tag_host_os(host, parsed)
    return host, (host.ip in hosts)


def _tag_host_os(host, parsed) -> None:
    if not host.os_family and parsed.get("os"):
        host.os_family = parsed["os"].capitalize()


def _ingest_service_output(svc: dict, paths: dict, args) -> int:
    """Fold recce-service.sh per-service findings into the datastore as confirmed
    service-enum Vulns on the matching host:port (creating a host entry if needed)."""
    from . import ingest
    from .models import Host, Port
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    vulns = ingest.service_findings_to_vulns(svc)
    by_ip: dict[str, list] = {}
    for v in vulns:
        by_ip.setdefault(v.ip, []).append(v)
    hosts_by_ip = {h.ip: h for h in store.all_hosts()}
    added_total = created = touched = 0
    for ip, vs in by_ip.items():
        h = hosts_by_ip.get(ip)
        if h is None:
            h = Host(ip=ip, subnet=".".join(ip.split(".")[:3]) + ".0/24",
                     enumerated=True)
            for pnum in sorted({v.port for v in vs if v.port}):
                h.ports.append(Port(portid=pnum, protocol="tcp", state="open",
                                    vuln_scanned=True))
            created += 1
        have = {(x.title, x.port) for x in h.vulns}
        added = [v for v in vs if (v.title, v.port) not in have]
        if not added:
            continue
        h.vulns.extend(added)
        aff = {v.port for v in added}
        for p in h.ports:
            if p.portid in aff:
                p.vuln_scanned = True
        store.upsert_host(h)
        added_total += len(added)
        touched += 1
    print(f"[+] Ingested {added_total} service finding(s) across {touched} host(s)"
          + (f" ({created} new host entry/entries)" if created else "") + ".")
    print("    Source: recce-service.sh output -> Vulnerabilities sheet "
          "(source 'service-enum'; advisory 'test X' lines kept as 'potential').")
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    from . import ingest
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum` first so there's a "
              "workbook to fold findings into.")
        return 1
    if not os.path.exists(args.loot):
        print(f"[x] Loot file not found: {args.loot}")
        return 1
    with open(args.loot, "r", errors="replace") as fh:
        text = fh.read()
    parsed = ingest.parse_loot(text)
    if not parsed["is_recce"]:
        # Maybe it's per-service enumeration output (recce-service.sh) instead.
        svc = ingest.parse_service_output(text)
        if svc["is_service"] and svc["findings"]:
            return _ingest_service_output(svc, paths, args)
        print("[!] This doesn't look like recce-enum.sh/.ps1 output (no "
              "'recce-enum host=...' banner). Parsing [!] lines anyway.")
    if not parsed["findings"]:
        print("[!] No [!] findings in that loot - nothing to ingest.")
        return 0

    source = os.path.basename(args.loot)
    new_rows = ingest.to_local_findings(parsed, source)
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)
    host, existed = _resolve_ingest_host(store, parsed, args)
    # Merge, de-duplicating against anything already ingested for this host AND
    # against each other (two sections can map to the same category, so distinct
    # parsed findings may collapse to the same (category, vector) key).
    have = {(f.get("category"), f.get("vector")) for f in host.local_findings}
    added = []
    for r in new_rows:
        key = (r["category"], r["vector"])
        if key not in have:
            have.add(key)
            added.append(r)
    host.local_findings.extend(added)
    # AV/EDR + defensive posture the on-target sweep fingerprinted, so the tester
    # knows what's watching this host (detection only - recce does not evade it).
    known = set(host.defenses)
    for d in ingest.extract_defenses(text):
        if d not in known:
            known.add(d)
            host.defenses.append(d)
    # Promote the high-signal findings to first-class Vulns so they count toward
    # severity totals and get write-ups (deduped against existing vulns by key).
    have_v = {v.key for v in host.vulns}
    promoted = [v for v in ingest.promote_to_vulns(host.ip, host.local_findings)
                if v.key not in have_v]
    host.vulns.extend(promoted)
    host.privesc_checked = True
    store.upsert_host(host)
    where = "existing host" if existed else "new host entry"
    hn = f" ({parsed['hostname']})" if parsed["hostname"] else ""
    print(f"[+] Ingested {len(added)} finding(s) from {source} into {where} "
          f"{host.ip}{hn}"
          + (f"; {len(new_rows) - len(added)} already present" if added != new_rows else "")
          + ".")
    if promoted:
        print(f"    Promoted {len(promoted)} high-signal finding(s) to the "
              "Vulnerabilities sheet.")
    print(f"    OS: {host.os_family or 'unknown'}. See the Priv-Esc tab "
          "(rows tagged 'on-target finding').")
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    return 0


def _collect_scan_files(paths: list[str]) -> list[str]:
    """Expand files / directories / globs into a list of nmap scan files. For a
    same-basename -oA set (base.xml + base.gnmap + base.nmap) keep only the richest
    format (xml > grepable > normal) so one scan isn't imported three times."""
    import glob
    found: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            for pat in ("*.xml", "*.gnmap", "*.grep", "*.nmap"):
                found += sorted(glob.glob(os.path.join(p, pat)))
        elif os.path.exists(p):
            found.append(p)
        else:
            found += sorted(glob.glob(p))          # maybe a glob pattern
    rank = {".xml": 0, ".gnmap": 1, ".grep": 1, ".nmap": 2}
    best: dict[str, tuple[int, str]] = {}
    order: list[str] = []
    for f in found:
        base, ext = os.path.splitext(f)
        r = rank.get(ext.lower(), 3)
        if base not in best:
            best[base] = (r, f)
            order.append(base)
        elif r < best[base][0]:
            best[base] = (r, f)
    return [best[b][1] for b in order]


def cmd_import(args: argparse.Namespace) -> int:
    """Import an already-completed nmap scan (XML -oX or grepable -oG) and build /
    update the workbook - no scanning, no network. Folds hosts into the datastore,
    runs the offline enrichment (version->CVE, AD roles, SMB signing), sets the
    checkmarks, and preserves any existing tracking."""
    from . import vulndb
    files = _collect_scan_files(args.files)
    if not files:
        print("[x] No nmap scan files found. Point at .xml (-oX) or .gnmap (-oG) "
              "files, a directory, or a glob.")
        return 1
    parsed: list[Host] = []
    for f in files:
        hs = np.parse_nmap_file(f)
        print(f"    {os.path.basename(f)}: {len(hs)} host(s)")
        parsed.extend(hs)
    if not parsed:
        print("[x] Nothing parsed. Point at nmap XML (-oX, best), grepable "
              "(-oG), or normal (-oN, .nmap) output.")
        return 1

    paths = _open_paths(args.output_dir)
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)          # honour existing ticks first
    if not store.get_meta("engagement"):
        store.set_meta("engagement", args.title)

    by_ip: dict[str, list[Host]] = {}
    for h in parsed:
        by_ip.setdefault(h.ip, []).append(h)
    use_ss = getattr(args, "searchsploit", False) and exploits.available()
    enum_only = getattr(args, "enum_only", False)
    n_hosts = n_ports = n_findings = n_scanned = 0
    for ip, group in by_ip.items():
        subnet = ".".join(ip.split(".")[:3]) + ".0/24" if ip.count(".") == 3 else ""
        host = _fold_host(ip, group, {ip: subnet})
        host.enumerated = True
        if not enum_only:
            for p in host.ports:                  # scan ran scripts here -> vuln step done
                if p.scripts and not p.vuln_scanned:
                    p.vuln_scanned = True
                    n_scanned += 1
        ad.identify_roles(host)
        ad.parse_signing_and_ntlm(host)
        vulndb.assess_host_inplace(host)          # offline version->CVE/CWE findings
        if use_ss:
            exploits.enrich_hosts([host])
        store.upsert_host(host)                    # merges with existing (tracking kept)
        n_hosts += 1
        n_ports += len(host.open_ports)
        n_findings += len(host.vulns)

    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    print(f"\n[+] Imported {n_hosts} host(s) / {n_ports} open port(s) from "
          f"{len(files)} file(s): {n_findings} offline finding(s), "
          f"{n_scanned} port(s) marked vuln-scanned (had NSE output).")
    print("    Checklist 'Enumerated'"
          + ("" if enum_only else " + 'Vuln-scan' (where scripts ran)")
          + " are ticked. Run `vulns` to add recce's deeper detection, or "
          "`status` to see what's left.")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)  # honor Excel edits before regenerating
    title = store.get_meta("engagement") or args.title
    _generate_reports(store, paths, title)
    store.close()
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)  # pick up latest Excel edits
    tracking = store.get_tracking()
    hosts = store.all_hosts()
    cov = tr.compute_coverage(hosts, tracking)
    labels = {"hosts": "Hosts", "services": "Services", "vulns": "Vulnerabilities",
              "exploits": "Exploits", "quick_wins": "AD Quick Wins",
              "accounts": "Users & Accounts"}

    def bar(pct):
        f = round(pct / 5)
        return "#" * f + "-" * (20 - f)

    title = store.get_meta("engagement") or "engagement"
    print(f"\n== Coverage: {title} ==\n")

    # Scan issues first - the operator needs to know if anything failed/incomplete.
    counts = store.count_issues()
    if counts.get("total"):
        print(f"  ⚠ {counts['total']} scan issue(s): {counts.get('error', 0)} error, "
              f"{counts.get('warning', 0)} incomplete "
              f"(Overview tab / {paths['log']})")
        for i in store.get_issues()[:8]:
            print(f"      [{i['level'].upper()}] {i['ip']} {i['message']}")
        if counts["total"] > 8:
            print(f"      ... and {counts['total'] - 8} more")
        print()

    o = cov["overall"]
    print(f"  OVERALL      [{bar(o['pct'])}] {o['pct']:3d}%  {o['done']}/{o['total']}")
    print()
    for cat in tr.COVERAGE_CATEGORIES:
        c = cov[cat]
        print(f"  {labels[cat]:<13}[{bar(c['pct'])}] {c['pct']:3d}%  {c['done']}/{c['total']}")

    # Per-step completion, counting only hosts the step applies to.
    def phase_count(step):
        applic = [h for h in hosts if tr.step_applies(h, step)]
        return sum(1 for h in applic if tr.step_auto(h, step)), len(applic)

    def manual_count(step):
        applic = [h for h in hosts if tr.step_applies(h, step)]
        done = sum(1 for h in applic
                   if tracking.get(tr.step_key(step, h.ip), (False, ""))[0])
        return done, len(applic)

    en_d, en_t = phase_count("enum")
    vs_d, vs_t = phase_count("vuln")
    web_d, web_t = phase_count("web")
    db_d, db_t = phase_count("db")
    open_ports = [p for h in hosts for p in h.open_ports]
    scanned_ports = sum(1 for p in open_ports if p.vuln_scanned)
    print("\n  Tool progress (auto) - per step, hosts complete / applicable:")
    print(f"    Enumerated    {en_d}/{en_t}")
    print(f"    Vuln-scanned  {vs_d}/{vs_t}"
          + (f"   ({scanned_ports}/{len(open_ports)} open ports)" if open_ports else ""))
    print(f"    Web           {web_d}/{web_t}   (hosts serving HTTP/HTTPS)")
    print(f"    DB-scanned    {db_d}/{db_t}   (hosts with DB services)")

    # Manual sign-offs (from your ticks): AD review + the kill-chain.
    ad_d, ad_t = manual_count("ad")
    ac_d, ac_t = manual_count("access")
    cr_d, cr_t = manual_count("creds")
    lat_d, lat_t = manual_count("lateral")
    pe_done = sum(1 for h in hosts if h.privesc_checked)
    print("\n  Manual sign-offs (from your ticks) - hosts done / applicable:")
    print(f"    AD reviewed   {ad_d}/{ad_t}   (domain controllers / directory hosts)")
    print(f"    Access gained {ac_d}/{ac_t}")
    print(f"    Priv-esc      {pe_done}/{len(hosts)}   (post-exploitation performed)")
    print(f"    Creds got     {cr_d}/{cr_t}")
    print(f"    Lateral       {lat_d}/{lat_t}")
    pending = [h.ip for h in hosts if h.enumerated
               and any(not p.vuln_scanned for p in h.open_ports)]
    if pending:
        print(f"    ! still to vuln-scan: {', '.join(pending[:15])}"
              + (" ..." if len(pending) > 15 else ""))

    print("\n  By subnet (hosts reviewed):")
    for subnet, s in sorted(tr.subnet_coverage(hosts, tracking).items()):
        print(f"    {subnet:<20} {s['pct']:3d}%  {s['done']}/{s['total']}")

    # Outstanding high-value items.
    unreviewed_dc = [h for h in ad.domain_controllers(hosts)
                     if not tracking.get(tr.host_key(h.ip), (False, ""))[0]]
    unreviewed_vuln_hosts = [
        h for h in hosts
        if any(v.severity in ("critical", "high") for v in h.vulns)
        and not tracking.get(tr.host_key(h.ip), (False, ""))[0]
    ]
    incomplete = [h for h in hosts if getattr(h, "incomplete_scan", False)]
    if incomplete:
        print("\n  !! INCOMPLETE port sweeps (host-timeout) - these port lists are "
              "PARTIAL, so downstream phases may be missing services:")
        print("     " + ", ".join(h.ip for h in sorted(incomplete, key=lambda x: _ip_key(x.ip))))
        print("     Re-scan with a larger --host-timeout (or --top-ports to narrow "
              "scope) to complete them.")
    if unreviewed_dc:
        print("\n  ! Unreviewed Domain Controllers: "
              + ", ".join(h.ip for h in unreviewed_dc))
    if unreviewed_vuln_hosts:
        print("  ! Unreviewed hosts with high/critical findings: "
              + ", ".join(h.ip for h in sorted(unreviewed_vuln_hosts, key=lambda x: _ip_key(x.ip))))

    # Suggested next step, so you always know what to run.
    o = args.output_dir
    if not hosts:
        nxt = f"recce enum <targets> -o {o}   # nothing scanned yet"
    elif en_d < en_t or vs_d < vs_t:
        nxt = f"recce vulns --unscanned -o {o}   # vuln-scan the rest"
    elif db_t and db_d < db_t:
        nxt = f"recce db -o {o}   # enumerate the databases"
    elif pe_done < len(hosts):
        nxt = f"recce privesc -o {o}   # build the priv-esc playbook"
    else:
        nxt = "all phases complete - review the workbook and tick Reviewed."
    print(f"\n  Next: {nxt}")
    print()
    store.close()
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    _import_excel_tracking(store, paths)  # capture pending Excel edits first
    reviewed = not args.undo
    keys: list[str] = []

    for ip in args.host or []:
        keys.append(tr.host_key(ip))
        if args.cascade:  # also mark all that host's services
            h = store.get_host(ip)
            if h:
                keys += [tr.svc_key(ip, p.protocol, p.portid) for p in h.open_ports]
    for spec in args.service or []:
        ip, _, port = spec.partition(":")
        keys.append(tr.svc_key(ip, "tcp", int(port)))
    keys += args.key or []

    if not keys:
        print("[x] Nothing to mark. Use --host, --service ip:port, or --key.")
        store.close()
        return 1
    for k in keys:
        store.set_reviewed(k, reviewed, notes=args.note)
    print(f"[+] Marked {len(keys)} item(s) as {'reviewed' if reviewed else 'not reviewed'}.")
    _generate_reports(store, paths, store.get_meta("engagement") or args.title, quiet=True)
    store.close()
    return 0


# --- demo command ----------------------------------------------------------------

def cmd_demo(args: argparse.Namespace) -> int:
    sample = os.path.join(os.path.dirname(__file__), "sample_scan.xml")
    if not os.path.exists(sample):
        print("[x] Sample XML missing.")
        return 1
    paths = _open_paths(args.output_dir)
    store = _open_store(paths["db"])
    if store is None:
        return 1
    store.set_meta("engagement", "DEMO engagement")
    store.set_scope("10.0.10.0/24", 254)   # demo scope: three /24s
    store.set_scope("10.0.20.0/24", 254)
    store.set_scope("10.0.30.0/24", 254)   # in scope but no live hosts found
    from .models import Exploit
    from .targets import _subnet_of
    # Stand-in for searchsploit output (unavailable offline in the demo).
    demo_exploits = {
        "10.0.20.6": [Exploit(ip="10.0.20.6", port=21, product="vsftpd", version="2.3.4",
                              edb_id="17491", title="vsftpd 2.3.4 - Backdoor Command Execution",
                              type="remote", path="unix/remote/17491.rb",
                              cves=["CVE-2011-2523"])],
        "10.0.20.5": [Exploit(ip="10.0.20.5", port=80, product="Apache httpd", version="2.4.41",
                              edb_id="50383", title="Apache 2.4.49/2.4.50 - Path Traversal & RCE",
                              type="webapps", path="multiple/webapps/50383.sh",
                              cves=["CVE-2021-41773", "CVE-2021-42013"])],
    }
    for h in np.parse_nmap_xml(sample):
        h.subnet = _subnet_of(h.ip)
        ad.identify_roles(h)
        ad.parse_signing_and_ntlm(h)
        h.exploits = demo_exploits.get(h.ip, [])
        from . import vulndb
        vulndb.assess_host_inplace(h)   # offline version->CVE findings
        h.enumerated = True
        # Leave one host enumerated-only to show the Checklist's mixed states.
        if h.ip != "10.0.20.6":
            for p in h.ports:
                p.vuln_scanned = True
            h.db_scanned = True
            h.privesc_checked = True
        store.upsert_host(h)
    _generate_reports(store, paths, "DEMO engagement")
    store.close()
    print("[+] Demo reports generated from bundled sample scan.")
    return 0


def _add_common(pp) -> None:
    pp.add_argument("-o", "--output-dir", default="engagement",
                    help="output directory (default: ./engagement)")
    pp.add_argument("--title", default="Recce Engagement",
                    help="engagement title shown in reports")
    pp.add_argument("--profile", choices=list(scanner.PROFILES), default="standard")
    pp.add_argument("--workers", type=int, default=6,
                    help="concurrent hosts to scan at once (default: 6)")
    pp.add_argument("--refresh-every", type=int, default=10, metavar="N",
                    help="regenerate reports every N hosts (0 to disable; default 10)")
    pp.add_argument("--host-timeout", type=int, metavar="MIN",
                    help="per-host time ceiling in minutes; nmap gives up on a "
                         "host after this and moves on (0 = no limit)")


def _add_creds(pp) -> None:
    pp.add_argument("-u", "--username", help="low-priv/user account for authenticated SMB/LDAP")
    pp.add_argument("-p", "--password", help="password for the user account")
    pp.add_argument("-d", "--domain", help="AD domain (e.g. corp.local) for authentication")
    pp.add_argument("--admin-user", dest="admin_username",
                    help="privileged/superuser account: runs the admin-only checks "
                         "(confirm local-admin reach, secretsdump hash dump)")
    pp.add_argument("--admin-pass", dest="admin_password",
                    help="password for the privileged account")
    pp.add_argument("--admin-domain", dest="admin_domain",
                    help="domain for the privileged account (defaults to -d)")
    pp.add_argument("--ldap-enum", action="store_true",
                    help="credentialed LDAP enumeration of discovered DCs")
    pp.add_argument("--ldap-anon", action="store_true", help="attempt anonymous LDAP bind")
    pp.add_argument("--ldap-ssl", action="store_true", help="use LDAPS (636)")
    pp.add_argument("--dc-ip", help="target this DC IP for LDAP instead of auto-detect")


def _add_discovery(pp) -> None:
    pp.add_argument("targets", nargs="+", help="CIDRs / ranges / IPs / hostnames, or @file")
    pp.add_argument("--exclude", nargs="*", help="hosts/CIDRs to exclude")
    pp.add_argument("--fast", action="store_true",
                    help="go fast: masscan network-wide sweep instead of per-host "
                         "nmap (and, in `scan`, top-signal vuln scripts only)")
    pp.add_argument("--masscan", action="store_true", help="use masscan for port sweep")
    pp.add_argument("--all-ports", action="store_true", help="force full 65535 TCP sweep")
    pp.add_argument("--top-ports", type=int, help="scan only top-N TCP ports")
    pp.add_argument("--min-rate", type=int, help="nmap --min-rate override")
    pp.add_argument("--max-retries", type=int, metavar="N",
                    help="nmap --max-retries on the port sweep (default 3; raise for "
                         "lossy links, lower for speed on clean ones)")
    pp.add_argument("--no-verify", action="store_true",
                    help="skip the confirmation re-scan of hosts that come back with "
                         "0 open ports (faster; may trust a missed sweep)")
    pp.add_argument("--verify-all", action="store_true",
                    help="also re-verify 0-port hosts under -Pn (not just discovered-"
                         "live ones) - catches every missed sweep, slower on dead-IP "
                         "scopes")
    pp.add_argument("--reliable", action="store_true",
                    help="rate-limited / lossy network: drop the --min-rate floor, "
                         "retry dropped probes more, let nmap's congestion control "
                         "adapt (recce also switches to this automatically when it "
                         "sees nmap dropping probes)")
    pp.add_argument("-Pn", "--no-discovery", action="store_true", dest="no_discovery",
                    help="skip the ping sweep and scan every target as if up (like "
                         "nmap -Pn). Use this when hosts block ping - common on "
                         "firewalled / Windows / AD networks.")
    pp.add_argument("--no-ad", action="store_true", help="skip SMB/LDAP AD scripts")
    pp.add_argument("--no-os", action="store_true", help="skip OS detection")
    pp.add_argument("--version-all", action="store_true",
                    help="max-effort service detection (--version-all: every probe)")
    pp.add_argument("--version-intensity", type=int, metavar="0-9",
                    help="nmap -sV probe intensity for service detection (default 8)")
    pp.add_argument("--resume", action="store_true", help="skip hosts already in datastore")


def _add_vuln_opts(pp) -> None:
    pp.add_argument("--aggressive", action="store_true",
                    help="run the full intrusive NSE 'vuln' category (can crash "
                         "fragile services); default is deep safe detection")
    pp.add_argument("--offline", action="store_true",
                    help="airgapped: disable internet-dependent NSE (vulners)")
    pp.add_argument("--no-searchsploit", action="store_true",
                    help="skip offline exploit mapping via searchsploit")
    pp.add_argument("--no-probes", action="store_true",
                    help="skip the stdlib HTTP-header / TLS enrichment probes")
    pp.add_argument("--udp-top", type=int, help="also scan top-N UDP ports")


def build_arg_parser() -> argparse.ArgumentParser:
    from . import __version__
    p = argparse.ArgumentParser(
        prog="recce",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Phased enumeration & reporting for pentest engagements. "
                    "Scans fill an Excel workbook you check off as you go.",
        epilog=(
            "typical engagement:\n"
            "  1. recce doctor                     # verify this box\n"
            "  2. recce enum 10.0.0.0/24 -o eng    # discover + services\n"
            "  3. open eng/enumeration.xlsx -> Start Here tab\n"
            "  4. recce vulns -o eng               # vuln-scan open ports\n"
            "  5. recce db -o eng ; recce privesc -o eng\n"
            "  6. recce status -o eng              # what's left\n\n"
            "targets: single IP, several IPs, range (10.0.0.10-40), CIDR, or @file.\n"
            "run 'recce <command> -h' for a command's options."
        ),
    )
    p.add_argument("-V", "--version", action="version",
                   version=f"recce {__version__}")
    sub = p.add_subparsers(dest="command", required=False, metavar="<command>")

    # Phase 1: fast enumeration -> sheet.
    e = sub.add_parser("enum", help="discover hosts, scan ports, ID services -> sheet")
    _add_discovery(e)
    _add_common(e)
    _add_creds(e)
    e.set_defaults(func=cmd_enum)

    # Phase 2: targeted vuln scanning of open ports already in the datastore.
    v = sub.add_parser("vulns", help="vuln-scan open ports found by `enum`")
    v.add_argument("targets", nargs="*",
                   help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_common(v)
    _add_vuln_opts(v)
    _add_creds(v)
    v.add_argument("--fast", action="store_true",
                   help="top-signal detection scripts only (skip the broad "
                        "'vuln and safe' net + deep enum) - much quicker on a /24, "
                        "shows live per-host progress + ETA")
    v.add_argument("--only", nargs="*", metavar="SVC",
                   help="only ports matching these service names / port numbers "
                        "(e.g. http smb 445)")
    v.add_argument("--unscanned", action="store_true",
                   help="only ports not already vuln-scanned")
    v.set_defaults(func=cmd_vulns)

    # Phase 2 (databases): DB-specific enumeration + vuln scan.
    dbp = sub.add_parser("db", help="database enumeration + vuln scan")
    dbp.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_common(dbp)
    dbp.add_argument("--aggressive", action="store_true",
                     help="intrusive DB checks (brute / xp_cmdshell / hash dump)")
    dbp.add_argument("--no-searchsploit", action="store_true")
    _add_creds(dbp)
    dbp.set_defaults(func=cmd_db)

    # Phase 3 (priv-esc): playbook + optional remote checks.
    pep = sub.add_parser("privesc", help="priv-esc playbook (Windows/Linux) + checks")
    pep.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_common(pep)
    pep.add_argument("--scan", action="store_true",
                     help="also run remote privesc NSE checks (smb-vuln-* etc.)")
    pep.add_argument("--aggressive", action="store_true",
                     help="include intrusive privesc NSE (may crash services)")
    _add_creds(pep)
    pep.set_defaults(func=cmd_privesc)

    # Phase 3 (credentialed): authenticated enum via netexec / impacket / ssh.
    cep = sub.add_parser("credenum",
                         help="credentialed enum (netexec/impacket/ssh) - needs creds")
    cep.add_argument("targets", nargs="*",
                     help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    _add_common(cep)
    _add_creds(cep)
    cep.add_argument("--ssh-user", help="username for SSH local checks on Linux hosts")
    cep.add_argument("--ssh-pass", help="SSH password (needs sshpass on PATH)")
    cep.add_argument("--ssh-key", help="SSH private-key path for local checks")
    cep.add_argument("--aggressive", action="store_true",
                     help="also dump hashes with secretsdump (needs admin/DA)")
    cep.set_defaults(func=cmd_credenum)

    # Reporting: per-finding Word write-ups from the template.
    wu = sub.add_parser("writeups",
                        help="generate one Word (.docx) write-up per finding")
    wu.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    wu.add_argument("-o", "--output-dir", default="engagement")
    wu.add_argument("--title", default="Recce Engagement",
                    help="engagement title shown on the combined report")
    wu.add_argument("--min-severity", default="low",
                    choices=["critical", "high", "medium", "low", "info"],
                    help="only findings at or above this severity (default: low - "
                         "excludes informational items; use 'info' to include them)")
    wu.add_argument("--include-potential", action="store_true",
                    help="also write up low-confidence, version-inferred 'potential' "
                         "findings (default: real findings only - those confirmed by "
                         "an actual check/observation)")
    wu.add_argument("--no-screenshots", action="store_true",
                    help="don't auto-capture web screenshots (add them in Word)")
    wu.add_argument("--no-combined", action="store_true",
                    help="skip the single combined findings_report.docx")
    wu.add_argument("--overwrite", action="store_true",
                    help="regenerate even where a write-up exists (loses tester edits)")
    wu.set_defaults(func=cmd_writeups)

    # Single-finding write-up, pre-filled with what's already looted/obtained.
    w1 = sub.add_parser("writeup",
                        help="write up ONE finding (pre-filled with looted/obtained "
                             "evidence); run with no selector to list findings")
    w1.add_argument("selector", nargs="?",
                    help="which finding: an F-id (F-007 / 7), a CVE, an IP or IP:port, "
                         "or a word from its title. Omit to list all findings.")
    w1.add_argument("-o", "--output-dir", default="engagement")
    w1.add_argument("--no-screenshots", action="store_true",
                    help="don't auto-capture web screenshots (add them in Word)")
    w1.add_argument("--overwrite", action="store_true",
                    help="regenerate even if this write-up already exists")
    w1.set_defaults(func=cmd_writeup)

    # Bridge: per-open-port enumeration commands from recce/scripts/.
    sv = sub.add_parser("services",
                        help="print the per-service enum command to run for every "
                             "open port recce found (bridges to recce/scripts/)")
    sv.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    sv.add_argument("-o", "--output-dir", default="engagement")
    sv.add_argument("-a", "--aggressive", action="store_true",
                    help="append -a to each command (enable the intrusive checks)")
    sv.set_defaults(func=cmd_services)

    # Per-finding exploitation plan: runnable artifacts driving existing tools.
    ep = sub.add_parser("exploitplan",
                        help="generate ready-to-run exploitation artifacts (msf .rc + "
                             "tool commands) for confirmed findings, params pre-filled")
    ep.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    ep.add_argument("-o", "--output-dir", default="engagement")
    ep.add_argument("--lhost", default="<LHOST>",
                    help="your callback IP for reverse payloads (fills LHOST in the "
                         ".rc files)")
    ep.add_argument("--lport", type=int, default=4444, help="callback port (default 4444)")
    ep.add_argument("--run", action="store_true",
                    help="arm the Metasploit launch lines (default: check-only, safe). "
                         "Use ONLY within your rules of engagement.")
    ep.set_defaults(func=cmd_exploitplan)

    # Attack-path synthesis: chain confirmed findings into a staged path.
    ap = sub.add_parser("attackpath",
                        help="chain confirmed findings into a prioritised attack path "
                             "(foothold -> priv-esc -> creds -> lateral -> domain)")
    ap.add_argument("targets", nargs="*",
                    help="restrict to these IPs / ranges / CIDRs / @file (default: all)")
    ap.add_argument("-o", "--output-dir", default="engagement")
    ap.set_defaults(func=cmd_attackpath)

    # Credential stacking + spray planning.
    cd = sub.add_parser("creds",
                        help="stack captured credentials and build a netexec/impacket "
                             "spray plan across the discovered surface")
    cd.add_argument("targets", nargs="*",
                    help="restrict spray targets to these IPs / ranges / CIDRs / @file")
    cd.add_argument("-o", "--output-dir", default="engagement")
    cd.add_argument("--add", action="append", metavar="USER:SECRET",
                    help="add a captured credential: 'user:secret', "
                         "'DOMAIN\\user:secret' (a 32-hex secret => NT hash). Repeatable.")
    cd.add_argument("--user", help="add a credential: username")
    cd.add_argument("--pass", dest="password", help="add a credential: password")
    cd.add_argument("--hash", help="add a credential: NT hash (for pass-the-hash)")
    cd.add_argument("--domain", help="add a credential: AD domain (blank = local)")
    cd.add_argument("--plan", action="store_true",
                    help="build the spray plan (write users/passwords/hashes files "
                         "+ print the netexec/impacket commands)")
    cd.set_defaults(func=cmd_creds)

    # Convenience: enum + vulns in one shot.
    s = sub.add_parser("scan", help="run enum then vulns in one shot")
    _add_discovery(s)
    _add_common(s)
    _add_vuln_opts(s)
    _add_creds(s)
    s.set_defaults(func=cmd_scan)

    # Fold on-target recce-enum.sh/.ps1 output into the Priv-Esc sheet.
    ing = sub.add_parser("ingest",
                         help="fold on-target recce-enum.sh/.ps1 output into Priv-Esc")
    ing.add_argument("loot", help="path to saved recce-enum output (-o / -OutFile file)")
    ing.add_argument("--host", help="attach findings to this IP (default: match the "
                                    "loot's hostname, else a 'local:<host>' entry)")
    ing.add_argument("-o", "--output-dir", default="engagement")
    ing.add_argument("--title", default="Recce Engagement")
    ing.set_defaults(func=cmd_ingest)

    # Import an existing nmap scan (XML / grepable) -> workbook, no scanning.
    imp = sub.add_parser("import",
                         help="import an existing nmap scan (-oX / -oG / -oN) -> sheet")
    imp.add_argument("files", nargs="+",
                     help="nmap .xml / .gnmap / .nmap file(s), a directory, or a glob")
    imp.add_argument("-o", "--output-dir", default="engagement")
    imp.add_argument("--title", default="Recce Engagement",
                     help="engagement title (only used when starting a fresh datastore)")
    imp.add_argument("--enum-only", action="store_true",
                     help="mark hosts enumerated only; don't auto-mark ports vuln-scanned "
                          "even if the imported scan ran NSE scripts")
    imp.add_argument("--searchsploit", action="store_true",
                     help="also map exploits via searchsploit (needs the tool)")
    imp.set_defaults(func=cmd_import)

    r = sub.add_parser("report", help="regenerate reports (preserves tracking)")
    r.add_argument("-o", "--output-dir", default="engagement")
    r.add_argument("--title", default="Recce Engagement")
    r.set_defaults(func=cmd_report)

    st = sub.add_parser("status", help="print live review coverage")
    st.add_argument("-o", "--output-dir", default="engagement")
    st.set_defaults(func=cmd_status)

    rv = sub.add_parser("review", help="mark items reviewed / not reviewed")
    rv.add_argument("-o", "--output-dir", default="engagement")
    rv.add_argument("--title", default="Recce Engagement")
    rv.add_argument("--host", nargs="*", help="host IP(s) to mark")
    rv.add_argument("--service", nargs="*", metavar="IP:PORT", help="service(s) to mark")
    rv.add_argument("--key", nargs="*", help="raw tracking key(s) to mark")
    rv.add_argument("--cascade", action="store_true",
                    help="with --host, also mark that host's services")
    rv.add_argument("--note", help="attach a note to the marked items")
    rv.add_argument("--undo", action="store_true", help="un-review instead of review")
    rv.set_defaults(func=cmd_review)

    d = sub.add_parser("demo", help="build reports from bundled sample scan (offline)")
    d.add_argument("-o", "--output-dir", default="demo_engagement")
    d.set_defaults(func=cmd_demo)

    doc = sub.add_parser("doctor", help="check this box can run the tool (env + tools + self-scan)")
    doc.add_argument("--no-self-scan", action="store_true",
                     help="skip the real localhost self-scan")
    doc.set_defaults(func=cmd_doctor)
    return p


_QUICKSTART = r"""
recce - phased enumeration & reporting. You mostly need three commands:

  1.  recce doctor                         check this box can run everything
  2.  recce enum   <targets> -o eng        find hosts, ports, services -> workbook
  3.  recce vulns  -o eng                   vuln-scan what enum found

Then open eng/enumeration.xlsx (the "Runbook" tab lists every command + options)
and, when you want more depth, run any of:
      recce db -o eng · privesc -o eng · credenum -u USER -p PASS -d DOMAIN -o eng
      recce writeups -o eng · recce status -o eng

Already have an nmap scan?   recce import scan.xml -o eng   (no scanning)

Targets: a single IP, several IPs, a range (10.0.0.10-40), a CIDR, or @file.
Hosts blocking ping (firewalled / Windows / AD)?  add  -Pn  to enum/scan.
Run scans with sudo for SYN + OS detection.  `recce <command> -h` for options.
"""


def _print_quickstart() -> int:
    print(BANNER)
    print(_QUICKSTART)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if getattr(args, "command", None) is None:
        # Bare `recce` (no subcommand): a friendly quickstart beats an argparse error.
        return _print_quickstart()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        # A scan phase catches this internally to save partial results; this is the
        # backstop for any command that doesn't, so Ctrl-C is never an ugly crash.
        print("\n[!] Interrupted. Results collected so far were saved; re-run "
              "(with --resume on a scan) to continue.")
        return 130
    except Exception as e:  # noqa: BLE001 - top-level safety net for field use
        # Never dump a raw traceback at a tester mid-engagement. Per-host scan work
        # is already persisted crash-safe, so their data survives; give a clean
        # message and a way to get the details for a bug report.
        print(f"\n[x] recce hit an unexpected error: {type(e).__name__}: {e}")
        if os.environ.get("RECCE_DEBUG"):
            import traceback
            traceback.print_exc()
        else:
            print("    Any data collected so far is saved. Re-run to continue; "
                  "set RECCE_DEBUG=1 to see the full traceback for a bug report.")
        return 1
