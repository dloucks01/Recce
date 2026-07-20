"""Command-line entrypoint for recce.

Subcommands:
  scan     run enumeration across targets, store results, generate reports
  report   (re)generate reports from an existing datastore (preserves tracking)
  status   print live review-coverage from the datastore
  review   mark hosts / services / items reviewed (or un-review) from the CLI
  demo     build reports from a bundled sample nmap XML (no network needed)

Authorization is confirmed at startup for scans.
"""

from __future__ import annotations

import argparse
import os
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
from .store import Store
from .targets import apply_exclusions, ip_matcher, load_targets

BANNER = r"""
  ____  _____ ____ ____ _____
 |  _ \| ____/ ___/ ___| ____|
 | |_) |  _|| |  | |   |  _|
 |  _ <| |__| |__| |___| |___
 |_| \_\_____\____\____|_____|
   recon & coverage tracker for airgapped pentests
"""

AUTH_NOTICE = (
    "AUTHORIZATION REQUIRED: Only scan hosts and networks you have explicit,\n"
    "written permission to test. Unauthorized scanning may be illegal.\n"
)


def _confirm_authorized(assume_yes: bool) -> None:
    print(AUTH_NOTICE)
    if assume_yes:
        print("[+] Authorization acknowledged via --yes.\n")
        return
    try:
        resp = input("Do you confirm you are authorized to scan these targets? [y/N] ")
    except EOFError:
        resp = ""
    if resp.strip().lower() not in ("y", "yes"):
        print("Aborting: authorization not confirmed.")
        sys.exit(2)
    print()


def _ports_for_host(xml_path: str, ip: str) -> list[int]:
    for h in np.parse_nmap_xml(xml_path):
        if h.ip == ip:
            return [p.portid for p in h.ports]
    return []


def _open_paths(out_dir: str) -> dict[str, str]:
    raw = os.path.join(out_dir, "raw")
    os.makedirs(raw, exist_ok=True)
    return {
        "raw": raw,
        "db": os.path.join(out_dir, "results.sqlite"),
        "xlsx": os.path.join(out_dir, "enumeration.xlsx"),
        "md": os.path.join(out_dir, "enumeration.md"),
        "csv": os.path.join(out_dir, "services.csv"),
    }


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
    except (PermissionError, OSError):
        return False


def _generate_reports(store: Store, paths: dict[str, str], title: str,
                      quiet: bool = False) -> None:
    """Regenerate all reports from the datastore (the source of truth)."""
    hosts = store.all_hosts()
    tracking = store.get_tracking()
    domains = _resolve_domains(store, hosts)
    update_workbook(paths["xlsx"], hosts, meta={"subtitle": title},
                    domains=domains, tracking=tracking, scope=store.get_scope(),
                    statuses=store.get_statuses())
    build_markdown(hosts, paths["md"], title=title, domains=domains)
    build_csv(hosts, paths["csv"])
    if not quiet:
        cov = tr.compute_coverage(hosts, tracking)["overall"]
        print(f"[+] Reports written ({cov['done']}/{cov['total']} items reviewed, "
              f"{cov['pct']}%):\n    {paths['xlsx']}\n    {paths['md']}\n    {paths['csv']}")


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
    if g("udp_top"):
        profile.udp_top = args.udp_top
    if g("masscan") or g("fast"):
        profile.scanner = "masscan"
    if g("offline"):
        profile.offline = True
    profile.ping_discovery = not g("no_discovery", False)


def _creds_of(args) -> dict | None:
    return {"username": args.username, "password": args.password,
            "domain": args.domain} if getattr(args, "username", None) else None


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
    except (PermissionError, OSError):
        print("[!] Could not write the workbook (open/locked). Your data is saved "
              "in the datastore - close the file and run `report` to rebuild it.")


# --- phase 1+2a: discovery + light service enumeration --------------------------

def _enum_worker(ip, profile, paths, creds, port_map, subnet_map) -> Host | None:
    if port_map is not None:
        open_ports = port_map.get(ip, [])
    else:
        fp_xml = os.path.join(paths["raw"], f"{ip}_ports.xml")
        scanner.full_port_scan(ip, fp_xml, profile)
        open_ports = _ports_for_host(fp_xml, ip)

    enum_xml = os.path.join(paths["raw"], f"{ip}_enum.xml")
    scanner.enum_scan(ip, open_ports, enum_xml, profile, creds=creds)
    host = _fold_host(ip, np.parse_nmap_xml(enum_xml), subnet_map)
    host.enumerated = True
    ad.identify_roles(host)
    ad.parse_signing_and_ntlm(host)
    from . import vulndb
    vulndb.assess_host_inplace(host)   # offline version->CVE findings, immediately
    return host


def _discover(args, profile, store, paths):
    hosts, subnet_map = load_targets(args.targets)
    hosts = apply_exclusions(hosts, args.exclude or [])
    if not hosts:
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
            scanner.discover_hosts(targets_file, disc_xml)
            live_ips = [h.ip for h in np.parse_nmap_xml(disc_xml)]
            os.unlink(targets_file)
            print(f"[+] {len(live_ips)} live host(s) found.")
        else:
            live_ips = hosts
            print("[*] Discovery skipped (treating all targets as up).")

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
                host = fut.result()
            except Exception as e:  # noqa: BLE001
                print(f"[!] {ip}: enum error: {e}")
                continue
            if host is None:
                continue
            store.upsert_host(host)   # durable immediately - crash-safe
            store.delete_tracking(tr.step_key("enum", ip))  # re-run clears override
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
                 use_probes=True) -> Host:
    ip = host.ip
    if portids:
        vx = os.path.join(paths["raw"], f"{ip}_vuln.xml")
        scanner.vuln_scan(ip, portids, vx, profile, creds=creds, aggressive=aggressive)
        _merge_vuln_results(host, np.parse_nmap_xml(vx))
    if profile.udp_top:
        ux = os.path.join(paths["raw"], f"{ip}_udp.xml")
        scanner.udp_scan(ip, ux, profile)
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
    return host


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
    use_ss = not getattr(args, "no_searchsploit", False) and exploits.available()
    use_probes = not getattr(args, "no_probes", False)
    if not getattr(args, "no_searchsploit", False) and not exploits.available():
        print("[!] searchsploit not found; skipping exploit mapping "
              "(apt install exploitdb).")
    if profile.offline:
        print("[*] Offline: vulners disabled; using local vuln scripts + searchsploit.")
    mode = "AGGRESSIVE (intrusive vuln category)" if aggressive else \
        "safe (vuln+safe detection only)"
    print(f"[*] Vuln-scan mode: {mode}"
          f"{' + searchsploit' if use_ss else ''}"
          f"{' + http/tls probes' if use_probes else ''}.")

    targets = _vuln_targets(store.all_hosts(), args)
    if not targets:
        print("[!] No open ports match the vuln-scan filters.")
        return
    workers = max(1, args.workers)
    total_ports = sum(len(p) for _, p in targets)
    print(f"[*] Vuln-scanning {len(targets)} host(s) / {total_ports} port(s) "
          f"with {workers} worker(s) ...")
    completed = 0
    refresher = _Refresher(args)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_vuln_worker, h, ports, profile, paths, creds,
                             aggressive, use_ss, use_probes): h.ip
                   for h, ports in targets}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                host = fut.result()
            except Exception as e:  # noqa: BLE001
                print(f"[!] {ip}: vuln-scan error: {e}")
                continue
            store.upsert_host(host)   # durable immediately - crash-safe
            store.delete_tracking(tr.step_key("vuln", ip))  # re-run clears override
            completed += 1
            bits = []
            if host.vulns:
                bits.append(f"{len(host.vulns)} finding(s)")
            if host.exploits:
                bits.append(f"{len(host.exploits)} exploit(s)")
            b = f" [{', '.join(bits)}]" if bits else ""
            print(f"    [{completed}/{len(targets)}] {ip}: vuln-scanned{b}")
            refresher.tick(store, paths, args.title)


# --- phase: database enumeration / vuln scan ------------------------------------

def _db_worker(host, portids, profile, paths, creds, aggressive, use_ss) -> Host:
    from . import db as dbmod
    vx = os.path.join(paths["raw"], f"{host.ip}_db.xml")
    scanner.nse_scan(host.ip, portids, vx, profile,
                     dbmod.script_selection(aggressive), creds=creds)
    _merge_vuln_results(host, np.parse_nmap_xml(vx))
    pset = set(portids)
    for p in host.ports:
        if p.portid in pset:
            p.vuln_scanned = True
    host.db_scanned = True
    if use_ss:
        exploits.enrich_hosts([host])
    return host


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
                host = fut.result()
            except Exception as e:  # noqa: BLE001
                print(f"[!] {ip}: db-scan error: {e}")
                continue
            store.upsert_host(host)
            store.delete_tracking(tr.step_key("db", ip))  # re-run clears override
            completed += 1
            print(f"    [{completed}/{len(targets)}] {ip}: db-scanned")
            refresher.tick(store, paths, args.title)


# --- phase: privilege-escalation --------------------------------------------------

def _privesc_worker(host, profile, paths, creds, aggressive) -> Host:
    from . import privesc as pe
    ports = [p.portid for p in host.open_ports
             if p.portid in (139, 445, 3389, 135) or "http" in (p.service or "")]
    if ports:
        vx = os.path.join(paths["raw"], f"{host.ip}_privesc.xml")
        scanner.nse_scan(host.ip, ports, vx, profile, pe.nse_scripts(aggressive),
                         creds=creds)
        _merge_vuln_results(host, np.parse_nmap_xml(vx))
        ad.identify_roles(host)
        ad.parse_signing_and_ntlm(host)
    return host


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
                host = fut.result()
            except Exception as e:  # noqa: BLE001
                print(f"[!] {ip}: privesc error: {e}")
                continue
            store.upsert_host(host)
            completed += 1
            refresher.tick(store, paths, args.title)


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
    paths = _open_paths(args.output_dir)
    store = Store(paths["db"])
    _import_excel_tracking(store, paths)
    return profile, paths, store


def cmd_enum(args: argparse.Namespace) -> int:
    print(BANNER)
    _confirm_authorized(args.yes)
    profile, paths, store = _setup_scan(args)
    if store is None:
        return 1
    store.set_meta("engagement", args.title)
    subnet_map, live_ips, port_map = _discover(args, profile, store, paths)
    if subnet_map is None:
        print("[x] No targets after expansion/exclusion.")
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
    print("\n[+] Enumeration done. Review the sheet, then run `vulns` on open ports.")
    return 0


def cmd_vulns(args: argparse.Namespace) -> int:
    _confirm_authorized(args.yes)
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
    print("\n[+] Vuln scan done.")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Convenience: run enum then vulns in one shot."""
    print(BANNER)
    _confirm_authorized(args.yes)
    profile, paths, store = _setup_scan(args)
    if store is None:
        return 1
    store.set_meta("engagement", args.title)
    subnet_map, live_ips, port_map = _discover(args, profile, store, paths)
    if subnet_map is None:
        print("[x] No targets after expansion/exclusion.")
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
    _confirm_authorized(args.yes)
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
    _confirm_authorized(args.yes)
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
        ("ldapsearch", False, "credentialed AD LDAP enumeration"),
    ]
    nmap_ok = False
    for name, required, desc in tools:
        present = shutil.which(name) is not None
        if name == "nmap":
            nmap_ok = present
        mark = "OK  " if present else ("MISSING (required)" if required else "-   (optional)")
        print(f"  {name:<15} {mark:<20} {desc}")
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
        degraded = [n for n, req, _ in tools if not req and not shutil.which(n)]
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
            scanner.enum_scan("127.0.0.1", ports or [80], deep, profile)
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
        print("[!] --ldap-enum requested but ldap3 is not installed "
              "(pip install ldap3); skipping.")
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
        base.last_scanned = h.last_scanned or base.last_scanned
        base.ports.extend(h.ports)
        base.vulns.extend(h.vulns)
        base.accounts.extend(h.accounts)
        base.exploits.extend(h.exploits)
        base.host_scripts.extend(h.host_scripts)
    base.subnet = subnet_map.get(ip, base.subnet)
    return base


# --- report / status / review ---------------------------------------------------

def cmd_report(args: argparse.Namespace) -> int:
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}")
        return 1
    store = Store(paths["db"])
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
    store = Store(paths["db"])
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
    o = cov["overall"]
    print(f"  OVERALL      [{bar(o['pct'])}] {o['pct']:3d}%  {o['done']}/{o['total']}")
    print()
    for cat in tr.COVERAGE_CATEGORIES:
        c = cov[cat]
        print(f"  {labels[cat]:<13}[{bar(c['pct'])}] {c['pct']:3d}%  {c['done']}/{c['total']}")

    # Tool progress (auto): per-step completion, counting only hosts the step
    # applies to (a Linux box isn't counted against DB/SMB-AD coverage).
    def phase_count(step):
        applic = [h for h in hosts if tr.step_applies(h, step)]
        return sum(1 for h in applic if tr.step_auto(h, step)), len(applic)

    en_d, en_t = phase_count("enum")
    vs_d, vs_t = phase_count("vuln")
    web_d, web_t = phase_count("web")
    ad_d, ad_t = phase_count("smbad")
    db_d, db_t = phase_count("db")
    pe_done = sum(1 for h in hosts if h.privesc_checked)
    open_ports = [p for h in hosts for p in h.open_ports]
    scanned_ports = sum(1 for p in open_ports if p.vuln_scanned)
    print("\n  Tool progress (auto) - per step, hosts complete / applicable:")
    print(f"    Enumerated    {en_d}/{en_t}")
    print(f"    Vuln-scanned  {vs_d}/{vs_t}"
          + (f"   ({scanned_ports}/{len(open_ports)} open ports)" if open_ports else ""))
    print(f"    Web           {web_d}/{web_t}   (hosts serving HTTP/HTTPS)")
    print(f"    SMB/AD        {ad_d}/{ad_t}   (Windows / domain-facing hosts)")
    print(f"    DB-scanned    {db_d}/{db_t}   (hosts with DB services)")
    print(f"    Priv-esc      {pe_done}/{len(hosts)}   (post-exploitation performed)")
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
    store = Store(paths["db"])
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
    store = Store(paths["db"])
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
    pp.add_argument("--title", default="Pentest Enumeration",
                    help="engagement title shown in reports")
    pp.add_argument("--profile", choices=list(scanner.PROFILES), default="standard")
    pp.add_argument("--workers", type=int, default=6,
                    help="concurrent hosts to scan at once (default: 6)")
    pp.add_argument("--refresh-every", type=int, default=10, metavar="N",
                    help="regenerate reports every N hosts (0 to disable; default 10)")
    pp.add_argument("-y", "--yes", action="store_true",
                    help="assume authorization is confirmed (non-interactive)")


def _add_creds(pp) -> None:
    pp.add_argument("--username", help="credential for authenticated SMB/LDAP")
    pp.add_argument("--password", help="credential for authenticated SMB/LDAP")
    pp.add_argument("--domain", help="AD domain (e.g. corp.local) for authentication")
    pp.add_argument("--ldap-enum", action="store_true",
                    help="credentialed LDAP enumeration of discovered DCs")
    pp.add_argument("--ldap-anon", action="store_true", help="attempt anonymous LDAP bind")
    pp.add_argument("--ldap-ssl", action="store_true", help="use LDAPS (636)")
    pp.add_argument("--dc-ip", help="target this DC IP for LDAP instead of auto-detect")


def _add_discovery(pp) -> None:
    pp.add_argument("targets", nargs="+", help="CIDRs / ranges / IPs / hostnames, or @file")
    pp.add_argument("--exclude", nargs="*", help="hosts/CIDRs to exclude")
    pp.add_argument("--fast", action="store_true",
                    help="masscan network-wide sweep instead of per-host nmap")
    pp.add_argument("--masscan", action="store_true", help="use masscan for port sweep")
    pp.add_argument("--all-ports", action="store_true", help="force full 65535 TCP sweep")
    pp.add_argument("--top-ports", type=int, help="scan only top-N TCP ports")
    pp.add_argument("--min-rate", type=int, help="nmap --min-rate override")
    pp.add_argument("--no-discovery", action="store_true",
                    help="skip ping sweep; treat all targets as up (-Pn)")
    pp.add_argument("--no-ad", action="store_true", help="skip SMB/LDAP AD scripts")
    pp.add_argument("--no-os", action="store_true", help="skip OS detection")
    pp.add_argument("--resume", action="store_true", help="skip hosts already in datastore")


def _add_vuln_opts(pp) -> None:
    pp.add_argument("--aggressive", action="store_true",
                    help="run the full intrusive NSE 'vuln' category (can crash "
                         "fragile services); default is safe detection only")
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
    sub = p.add_subparsers(dest="command", required=True, metavar="<command>")

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

    # Convenience: enum + vulns in one shot.
    s = sub.add_parser("scan", help="run enum then vulns in one shot")
    _add_discovery(s)
    _add_common(s)
    _add_vuln_opts(s)
    _add_creds(s)
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("report", help="regenerate reports (preserves tracking)")
    r.add_argument("-o", "--output-dir", default="engagement")
    r.add_argument("--title", default="Pentest Enumeration")
    r.set_defaults(func=cmd_report)

    st = sub.add_parser("status", help="print live review coverage")
    st.add_argument("-o", "--output-dir", default="engagement")
    st.set_defaults(func=cmd_status)

    rv = sub.add_parser("review", help="mark items reviewed / not reviewed")
    rv.add_argument("-o", "--output-dir", default="engagement")
    rv.add_argument("--title", default="Pentest Enumeration")
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


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    return args.func(args)
