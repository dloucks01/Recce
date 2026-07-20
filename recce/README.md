# recce

Multi-subnet enumeration and reporting for penetration-testing engagements.

`recce` orchestrates **nmap** (optionally **masscan**) across many hosts
and subnets, normalizes everything into a resumable datastore, and produces an
**Excel workbook** built for tracking your engagement — plus Markdown and CSV.

It is designed for mixed **Linux + Windows / Active Directory** environments:
full TCP port sweeps, service/version + OS detection, initial vulnerability
identification (NSE `vuln` + `vulners`), and deep **Active Directory** analysis —
DC identification, NTLM-relay target discovery, and credentialed LDAP
enumeration of users, SPNs, roastable accounts, delegation, groups and trusts.

> ⚠️ **Authorization required.** Only scan systems you have explicit, written
> permission to test. The tool asks you to confirm authorization at startup.

> 🚀 **New here? Read [QUICKSTART.md](QUICKSTART.md)** — a one-page guide that
> gets you from zero to a filled-in workbook in five commands. There is also a
> `./bin/recce` wrapper so you can skip typing `python3 -m recce`, and a
> **Start Here** tab inside every workbook that explains each sheet.

## Why this over raw nmap / AutoRecon?

Existing tools scan well but leave you with per-host output files. `recce`
adds the layer engagements actually need:

- **Cross-host, checkable deliverable.** Every host, service, vuln and account
  lands in one filterable workbook with `Reviewed`/`Checked`/`Triaged` checkbox
  columns so you can track what's been looked at.
- **Persistent coverage tracking.** Your checkboxes live in the datastore, not
  just the spreadsheet — re-scanning and re-reporting **never wipe your
  progress**. A **Coverage** sheet and a `status` command show exactly what's
  left, at any time (see [Coverage tracking](#coverage-tracking)).
- **"Who else runs this?" pivot.** A *Services by Product/Version* sheet groups
  every endpoint by exact product+version — instantly see all systems running
  the same vulnerable service.
- **Built for a tight clock.** Host-level **concurrency** and a **masscan
  fast-path** collapse hours of sequential `-p-` scans; reports refresh
  incrementally so you can start reviewing while the scan is still running (see
  [Speed](#speed)).
- **Resumable across long, multi-subnet scans.** Results are stored in SQLite and
  merged on re-run; interrupt and `--resume` any time.

## Install

**No pip install required.** The tool uses only the Python standard library
(3.9+), so it runs on an **airgapped** box out of the box — including writing and
reading `.xlsx` (a self-contained stdlib writer, no openpyxl). Just copy the
folder over.

It orchestrates these **system tools** if present (all standard on Kali):

| Tool | Needed for |
|------|-----------|
| `nmap` | **required** — scanning, service/version/OS detection, NSE vuln + AD scripts |
| `masscan` | optional — `--fast` network-wide sweep |
| `searchsploit` (exploitdb) | optional — offline exploit mapping (Exploits sheet) |
| `ldapsearch` (ldap-utils) | optional — credentialed AD LDAP enumeration |

Run scans as **root** (SYN scan + OS detection need raw sockets); it falls back
to a TCP connect scan otherwise.

> The `.xlsx` files it writes open in Excel and LibreOffice. If you happen to
> have `openpyxl` on a connected box, the files are fully compatible — but it is
> never required.

## Workflow (two phases)

The tool is built around the way you actually work an engagement: **get the
sheet populated fast, then scan for vulns per open port** — the two are separate,
cheap, resumable commands.

```bash
# FIRST, on any new box: verify it can run the tool (env + tools + a real
# localhost self-scan). Do this before every engagement.
python -m recce doctor

# See the whole thing with no network (bundled sample):
python -m recce demo -o demo_out

# ── Phase 1: fast enumeration across subnets → populates the sheet ──
#   discovery → port scan → service/version ID only. No vuln scanning yet.
sudo python -m recce enum 10.0.10.0/24 10.0.20.0/24 -o acme \
     --title "ACME internal"

#   ...now open acme/enumeration.xlsx: hosts, ports, services, apps are there.
#   Work the sheet, tick Reviewed as you go. Check where you stand any time:
python -m recce status -o acme

# ── Phase 2: vuln-scan the open ports it found (safe by default) ──
sudo python -m recce vulns -o acme                 # all open ports
sudo python -m recce vulns 10.0.20.0/24 -o acme    # just one subnet
sudo python -m recce vulns 10.0.10.5 -o acme       # just one host
sudo python -m recce vulns -o acme --only http smb # just web + SMB
sudo python -m recce vulns -o acme --unscanned     # only what's left
sudo python -m recce vulns -o acme --aggressive    # intrusive vuln NSE

# ── Databases (per host / subnet / range, safe by default) ──
sudo python -m recce db -o acme                    # all DB services
sudo python -m recce db 10.0.20.6 -o acme --aggressive  # brute/xp_cmdshell

# ── Priv-esc playbook + optional remote checks ──
python -m recce privesc -o acme                    # playbook from data (no scan)
sudo python -m recce privesc 10.0.10.0/24 -o acme --scan  # + smb-vuln-* checks

# One-shot (enum then vulns):
sudo python -m recce scan 10.0.10.0/24 -o acme

# Regenerate reports from the datastore (no re-scan; preserves your ticks):
python -m recce report -o acme
```

**Every phase takes targets** — a single IP, several IPs, ranges
(`10.0.0.10-40`), whole subnets (CIDR), or `@file`. `enum`/`scan` take them as
the positional scope; `vulns`/`db`/`privesc` take them to restrict to a subset of
what's already in the datastore (plus `--only`, `--unscanned`).

### The Checklist tab

The **Checklist** sheet (right after Coverage) is the at-a-glance answer to
"which IPs are done and what's left." One row per IP, with a **checkbox for each
workflow step**:

| Reviewed | IP | Hostname | OS | # Open | # Vulns | Enumerated | Vuln-scan | Web | SMB/AD | DB | Priv-esc | Notes |
|:--:|---|---|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|---|
| ☐ | 10.0.10.10 | dc01 | Windows | 6 | 1 | ✅ | ☐ | — | ✅ | — | — | |
| ☐ | 10.0.20.5 | web01 | Linux | 3 | 4 | ✅ | ✅ | ✅ | — | ☐ | — | |
| ☐ | 10.0.20.9 | file01 | Linux | 1 | 0 | ✅ | ☐ | — | — | — | — | |

The step checkboxes are **auto-default, manual-override — and only appear where
the step actually applies to the host:**

- **Not every host gets every box.** A step that's irrelevant shows **`—` (N/A)**
  instead of a checkbox, so a checked box always means real work happened:
  - **Enumerated** and **Vuln-scan** — universal (Vuln-scan is `—` only if the
    host has no open ports).
  - **Web** — only on hosts serving HTTP/HTTPS.
  - **SMB/AD** — only on Windows / domain-facing hosts (SMB/LDAP/Kerberos or a
    discovered role). A plain Linux box never shows an AD box. This one is a
    **manual sign-off** — it starts unchecked and you tick it once you've actually
    reviewed users/shares/roasting/relay (the tool can't know when you're done).
  - **DB** — only on hosts running a database.
  - **Priv-esc** — appears once you've run the `privesc` phase against the host
    (i.e. you have a foothold to escalate from); `—` until then, so it isn't a
    column of permanently-empty boxes.
- Each (except the manual SMB/AD box) **auto-checks (turns green)** when the tool
  completes that step — `enum` ticks Enumerated, `vulns` ticks Vuln-scan/Web once
  the relevant ports are scanned, `db` ticks DB, `privesc` ticks Priv-esc.
- You can **tick or untick any real box by hand** — mark a step you did manually,
  or untick one to flag "redo." Your manual choice **persists and overrides the
  tool** on later report refreshes.
- Re-running that phase on the host **resets the box to the tool's state**.
- Filter `Vuln-scan = ☐` to see exactly which hosts still need scanning; `—`
  cells are skipped by the filter, so you never chase a phase that doesn't apply.
- Rows are **grouped by subnet** (a Subnet column, sorted), so each subnet's hosts
  sit together — filter to one subnet to work it end to end.

The **Overview** tab's per-subnet coverage table accounts for **every subnet in
scope** — even ones with no live hosts — showing addresses in range, live hosts
found, and per-surface completion (Enumerated / Vuln-scanned / Web / SMB-AD / DB)
where the denominator counts only hosts that surface applies to. That's your
guarantee no subnet — or surface — is missed.

The **Reviewed** checkbox is your per-host sign-off (ticking it here or on the
Hosts tab both count). `status` prints per-step completion counts.

### The Services tab — per-port status

The Checklist tracks whole hosts; the **Services** tab tracks **each open port**.
One row per `IP:port`, grouped by IP, each with its own **tri-state Status**
dropdown so you can mark exactly where you are on that specific port:

| Status | IP | Port | Service | Product | … | Notes |
|---|---|---|---|---|---|---|
| ☑ Done | 10.0.20.5 | 80 | http | Apache 2.4.41 | | creds found, admin panel |
| ◐ In progress | 10.0.20.5 | 443 | https | | | testing TLS + login |
| ☐ Not started | 10.0.20.5 | 22 | ssh | OpenSSH 8.2 | | |

- Pick **☐ Not started / ◐ In progress / ☑ Done** from the dropdown on each port.
  Done rows turn **green**, In-progress rows **amber**, so a host's remaining work
  is obvious at a glance.
- Every port has its own **Notes** cell for findings, creds, payloads, next steps.
- Your status + notes **persist in the datastore** and survive every rescan and
  report rebuild, exactly like the checklist boxes. Filter `Status = ☐ Not
  started` to see every port nobody has touched yet.

> Because the tool rewrites the sheet, "manual wins" works by recording a step
> override only when your box differs from the tool's current state — so re-tick a
> box to match the tool and it goes back to following the tool automatically.
> Edit step boxes *between* scans (not while a scan of that host is running).

Other targets syntax: CIDR, `10.0.0.10-40` ranges, single IPs/hostnames, or
`@scope.txt`. Speed flags (`--fast`, `--workers`, `--resume`, `--all-ports`) live
on `enum`/`scan`.

### Target syntax
CIDR (`10.0.0.0/24`), dash range (`10.0.0.10-40`), single IP, hostname, or
`@file`. Mix as many as you like on one command line.

## What each phase runs

**`enum` (light, feeds the sheet):**
1. **Discovery** — ping/ARP sweep (skip with `--no-discovery` for `-Pn`).
2. **Port sweep** — full TCP (`-p-`) or `--top-ports N` (or `--fast` masscan).
3. **Service ID** — `-sV -sC` (+ `-O`) and safe SMB/LDAP AD facts. No vuln
   scanning — this stays cheap so the sheet is useful in minutes.

**`vulns` (targeted, per open port):** for the open ports already in the
datastore, runs the vulnerability + weak-config scripts below, marks each port
`vuln-scanned`, and maps exploits. **Safe by default** (`vuln and safe` — nmap's
non-intrusive detection scripts); `--aggressive` runs the full intrusive `vuln`
category (can hang printers/OT/old services). Optional top-N UDP with `--udp-top`.

## Enumeration & vulnerability identification

The `vulns` phase runs a large, **service-aware** NSE set — nmap only executes
the scripts whose portrule matches each detected service, so coverage is broad
but cheap:

- **Web**: `http-enum`, `http-title`, `http-headers`, `http-methods`,
  `http-webdav-scan`, `http-git`, `http-auth`, `http-open-proxy`
- **TLS**: `ssl-cert`, `ssl-enum-ciphers` (weak ciphers/protocols, expired/self-signed certs)
- **SSH**: `ssh2-enum-algos`, `ssh-auth-methods`, `ssh-hostkey`
- **FTP/mail**: `ftp-anon`, `smtp-open-relay`, `smtp-commands`, POP3/IMAP caps
- **Databases**: `mysql-info`/`-empty-password`, `ms-sql-*`, `oracle-tns-version`,
  `mongodb-info`, `redis-info`, `pgsql-info`
- **SNMP/DNS/misc**: `snmp-info`, `dns-zone-transfer`, `nfs-showmount`, `rpcinfo`,
  `vnc-info`, `telnet-encryption`, `rdp-enum-encryption`

**Four vulnerability channels feed the Vulnerabilities sheet** (all work
airgapped, none need internet):

1. **NSE `vuln` category** (local) plus **weak-config findings** parsed from the
   enumeration scripts above — anonymous FTP, weak/expired TLS, risky HTTP
   methods, empty DB passwords, cleartext Telnet, SMTP open relay, exposed
   Redis/Mongo, SNMP community strings, DNS zone transfer, etc.
2. **Offline version→CVE engine** (`vulndb.py`) — a curated knowledge base of
   50+ high-signal signatures that matches the product+version data `enum`
   already collected against known CVEs, with a description and **remediation**.
   Covers FTP/SSH/web servers, Samba/SMB, databases, CI/web apps (Jenkins,
   Tomcat, Drupal, Confluence, GitLab, Grafana…), VPN/edge appliances (Fortinet,
   Pulse, Citrix, Palo Alto), Exchange, and default-credential advisories for
   Tomcat/Jenkins/iLO/iDRAC. This is the airgapped replacement for nmap's
   internet-only `vulners` script. Findings are tagged `likely` (a concrete
   version range matched) or `potential` (a product-only advisory lead).
3. **Pure-Python enrichment probes** (`probes.py`, stdlib only) — an active
   layer stock Kali needs extra tooling (testssl.sh, nikto, httpx) for:
   **HTTP security-header analysis** (missing HSTS/CSP/X-Frame-Options/
   X-Content-Type-Options, version-disclosing `Server` banners) and **TLS
   certificate & protocol analysis** (expired/self-signed/soon-to-expire certs,
   hostname mismatch, negotiable SSLv3/TLS 1.0/1.1). Disable with `--no-probes`.
4. **`searchsploit` (Exploit-DB, offline)** maps every service's product+version
   to known public exploits on a dedicated **Exploits** sheet (EDB-ID, type,
   title, CVEs, local path).

Every finding also carries **CWE** references (in a dedicated column) alongside
its CVEs, so you can group and report weaknesses by class.

> **Airgapped tip:** run with `--offline` to drop the internet-dependent
> `vulners` script; you still get the local `vuln` category, all weak-config
> findings, the offline version→CVE engine, the HTTP/TLS probes, and
> `searchsploit` exploit mapping. Install `exploitdb` for searchsploit
> (`apt install exploitdb`, and it ships on Kali).

Toggles (on `vulns`/`scan`): `--aggressive`, `--offline`, `--no-searchsploit`,
`--no-probes`, `--udp-top N`, plus positional targets, `--only`, `--unscanned`
to target a subset.

## Databases (`db`)

`db` finds database services (MySQL, MSSQL, Oracle, PostgreSQL, MongoDB, Redis,
CouchDB, …) and runs engine-specific NSE. **Safe by default** — version/config
enumeration, database & user listing, empty-password checks. `--aggressive` adds
intrusive checks (brute force, `xp_cmdshell`, hash dumping). Results populate a
**Databases** sheet (engine, version, auth posture, databases, users, findings);
security issues also land in the Vulnerabilities sheet. Credentials via
`--username/--password` are passed to the DB scripts for authenticated checks.

## Priv-Esc (`privesc`)

`privesc` produces a per-host **Priv-Esc** sheet with two parts:

- **Remote findings** we actually observed — missing patches with public
  exploits (MS17-010, ZeroLogon, BlueKeep, PrintNightmare), SMB signing off,
  unauthenticated services, and local/remote exploit candidates from searchsploit.
- **An OS-specific playbook** — the prioritised checks/commands to run once you
  have a foothold. Windows: winPEAS/PowerUp, service perms & unquoted paths,
  `AlwaysInstallElevated`, token privileges (`SeImpersonate`→Potato), stored
  creds, scheduled tasks, DLL hijacking. Linux: linPEAS, `sudo -l`+GTFOBins,
  SUID/SGID, capabilities, cron, writable sensitive files, NFS `no_root_squash`,
  docker/lxd group.

The playbook is generated offline from what `enum` already found (no scanning);
`--scan` additionally runs the remote privesc NSE checks (`--aggressive` includes
intrusive ones like MS08-067 that can crash services).

## Coverage tracking

The goal: know **at any moment** which systems/services you've looked at and
which you haven't — and never lose that as scans grow.

- **Check items off two ways:** tick the `Reviewed`/`Checked`/`Triaged` box in any
  tracked sheet in Excel, **or** use the `review` command. Both write to the
  persistent datastore.
- The datastore is the source of truth. Regenerating reports (`report`, or the
  auto-refresh during a scan) **preserves every check and note**. Each tracked
  sheet carries a hidden `Key` column that ties a row to its datastore item, so
  read-back is exact.
- The **Coverage** sheet (data-bar progress per category + per subnet) and the
  `status` command give a live picture.

```bash
# Live coverage in the terminal (also flags unreviewed DCs / high-risk hosts):
python -m recce status -o engagement

# Mark from the CLI: a host and all its services, with a note:
python -m recce review -o engagement --host 10.0.10.10 --cascade \
       --note "DC enumerated, NTDS dump pending"

# Mark specific services / undo:
python -m recce review -o engagement --service 10.0.20.5:80 10.0.20.5:443
python -m recce review -o engagement --host 10.0.10.25 --undo

# Edit checkboxes in Excel, then pull them into the datastore + refresh:
python -m recce report -o engagement
```

`status` output:

```
  OVERALL      [####----------------]  18%  5/27
  Hosts        [#####---------------]  25%  1/4
  Services     [######--------------]  30%  4/13
  ...
  ! Unreviewed Domain Controllers: 10.0.10.10
```

### How new IPs appear (in-place update)

The spreadsheet is generated from scans — it can't discover IPs on its own, so a
`scan` (or `report`) run is what brings new systems in. When that happens the
workbook is updated **in place**:

- **rows you've already reviewed keep their position and your checkbox/notes**,
- **new IPs/services are appended at the bottom** of each sheet (so nothing you've
  worked through shifts around), and
- the Dashboard/Coverage/AD tabs recompute.

Practical rule for a spreadsheet-only workflow: **do your tracking in the
checkbox and `Notes` columns.** The tool re-lays-out the sheets each run, so those
columns survive — but ad-hoc cell coloring or extra columns you add by hand will
not.

**You can keep working in the sheet while a scan runs.** The auto-refresh
re-imports your saved checkboxes/notes *before* regenerating, and writes
atomically — so saved edits are never lost. If the workbook is open and locked
when a refresh fires, the tool skips that write (your edits are already captured)
and retries; it never corrupts the open file. Just **save in Excel** so the
refresh can see your latest ticks.

## Nothing is wasted if a run is slow or crashes

Findings are written to the SQLite datastore **the moment each host finishes** —
not at the end. On top of that:

- The workbook refreshes **after every N hosts *or* every ~20 seconds**, whichever
  comes first (so even slow hosts produce visible progress), controlled by
  `--refresh-every`.
- **Ctrl-C** stops cleanly and still writes a final report from everything done
  so far.
- A hard crash or kill loses at most the one in-flight host; run
  `report -o <dir>` to rebuild the full sheet from the datastore.
- `--resume` skips hosts already scanned, so re-running after an interruption
  picks up where it left off.

## Speed

For a time-boxed engagement, three levers cut wall-clock dramatically:

- **Two phases** — `enum` is cheap, so the sheet is usable in minutes; the
  expensive `vulns` pass runs later and only where you point it (`--only`,
  `--subnet`, `--unscanned`).
- **`--workers N`** — scan N hosts concurrently (default 6). The single biggest
  win for large scopes.
- **`--fast`** — one **network-wide masscan sweep** finds open ports across the
  whole scope at high packet-rate, then nmap scans *only* those host:port pairs
  concurrently. Skips slow per-host `-p-` entirely. Falls back to nmap if masscan
  isn't installed.
- **`--refresh-every N`** — regenerate the workbook every N hosts (default 10) so
  you can start triaging in Excel while the scan continues. `0` disables.
- **`--profile quick`** for first-pass triage (top-200 ports, no vuln scripts),
  then a targeted `--profile thorough` pass on what matters.

```bash
# Fast full-scope sweep, 12 hosts at a time, report refresh every 20 hosts:
sudo python -m recce scan 10.0.0.0/22 --fast --workers 12 --refresh-every 20 -o eng

# Resume where you left off after a break (skips already-scanned hosts):
sudo python -m recce scan 10.0.0.0/22 --fast --workers 12 --resume -o eng
```

## Active Directory

AD analysis runs in two tiers.

**Tier 1 — credential-free (always on).** Purely from what nmap already collected,
the tool tags roles (**Domain Controller**, Global Catalog, WinRM, RDP, MSSQL…),
determines **SMB signing** posture, and harvests domain/NetBIOS/FQDN facts and
the **password policy** (from `smb-enum-domains`). It then derives target lists:

- **Domain Controllers** — your primary AD targets
- **NTLM relay targets** — hosts where *SMB signing is not required* (feed to `ntlmrelayx`)
- **SMBv1 / MS17-010** candidates

**Tier 2 — credentialed LDAP (`--ldap-enum`, needs `ldap3`).** Binds to each
discovered DC and enumerates:

- **Users** with UAC flags → **AS-REP roastable** (`DONT_REQ_PREAUTH`) accounts
- **SPNs** → **Kerberoastable** service accounts (krbtgt excluded)
- **Unconstrained / constrained delegation** on users and computers
- **Computers** with OS/build
- **Privileged groups** and their members (Domain/Enterprise Admins, `adminCount=1`)
- **Domain trusts**, functional level, `ms-DS-MachineAccountQuota`, anonymous-bind check

```bash
# Credentialed LDAP enumeration of every discovered DC:
sudo python -m recce scan 10.0.10.0/24 --ldap-enum \
     --username jsmith --password 'P@ss' --domain corp.local

# Point LDAP at a specific DC (skip auto-detect); try anonymous bind:
python -m recce scan 10.0.10.0/24 --ldap-enum --ldap-anon --dc-ip 10.0.10.10

# Credentials are also passed to the SMB/LDAP NSE scripts during the scan so
# authenticated user/share/group enumeration succeeds:
sudo python -m recce scan 10.0.10.0/24 --username jsmith --password 'P@ss' --domain corp.local
```

Everything lands in the **Active Directory** and **AD Quick Wins** sheets (see
below), plus an enriched **Users & Accounts** sheet (roastable/delegation cells
are color-flagged).

## Output (`<output-dir>/`)

| File | Contents |
|------|----------|
| `enumeration.xlsx` | **Start Here** (self-guide) · Dashboard · **Coverage** · **Checklist** (per-IP step completion) · Hosts · Services · **Services by Product/Version** · Vulnerabilities · **Exploits** · **Databases** · **Active Directory** · **AD Quick Wins** · **Priv-Esc** · Users & Accounts · Subnets — all with autofilter, freeze panes, and persistent checkbox tracking |
| `enumeration.md`   | Summary + per-host checklist (great for notes / git) |
| `services.csv`     | Flat services table for import/pivot anywhere |
| `results.sqlite`   | Normalized datastore (resume + re-report) |
| `raw/*.xml`        | Every raw nmap XML, for auditing / re-parsing |

## Profiles

| Profile | Ports | OS | Notes |
|---------|-------|----|-------|
| `quick` | top 200 | no | fast triage |
| `standard` (default) | full TCP | yes | balanced |
| `thorough` | full TCP | yes | + top-100 UDP, slower/quieter |

Override with `--all-ports`, `--top-ports`, `--no-ad`, `--no-os`, `--min-rate`,
`--udp-top`. (Vuln scanning is its own `vulns` phase, safe-by-default.)

## Layout

```
bin/recce            convenience wrapper (run: ./bin/recce ...)
QUICKSTART.md        one-page user guide
recce/               the package (python -m recce)
  targets.py         target parsing / subnet expansion / IP matcher
  scanner.py         nmap / masscan orchestration (discover / enum / vuln / nse)
  parser.py          nmap XML -> normalized model (+ vuln & AD harvesting)
  models.py          Host / Port / Vuln / Exploit / Account / Domain dataclasses
  ad.py              AD analysis: roles, signing/relay, LDAP enumeration
  db.py              database detection + engine-specific NSE + inventory
  privesc.py         Windows/Linux priv-esc findings + playbook knowledge base
  exploits.py        offline exploit mapping via searchsploit (Exploit-DB)
  vulndb.py          offline version->CVE/CWE vulnerability engine (+ remediation)
  probes.py          stdlib HTTP-header + TLS enrichment probes (airgapped)
  tracking.py        coverage + per-step keys, progress computation (shared)
  xlsx.py            standard-library .xlsx writer/reader (no openpyxl)
  store.py           SQLite datastore: hosts + domains + tracking, merge-on-rescan
  report_excel.py    the Excel workbook (Start Here, Overview, Checklist, ...)
  report_markdown.py Markdown + CSV
  cli.py             command-line interface (enum/vulns/db/privesc/... commands)
  sample_scan.xml    bundled sample for `demo`
```
