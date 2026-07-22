# Changelog

All notable changes to recce are documented here. Dates are UTC.

## [Unreleased]

_Accumulating fixes since 0.2.3; folded into the next tagged release._

### Added
- **`deploy` — credentialed mass local-enum & priv-esc.** Hand recce credentials
  and it runs the read-only on-target enum scripts (`recce-enum.sh`/`.ps1`) across
  every host it can reach, in parallel, and folds the results straight into the
  report — no more per-box copy/run/`ingest` by hand. Transport is auto-selected
  per host from its open ports + OS: **SSH** (script piped over stdin, nothing
  written to disk), **WinRM** (run in-memory via `nxc winrm -X powershell
  -EncodedCommand`), or **SMB** (pushed to `%TEMP%`, run, deleted). Shells out to
  the same `ssh`/`sshpass` and `netexec`/`nxc` `credenum` already uses — and the
  Windows exec is **engine-agnostic**: if `nxc` isn't installed it uses **impacket**
  (`wmiexec`, plus `smbclient` for the push) instead, so it works on a stock Kali
  either way (impacket pairs especially cleanly with `--stager` — wmiexec runs the
  download cradle in memory, no file push at all). Creds:
  `--ssh-user/--ssh-pass/--ssh-key` for Linux, `-u/-p/-d` or `--hash` (pass-the-
  hash) for Windows. `--dry-run` previews the per-host transport plan; per-host
  failures are isolated and logged; loot is saved to `eng/loot/<ip>.txt`. The
  scripts are read-only and run no exploit code / no evasion. (The `ingest`
  folding logic is now shared via `_fold_loot`, so `deploy` and `ingest` fold
  identically.)
  - **nxc credential precheck.** Before running, `deploy` uses netexec to see which
    protocols the given creds actually authenticate to across the targets (SMB
    admin / WinRM / SSH) and picks the transport *proven* to work per host, rather
    than guessing from open ports — so it only runs where it truly can.
    `--no-validate` skips it.
  - **`--stager` (in-memory Windows exec over HTTP).** The 39 KB Windows script is
    too big to inline over SMB and a bloated blob over WinRM; with `--stager`,
    recce stands up a short-lived stdlib HTTP server (random token path, torn down
    after the run) and Windows hosts fetch + run it **in memory** via a one-line
    download cradle — no temp file, no size limit. **Auto-falls-back** to the push
    path if a host can't route back to `--lhost` (autodetected if omitted). SSH is
    unchanged (its stdin-pipe already runs in memory at any size).

### Added
- **Better service detection — no more dead "unknown" ports.** nmap's `-sV` is
  still the primary identifier, but the ports it leaves as `unknown`/`tcpwrapped`
  (especially Windows RPC/ephemeral services like **5040 CDPSvc**, 5357 wsdapi,
  47001 winrm-http, dynamic MSRPC) are now recovered by a new `svcdetect` layer,
  airgapped-safe and stdlib-only, in three escalating steps:
  1. **servicefp mining** — nmap already collected the service's raw response but
     couldn't match it; recce now keeps that fingerprint (previously discarded)
     and keyword-matches it itself (SSH/VNC/TLS/RDP/Redis/… signatures). No new
     traffic.
  2. **curated port map** — a well-known port with no name gets an *inferred*
     label from the port number (e.g. 5040 → "Windows CDPSvc"). No new traffic.
  3. **active banner grab** — a timeout-bounded connect-and-read (plus a few
     protocol nudges: HTTP HEAD, Redis PING, RDP X.224) fingerprints what the
     first two missed. Only touches the target; runs on a stock airgapped Kali.

  The Services tab gains an **"ID source"** column (nmap / inferred / banner) so
  you can see *how confident* each label is, and a still-unknown port now shows a
  **suggested identification command** (`nmap -sV --version-all` / `amap`) in its
  Enum-command cell instead of being a dead end. `--no-probes` disables the active
  grab; the free passive layers always run.
- **Domain-qualified usernames are accepted anywhere creds are given.** `-u` now
  takes the credential however AD hands it to you — `CORP\user`,
  `corp.local/user`, or `user@corp.local` — and splits the domain out for you, so
  `-d` becomes optional (an explicit `-d` still wins, keeping e.g. the FQDN form
  over an embedded NetBIOS name). The domain flows through the whole authenticated
  path: nxc (`-d`), impacket (`domain/user`), WinRM and SMB. Applies to every
  credentialed command (`deploy`, `credenum`, `vulns`, `db`, `privesc`) and to the
  privileged `--admin-user` account.

### Changed
- **`deploy` now reports every host's outcome: succeeded / errored / unable.**
  Previously a host with no usable transport (no SSH/WinRM/SMB port, or creds that
  didn't validate) was silently rolled into a single "N skipped" count. Now every
  un-deployable host carries a plain-English reason (`skip_reason()` — e.g. "no
  remote-exec port open", "port open but missing SSH creds", "credentials did not
  authenticate"), and `deploy`: (1) lists both **WILL RUN** and **UNABLE / SKIPPED**
  (with reasons) in `--dry-run`; (2) ends a real run with a three-way
  **`DEPLOY RESULTS: X succeeded · Y errored · Z unable`** summary that lists the
  errored and unable hosts; and (3) writes the unable hosts to the **Overview
  issues tab** too, so the workbook shows what completed and what couldn't — not
  just the successes.
- **`--help` is scannable instead of a flat wall of flags.** Every command's
  options are now sorted into labelled groups — the one or two flags a normal run
  uses (`-o`, `-Pn`, `--fast`, `-u/-p/-d`) stay up top, and the tuning knobs fold
  into clearly-titled *(optional)* sections (`scan tuning`, `output & performance`,
  `privileged & LDAP`, `deploy options`). No flags were added, removed, or renamed
  and every existing invocation is unchanged — `recce <cmd> -h` just reads as
  "here's what you need, advanced stuff is over there." The common runs stay
  short: `recce enum 10.0.0.0/24 -o eng`, `recce vulns -o eng`,
  `recce deploy -u USER -p PASS -o eng`.
- **Port sweep is now completeness-first — it won't silently miss open ports.**
  The sweep is the foundation every later phase keys off, so three ways an open
  port could be silently dropped are closed:
  - **Retries.** `-Pn` used `--max-retries 1` ("fail fast on dead IPs"), so a
    single dropped SYN lost an open port. The sweep now uses `--max-retries 3` by
    default (tunable with `--max-retries`); dead IPs stay bounded by
    `--host-timeout`, not by starving retries.
  - **Verification re-scan.** A host that comes back with **0 open ports** is now
    re-scanned with an independent congestion-adaptive sweep before "no ports" is
    trusted — discovered-live hosts always, `-Pn` hosts with `--verify-all`. If
    the re-scan finds ports, the fast pass under-reported and the re-scan wins.
    `--no-verify` opts out.
  - **Truncation is no longer silent.** A sweep cut short by `--host-timeout`
    returns a *partial* port list; the host is now flagged `incomplete_scan`,
    called out in `status` and marked `⚠ PARTIAL` on the Checklist, so a truncated
    host is never mistaken for a fully-scanned empty one. (Ports union across
    scans, so a later complete sweep clears the flag.)

### Fixed
- **Exploits / exploitation surface was misleading — overhauled.** The
  Vulnerabilities "Proven exploit" column matched a searchsploit hit to a finding
  by **port alone**, so every finding on a port inherited that port's exploit — a
  weak-TLS finding claimed a Heartbleed exploit, "anonymous FTP login" claimed the
  vsftpd backdoor, unrelated Apache advisories all claimed the same path-traversal
  RCE. Now: (1) a searchsploit hit only links to a finding whose **CVEs actually
  match**, and is shown as a labelled **"candidate — verify"**, never as proof;
  (2) the column is renamed **"Exploit"** and only curated, named exploits
  (`proven_exploit_ref`) count as *proven* (and toward the Overview tile);
  (3) config/crypto-hardening findings (weak ciphers, old TLS, missing headers,
  anon login) never carry a proven exploit even if a CVE leaked into their output;
  (4) the **Exploits** sheet gains a **"Corroborates finding?"** column (which
  confirmed finding a candidate's CVEs line up with, else "product/version guess")
  and lists corroborated candidates first — leads to verify, not noise.
- **Truncated sweep no longer counts as fully scanned.** A host with a partial
  (host-timeout) port list is no longer auto-marked Enumerated/Vuln-scanned *done*
  in the Checklist/Overview coverage — it stays outstanding, matching the
  `⚠ PARTIAL` marker (the operator can still tick it).
- **`deploy`: a rejected Windows login is no longer folded as a successful run.**
  `run_winrm`/`run_smb` now require the on-target script's own banner in the output
  before declaring success (as the stager path already did), and the auth-failure
  markers are tightened — recognize nxc's bare `[-]` reject and impacket `STATUS_*`
  codes, and **stop** matching a benign "Proxy Authentication Required" as an auth
  failure (which had suppressed the push fallback). A stager bind failure no longer
  leaks the open datastore.
- **Port sweep missed open ports on rate-limiting / lossy networks.** The sweep
  pinned `nmap --min-rate 1500` (with `--max-retries` 1–2), which prevents nmap's
  congestion control from backing off; on a network that drops probes the SYNs to
  open ports were dropped and never retried, so hosts came back with "no open
  ports" even though a manual nmap (which slows down — "increasing send delay due
  to dropped probes") found them. recce now **detects the drop condition in
  nmap's output and automatically re-scans that host congestion-adaptively** (no
  `--min-rate` floor, `--max-retries 6`, `-T3`), which is what finds the ports.
  The adaptive re-scan stays bounded by the same `--host-timeout` as any host, so
  it returns partial results rather than running for hours (raise `--host-timeout`
  for more completeness, or set a gentle `--min-rate 200` floor to bound it more
  tightly). New `--reliable` flag forces adaptive mode from the first pass for
  networks you already know rate-limit (and avoids the double scan). Clean scans
  are unaffected (no second pass).
- **Browser detection missed installed browsers off PATH.** `doctor` (and the
  auto-screenshot feature) reported "browser not present" when Firefox/Chromium
  were installed but not on the PATH recce sees — common on Kali when scans run
  under `sudo` (which strips PATH to `secure_path`), for snap installs
  (`/snap/bin`), or `/opt` vendor layouts. `screenshot.browser_tool()` now falls
  back to scanning `/usr/bin`, `/usr/local/bin`, `/bin`, `/snap/bin`, `/opt/bin`
  and a shallow `/opt/*/…` glob when nothing is on PATH (the `RECCE_BROWSER`
  override still wins).
- **`doctor` LDAP check was a false negative.** It reported `ldapsearch` missing
  when only the `ldap3` Python package was installed, even though LDAP
  enumeration works fine via ldap3 (the runtime gate `ad.ldap_available()` accepts
  either). The check now mirrors that gate and is labelled `ldap` (shows which
  backend it found — `ldapsearch` or the `ldap3 package`).
- **`doctor` summary contradicted its own tool list.** The "Optional tools
  missing" line recomputed presence with a naive `which()`, so `browser`/`netexec`
  could show `OK` in the detailed list yet still be listed as missing in the
  summary. The summary now reuses the same detection the list prints, and
  `searchsploit` is checked via its runtime gate (`exploits.available()`) too.
  An audit confirmed the remaining checks (nmap, masscan, ssh, impacket,
  openpyxl) already match their runtime gates.

## [0.2.3] - 2026-07-22

### Changed
- **Enum hardened to be robust host-by-host.** A single host that crashes the
  worker, times out, returns hostile data (control chars, huge port counts), or
  fails to persist can no longer abort the run or corrupt the workbook. The
  per-host datastore write is now isolated in every scan phase (enum, vulns, db,
  privesc, credenum) the same way worker failures already were — a persist error
  on one host is recorded as an issue and the phase continues (`_persist_host`).
  Audited and fault-injection-tested end to end: good hosts persist, failures are
  logged, the workbook stays valid (atomic write + illegal-char scrubbing), and
  the final report always runs in `finally` (survives Ctrl-C and locked files).

## [0.2.2] - 2026-07-22

### Fixed
- **Overview phase table now honors operator overrides.** The per-subnet
  "Coverage by subnet" completion cells read only tool auto-progress, so an
  operator who un-ticked a step on the Checklist (e.g. to flag a redo) saw the
  Overview still count that host as done — the two tables could disagree. The
  phase counts now consult the same tracking overrides the Checklist does
  (`report_excel` Overview `phase()`).
- **Accounts differing only by RID no longer collide.** The datastore keeps
  accounts distinct by `(source, kind, name, domain, rid)`, but the workbook/
  coverage key omitted `rid`, so two such accounts collapsed to one Users &
  Accounts row and undercounted. `acct_key` now includes `rid` (appended only
  when present, so existing rid-less keys stay stable).
- **Product-only advisories reported on every affected port.** A product exposed
  on two ports (e.g. Confluence on 8090 and 8091) was deduped by title alone, so
  only the first port was flagged and the write-up's affected-port list was
  short. Dedup is now per `(title, port)` (`vulndb.assess_host`).

## [0.2.1] - 2026-07-22

### Fixed
- **False HIGH on patched MariaDB.** MariaDB 10.x announces itself with a legacy
  MySQL-compat handshake prefix (`5.5.5-10.11.6-MariaDB-…`); the version parser
  read the leading `5.5.5` and flagged a fully-patched MariaDB as end-of-life
  MySQL **and** fabricated a high-severity `CVE-2012-2122` finding. The version
  normalizer now strips the `5.5.5-` prefix, so the real version (10.11.6) is
  compared; genuine old MySQL 5.5.x is still flagged (`vulndb._clean_version`).
- **CVSS vector strings mis-scored.** A `CVSS:3.1/AV:N/…` vector was read as base
  score `3.1`, silently downgrading criticals to "low", and `CVSS Base Score: 7.5`
  wasn't matched at all. The score regex now skips the vector version and
  recognizes the "Base Score" / parenthetical phrasings (`parser._CVSS_RE`).
- **Vulnerability sheet row loss / coverage undercount.** The workbook & coverage
  key truncated the finding title to 40 chars while the datastore dedups on 60,
  so two store-distinct findings (e.g. same title differing only in the CVE id)
  collapsed to one Vulnerabilities row and the coverage total was short by one.
  The keys now use the same 60-char slice (`tracking.vuln_row_key`).

### Changed
- **Docs accuracy pass.** Dropped a non-existent `--subnet` flag from the README
  Speed section (use positional targets); corrected the credentialed-LDAP note to
  say it needs `ldapsearch` (ldap-utils) **or** `ldap3` (not `ldap3` only); added
  the `exploit-plan/` and `creds/` output dirs to the deliverables tables
  (README/QUICKSTART/CHEATSHEET); and fixed stale CLI `--help`/error strings that
  understated `import` (`-oN` is fully supported) and listed only 5 of 19 commands.

## [0.2.0] - 2026-07-22

### Added
- **Stylized tester docs.** `QUICKSTART.md` rewritten as a scannable field guide
  (workflow diagram, command cheat-sheet table, per-step sections, callouts), and
  a new self-contained **`CHEATSHEET.html`** — a printable one-page reference
  matching the report's teal theme (workflow, core commands, targeting, workbook
  legend, deliverables, troubleshooting). Ships in the burn package.
- **Burn-package builder (`make_package.sh`).** Produces a self-contained
  `dist/recce-<version>.tar.gz` (+ `.zip`) with `SHA256SUMS` — copy to a Kali box
  or burn to disk, `tar xzf` and run `./bin/recce doctor`. Runtime stays
  stdlib-only (no pip install). `pyproject` package-data now also ships the
  `scripts/` per-service suite (was only `local/*`).
- **Self-contained HTML report (`report.html`).** Every report run now also writes
  a single shareable `report.html` — inline CSS, **zero external assets**
  (airgapped-safe) — that a client can open in any browser: an executive summary +
  stat tiles, a severity rollup, the findings table, the synthesised attack path,
  and a per-host table (with AV/EDR). Print-friendly. Built from the same data as
  the workbook; stdlib-only.
- **`creds` command — credential stacking + spray planning.** Accumulates every
  credential recce has seen — auto-harvested from AD accounts with a recovered
  secret, default/blank service logins, and autologon/stored creds in ingested
  loot — together with any you captured by hand (`--add 'CORP\alice:Pw!'`, or
  `--user/--pass/--hash/--domain`; a 32-hex secret is auto-detected as an NT
  hash), deduped into one set (a **Credentials** workbook sheet). `--plan` writes
  `creds/users.txt|passwords.txt|nthashes.txt` and prints the exact **netexec /
  impacket** commands to validate and spray the set across the discovered
  SMB/WinRM/LDAP/MSSQL/RDP/SSH surface (pass-the-hash variants where the protocol
  supports it, paired lists to avoid a cartesian brute, and a lockout caution).
  Credentials persist in the datastore (new `credentials` table).
- **`attackpath` command + Attack Path sheet** — chains the **confirmed** findings
  into a prioritised, client-ready attack path: *foothold → privilege escalation →
  credential access → lateral movement → domain dominance*. Grounded entirely in
  what recce found (it reuses the exploitation actions and stages them); every
  step names the specific host and the existing tool, and a one-line narrative
  summarises the likely chain (e.g. *foothold via vsftpd backdoor on X → harvest
  creds → pivot to domain compromise on the DC*). It's the "so what" — how the
  individual findings combine into an attacker's route. Empty until findings are
  confirmed.
- **AV/EDR awareness (detection, not evasion)** — when you `ingest` a
  `recce-enum.ps1` run, recce now captures the host's **AV/EDR product + defensive
  posture** (Defender real-time/tamper state, EDR agents like CrowdStrike/
  SentinelOne, Sysmon logging, LSASS `RunAsPPL`, AppLocker, Credential Guard,
  PowerShell script-block logging) and surfaces it where you decide what to run:
  a new **AV / EDR** column on the Checklist, a **Defenses (host)** column on the
  Exploitation sheet (right next to the GodPotato/PrintSpoofer/msf action), a
  **Hosts with AV/EDR seen** total on the Overview, and a per-host banner in the
  `exploit-plan` scripts. Every surface carries the **legitimate** guidance —
  coordinate a scoped testing exclusion with the blue team (detection of your
  tooling is a finding *for the defender*) or validate in a lab. recce flags what
  is watching a host; **it does not evade AV/EDR**.
- **`exploitplan` command** — turns each **confirmed** finding into a ready-to-run
  artifact that drives an **existing, published** tool/module with the parameters
  recce discovered already filled in: a Metasploit resource (`.rc`) script per
  finding that maps to a module (EternalBlue, vsftpd backdoor, SambaCry, Ghostcat,
  …) with `RHOSTS`/`RPORT`/`PAYLOAD`/`LHOST` set; parameterized impacket/netexec/
  GTFOBins invocations (AS-REP roast, Kerberoast, ntlmrelayx, secretsdump, …) with
  the domain/DC/host filled in; and a per-host `exploit-plan.sh` chaining the
  remote steps plus a post-shell priv-esc reference section. It **selects and
  configures** published exploits against the specific targets — it authors no
  exploit code. Gated to confirmed findings (never "potential" version guesses).
  **Safe by default**: `.rc` launch lines are commented (a non-intrusive `check`
  runs); `--run` arms them, `--lhost/--lport` set the callback. The same actions
  are surfaced **in the workbook** (the *Exploitation* sheet now unifies remote
  exploits + remote tools + post-shell priv-esc) and **in the write-ups** (each
  finding that maps to a module gets a ready-to-run *Exploit with the published
  module* step).
- **`ingest` now also folds in `recce-service.sh` output** — point `ingest` at a
  saved per-service enumeration run and its `[!]` findings land on the
  Vulnerabilities sheet (source `service-enum`) against the right host:port,
  creating a host entry if needed. Observed findings are confirmed; advisory
  "test/verify X" lines are kept low-confidence (`potential`, off the findings
  report by default). Auto-detected — same command as recce-enum loot.
- **Services sheet: an *Enum command* column** — every open-port row now shows the
  exact `recce-service.sh` command to run for that service, so the next step is
  visible where you already track ports.
- **`services` command** — the bridge from recce's findings to the per-service
  suite. `recce services -o eng` prints the exact `recce-service.sh` command to
  run for **every open port** recce found, grouped by host (with roles and a
  one-shot `from-nmap` sweep line); `-a` appends the intrusive flag. Directly
  answers the field complaint "hard to know what command to type" — after `enum`,
  recce now tells you. Mirrors the dispatcher's port/name→script map (new
  `serviceenum` module), including the WinRM-on-5985 fix (nmap labels it `http`).
- **Single-finding write-up** — `recce writeup <selector>` generates one Word
  (.docx) report for a chosen finding, **pre-filled with what's already been
  looted or obtained** on the affected host(s): ingested on-target (recce-enum)
  findings and harvested accounts/credentials go into a new *Obtained Access /
  Looted Evidence* section. Select by F-id (`F-007` / `7`), CVE, IP, `IP:port`,
  or a word from the title; run with no selector to list every finding to pick
  from. Ambiguous selectors list the candidates. F-ids are stable and match the
  bulk write-ups and the combined report.
- **Per-service enumeration suite** (`recce/scripts/`) — Kali-side scripts that
  take a service recce/nmap/masscan found and run the *right* enumeration for it,
  flagging likely vulns and pointing at the existing tool that acts on each.
  Covers 25 services (ftp, ssh, telnet, smtp, dns, finger, http, pop/imap,
  rpc/nfs, msrpc, smb, kerberos, ldap, snmp, mssql, mysql, postgres, rdp, vnc,
  redis, winrm, mongodb, oracle, ajp, elasticsearch). Read-only / safe by
  default (banners, versions, anon/null checks, TLS, NSE `safe`, config
  disclosure); intrusive checks (brute, nikto, dir-bust, user-enum spraying) are
  gated behind `-a`. A `recce-service.sh from-nmap <scan.xml|.gnmap|.nmap>`
  driver sweeps an entire scan — one enumeration per open port — and reads all
  three nmap formats plus masscan/rustscan XML (point it at recce's own
  `raw/*.xml`). Missing tools self-skip; nothing generates exploit code.
- **`import` command** — build (or update) the workbook from **already-completed
  nmap scans** with no scanning. Accepts all three nmap formats — XML (`-oX`),
  grepable (`-oG`), and normal text (`-oN`) — plus nmap-compatible XML from tools
  like masscan; multiple files, directories, and globs at once (a `-oA` set is
  imported once, from the richest file). Folds hosts into the datastore, runs the
  same offline enrichment as `enum` (version→CVE/CWE, AD role/DC ID, SMB signing),
  ticks Enumerated (+ Vuln-scan where the scan ran NSE scripts), and preserves any
  existing ticks/notes. New `parser.parse_gnmap` / `parser.parse_normal` /
  `parser.parse_nmap_file`. Multiple scans across subnets/ranges/IPs **append and
  merge, never duplicate**.
- **Exploitation playbook** — a new **Exploitation** workbook sheet (and an
  *Escalate with existing tooling* step in each write-up) that maps every
  confirmed priv-esc finding to the exact **existing** public tool, the command
  with the finding's own values filled in, prerequisites, and a validation step.
  References vetted tooling (Metasploit, PowerUp, the Potato family, impacket,
  GTFOBins, gpp-decrypt, public PoCs) — it does not generate exploit code. Gated
  to confirmed findings. Expanded the curated proven-exploit + NSE→CVE references
  for Windows (MS08-067, EternalBlue set, SMBGhost, ZeroLogon, MS14-068, …).
- **Runbook** workbook tab — a step-by-step "what to type" for every phase and
  the options that matter, so the workbook is self-serve.
- **`vulns --fast`** — a top-signal detection tier (skips the broad
  `vuln and safe` net and deep enum) with a live per-host **progress % + ETA**,
  making a large `/24` tractable. Unifies with the sweep `--fast`.
- **`ingest <loot>`** — fold on-target `recce-enum.sh` / `recce-enum.ps1` `[!]`
  findings into a host's **Priv-Esc** rows. Parses text recce itself produced
  (no tools, no network), matches the host by name or `--host`, dedupes, and is
  idempotent. High-signal findings (writable `/etc/shadow`, docker socket,
  `SeImpersonate`, NOPASSWD sudo, …) are **promoted to first-class
  Vulnerabilities** so they count toward severity totals and get write-ups.
- **Dual-account credentialed enum** — a normal user does the enumeration; an
  optional privileged account (`--admin-user/--admin-pass/--admin-domain`) runs
  the admin-only power moves, each result labelled by the account that produced
  it. A **credentialed access matrix** on the Overview summarises reach.
- **On-target enum scripts** (`recce/local/recce-enum.sh`, `recce-enum.ps1`) —
  read-only, winPEAS/linPEAS-style deep sweeps with `-t`/`-SelfTest` pre-flight.
  Detection deepened well past the first cut: Linux now flags Dirty COW,
  OverlayFS / GameOver(lay), Looney Tunables, `sudo` CVE-2023-22809, non-standard
  SUID roots, per-binary NOPASSWD→GTFOBins mapping, cron wildcard injection,
  writable `ld.so.preload`, MySQL-as-root / unauth-Redis, and creds on process
  command lines; Windows adds HiveNightmare/SeriousSAM, PrintNightmare surface,
  SeManageVolume / SeCreateToken / SeTcb, and admin-token/UAC state — each with
  the exact discovered artifact. The closing **"how to exploit"** section is now
  a **tailored, per-finding runbook**: it prints only the vectors that actually
  fired on the host, substitutes in the specific file / binary / privilege
  found, and gives prereq → command → how-to-confirm → cleanup for each, pointing
  at existing public tools (GTFOBins, the Potato family, impacket, PwnKit/Dirty
  Pipe PoCs, gpp-decrypt, …) — it does not generate exploit code.
- **Louder failures** — per-phase error summaries, a per-host **auth
  success/fail table** (distinguishing rejected credentials `FAIL` from tool/
  connection errors `ERR`), and explicit missing-tool stops.
- **Packaging** — `pyproject.toml` provides a real `recce` console command and
  a version; still stdlib-only at runtime.
- **Real-nmap integration tests** — the pipeline is now validated against actual
  nmap on localhost (discover → full/enum/vuln incl. `--fast`), not only mocks.
- **Documentation** — a full **TROUBLESHOOTING.md** (symptom → cause → fix per
  phase), a consolidated command/option reference in the README, and an
  in-workbook troubleshooting section on the **Runbook** tab.

### Changed
- **Priv-Esc sheet now verdicts what's *actually* escalatable.** Ingest a
  `recce-enum.sh/.ps1` run and each `[!]` finding is classified with a new **Type**
  column: **Escalation path** (a confirmed on-target finding that maps to a real
  technique — the How-to shows the exact existing tool + command, verdicted with
  the same engine as the Exploitation sheet), **Finding** (an observation with no
  auto-mapped escalation — worth a look, not a confirmed path), or **Checklist**
  (the generic per-OS "what to run once you have a shell" reference). Rows sort
  escalation → finding → checklist and are colour-tinted, so the real paths sit on
  top and the generic checklist no longer reads as findings. Before any local enum
  a host shows only the **Checklist** (clearly labelled); after ingest the checklist
  is tagged "host already swept — see the findings above."
- **Write-ups now cover REAL findings by default.** `recce writeups` generates a
  document only for findings backed by an actual check/observation (an NSE script
  that reported VULNERABLE, a config/probe observation, or an ingested on-target
  finding); low-confidence, version-inferred **"potential"** guesses are skipped
  (and counted in a one-line note). Pass `--include-potential` to write them up
  too. The combined `findings_report.docx` follows the same default.
- **Ping-blocking networks no longer come back empty.** Discovery now auto-falls
  back to `-Pn` (scan every target as up) when **zero** hosts answer the sweep,
  and hints to use `-Pn` when some don't respond. Added a `-Pn` alias for
  `--no-discovery` (matches nmap). This was the #1 real-engagement pain point:
  firewalled / Windows / AD hosts block ping and were being skipped. Under `-Pn`
  the port sweep **fails fast on dead IPs** (`--max-retries 1`) while the per-host
  `--host-timeout` cap and `--min-rate` floor keep the run bounded and moving.
- **Friendlier first run.** Bare `recce` (no subcommand) prints a short quickstart
  instead of an argparse error; `enum`/`vulns` end with an explicit copy-paste
  `Next:` command.

- Deeper scanning by default: a curated `_VULN_DETECT` set (ms17-010, heartbleed,
  vsftpd backdoor, …) always layers into the vuln pass, since the bare
  `vuln and safe` category misses these.
- The `.xlsx` and `.docx` deliverables match the HTML-preview design language
  (teal accent, monospace machine data, zebra banding, collapsible host groups,
  navigation + per-host deep links). Reports are findings-only by default.
- Removed the interactive authorization prompt and the `--yes` flag.

### Fixed
- **Triaged findings now count toward coverage.** The Vulnerabilities sheet keyed
  each row as `vuln:<ip>:<port>:<script_id>:<title>` but coverage counting
  enumerated `vuln:<ip>:<port>:<script_id>` (no title), so the two keys never
  matched and ticking a finding's *Triaged* box was invisible to `compute_coverage`
  — the vulns %, the Overview rollup, and `status` stayed at 0% however many you
  triaged. The key is now defined once in `tracking.vuln_row_key(v)` and used by
  both the sheet writer and the counter.
- **OpenSSH `pN` patch level no longer dropped in version comparison.** The greedy
  `[a-z]*` in `vulndb._ver_tuple` swallowed the `p`, so `9.3p1` and `9.3p2`
  collapsed to the same tuple and the *OpenSSH 8.5–9.3 double-free (< 9.3p2)*
  signature never fired on `9.3p1` (a real false negative). Matching `pN` before
  the trailing letter fixes the ordering (`8.2p1 -> (8,2,1)`, `9.3p1 < 9.3p2`)
  while leaving OpenSSL-style suffixes (`1.0.2k`) unchanged.
- **Checkbox ticks on the Exploitation, Attack Path, and Credentials sheets now
  persist.** Their checkbox columns use the headers *Done* / *Worked*, which the
  workbook read-back didn't recognise (only *Reviewed*/*Checked*/*Triaged*), so an
  operator's ticks on those sheets were silently dropped on the next regenerate.
  Added *Done*/*Worked* to the recognised set, plus a regression test that asserts
  **every** checkbox column across all sheets round-trips.
- **`recce-enum.sh -o` now captures the COMPLETE run.** Previously only lines
  that passed through the emit helper reached the report file; raw command dumps
  (SUID/SGID lists, root processes, sockets, software inventory, interfaces, …)
  were printed to the terminal but omitted from `report.txt`. The whole run is
  now teed to the file, so the report matches the screen exactly. Also fixed the
  bounded secret-grep swallowing its own matches.
- credenum no longer reports a **missing tool** as an auth `FAIL`, and no longer
  runs `secretsdump` where the bind was rejected/errored.
- `ingest --host` records the loot hostname; incoming rows dedupe against each
  other on a brand-new host.
- Re-running a phase replaces its own scan-issue rows instead of appending
  duplicates (which inflated the Overview count).
- `distance` (network hops) is preserved through fold/merge and shown on the
  Checklist.
- Removed dead code and corrected stale return-type annotations.

## [0.1.0]

- Initial release: phased enumeration (discover → full port sweep → service
  enum → vuln scan), an offline version→CVE/CWE vulnerability database, Active
  Directory analysis, an Excel coverage-tracking workbook, per-finding Word
  write-ups, and searchsploit exploit mapping — all stdlib-only for airgapped
  Kali use.
