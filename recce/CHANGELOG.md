# Changelog

All notable changes to recce are documented here. Dates are UTC.

## [0.2.0]

### Added
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
