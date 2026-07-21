# Changelog

All notable changes to recce are documented here. Dates are UTC.

## [0.2.0]

### Added
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
