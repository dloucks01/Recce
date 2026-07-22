# recce — Quick Start

A simple, no-nonsense guide. (Full details are in `README.md`.)

## What it does

You point it at IPs or subnets. It scans them with `nmap` and fills in one
**Excel workbook** — a per-IP checklist plus tabs for services, vulnerabilities,
databases, Active Directory, and priv-esc. You **check things off** as you go,
and your ticks are saved (re-scanning never wipes them).

## Setup (once)

Nothing to install — it uses only Python 3.9+ and the tools already on Kali
(`nmap` required; `masscan`, `searchsploit`, `ldapsearch`, `netexec`, `impacket`,
and a headless browser — `firefox` or `chromium` — optional). It runs entirely
inside your **Kali VM**.

**Getting it into the Kali VM** (Windows 11 host → Kali guest):
- Best: `git clone` the repo *inside Kali* — that preserves LF line endings and
  the executable bit automatically.
- Or copy the folder in (shared folder / scp / USB). If it came through Windows
  and `./bin/recce` says *"bad interpreter"* or *"Permission denied"*, either run
  `python3 -m recce …` (identical, no wrapper needed) or `chmod +x bin/recce`.

```bash
cd recce
./bin/recce doctor          # first thing to run: confirms nmap + shows optional tools
```

> `./bin/recce` is just a shortcut for `python3 -m recce` — use whichever works.
> Run scans with `sudo` so nmap can do SYN/OS detection.
> Auto web-screenshots use a headless browser — **`firefox`** (the Kali default)
> or `chromium`, whichever is present. Point `RECCE_BROWSER` at a specific binary
> to override. Without any browser you just paste screenshots into the Word
> write-ups yourself, which is the normal flow.

## The 5-step engagement

```bash
# 1) Fast enumeration -> fills the sheet (hosts, ports, services)
sudo ./bin/recce enum 10.0.10.0/24 10.0.20.0/24 -o eng --title "Client X"
#    Hosts blocking ping (firewalled / Windows / AD)? add -Pn to scan all as up:
#    sudo ./bin/recce enum 10.0.10.0/24 -Pn -o eng
#    ...or, if you ALREADY have an nmap scan, skip enum and import it:
#    ./bin/recce import scan.xml -o eng      # -oX XML (best), -oG .gnmap, dir, or glob

# 2) Open the workbook and start working
#    eng/enumeration.xlsx  ->  read the "Start Here" tab, then use "Checklist"

# 3) Vuln-scan the open ports it found (safe by default)
#    Runs: NSE vuln+weak-config, the offline version->CVE/CWE engine,
#    stdlib HTTP-header + TLS probes, and searchsploit exploit mapping.
sudo ./bin/recce vulns -o eng

# 3b) Deep per-service enumeration (SMB shares, HTTP paths/TLS, SNMP walk,
#     anon FTP/LDAP, Redis unauth, ...). Runs the RIGHT tool per open port and
#     flags likely vulns. Safe by default; -a adds brute/nikto/dir-busting.
#     Not sure what to run? recce prints the exact command for every open port:
./bin/recce      services -o eng                         # per-port enum commands
#     Then run one, or sweep the whole engagement from recce's own nmap output:
./scripts/recce-service.sh from-nmap eng/raw/*.xml       # or: smb 10.0.10.5

# 4) Optional deeper phases (any time, on any subset)
sudo ./bin/recce db -o eng                 # databases
./bin/recce      privesc -o eng            # priv-esc playbook
# ...and once you have creds (needs netexec/impacket/ssh on Kali):
./bin/recce      credenum -u alice -p 'Pw!' -d corp.local -o eng  # authed SMB/AD/SSH
#   Have a user AND a privileged account? Pass both - the user account does the
#   enumeration, the privileged one runs the admin-only checks (confirm local
#   admin, secretsdump), and the report labels what each account reached:
./bin/recce      credenum -u alice -p 'Pw!' -d corp.local \
                 --admin-user admin --admin-pass 'AdmPw!' -o eng

# 4b) On-target enum: got a shell on a box? Run the bundled read-only sweep
#     (recce/local/), bring the output back, and fold its [!] findings into the
#     Priv-Esc tab for that host. The sweep ends with a "How to exploit" runbook
#     tailored to THAT host's findings (prereq -> command -> confirm -> cleanup,
#     using existing public tools):
#       target$  ./recce-enum.sh -o loot.txt          # Linux  (-t self-tests first)
#       target>  powershell -ep bypass -File recce-enum.ps1 -OutFile loot.txt  # Windows
./bin/recce      ingest loot.txt -o eng    # matches the host by name (or --host IP)

# 4b2) Turn confirmed findings into ready-to-run exploitation artifacts:
#      Metasploit .rc scripts (params pre-filled) + parameterized impacket/GTFOBins
#      commands + a per-host plan. Drives EXISTING tools; safe by default (check-only).
./bin/recce      exploitplan -o eng --lhost 10.10.14.7   # add --run to arm msf launch

# 4c) Generate Word (.docx) write-ups, then finish each in Word
./bin/recce      writeups -o eng           # one per REAL finding (+ combined report)
#    --include-potential also writes up low-confidence version-inferred guesses.
#    Just want ONE finding, pre-filled with what you've already looted/obtained?
./bin/recce      writeup -o eng            # list findings to pick from
./bin/recce      writeup F-007 -o eng      # or by CVE / IP / a word from the title

# 5) See what's left (prints progress + the suggested next command)
./bin/recce status -o eng
```

That's it. Repeat steps 3–5 until `status` says everything's done.

## Targeting (every phase accepts these)

| You want to scan… | Type |
|---|---|
| one host | `10.0.10.5` |
| several hosts | `10.0.10.5 10.0.10.9` |
| a range | `10.0.10.10-40` |
| a whole subnet | `10.0.10.0/24` |
| a list in a file | `@scope.txt` |

`enum`/`scan` take targets as the scope to scan. `vulns`/`db`/`privesc` take
targets to work on **just that subset** of what's already been enumerated —
e.g. `sudo ./bin/recce vulns 10.0.20.0/24 -o eng`.

Handy filters on `vulns`: `--only http smb` (just those services),
`--unscanned` (only ports not yet done), `--aggressive` (intrusive checks),
`--fast` (top-signal detection scripts only — much quicker on a big /24, and
shows a live per-host **progress % + ETA**), `--no-probes` (skip the
HTTP-header/TLS probes), `--no-searchsploit`.

Every finding on the **Vulnerabilities** tab carries a severity, source
(nse / version-db / probe / config), confidence, CVE refs and **CWE** refs, so
you can sort and report by weakness class.

## Using the workbook

- **Start Here** tab explains every tab; the **Runbook** tab is a step-by-step
  "what to type" for each phase and its options — start there if you just want
  the commands.
- **Checklist** tab = one row per IP, **grouped by subnet**, with two kinds of
  step box:
  - **Auto** (Enumerated / Vuln-scan / Web / DB) **turn green automatically** when
    the tool finishes that step.
  - **Manual sign-offs** (AD / Access / Priv-esc / Creds / Lateral) start
    unchecked — you tick them as you work. AD = you reviewed the DC's users/
    shares/roasting; then the kill-chain: **Access** gained → **Priv-esc** →
    **Creds** harvested → **Lateral** movement tried.
  Tick **Reviewed** when you're personally done with a host.
- **Boxes only show where the step applies.** A step that's irrelevant shows
  **`—`** — no Web box without a web server, no AD box off a non-DC, no DB box
  without a database. So a checked box always means real work.
- **SMB, remote access (SSH/RDP/WinRM), mail, SNMP, …** aren't checklist columns —
  each such port is tracked with its own Status on the **Services** tab (below),
  which keeps the checklist readable while still covering every service.
- **Services** tab = one row per **open port**, grouped by IP, each with its own
  **Status** dropdown — **☐ Not started / ◐ In progress / ☑ Done** — plus a Notes
  cell. Done rows go green, in-progress amber. This is where you track exactly
  which ports you've looked at, are working, or haven't touched yet.
- **Overview** tab = every subnet in scope (even ones with no live hosts), showing
  addresses in range, live hosts found, and per-surface completion — so no subnet
  (or surface) gets missed.
- **Filter a step column to `☐`** (or filter by Subnet) to see what's left; `—`
  cells are ignored, so you never chase a phase that doesn't apply.
- After editing in Excel, **save**, then run `./bin/recce report -o eng` (or
  any scan) to fold your edits back in. Close the file before a scan rewrites it.

## If a scan is slow or crashes

Nothing is lost — every host is saved the moment it finishes. Press **Ctrl-C** to
stop cleanly (it still writes the sheet), use **`--resume`** to skip hosts already
done, and run **`report -o eng`** any time to rebuild the workbook from saved data.
On a large scope, `vulns --fast` finishes far quicker (top-signal checks only) and
prints a live **progress % + ETA**; each phase ends with a loud summary of any
hosts that errored so a failure can't scroll past unseen.

## Troubleshooting (the quick hits)

Run **`recce doctor`** first — it reports what's missing and self-tests the whole
pipeline on this box. The usual snags:

| Symptom | Fix |
|---|---|
| `nmap ... not found` | Install nmap — the only hard requirement. |
| "Not running as root" / weak scan | Run with `sudo`; use `sudo ./bin/recce ...` so PATH survives sudo. |
| Hosts show zero ports / few live | They block ping — add **`-Pn`** to `enum`/`scan` (scan all as up). recce also auto-falls-back to `-Pn` if discovery gets zero responses. |
| Too slow | `--fast`, `--workers N`, `vulns --fast`, `--profile quick`, `--host-timeout`. |
| Crashed / interrupted | Re-run with `--resume`, or `report -o eng`. `RECCE_DEBUG=1` for the traceback. |
| "No open ports match" on `vulns` | Run `enum` first; `--unscanned` finds nothing once all is scanned. |
| No findings (but expected some) | Improve service ID (`--version-all`) then `vulns --aggressive`. |
| credenum: `No ... tools found` | Install netexec + impacket (or ssh). |
| Auth table shows `FAIL`/`ERR` | `FAIL` = creds rejected (check user/pass/**domain**); `ERR` = unreachable/tool error. |
| Workbook won't update | Close it in Excel first — an open file is locked. |

**Re-running any phase is safe** — every phase is idempotent (never duplicates
rows). Full guide: **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)**.
