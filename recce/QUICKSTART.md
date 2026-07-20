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

# 2) Open the workbook and start working
#    eng/enumeration.xlsx  ->  read the "Start Here" tab, then use "Checklist"

# 3) Vuln-scan the open ports it found (safe by default)
#    Runs: NSE vuln+weak-config, the offline version->CVE/CWE engine,
#    stdlib HTTP-header + TLS probes, and searchsploit exploit mapping.
sudo ./bin/recce vulns -o eng

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

# 4b) Generate a Word (.docx) write-up per finding, then finish each in Word
./bin/recce      writeups -o eng           # auto-fills fields + web screenshots

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
`--no-probes` (skip the HTTP-header/TLS probes), `--no-searchsploit`.

Every finding on the **Vulnerabilities** tab carries a severity, source
(nse / version-db / probe / config), confidence, CVE refs and **CWE** refs, so
you can sort and report by weakness class.

## Using the workbook

- **Start Here** tab explains every tab.
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
