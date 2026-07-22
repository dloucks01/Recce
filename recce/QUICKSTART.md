# recce — Quick Start

> **Airgapped pentest enumeration → one Excel workbook you check off as you go.**
> Point it at IPs/subnets, it scans with `nmap` and fills the sheet. Your ticks
> are saved — re-scanning never wipes them.

📄 Prefer a printable one-pager? Open **[`CHEATSHEET.html`](CHEATSHEET.html)** in a browser.
📚 Full reference: **[`README.md`](README.md)** · 🧰 Deep troubleshooting: **[`TROUBLESHOOTING.md`](TROUBLESHOOTING.md)**

---

## 1 · Get it running

Nothing to install — Python 3.9+ and the tools already on Kali. Only **`nmap`** is
required; everything else is optional and degrades cleanly.

```bash
cd recce
./bin/recce doctor          # run this first: confirms nmap + shows optional tools
```

> [!TIP]
> `./bin/recce` is just a shortcut for `python3 -m recce` — use whichever works.
> Run scans with **`sudo`** so nmap can do SYN/OS detection.

> [!NOTE]
> **Getting it onto Kali** (Windows host → Kali guest): best is `git clone` *inside
> Kali* (preserves LF endings + the executable bit). If you copied it through
> Windows and see *"bad interpreter"* / *"Permission denied"*, run
> `python3 -m recce …` (identical) or `chmod +x bin/recce`.

---

## 2 · The engagement at a glance

```
 enum ─▶ vulns ─▶ services ─▶ (foothold) ─▶ ingest / creds ─▶ writeups
 scan     deep      per-port     exploitplan    attackpath        report
 hosts    NSE+CVE   enum cmds    runnable .rc   the "so what"     deliverables
```

| Phase | Command | What it does |
|---|---|---|
| **Enumerate** | `sudo ./bin/recce enum <targets> -o eng` | discover hosts/ports/services → fills the sheet |
| _(have a scan?)_ | `./bin/recce import scan.xml -o eng` | build the sheet from existing nmap output |
| **Vuln-scan** | `sudo ./bin/recce vulns -o eng` | NSE + offline CVE/CWE engine + TLS/HTTP probes |
| **Per-service** | `./bin/recce services -o eng` | prints the exact enum command for each open port |
| **Databases** | `sudo ./bin/recce db -o eng` | database services |
| **Priv-esc** | `./bin/recce privesc -o eng` | per-host escalation playbook |
| **Credentialed** | `./bin/recce credenum -u U -p P -d dom -o eng` | authed SMB/AD/SSH enum |
| **On-target loot** | `./bin/recce ingest loot.txt -o eng` | fold `recce-enum.sh/.ps1` findings in |
| **Mass local-enum** | `./bin/recce deploy -u U -p P -o eng` | run the local-enum + priv-esc scan on every host you have creds for (SSH/WinRM/SMB) |
| **Exploit plan** | `./bin/recce exploitplan -o eng --lhost <ip>` | runnable msf `.rc` + tool commands |
| **Attack path** | `./bin/recce attackpath -o eng` | chains findings → domain compromise |
| **Credentials** | `./bin/recce creds --add 'dom\u:p' -o eng` | stack creds → spray plan (`--plan`) |
| **Write-ups** | `./bin/recce writeups -o eng` | one Word doc per real finding |
| **Status** | `./bin/recce status -o eng` | what's left + the next command |

> [!IMPORTANT]
> **Keep `-o eng` the same across every command** — it's the one engagement folder
> they all read, update, and write. Different `-o` = a separate engagement.

---

## 3 · Step by step

### ① Enumerate
```bash
sudo ./bin/recce enum 10.0.10.0/24 10.0.20.0/24 -o eng --title "Client X"
```
> [!WARNING]
> **Hosts showing zero ports?** They block ping (firewalled / Windows / AD). Add
> **`-Pn`** to scan every target as up: `sudo ./bin/recce enum 10.0.10.0/24 -Pn -o eng`.
> recce also auto-falls-back to `-Pn` when discovery gets zero responses.
>
> Still zero ports under `-Pn` but a manual `nmap` finds them (and prints
> *"increasing send delay … dropped probes"*)? The network is **rate-limiting**.
> recce auto-detects that and re-scans adaptively; add **`--reliable`** to force it
> from the start.

Already have an nmap scan? Skip enum and **import** it (XML best; `.gnmap`, a dir, or a glob):
```bash
./bin/recce import scan.xml -o eng
```

### ② Open the workbook
`eng/enumeration.xlsx` → read the **Start Here** tab, then work out of **Checklist**.

### ③ Vuln-scan (safe by default)
```bash
sudo ./bin/recce vulns -o eng
```
Runs NSE vuln+weak-config, the offline version→CVE/CWE engine, stdlib HTTP-header +
TLS probes, and searchsploit mapping.

> [!TIP]
> Filters: `--only http smb` · `--unscanned` · `--aggressive` · `--fast` (top-signal
> only, shows a live **% + ETA** on a big /24) · `--no-probes` · `--no-searchsploit`.

### ④ Deep per-service enumeration
```bash
./bin/recce services -o eng                        # the exact command per open port
./scripts/recce-service.sh from-nmap eng/raw/*.xml # or sweep the whole scan; smb 10.0.10.5
```
Runs the **right** tool per service (SMB shares, HTTP paths/TLS, SNMP walk, anon
FTP/LDAP, unauth Redis…). Safe by default; **`-a`** adds brute/nikto/dir-busting.

### ⑤ Post-exploitation
```bash
# Got a shell? Run the bundled read-only sweep, bring the output back, fold it in:
#   target$  ./recce-enum.sh -o loot.txt                                   # Linux (-t self-test)
#   target>  powershell -ep bypass -File recce-enum.ps1 -OutFile loot.txt  # Windows
./bin/recce ingest loot.txt -o eng          # or ingest recce-service.sh output too

# ...or have creds? Run the local-enum + priv-esc scan on EVERY reachable host at once:
./bin/recce deploy --ssh-user root --ssh-key id_rsa -o eng           # all Linux via SSH
./bin/recce deploy -u admin -p 'Pw!' -d corp.local -o eng            # all Windows via WinRM/SMB
#   picks SSH / WinRM / SMB per host, runs the script, folds results in. --dry-run to preview.

./bin/recce exploitplan -o eng --lhost 10.10.14.7   # runnable msf .rc (--run to arm)
./bin/recce attackpath  -o eng                       # foothold → priv-esc → … → domain
./bin/recce creds --add 'CORP\alice:Pw!' -o eng      # then: creds --plan  (spray plan)
```

> [!NOTE]
> **Credentialed enum** with a normal + privileged account — the user account
> enumerates, the admin one runs admin-only checks; the report labels what each reached:
> ```bash
> ./bin/recce credenum -u alice -p 'Pw!' -d corp.local \
>              --admin-user admin --admin-pass 'AdmPw!' -o eng
> ```

### ⑥ Report & track
```bash
./bin/recce writeups -o eng     # Word write-up per REAL finding (--include-potential for guesses)
./bin/recce writeup  F-007 -o eng   # or ONE finding, pre-filled with what you've looted
./bin/recce status   -o eng     # progress + suggested next command
```

Repeat ③–⑥ until `status` says everything's done.

---

## 4 · 🎯 Targeting (every phase accepts these)

| Scan… | Type |
|---|---|
| one host | `10.0.10.5` |
| several | `10.0.10.5 10.0.10.9` |
| a range | `10.0.10.10-40` |
| a subnet | `10.0.10.0/24` |
| a file list | `@scope.txt` |

`enum`/`scan` take the **scope to scan**. `vulns`/`db`/`privesc` take targets to
work on **just that subset** of what's already enumerated — e.g.
`sudo ./bin/recce vulns 10.0.20.0/24 -o eng`.

---

## 5 · 📗 Using the workbook

- **Start Here** explains every tab; **Runbook** is a "what to type" for each phase.
- **Checklist** — one row per IP, grouped by subnet, with two kinds of box:
  - 🟩 **Auto** (Enumerated / Vuln-scan / Web / DB) turn green when the tool finishes.
  - ✍️ **Manual sign-offs** (AD / Access / Priv-esc / Creds / Lateral) you tick as
    you work the kill-chain. Tick **Reviewed** when you're done with a host.
- **`—` means the step doesn't apply** (no Web box off a non-web host), so a checked
  box always means real work.
- **Services** — one row per open port with its own **☐ / ◐ / ☑** status + notes.
- **Overview** — every subnet in scope with live-host + per-surface completion.

> [!TIP]
> Filter a step column to **`☐`** (or filter by Subnet) to see what's left. After
> editing in Excel, **save + close**, then `./bin/recce report -o eng` folds your
> edits back in.

---

## 6 · 📦 Deliverables (written into `eng/`)

| File | What it is |
|---|---|
| **`enumeration.xlsx`** | the tracking workbook you work out of |
| **`report.html`** | self-contained client-ready page (exec summary, severity, findings, attack path) |
| `enumeration.md` / `services.csv` | notes-friendly + flat pivot data |
| `writeups/*.docx` | per-finding Word write-ups + a combined report (after `writeups`) |
| `exploit-plan/*` | runnable msf `.rc` + per-host plans (after `exploitplan`) |
| `creds/*.txt` | `users` / `passwords` / `nthashes` lists for spraying (after `creds --plan`) |

---

## 7 · 🧰 Troubleshooting (quick hits)

Run **`recce doctor`** first — it self-tests the whole pipeline on this box.

| Symptom | Fix |
|---|---|
| `nmap … not found` | Install nmap — the only hard requirement. |
| weak scan / "not root" | Run with `sudo` (`sudo ./bin/recce …` so PATH survives). |
| **zero ports / few live** | They block ping — add **`-Pn`**. |
| zero ports but manual nmap finds them | Network rate-limiting — add **`--reliable`** (recce also auto-detects dropped probes). |
| too slow | `--fast`, `--workers N`, `--profile quick`, `--host-timeout`. |
| crashed / interrupted | Re-run with `--resume`, or `report -o eng`. `RECCE_DEBUG=1` for the traceback. |
| "No open ports match" | Run `enum` first; `--unscanned` is empty once all is scanned. |
| no findings (expected some) | `--version-all` then `vulns --aggressive`. |
| `credenum: No … tools` | Install netexec + impacket (or ssh). |
| auth `FAIL` / `ERR` | `FAIL` = creds rejected (check **domain**); `ERR` = unreachable/tool error. |
| workbook won't update | Close it in Excel first — an open file is locked. |

> [!NOTE]
> **Re-running any phase is safe** — every phase is idempotent (never duplicates rows).
