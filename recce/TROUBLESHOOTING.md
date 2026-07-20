# recce — Troubleshooting

Symptom → cause → fix, in the order a tester hits them. Run **`recce doctor`**
first on any new box: it prints exactly what's present/missing and proves the
pipeline with a real localhost self-scan. Almost every problem below is one
`doctor` line.

> Prefix commands with `python3 -m recce`, or use the bundled `./bin/recce`
> wrapper (it also fixes `sudo` PATH — see below). `-o DIR` is the engagement
> folder; keep it the same across every phase.

---

## 1. Install / first run

| Symptom | Cause | Fix |
|---|---|---|
| `recce: command not found` | not pip-installed | Use `python3 -m recce ...` or `./bin/recce ...`; or `pip install .` from the project dir to get the `recce` command. |
| `ModuleNotFoundError: No module named 'recce'` | run from the wrong dir / PATH lost under sudo | Use `./bin/recce` (sets PYTHONPATH), or run from the project root. |
| `SyntaxError` / f-string errors on start | Python < 3.9 | recce needs **Python 3.9+**. Check `python3 --version`. |
| Nothing to `pip install`? | intentional | recce is **stdlib-only** at runtime. There are no Python deps — only the *system* tools below. `requirements.txt` documents them. |

## 2. "nmap is required but was not found on PATH"

nmap is the **only hard requirement**. Install it (`apt install nmap`). Every
other tool is optional and its phase degrades cleanly with a logged note.

## 3. Not running as root / weak scan

`[!] Not running as root: falling back to TCP connect scan (-sT); OS detection
and SYN scan need root/CAP_NET_RAW.`

- Run with **`sudo`** for SYN scan, OS detection, and UDP.
- Under `sudo` the environment resets and can lose your PATH / the `recce`
  package. Use **`sudo ./bin/recce ...`** (the wrapper re-adds PYTHONPATH), or
  `sudo env "PATH=$PATH" python3 -m recce ...`.

## 4. Discovery finds no hosts / "No targets after expansion/exclusion"

- **Hosts are up but a firewall drops ping/discovery probes.** Re-run enum with
  **`--no-discovery`** (treats every target as up, `-Pn`). This is the #1 cause
  of "it found nothing" on hardened networks.
- **Targeting typo.** Valid forms: single `10.0.0.5`, list `10.0.0.5 10.0.0.9`,
  range `10.0.0.10-40`, CIDR `10.0.0.0/24`, or `@file` (one per line, `#`
  comments ok). `--exclude` carves hosts back out.
- **Everything excluded.** Check your `--exclude`.

## 5. Scans are too slow

For a time-boxed engagement, in rough order of impact:

- **`--fast`** — one network-wide **masscan** sweep instead of per-host nmap
  (needs `masscan`; falls back to nmap if absent). In `scan` it also selects the
  top-signal vuln tier.
- **`--workers N`** — scan N hosts at once (default 6). Biggest win for big scopes.
- **`vulns --fast`** — top-signal detection scripts only, with a live per-host
  **progress % + ETA**. Much quicker on a `/24`.
- **`--profile quick`** — top-200 ports, no deep enum, for a first pass.
- **`--top-ports N`** — cap the port sweep instead of full `-p-`.
- **`--host-timeout MIN`** — give up on a slow host after MIN minutes and move on.

## 6. A scan hangs

- Every external tool call has a timeout; a single host can't stall the run.
- Give a hard per-host ceiling with **`--host-timeout 10`** (minutes).
- Press **Ctrl-C** — it saves everything collected so far and writes the sheet,
  then re-run with **`--resume`** to skip finished hosts.

## 7. A scan crashed / was interrupted

- **Nothing is lost.** Every host is persisted the moment it finishes.
- Re-run the same command with **`--resume`** (skips hosts already in the
  datastore), or **`recce report -o DIR`** to rebuild the workbook from saved data.
- Saw `recce hit an unexpected error`? Your data is intact. Re-run with
  **`RECCE_DEBUG=1`** to get the full traceback for a bug report.

## 8. "No open ports match the vuln-scan filters"

- You ran **`vulns` before `enum`** — run `enum` first so there are open ports.
- **`--unscanned`** after everything is already scanned finds nothing (expected).
- **`--only http smb`** filtered everything out — widen or drop it.

## 9. vuln-scan finds nothing (but you expected findings)

- **Correct on a benign host** — recce does not invent findings.
- The offline version→CVE engine needs **accurate service versions**. Improve
  detection with **`--version-intensity 9`** or **`--version-all`** on `enum`.
- Go deeper with **`vulns --aggressive`** (full intrusive NSE `vuln` category —
  slower/noisier, and can crash fragile services).

## 10. Credentialed enum problems (`credenum`)

- `credenum needs credentials but none were given` → pass `-u USER -p PASS
  [-d DOMAIN]` for SMB/AD and/or `--ssh-user` for Linux.
- `No credentialed-enum tools found (netexec/impacket/ssh)` → install
  **netexec** (or crackmapexec) + **impacket**, or ensure **ssh** is on PATH.
- **Reading the auth summary table** (printed at the end of the phase):
  - `OK` / `OK (admin)` — authenticated (and holds local admin).
  - **`FAIL`** — the credential was **rejected**. Check username / password /
    **domain** for that row (domain mismatches are the usual culprit).
  - **`ERR`** — the attempt **errored** (host unreachable, timed out, or the tool
    failed). This is *not* a credential problem — check reachability.
  - **`-`** — not attempted (that tool wasn't present, or that account/port
    didn't apply). A missing tool is never shown as `FAIL`.
- Two accounts: a normal `-u/-p/-d` does the enumeration; add
  `--admin-user/--admin-pass[/--admin-domain]` to run the admin-only moves
  (confirm local admin, `secretsdump`). secretsdump only runs where that account
  actually authenticated.

## 11. LDAP enumeration fails / skips

- `no LDAP client found` → install **ldap-utils** (`ldapsearch`).
- `No Domain Controllers found` → point it at one with **`--dc-ip <IP>`**.
- Bad bind → check `-d/-u/-p`; try **`--ldap-anon`** for an anonymous bind, or
  **`--ldap-ssl`** for LDAPS (636).

## 12. searchsploit / exploit mapping missing

`searchsploit not found; skipping exploit mapping` → optional. Install with
`apt install exploitdb`, or pass **`--no-searchsploit`** to silence it.

## 13. Web screenshots not captured in write-ups

- Screenshots are auto-added only when a **headless browser** is present
  (firefox/firefox-esr or chromium/chrome). Install one, or point
  **`RECCE_BROWSER=/path/to/browser`** at it.
- Or pass **`writeups --no-screenshots`** and add them by hand in Word.

## 14. Workbook / reporting issues

- **Edits don't stick / "file is locked".** Close the workbook in Excel/
  LibreOffice **before** running another scan or `report` — an open file is
  locked and can't be rewritten. Your ticks/notes are read back on the next
  scan or `recce report`.
- **A corrupt or half-written workbook** is tolerated on read (your tracking
  just isn't imported that run); re-run `recce report -o DIR` to regenerate.
- **Reports only include findings.** `writeups` defaults to `--min-severity low`
  (excludes info). Use `--min-severity info` to include everything.
- **Regenerate anytime** without re-scanning: `recce report -o DIR` (preserves
  your ticks and notes). `recce status -o DIR` prints coverage without rebuilding.

## 15. `ingest` (on-target loot → Priv-Esc)

- `doesn't look like recce-enum.sh/.ps1 output` → it still parses `[!]` lines;
  this is just a note. Make sure you saved the script's `-o`/`-OutFile` output.
- Findings land under the wrong host? Pass **`--host <IP>`** to attach explicitly
  (otherwise it matches the loot's hostname, else makes a `local:<host>` entry).
- Re-ingesting the same loot is safe — findings de-duplicate (idempotent).

## 16. On-target scripts (`recce-enum.sh` / `.ps1`)

- Always run the pre-flight first: **`./recce-enum.sh -t`** /
  `powershell -ep bypass -File recce-enum.ps1 -SelfTest`. It parse-checks the
  script and reports what will run — no enumeration, safe first step.
- Windows: if the script won't run, use **`-ep bypass`** (execution policy).
- They are **read-only** — no exploit code, no obfuscation. If an EDR still
  false-positives, coordinate an allow-list; don't try to evade it.

## 17. "No space left on device"

Writable disk is a fixed allowance. Deletes still succeed while writes fail:
remove old engagement folders / `raw/` XML you no longer need and re-run. Freed
space is immediately writable.

---

## Reference

**Environment variables**
- `RECCE_DEBUG=1` — print full tracebacks instead of a one-line error.
- `RECCE_BROWSER=/path` — use this browser for screenshots (overrides PATH search).

**Exit codes**
- `0` success · `1` error (missing datastore, no targets, unexpected error) ·
  `2` bad arguments · `130` interrupted (Ctrl-C, partial results saved).

**Re-running is always safe.** Every phase is idempotent — re-running `enum`,
`vulns`, `credenum`, `ingest`, etc. never duplicates hosts, findings, accounts,
or issues. Run any phase as many times as you like.

**Still stuck?** `recce doctor` (capabilities + self-scan), `recce <cmd> -h`
(every option), and the **Runbook** tab inside the workbook (what to type per
phase) cover most questions.
