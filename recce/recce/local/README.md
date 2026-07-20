# recce/local — on-target enumeration scripts

The on-host companions to recce. recce scans and reports from the network side;
these run **on a host you have a shell on** to surface local privilege-escalation
vectors and sensitive exposure — a linPEAS / winPEAS–style deep sweep.

| Script | Target | Run it |
|---|---|---|
| `recce-enum.sh` | Linux / Unix | `./recce-enum.sh [-q] [-o report.txt]` |
| `recce-enum.ps1` | Windows | `powershell -ep bypass -File .\recce-enum.ps1 [-Quiet] [-OutFile report.txt]` |

- `-q` / `-Quiet` — print findings only (skip the raw dumps).
- `-o` / `-OutFile` — also write everything to a file.

Lines marked **`[!]`** are worth a closer look.

## What they check (deep dive)

**Linux:** kernel + LPE hints (PwnKit CVE-2021-4034, Dirty Pipe CVE-2022-0847,
old-kernel LES), sudo (`-l`, Baron Samedit, `LD_PRELOAD`), SUID/SGID vs GTFOBins,
file capabilities, cron/timers (+ writable scripts), services & root processes
running writable binaries, writable PATH dirs, `/etc/passwd|shadow|sudoers`
state, container escape (docker/lxd group, `docker.sock`, in-container caps),
NFS `no_root_squash`, credential hunting (SSH keys, history, `.env`/app configs,
cloud creds, Kerberos ccache/keytab, GPG), root-process `/proc/*/environ` leaks,
web-app config files, writable shared-library dirs, network, installed software.

**Windows:** OS/build + hotfixes (for WES-NG), token privileges → **Potato**
recommendations (SeImpersonate → GodPotato/PrintSpoofer/EfsPotato/JuicyPotatoNG),
SeBackup/Restore/TakeOwnership/LoadDriver/Debug, users/groups/password policy,
services (unquoted paths, writable binaries/keys), scheduled tasks,
AlwaysInstallElevated, autoruns & startup, credential hunting (cmdkey, autologon,
unattend/sysprep, SAM/SYSTEM backups, PowerShell history, WiFi keys, IIS
web.config, registry password search), hardening state (UAC, WDigest, LSA PPL,
Credential/Device Guard, Defender, AppLocker, language mode), writable
PATH/Program Files dirs (DLL hijack), installed software, network, SYSTEM
processes, environment.

## Safety & AV

They are **read-only** — they only *read* system state with built-in tools and
change nothing. There is no exploit code, no download, no obfuscation, and no
AMSI/Defender tampering. That transparency is precisely why a plain `Get-*` /
built-in-command script does not match malware signatures. If an EDR still
false-positives during an **authorized** engagement, coordinate an allow-list /
exclusion with the client — do not try to evade it. Use only where you have
written authorization to test.
