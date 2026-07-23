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

### Changed
- **PoCs are stronger, unambiguous proofs with an explicit ROE hand-off.** Each
  generated PoC now states a clear **`PROVEN:`** verdict and marks the single
  **`ACTION (ROE)`** line where the operator substitutes their authorized action:
  the **JWT** PoC forges the `alg:none` token *and replays it*, printing
  accepted-vs-denied so a CONFIRMED is unarguable; **SSTI** declares PROVEN on the
  `7*7→49` evaluation and fingerprints the engine; **PUT** shows the stored file
  then removes it; **git/heapdump/GraphQL/downloads** print a PROVEN line with a
  count of what was recovered. (The word "benign" was dropped from the wording;
  the "no AV/EDR evasion" boundary stays.)

### Added
- **Per-web-finding PoC generation.** `exploitplan` now writes a tailored, benign,
  runnable proof for *each* web finding into `exploit-plan/poc/`, with the target
  URL filled in: a **`git-dumper` script** for exposed `.git`, an **HTML page** that
  proves the CORS cross-origin credentialed read, a pure-python **`alg:none` JWT
  forge**, an **SSTI engine-identification script** (then `tplmap` for RCE in ROE),
  a **GraphQL schema dump**, an **actuator heapdump → secrets grep**, a **PUT
  write-primitive** proof, a **JS-secret extractor**, and a read-only fetch for
  exposed `.env`/`.aws`/`.htpasswd`/backups/`server-status`/`metrics`/`phpinfo`.
  Each is a benign proof (marker file / schema dump / redacted read); RCE
  escalations reference the published tool to run within ROE. The generated Python
  and shell are validated (compile / `sh -n`) by tests. Nothing obfuscated or
  AV-evasive.
- **`recce web` — web-facing services get their own category + deep scanning.**
  Every HTTP/HTTPS endpoint recce found (on ANY port, not just 80/443) is
  identified, categorized on a new **Web** workbook tab with its tech stack and
  the exact Kali deep-scan commands (whatweb / nikto / nuclei / gobuster / wpscan /
  sslscan, tailored to the detected stack). `recce web` then runs a stdlib,
  non-intrusive deep scan of each endpoint:
  - **tech fingerprint** (Server / X-Powered-By, framework cookies, CMS body
    signatures, `<title>`, meta generator),
  - **high-signal exposures** — `.git`/`.env`/`.svn`, Apache `server-status`,
    Spring **actuator** (+`/env`), `phpinfo`, readable `web.config`, Swagger,
    Tomcat Manager, WordPress — flagged **only when the response actually matches
    the signature** (the probe fetches it, so it's a real observation),
  - **directory listing**, **dangerous HTTP methods** (PUT/DELETE/TRACE via
    OPTIONS), **weak cookie flags** (HttpOnly/Secure), plus the existing
    security-header + TLS analysis.
  Findings fold into Vulnerabilities and flow through the **same prove + PoC**
  machinery: `recce prove` renders web verdicts (an exposed `.git` the probe
  fetched is CONFIRMED; a PUT advertised in OPTIONS is LIKELY with the curl to
  finish proving), and `exploitplan` writes a benign `recce_poc_web.sh` (curl-based
  proof requests). Airgapped-safe, stdlib only; heavier scanning is bridged to the
  Kali tools. `--no-active` keeps it to passive fingerprint + headers/TLS.
  - **Web scanning now runs automatically in the `vulns` phase** (the deep web
    enum replaced the old headers/TLS-only probe), so `.git`/`.env`/actuator/method
    exposures are found without a separate step; `recce web` re-runs or deep-dives.
    Non-HTTP TLS ports (LDAPS/IMAPS) skip the HTTP path probes but keep TLS checks.
  - **Authenticated web scanning**: `recce web --cookie 'session=…'` and repeatable
    `--header 'Authorization: Bearer …'` run the whole scan as a logged-in user.
  - **Authenticated crawling** (`recce web --crawl`): a same-origin BFS crawler
    (as the logged-in user) discovers pages, forms and params, tests each
    **discovered param** for reflection/SSTI (so the `7*7→49` proof lands on real
    parameters), and flags **password forms over cleartext HTTP** and **POST login
    forms without an anti-CSRF token**. Bounded (≤40 pages, depth 2), stdlib-only.
  - **Per-endpoint screenshots**: `recce web --screenshots` captures each endpoint
    with the headless browser into `engagement/screenshots/`.
  - **Web is now a coverage category.** Every HTTP/HTTPS endpoint counts toward a
    new **Web** line on the Overview / `status` coverage roll-up (ticked per
    endpoint from the Web tab's Status column), so Start-Here progress reflects the
    web surface, not just ports/vulns.
  - **More high-value exposures**: exposed **`.DS_Store`**, permissive
    **`crossdomain.xml`** (wildcard), **Prometheus `/metrics`**, **`.htpasswd`**
    (password hashes), Apache **`/server-info`**, exposed **`.aws/credentials`**,
    **WordPress REST user enumeration**, **GraphQL introspection** (POST probe),
    and **CORS that reflects an arbitrary Origin with credentials** — each flagged
    only on a positive signal and wired into prove + PoC.
  - **Deepened further:**
    - **Full Spring Boot Actuator dive** (self-gated on `/actuator`): `/env`,
      `/configprops`, **downloadable `/heapdump`** (full memory → secrets),
      `/mappings`, `/threaddump`, and **`/gateway/routes`** (Spring Cloud Gateway
      SpEL RCE surface, CVE-2022-22947).
    - **Secret extraction, redacted** — exposed `.env` / `.aws/credentials` /
      `.htpasswd` / actuator `/env` / `/configprops` now show *which* secrets
      leaked as `key=ab…yz` (never the raw value).
    - **Backup / source-file exposure** — `backup.sql`, `db.sql`, `*.zip`,
      `.env.bak`, `wp-config.php.bak`, … confirmed by content signature (SQL dump /
      zip magic / PHP / leaked secrets).
    - **`.git/config`** (remote URL, sometimes embedded creds), in addition to
      `.git/HEAD`.
    - **Product+version fingerprinting** (Jenkins/Confluence/GitLab/WordPress/…)
      enriches the port's product when nmap missed it — and the web scan now runs
      **before** the CVE mapping in `vulns`, so those recovered versions get
      matched to known CVEs.
    - **Opt-in default-credential probe** (`recce web --creds`): a tiny documented
      list against HTTP Basic-auth endpoints, capped at ≤5 tries/endpoint
      (lockout-aware).
    - **JWT weaknesses** — JWTs seen in cookies/headers/body are decoded and
      flagged: **`alg:none`** (forgeable, high), HS* (offline-crackable secret),
      RS*/ES* (algorithm-confusion). Free (reads the root response), so it runs even
      passively.
    - **SSTI / reflected-input quick check** — injects `{{7*7}}` / `${7*7}` /
      `<%=7*7%>` into a throwaway param; **`49` evaluating next to the canary is a
      strong, low-false-positive SSTI hit** (CONFIRMED in `prove`), and an
      unencoded `<i>` reflection is flagged as a reflected-XSS lead. One request,
      non-destructive.
    - **Client-side JS secret scraping** — same-origin `<script src>` files are
      fetched (bounded) and scanned for Google/AWS/Stripe/GitHub/Slack keys,
      private-key blocks and hardcoded `apiKey`s.
    - **WordPress plugin/version enum (wpscan-lite)** — core version (generator /
      `readme.html`), XML-RPC status, and a common-plugin sweep with each plugin's
      version from its `readme.txt` Stable tag.
- **`ad` — SharpHound + Certipy (ADCS) import: AD vulns, ESC findings, and paths to
  Domain Admin.** One simple command, credentials-first:
  `recce ad loot.zip certipy.json -u alice -p 'Passw0rd!' -d corp.local -o eng`.
  Pass a SharpHound collection (`.zip` / directory / single `.json`) and/or a
  `certipy find -json` file - any mix; each input is auto-detected. recce parses
  the AD object graph offline (stdlib `json`/`zipfile`, no BloodHound/neo4j needed)
  and turns it into a provable runbook. (`bloodhound` is kept as an alias.)
  - **Credentials-first & copy-paste ready.** Give recce your account with
    `-u/-p/-d` (no NT hash needed) and it (a) starts the attack-path search **from
    your account** by default and (b) **pre-fills every generated command** with
    your username / password / domain / DC IP, so each line in the sheet runs as-is.
  - **ADCS / ESC findings (Certipy).** Every ESC Certipy flags (ESC1-ESC11, ESC13,
    ESC15/EKUwu) becomes a finding with the exact `certipy` command to prove/abuse
    it, the real template/CA name filled in, and *who* can enrol - e.g. ESC1 ->
    `certipy req … -template VulnUser -upn administrator@corp.local && certipy auth
    -pfx administrator.pfx`, ESC8 -> `certipy relay` + coercion.
  - **AD Findings sheet** — every misconfiguration / vulnerability the graph
    reveals, most-severe first, each with the **exact EXISTING-tool command to
    prove or abuse it**: Kerberoastable & AS-REP-roastable accounts (with the
    `GetUserSPNs`/`GetNPUsers` + hashcat lines), **DCSync rights held off tier-0**
    (`secretsdump -just-dc`), unconstrained/constrained delegation & **RBCD**,
    **shadow-credential** (`AddKeyCredentialLink`) edges (`certipy shadow`),
    dangerous ACLs from low-priv principals (`dacledit`/`bloodyAD`), passwords in
    descriptions, `PASSWD_NOTREQD`, and a non-zero **MachineAccountQuota**.
  - **AD Attack Paths sheet** — the **shortest privilege-escalation path from an
    owned / low-priv principal to Domain Admins / the domain object / a DC**
    (`--owned USER` to start from a principal you control; otherwise it shows what
    *any authenticated user* can reach), rendered as an edge chain with the exact
    tool + action to walk each hop.
  - **Kerberos for effect** — with your credential supplied, recce stages the
    actions to run: roast, AS-REP, DCSync, and delegation ticket forging, each
    parametrised with your account (a 32-hex secret is auto-treated as an NT hash
    and rendered as `-hashes`).
  - Merges the collected domain facts (functional level, trusts, MachineAccountQuota)
    into the Active Directory sheet even with no network scan. References existing
    published tooling (impacket / certipy / netexec / bloodyAD / Rubeus); generates
    no exploit code.
- **Engagement folder stays operator-accessible after sudo runs.** recce often
  runs under sudo (raw-socket scans, reading protected files), which left the
  output files root-owned and unreadable/uneditable to the normal user afterward.
  recce now chmods the whole engagement folder — every subdirectory and file — to
  **777** on every exit path (success, Ctrl-C, or crash, via a `finally`), and
  relaxes the folder as soon as it's created, so the operator always keeps full
  access to the workbook/reports/loot regardless of how recce was invoked.
  Best-effort: a file owned by another user that can't be chmod'd is skipped, never
  fatal.
- **On-target listener backfill — the binary behind every service.** The read-only
  enum scripts now emit a machine-parseable **listening-service inventory**: for
  each listening socket, `proto/addr/port` + the owning **process**, its **PID**,
  the hosting **Windows service** (svchost-backed ports resolve to the real
  service, e.g. `WinRM`), and — the part a remote scan can never see — the exact
  **backing binary** path (`readlink /proc/<pid>/exe` on Linux, the process
  `.Path` / service `ImagePath` on Windows). `ingest`/`deploy` fold this onto the
  host's ports: an existing scanned port keeps nmap's service name but gains the
  **Backing binary** (new Services-sheet column), and a **loopback-only** listener
  the network scan never reached is added as a fresh port tagged **`ID source =
  local`** so the sheet shows exactly where each fact came from. Purely
  read-only (`readlink` / `command -v` / `Get-*` queries) and degrades gracefully
  on older loot that lacks the section.
- **Richer HTML report — detailed findings appendix.** The shareable one-file HTML
  report now carries a **Finding details** section (below the summary table): one
  card per grounded finding, severity-ranked, with the **vulnerability type**,
  **CWE** and **CVE** references, **security aspect impacted (C/I/A)**, the
  **tools/checks** that found it, the full **affected-systems** list, a
  **Recommendation** block (the finding's remediation), and a trimmed **evidence
  excerpt** — the client-facing detail that previously lived only in the DOCX,
  now travelling in the self-contained HTML. Also embeds the Mermaid attack-path
  graph in the Attack-path section (offline, copyable).
- **Deeper service enum — product/version recovery (feeds CVE mapping).** `svcdetect`
  now mines a concrete **product + version** out of the banner it already holds
  (OpenSSH/dropbear, vsFTPd/ProFTPD/Pure-FTPd, Postfix/Exim/Sendmail,
  MySQL/MariaDB, Dovecot/Courier, Apache/nginx/IIS/Tomcat `Server:` headers, …) —
  so a port nmap named but left version-blank (or one recce banner-grabbed itself)
  gets a version the offline CVE mapper can key on. A no-traffic `enrich_versions`
  pass runs over **every** open port (even nmap-named ones) reading the servicefp
  and captured banner; it only ever *fills* a blank product, never overwrites what
  nmap concretely reported. Runs automatically in the enum path just before the
  version→CVE assessment.
- **Attack-path graph.** `recce attackpath` now also writes the synthesised path
  as a diagram — `attack_path.mmd` (Mermaid: stage subgraphs left-to-right, one
  node per confirmed step `host + finding`, dashed edges tracking a single box
  walked through the stages) and `attack_path.dot` (Graphviz: `dot -Tpng
  attack_path.dot -o attack_path.png`). Both are grounded purely in confirmed
  findings — no new scanning. The Mermaid source is also embedded, copyable, in
  the HTML report's Attack-path section (offline: no external JS), so the graph
  travels with the report and pastes straight into mermaid.live / GitHub.
- **`exploitplan` now emits benign PoC build recipes — the payload source, the
  build command, and the delivery — not just "drop a binary here."** For each
  confirmed finding it writes the standard, documented artifact to
  `exploit-plan/poc/` with the exact `gcc`/`x86_64-w64-mingw32-gcc`/`msfvenom`
  line: the LD_PRELOAD `.so` (SUID env-injection / writable-lib), a root-job shell
  PoC (writable cron/service/PATH-hijack), the `/etc/passwd` UID-0 recipe, a
  Windows service/intercept exe (unquoted-path / writable-binary / autorun), a
  hijack DLL (writable dir / COM), and an AlwaysInstallElevated MSI. Each per-host
  plan script embeds the **build → deliver → proof** block. The payloads are
  deliberately **benign proofs** (run `id`/`whoami` into a marker file, or add a
  clearly-named throwaway `recce_poc` account) — you swap the single ACTION line
  for your ROE command. Nothing is obfuscated or AV-evasive; a control that blocks
  a plain PoC is a scoping/exclusion conversation, which recce still says to have
  rather than engineering evasion. (The emitted `.so` source is covered by a test
  that actually compiles it.)
- **`recce prove` — is this finding real, or a false positive?** A new
  verification engine reasons over the evidence recce already collected (the exact
  version, the port state, the NSE detection result, the on-target privilege
  state) and returns a per-finding verdict for the noisy types testers can never
  easily disposition. Covered: **ActiveMQ (CVE-2023-46604), SMB signing / relay,
  MS17-010, SMBGhost, SeImpersonate/GodPotato, PrintNightmare (CVE-2021-34527/1675),
  BlueKeep (CVE-2019-0708), Heartbleed (CVE-2014-0160), Log4Shell (CVE-2021-44228),
  ZeroLogon (CVE-2020-1472), Kerberoast / AS-REP, null-session, anonymous-FTP,
  default-credentials and weak-TLS** — each with an OS/version/role/state gate so a
  patched build, a non-DC, or a newer OS is called out as a false positive:
  - **CONFIRMED** — the evidence positively proves it (an NSE detection fired,
    signing really is off, the privilege really is *Enabled*, we negotiated the
    weak cipher ourselves).
  - **FALSE POSITIVE** — the evidence disproves it (ActiveMQ build is ≥ the branch
    fix, SMB signing is *required*, the NSE check says NOT VULNERABLE, the OS build
    is outside the SMBGhost window). These are the ones you can safely dismiss.
  - **LIKELY** — preconditions hold but the final proof is the PoC; the exact safe
    command to finish proving is given.
  - **INCONCLUSIVE** — what to collect next (e.g. get the exact version, or run the
    on-target `whoami /priv` to confirm SeImpersonate is Enabled).

  Each verdict lists the evidence it used, the preconditions, the exact
  finish-proving command (within ROE — `nmap --script smb-vuln-ms17-010`,
  `nxc smb … --gen-relay-list`, `GodPotato -cmd whoami`, the msf module) and what a
  false positive looks like. `recce prove --run` additionally re-runs the
  NON-INTRUSIVE SMB detection NSE to move LIKELY verdicts to CONFIRMED / FALSE
  POSITIVE on fresh evidence. Results land on a new **Verification** workbook tab
  (real first, noise last). Nothing here exploits anything — it reasons and tells
  you the safe check to run.
- **Windows privesc: fully-qualified exploits, not just flagged classes.** Where
  the script used to say "unquoted service path" or "DLL hijack," it now computes
  and prints the exact artifact and the precise steps:
  - **Unquoted service paths** are resolved to the exact intercept exe Windows
    would load first (e.g. `C:\Program Files\Sub.exe`), the script checks which
    candidate directory *this* user can actually write, and the finding names the
    plant path, the service, its run-as account, and the `sc stop/start` line.
  - **Writable service binary / registry key** findings carry the exact
    `copy /Y … "<binPath>"` or `reg add … /v ImagePath …` command plus the
    service account.
  - **DLL hijacking** distinguishes writable **SYSTEM PATH** vs user PATH, names
    the writable Program-Files app dirs **and the exe(s) in them**, and flags
    **services whose binary sits in a writable dir** — each with the exact planting
    procedure (ProcMon → `NAME NOT FOUND` → `msfvenom -f dll`).
  - **COM hijack** prints the exact `reg add …\InprocServer32 /ve /d C:\evil.dll`.
  - Deeper Windows credential hunting: profile SSH/PEM keys (triaged), IIS
    `applicationHost.config`, scheduled-task passwords, PS transcripts, RDP files,
    and a profile-wide high-signal secret sweep.
  - All new findings promote to first-class Vulnerabilities and map to
    Exploitation-sheet plays (win-unquoted / win-writable-service / win-dll-hijack).
    Still 100% read-only.
- **On-target scripts now identify the EXACT exploit, not just the vector.** The
  goal is to beat lin/winPEAS at turning a finding into an action:
  - **Embedded GTFOBins-lite engine.** A SUID or NOPASSWD-sudo binary no longer
    says "look it up on gtfobins" — it prints the precise command for *that*
    binary (`find . -exec /bin/sh -p \; -quit`, `sudo vim -c ':!/bin/sh'`,
    `python3 -c 'import os;os.setuid(0);os.system("/bin/sh -p")'`, …), for ~50
    binaries in both SUID and sudo contexts. Capabilities (`cap_setuid`,
    `cap_dac_*`) print their exact commands too.
  - **Deeper analysis of custom SUID binaries.** A non-standard SUID root binary
    is statically analysed (read-only, `strings` only — never executed) to find
    the *actual* vector: which command it shells out to by bare name (**PATH
    hijack**, with the exact planting command), whether it reads `LD_*` (**env
    injection**), and any **writable file/config it opens** — each surfaced as its
    own finding with the concrete exploit.
  - **Serious credential & secret hunting.** SSH/PEM private keys are triaged
    (encrypted → `ssh2john`; unencrypted → ready-to-use, with the matching pubkey/
    host), plus a high-signal sweep for cloud keys (`AKIA…`, `AIza…`), tokens
    (`ghp_…`, `xox…`, GitLab PATs), JWTs, private-key blocks and `password=`/`api_key=`
    assignments across the likely locations, and named credential stores
    (`.git-credentials`, `.netrc`, `.npmrc`, `.aws`, docker/gcloud, mail spools).
    Windows gains the same: profile SSH keys, IIS `applicationHost.config`,
    scheduled-task passwords, PS transcripts, RDP files, and a profile-wide secret
    regex sweep. Everything remains 100% read-only.
- **On-target enum scripts go well beyond privesc: lateral movement, shell
  escape, persistence.** `recce-enum.sh` / `recce-enum.ps1` (run via `deploy` /
  `ingest`) gained whole new read-only sections, and their findings flow through
  the same parse → categorize → promote → playbook pipeline into the workbook:
  - **Lateral movement & pivoting.** Linux: live ssh-agent sockets, SSH trust
    graph (`known_hosts`/`config` ProxyJump), Kubernetes service-account tokens &
    kubeconfigs, config-management inventories (Ansible/Salt/Puppet), dual-homed
    detection, established-connection pivot leads, DB client creds. Windows:
    mapped drives, WinRM/PSRemoting reach + TrustedHosts, and read-only LDAP for
    the classic AD targets — **Kerberoastable** (SPN), **AS-REP roastable**, and
    **unconstrained-delegation** hosts.
  - **Restricted-shell / restricted-environment escape.** Linux: detects
    rbash/lshell/git-shell/`$-` jails and lists candidate escape interpreters.
    Windows: PowerShell **ConstrainedLanguage** mode, JEA session endpoints,
    AppLocker effective policy.
  - **Persistence footholds (read-only detection).** Writable login/boot hooks —
    Linux `.bashrc`/`profile.d`/`update-motd.d`/`authorized_keys`/PAM; Windows
    PowerShell profile, HKCU COM InprocServer32, WMI event subscriptions,
    AppInit_DLLs, accessibility (sethc/utilman) debugger hijacks, netsh helpers.
  - **Current-era kernel privesc.** nf_tables **CVE-2024-1086** range, plus
    `ptrace_scope`, unprivileged-userns and LSM (SELinux/AppArmor) posture.
  - Each new high-value finding is categorized (`lateral` / `escape` /
    `persistence`), the strongest promote to first-class Vulnerabilities, and the
    tailored **How-to-exploit** blocks + Exploitation-sheet plays reference only
    EXISTING public tooling (Rubeus/impacket GetUserSPNs/GetNPUsers, GTFOBins,
    kubectl, public PoCs). Still 100% read-only — no exploit code, no evasion.
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
  4. **second-opinion re-probe** — any ports STILL unnamed get one focused nmap
     `-sV --version-all` (intensity 9, every probe) aimed at just those. It's
     cheap because it's a handful of ports, and nmap's answer is authoritative
     (it upgrades our inferred/banner guess and is marked `nmap`). The first enum
     pass spends its version-detection budget across the whole host; this spends a
     fresh one on only the leftovers.

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
- **Priv-Esc tab is real findings now, not boilerplate.** It used to emit the
  generic Windows/Linux privesc *playbook* for every host in the datastore — so a
  host you'd never touched (even a network/broadcast address like `10.200.37.0`
  that slipped into scope) showed ~18 rows of "what to run once you have a shell,"
  making the whole tab read as filler. Fixed three ways:
  - **The tab is driven by the local sweep.** Confirmed escalation paths and
    on-target observations come from `recce deploy` / `ingest` folding the
    read-only `recce-enum.sh/.ps1` output into `local_findings` — that's what the
    Priv-Esc tab shows, plus remotely-observed signals (MS17-010, SMB signing off,
    IIS/MSSQL SeImpersonate, …).
  - **Un-swept hosts get one actionable to-do**, not a checklist: a host with open
    ports but no local sweep shows a single "Local privesc enum not yet run → run
    `recce deploy`" row. A host with no open ports and nothing observed produces
    **no rows at all** (so dead IPs never fabricate entries).
  - **The generic playbook moved to a new `Priv-Esc Playbook` reference sheet**,
    listed once per OS in scope instead of repeated per host.
- **Target hygiene: ranges drop the network / broadcast address.** A full-octet
  range like `10.200.37.0-255` now expands to `.1`–`.254` (it means "the subnet",
  not "scan `.0` and `.255`"), matching how CIDR expansion already behaved. An
  explicitly-typed single `…​.0` is still respected.
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
