"""Web-facing service enumeration + deep, non-intrusive checks (stdlib only).

Identifies every HTTP/HTTPS endpoint recce found - on ANY port, not just 80/443 -
fingerprints its tech stack, and runs a bounded set of high-signal, non-destructive
checks: exposed VCS/config files (.git/.env), server-status / Spring actuator,
directory listing, dangerous HTTP methods, weak cookie flags, and (via probes) the
security-header / TLS analysis. Everything positive becomes a Vuln, so web findings
flow into the Vulnerabilities / Verification / Exploitation sheets like anything
else. Heavier scanning is bridged to the Kali tools (whatweb / nikto / nuclei /
gobuster / wpscan / sslscan). Airgapped-safe: only touches the target, stdlib only.
"""

from __future__ import annotations

import http.client
import re
import ssl

from .models import Host, Port, Vuln
from . import probes

_TIMEOUT = 6.0
_UA = "recce-web/1.0"


def is_web(port: Port) -> bool:
    return port.state == "open" and probes._is_http(port)


def scheme_for(port: Port) -> str:
    return "https" if probes._is_tls(port) else "http"


def url_for(ip: str, port: Port) -> str:
    sch = scheme_for(port)
    if (sch == "http" and port.portid == 80) or (sch == "https" and port.portid == 443):
        return f"{sch}://{ip}"
    return f"{sch}://{ip}:{port.portid}"


def _mk(ip: str, port: Port, sid: str, sev: str, title: str, cwes, output: str,
        remediation: str, confidence: str = "confirmed") -> Vuln:
    return Vuln(ip=ip, port=port.portid, protocol=port.protocol, script_id=sid,
                state="finding", title=title, output=output, severity=sev,
                cwes=list(cwes), source="web", remediation=remediation,
                confidence=confidence)


def _fetch(ip: str, port: Port, path: str = "/", method: str = "GET", read: int = 16384,
           auth: dict | None = None, body: str | None = None):
    """One request. Returns (status, headers_lower, body_text) or None on failure.
    `auth` supplies extra request headers (Cookie / Authorization / custom) so the
    scan can run as an authenticated user; `body` sends a request body (POST)."""
    use_tls = probes._is_tls(port)
    conn = None
    try:
        if use_tls:
            conn = http.client.HTTPSConnection(
                ip, port.portid, timeout=_TIMEOUT, context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(ip, port.portid, timeout=_TIMEOUT)
        req_headers = {"User-Agent": _UA, "Connection": "close", "Accept": "*/*"}
        if auth:
            req_headers.update(auth)
        if body is not None:
            req_headers.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=body, headers=req_headers)
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        body = b""
        if method != "HEAD":
            body = resp.read(read)
        return resp.status, headers, body.decode("latin-1", "replace")
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


# --- fingerprinting -------------------------------------------------------------

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
# body/header signatures -> technology label.
_TECH_BODY = [
    (re.compile(r"wp-content|wp-includes|wordpress", re.I), "WordPress"),
    (re.compile(r"Joomla!|/media/jui/", re.I), "Joomla"),
    (re.compile(r"Drupal.settings|/sites/default/", re.I), "Drupal"),
    (re.compile(r"csrf-param|content=\"Ruby on Rails", re.I), "Ruby on Rails"),
    (re.compile(r"__VIEWSTATE", re.I), "ASP.NET WebForms"),
    (re.compile(r"jenkins|X-Jenkins", re.I), "Jenkins"),
    (re.compile(r"grafana", re.I), "Grafana"),
    (re.compile(r"phpMyAdmin", re.I), "phpMyAdmin"),
]
_COOKIE_TECH = {"phpsessid": "PHP", "jsessionid": "Java/Servlet", "asp.net_sessionid": "ASP.NET",
                "laravel_session": "Laravel", "ci_session": "CodeIgniter", "django": "Django"}


def fingerprint(headers: dict, body: str) -> dict:
    tech: list[str] = []
    for h in ("server", "x-powered-by", "x-generator", "x-aspnet-version", "x-drupal-cache"):
        if headers.get(h):
            tech.append(f"{h}={headers[h]}")
    cookie = (headers.get("set-cookie") or "").lower()
    for name, label in _COOKIE_TECH.items():
        if name in cookie:
            tech.append(label)
    for rx, label in _TECH_BODY:
        if rx.search(body):
            tech.append(label)
    m = _GENERATOR.search(body)
    if m:
        tech.append(f"generator={m.group(1).strip()}")
    title = ""
    tm = _TITLE.search(body)
    if tm:
        title = re.sub(r"\s+", " ", tm.group(1)).strip()[:80]
    # dedupe, order-stable
    seen: set[str] = set()
    tech = [t for t in tech if not (t in seen or seen.add(t))]
    return {"tech": tech, "title": title}


def product_version(headers: dict, body: str) -> tuple[str, str]:
    """Best-effort (product, version) for CVE mapping, from headers/body. Used to
    enrich a port's product when nmap left it blank."""
    if headers.get("x-jenkins"):
        return "Jenkins", headers["x-jenkins"]
    if headers.get("x-confluence-request-time") or "Atlassian Confluence" in body:
        m = re.search(r"Confluence[^0-9]*([\d.]+)", body)
        return "Atlassian Confluence", (m.group(1) if m else "")
    if "gitlab" in (headers.get("x-gitlab-meta", "") + body[:2000]).lower():
        return "GitLab", ""
    m = _GENERATOR.search(body)
    if m:
        g = re.match(r"([A-Za-z][A-Za-z ]+?)\s*([\d][\d.]*)?\s*$", m.group(1).strip())
        if g:
            return g.group(1).strip(), (g.group(2) or "")
    m = re.search(r"([A-Za-z][\w.-]+)/([\d][\d.]+)", headers.get("server", ""))
    if m:
        return m.group(1), m.group(2)
    return "", ""


# --- secret extraction (redacted) ----------------------------------------------

_SECRET_RE = re.compile(
    r'([A-Za-z0-9_.\-]*(?:pass(?:word)?|secret|token|api[_-]?key|access[_-]?key|'
    r'private[_-]?key|db[_-]?pass|aws[_-]?\w+|client[_-]?secret)[A-Za-z0-9_.\-]*)'
    # flat  key=val / key: val   OR   Spring actuator nested  key:{"value":"val"}
    r'["\']?\s*[:=]\s*(?:\{?\s*["\']?value["\']?\s*:\s*)?["\']?([^\s"\',}{]{4,})', re.I)


def _leaked_secrets(body: str, limit: int = 8) -> list[str]:
    """Redacted 'key=ab…yz' pairs pulled from an exposed config/env body, so the
    finding shows WHAT leaked without dumping the raw secret."""
    out: list[str] = []
    for m in _SECRET_RE.finditer(body):
        key, val = m.group(1), m.group(2)
        red = f"{val[:2]}…{val[-2:]}" if len(val) > 6 else "…"
        pair = f"{key}={red}"
        if pair not in out:
            out.append(pair)
        if len(out) >= limit:
            break
    return out


# --- Spring Boot Actuator deep-dive --------------------------------------------
# Only probed when the base /actuator responds, so it costs nothing elsewhere.
_ACTUATOR_SUB = [
    ("actuator/env", "high", "web-actuator-env", "Actuator /env exposed (config + secrets)", True),
    ("actuator/configprops", "high", "web-actuator-configprops",
     "Actuator /configprops exposed (config + secrets)", True),
    ("actuator/heapdump", "high", "web-actuator-heapdump",
     "Actuator heapdump downloadable (full memory - secrets/tokens)", False),
    ("actuator/mappings", "medium", "web-actuator-mappings", "Actuator /mappings exposed (route map)", False),
    ("actuator/threaddump", "medium", "web-actuator-threaddump", "Actuator /threaddump exposed", False),
    ("actuator/gateway/routes", "high", "web-actuator-gateway",
     "Spring Cloud Gateway actuator exposed (SpEL RCE surface, CVE-2022-22947)", False),
]


def _scan_actuator(ip: str, port: Port, base_url: str, auth) -> list[Vuln]:
    root = _fetch(ip, port, "/actuator", auth=auth)
    if not (root and root[0] == 200 and ('"_links"' in root[2] or '"health"' in root[2])):
        return []
    out = [_mk(ip, port, "web-actuator", "high", "Spring Boot Actuator exposed (/actuator)",
               ["CWE-200"], f"GET {base_url}/actuator -> HTTP 200 (actuator index).",
               "Secure/limit the actuator endpoints (management.endpoints.web.exposure).")]
    for path, sev, sid, title, extract in _ACTUATOR_SUB:
        r = _fetch(ip, port, "/" + path, auth=auth)
        if not r or r[0] != 200:
            continue
        st, hd, bd = r
        if "heapdump" in path:
            ct = hd.get("content-type", "")
            if "octet-stream" not in ct and "HPROF" not in bd[:16] and "JAVA PROFILE" not in bd[:32]:
                continue
        detail = f"GET {base_url}/{path} -> HTTP {st}."
        if extract:
            secrets = _leaked_secrets(bd)
            if secrets:
                detail += "  leaked: " + "; ".join(secrets)
        out.append(_mk(ip, port, sid, sev, title, ["CWE-200"], detail,
                       "Disable or authenticate the actuator endpoints."))
    return out


# --- backup / source-file exposure ---------------------------------------------
_BACKUPS = [
    ("backup.zip", "zip"), ("site.zip", "zip"), ("www.zip", "zip"), ("backup.tar.gz", "gz"),
    ("backup.sql", "sql"), ("db.sql", "sql"), ("database.sql", "sql"), ("dump.sql", "sql"),
    (".env.bak", "secret"), (".env.save", "secret"), ("wp-config.php.bak", "php"),
    ("config.php.bak", "php"), ("web.config.bak", "xml"), ("index.php.bak", "php"),
]


def _confirm_backup(kind: str, body: str) -> bool:
    if kind == "zip":
        return body[:2] == "PK"
    if kind == "gz":
        return body[:2] == "\x1f\x8b"
    if kind == "sql":
        return bool(re.search(r"INSERT INTO|CREATE TABLE|MySQL dump|PostgreSQL database dump", body, re.I))
    if kind == "php":
        return "<?php" in body or bool(_leaked_secrets(body))
    if kind == "xml":
        return "<configuration" in body.lower()
    return bool(_leaked_secrets(body))


def _scan_backups(ip: str, port: Port, base_url: str, auth) -> list[Vuln]:
    out: list[Vuln] = []
    for name, kind in _BACKUPS:
        r = _fetch(ip, port, "/" + name, auth=auth)
        if r and r[0] == 200 and _confirm_backup(kind, r[2]):
            detail = f"GET {base_url}/{name} -> HTTP 200 ({kind})."
            if kind in ("secret", "php"):
                sec = _leaked_secrets(r[2])
                if sec:
                    detail += "  leaked: " + "; ".join(sec)
            out.append(_mk(ip, port, "web-backup", "high",
                           f"Exposed backup/source file: {name}", ["CWE-538"], detail,
                           "Remove backups/source from the web root; deny access."))
    return out


# --- opt-in default-credential probe (bounded, lockout-aware) -------------------
_BASIC_DEFAULTS = [("admin", "admin"), ("admin", "password"), ("tomcat", "tomcat"),
                   ("root", "root"), ("admin", "")]


def _basic_auth_defaults(ip: str, port: Port, base_url: str, paths: list[str]) -> list[Vuln]:
    """Try a TINY documented default list against endpoints that ask for HTTP Basic
    auth. Capped at 5 attempts per endpoint - stays well under lockout thresholds."""
    import base64
    out: list[Vuln] = []
    for path in paths:
        r = _fetch(ip, port, path)
        if not r or r[0] != 401 or "basic" not in r[1].get("www-authenticate", "").lower():
            continue
        for user, pw in _BASIC_DEFAULTS:
            token = base64.b64encode(f"{user}:{pw}".encode()).decode()
            a = _fetch(ip, port, path, auth={"Authorization": f"Basic {token}"})
            if a and a[0] in (200, 301, 302):
                out.append(_mk(ip, port, "web-default-creds", "high",
                               f"Default HTTP Basic credentials: {user}:{pw or '<blank>'}",
                               ["CWE-1392", "CWE-287"],
                               f"{base_url}{path} accepted {user}:{pw or '<blank>'} (HTTP {a[0]}).",
                               "Change the default credentials; restrict the endpoint."))
                break
    return out


# --- high-signal exposure paths (GET, confirmed only on positive content) -------
# (path, severity, script_id, title, cwes, remediation, confirm(status, body))
_PATHS = [
    (".git/HEAD", "high", "web-git", "Exposed Git repository (.git) - source/secret disclosure",
     ["CWE-538"], "Deny access to .git and remove it from the web root.",
     lambda s, b: s == 200 and b.strip().startswith("ref:")),
    (".git/config", "high", "web-gitconfig", "Exposed .git/config (remote URL - may embed credentials)",
     ["CWE-538"], "Deny access to .git and remove it from the web root.",
     lambda s, b: s == 200 and "[core]" in b),
    (".env", "high", "web-dotenv", "Exposed .env file (app secrets / DB credentials)",
     ["CWE-538", "CWE-215"], "Move .env outside the web root; deny access.",
     lambda s, b: s == 200 and re.search(r"APP_KEY|DB_(PASSWORD|HOST|USER)|SECRET|API_?KEY", b, re.I)),
    (".svn/entries", "medium", "web-svn", "Exposed SVN metadata (.svn)",
     ["CWE-538"], "Remove .svn from the web root.",
     lambda s, b: s == 200 and ("dir" in b[:50] or b[:10].strip().isdigit())),
    ("server-status", "medium", "web-serverstatus", "Apache mod_status exposed (/server-status)",
     ["CWE-200"], "Restrict <Location /server-status> to localhost/admins.",
     lambda s, b: s == 200 and "Apache Server Status" in b),
    ("phpinfo.php", "medium", "web-phpinfo", "phpinfo() page exposed",
     ["CWE-200"], "Remove phpinfo() pages from production.",
     lambda s, b: s == 200 and "phpinfo()" in b.lower()),
    ("info.php", "medium", "web-phpinfo", "phpinfo() page exposed",
     ["CWE-200"], "Remove phpinfo() pages from production.",
     lambda s, b: s == 200 and "phpinfo()" in b.lower()),
    ("web.config", "medium", "web-webconfig", "IIS web.config readable",
     ["CWE-538"], "Deny direct access to web.config.",
     lambda s, b: s == 200 and "<configuration" in b.lower()),
    ("swagger.json", "info", "web-swagger", "API schema exposed (Swagger/OpenAPI)",
     ["CWE-200"], "Restrict API schema exposure if not intended public.",
     lambda s, b: s == 200 and ('"swagger"' in b or '"openapi"' in b)),
    ("manager/html", "medium", "web-tomcat-manager", "Apache Tomcat Manager reachable",
     ["CWE-1188"], "Restrict/authenticate the Tomcat Manager app.",
     lambda s, b: s in (200, 401, 403)),
    ("wp-login.php", "info", "web-wordpress", "WordPress login page (WordPress in use)",
     ["CWE-200"], "Ensure WordPress + plugins are current; restrict wp-login/xmlrpc.",
     lambda s, b: s == 200 and ("user_login" in b or "wordpress" in b.lower())),
    ("robots.txt", "info", "web-robots", "robots.txt discloses paths",
     ["CWE-200"], "Review Disallow entries (they hint at sensitive paths).",
     lambda s, b: s == 200 and "disallow" in b.lower()),
    # --- high-value exposures --------------------------------------------------
    (".DS_Store", "low", "web-dsstore", "Exposed .DS_Store (directory structure disclosure)",
     ["CWE-548"], "Remove .DS_Store from the web root; deny dotfiles.",
     lambda s, b: s == 200 and "Bud1" in b[:16]),
    ("crossdomain.xml", "medium", "web-crossdomain",
     "Permissive crossdomain.xml (wildcard allow-access-from)",
     ["CWE-942"], "Remove the wildcard; restrict allow-access-from to trusted domains.",
     lambda s, b: s == 200 and "cross-domain-policy" in b
     and bool(re.search(r'allow-access-from[^>]*domain="\*"', b))),
    ("metrics", "medium", "web-metrics", "Prometheus /metrics endpoint exposed",
     ["CWE-200"], "Restrict /metrics to the scraper - it leaks internal metrics/paths.",
     lambda s, b: s == 200 and ("# HELP" in b or "# TYPE" in b)),
    (".htpasswd", "high", "web-htpasswd", "Exposed .htpasswd (password hashes)",
     ["CWE-538"], "Deny access to .ht* files in the web server config.",
     lambda s, b: s == 200 and bool(re.search(r":\$(apr1|2[aby]|1|5|6)\$|:\{SHA\}", b))),
    ("server-info", "medium", "web-serverinfo", "Apache mod_info exposed (/server-info)",
     ["CWE-200"], "Restrict <Location /server-info> to localhost/admins.",
     lambda s, b: s == 200 and "Apache Server Information" in b),
    (".aws/credentials", "high", "web-aws", "Exposed AWS credentials file",
     ["CWE-538"], "Remove cloud creds from the web root and rotate them.",
     lambda s, b: s == 200 and "aws_access_key_id" in b.lower()),
    ("wp-json/wp/v2/users", "low", "web-wpusers", "WordPress user enumeration via REST API",
     ["CWE-200"], "Restrict the users REST endpoint / disable REST user listing.",
     lambda s, b: s == 200 and '"slug"' in b and b.lstrip().startswith("[")),
]

_DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}


def scan_endpoint(ip: str, port: Port, active: bool = True,
                  auth: dict | None = None, creds: bool = False) -> tuple[dict, list[Vuln]]:
    """Deep, non-intrusive scan of one web endpoint. Returns (profile, [Vuln]).
    `auth` (Cookie/Authorization headers) runs the scan as an authenticated user;
    `creds` opts into a tiny, lockout-aware default-credential probe."""
    findings: list[Vuln] = []
    base = url_for(ip, port)
    # Root fetch: fingerprint + directory listing + cookie flags.
    root = _fetch(ip, port, "/", auth=auth)
    status = root[0] if root else None
    headers = root[1] if root else {}
    body = root[2] if root else ""
    fp = fingerprint(headers, body) if root else {"tech": [], "title": ""}
    # Enrich the port's product/version from the web fingerprint when nmap left it
    # blank, so it flows into the CVE mapping + Services-by-Product pivot.
    if root and not port.product:
        prod, ver = product_version(headers, body)
        if prod:
            port.product = prod
            port.version = port.version or ver
            port.detect_source = port.detect_source or "web"
    profile = {"ip": ip, "port": port.portid, "scheme": scheme_for(port),
               "url": base, "status": status,
               "server": headers.get("server", ""), "tech": fp["tech"],
               "title": fp["title"]}
    # Security headers + TLS (reuse the existing stdlib probes).
    findings.extend(probes.http_findings(ip, port))
    if probes._is_tls(port):
        findings.extend(probes.tls_findings(ip, port))
    # The active HTTP checks only make sense if the port actually spoke HTTP -
    # skip them for a TLS-only non-HTTP port (LDAPS/IMAPS) so we don't waste a
    # dozen dead requests there (its TLS findings above still count).
    if not active or root is None:
        profile["findings"] = len(findings)
        return profile, findings
    # Directory listing on the root.
    if root and status == 200 and re.search(r"<title>Index of /|Directory listing for", body, re.I):
        findings.append(_mk(ip, port, "web-dirlisting", "medium",
                            "Directory listing enabled", ["CWE-548"],
                            f"GET {profile['url']}/ returned an auto-index page.",
                            "Disable automatic directory indexing (Options -Indexes)."))
    # Weak cookie flags.
    ck = headers.get("set-cookie", "")
    if ck:
        low = ck.lower()
        if "httponly" not in low:
            findings.append(_mk(ip, port, "web-cookie", "low",
                                "Session cookie without HttpOnly", ["CWE-1004"],
                                f"Set-Cookie: {ck[:120]}", "Set HttpOnly on session cookies."))
        if probes._is_tls(port) and "secure" not in low:
            findings.append(_mk(ip, port, "web-cookie", "low",
                                "Session cookie without Secure (over HTTPS)", ["CWE-614"],
                                f"Set-Cookie: {ck[:120]}", "Set the Secure flag on HTTPS cookies."))
    # Dangerous HTTP methods.
    opt = _fetch(ip, port, "/", method="OPTIONS", auth=auth)
    if opt and opt[1].get("allow"):
        allowed = {m.strip().upper() for m in opt[1]["allow"].split(",")}
        bad = sorted(allowed & _DANGEROUS_METHODS)
        if bad:
            sev = "high" if "PUT" in bad else "medium"
            findings.append(_mk(ip, port, "web-methods", sev,
                                f"Dangerous HTTP methods enabled: {', '.join(bad)}",
                                ["CWE-650"], f"OPTIONS / -> Allow: {opt[1]['allow']}",
                                "Disable PUT/DELETE/TRACE/CONNECT unless required."))
    # CORS: does the server reflect an arbitrary Origin AND allow credentials?
    probe_origin = "https://recce.example"
    cors = _fetch(ip, port, "/", auth={**(auth or {}), "Origin": probe_origin})
    if cors:
        ch = cors[1]
        acao = ch.get("access-control-allow-origin", "")
        acac = ch.get("access-control-allow-credentials", "").lower()
        if acao == probe_origin and acac == "true":
            findings.append(_mk(ip, port, "web-cors", "high",
                                "CORS reflects arbitrary Origin with credentials", ["CWE-942"],
                                f"Origin: {probe_origin} -> Access-Control-Allow-Origin: {acao}, "
                                "Allow-Credentials: true (any site can read authenticated responses).",
                                "Echo only an allow-list of trusted origins; never reflect + credentials."))
    # GraphQL introspection enabled?
    gql = '{"query":"query{__schema{queryType{name}}}"}'
    for gp in ("graphql", "api/graphql", "v1/graphql", "query"):
        r = _fetch(ip, port, "/" + gp, method="POST", body=gql, auth=auth)
        if r and r[0] == 200 and ("__schema" in r[2] or '"queryType"' in r[2]):
            findings.append(_mk(ip, port, "web-graphql", "medium",
                                "GraphQL introspection enabled", ["CWE-200"],
                                f"POST {profile['url']}/{gp} (__schema query) returned the schema.",
                                "Disable GraphQL introspection in production."))
            break
    # High-signal exposure paths.
    seen_sid: set[str] = set()
    for path, sev, sid, title, cwes, fix, confirm in _PATHS:
        r = _fetch(ip, port, "/" + path, auth=auth)
        if not r:
            continue
        st, _hd, bd = r
        try:
            if confirm(st, bd):
                if sid in seen_sid:
                    continue
                seen_sid.add(sid)
                detail = (f"GET {base}/{path} -> HTTP {st} "
                          f"(content matched the {title.split('(')[0].strip()} signature).")
                # For secret-bearing files, show WHAT leaked (redacted).
                if sid in ("web-dotenv", "web-aws", "web-htpasswd"):
                    sec = _leaked_secrets(bd)
                    if sec:
                        detail += "  leaked: " + "; ".join(sec)
                findings.append(_mk(ip, port, sid, sev, title, cwes, detail, fix))
        except Exception:  # noqa: BLE001 - a bad body never breaks the sweep
            continue
    # Deep dives (each self-gates so they cost nothing when absent).
    findings.extend(_scan_actuator(ip, port, base, auth))
    findings.extend(_scan_backups(ip, port, base, auth))
    if creds:
        findings.extend(_basic_auth_defaults(ip, port, base,
                                             ["/", "/manager/html", "/admin", "/console"]))
    profile["findings"] = len(findings)
    return profile, findings


def scan_host(host: Host, active: bool = True, auth: dict | None = None,
              creds: bool = False) -> list[dict]:
    """Scan every web endpoint on a host, appending deduped Vulns. Returns the web
    endpoint profiles (for the Web sheet)."""
    existing = {v.key for v in host.vulns}
    profiles: list[dict] = []
    for port in host.open_ports:
        if not is_web(port):
            continue
        profile, findings = scan_endpoint(host.ip, port, active=active, auth=auth, creds=creds)
        for v in findings:
            if v.key in existing:
                continue
            existing.add(v.key)
            host.vulns.append(v)
        profiles.append(profile)
    return profiles


# --- categorization + Kali bridge ----------------------------------------------

def web_endpoints(hosts: list[Host]) -> list[dict]:
    """Every web endpoint across all hosts (from stored data - no network), for the
    Web sheet: url, server/tech (nmap), and how many web findings it carries."""
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_web(p):
                continue
            wv = [v for v in h.vulns if v.port == p.portid and v.source == "web"]
            tech = " ".join(t for t in (p.product, p.version, p.extrainfo) if t)
            out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                        "url": url_for(h.ip, p), "scheme": scheme_for(p),
                        "tech": tech or p.service or "http", "findings": len(wv),
                        "commands": bridge_commands(url_for(h.ip, p), tech, p)})
    return out


def bridge_commands(url: str, tech: str, port: Port) -> str:
    """The exact Kali deep-scan commands for an endpoint, tailored to its stack."""
    host_port = url.split("://", 1)[-1]
    cmds = [f"whatweb -a3 {url}",
            f"nuclei -u {url}",
            f"nikto -h {url}",
            f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak"]
    low = f"{tech} {url}".lower()
    if "wordpress" in low:
        cmds.append(f"wpscan --url {url} --enumerate p,t,u")
    if "tomcat" in low or ":8080" in url:
        cmds.append(f"nxc http {host_port.split(':')[0]} -M tomcat  # or hydra manager default creds")
    if probes._is_tls(port):
        cmds.append(f"sslscan {host_port}")
    return "  ;  ".join(cmds)
