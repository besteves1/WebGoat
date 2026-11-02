#!/usr/bin/env python3
"""
recon.py - Reconhecimento leve de aplicações web (somente stdlib).

USO AUTORIZADO APENAS. Rode somente contra alvos que você possui ou tem
autorização por escrito para testar (ex.: seu WebGoat local).
Por padrão o script recusa alvos fora de redes privadas/loopback; use
--authorized para confirmar que você tem autorização para alvos públicos.

Etapas:
  1. Resolução DNS
  2. Scan TCP connect nas portas comuns (ou --ports)
  3. Probe HTTP/HTTPS nas portas abertas: status, título, headers, tecnologias
  4. Auditoria de headers de segurança e flags de cookies
  5. Certificado TLS (quando HTTPS)
  6. robots.txt / sitemap.xml + descoberta de caminhos comuns (Spring/WebGoat)
  7. Relatório em JSON e Markdown

Exemplos:
  python3 recon.py --target localhost
  python3 recon.py --target 127.0.0.1 --ports 8080,9090 --base-path /WebGoat
  python3 recon.py --target 10.0.0.5 --wordlist minha_lista.txt -o saida/
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3000, 3306, 5000,
                 5432, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
                 9200, 27017]

WEB_HINT_PORTS = {80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888,
                  9000, 9090, 9200}

DEFAULT_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/login", "/login.mvc", "/register.mvc", "/admin", "/console",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/actuator/beans", "/actuator/heapdump", "/env", "/health", "/info",
    "/swagger-ui.html", "/swagger-ui/index.html", "/v2/api-docs",
    "/v3/api-docs", "/h2-console", "/service/", "/WebGoat", "/WebWolf",
    "/.git/HEAD", "/.env", "/server-status", "/error", "/api",
]

SECURITY_HEADERS = {
    "content-security-policy": "Mitiga XSS/injeção de conteúdo",
    "strict-transport-security": "Força HTTPS (HSTS)",
    "x-frame-options": "Mitiga clickjacking",
    "x-content-type-options": "Impede MIME sniffing",
    "referrer-policy": "Controla vazamento de Referer",
    "permissions-policy": "Restringe APIs do navegador",
}

LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version",
                 "x-application-context", "via"]

TECH_SIGNATURES = [
    (r"JSESSIONID", "Java Servlet container"),
    (r"Whitelabel Error Page", "Spring Boot"),
    (r"X-Application-Context", "Spring Boot"),
    (r"Apache-Coyote|Tomcat", "Apache Tomcat"),
    (r"Undertow", "Undertow"),
    (r"Jetty", "Jetty"),
    (r"nginx", "nginx"),
    (r"Apache/", "Apache httpd"),
    (r"PHPSESSID|X-Powered-By: PHP", "PHP"),
    (r"Express", "Node.js Express"),
    (r"WebGoat", "OWASP WebGoat"),
    (r"WebWolf", "OWASP WebWolf"),
    (r"thymeleaf", "Thymeleaf"),
    (r"jquery", "jQuery"),
    (r"bootstrap", "Bootstrap"),
]

UA = "recon.py/1.0 (authorized security assessment)"


# --------------------------------------------------------------------- utils
def log(msg: str) -> None:
    ts = dt.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", file=sys.stderr, flush=True)


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def parse_ports(spec: str | None) -> list[int]:
    if not spec:
        return DEFAULT_PORTS
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))
    bad = [p for p in ports if not 0 < p < 65536]
    if bad:
        raise ValueError(f"portas inválidas: {bad}")
    return sorted(ports)


# ---------------------------------------------------------------- 1. DNS
def resolve(host: str) -> dict:
    out = {"host": host, "addresses": [], "reverse": None}
    try:
        infos = socket.getaddrinfo(host, None)
        out["addresses"] = sorted({i[4][0] for i in infos})
    except socket.gaierror as e:
        out["error"] = str(e)
        return out
    try:
        out["reverse"] = socket.gethostbyaddr(out["addresses"][0])[0]
    except (socket.herror, socket.gaierror, OSError):
        pass
    return out


# ---------------------------------------------------------- 2. Port scan
def check_port(ip: str, port: int, timeout: float) -> dict | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            banner = ""
            s.settimeout(0.8)
            try:
                data = s.recv(256)
                banner = data.decode(errors="replace").strip()
            except (socket.timeout, OSError):
                pass
            return {"port": port, "state": "open", "banner": banner[:200]}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def port_scan(ip: str, ports: list[int], timeout: float, workers: int,
              delay: float) -> list[dict]:
    results = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = []
        for p in ports:
            futs.append(ex.submit(check_port, ip, p, timeout))
            if delay:
                time.sleep(delay)
        for f in cf.as_completed(futs):
            r = f.result()
            if r:
                results.append(r)
                log(f"  porta aberta: {r['port']}")
    return sorted(results, key=lambda r: r["port"])


# ------------------------------------------------------------- 3. HTTP
def http_request(scheme: str, host: str, port: int, path: str,
                 timeout: float, method: str = "GET") -> dict:
    # Verificação desligada de propósito: recon precisa inspecionar alvos com
    # certificados autoassinados/expirados. Nenhuma credencial é enviada.
    ctx = ssl._create_unverified_context()
    conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    kwargs = {"timeout": timeout}
    if scheme == "https":
        kwargs["context"] = ctx
    conn = conn_cls(host, port, **kwargs)
    try:
        conn.request(method, path, headers={"User-Agent": UA, "Accept": "*/*"})
        resp = conn.getresponse()
        body = resp.read(200_000)
        return {
            "status": resp.status,
            "reason": resp.reason,
            "headers": [(k, v) for k, v in resp.getheaders()],
            "body": body.decode(errors="replace"),
            "length": len(body),
        }
    finally:
        conn.close()


def detect_scheme(host: str, port: int, timeout: float) -> str | None:
    order = ["https", "http"] if port in (443, 8443) else ["http", "https"]
    for scheme in order:
        try:
            http_request(scheme, host, port, "/", timeout, "HEAD")
            return scheme
        except (ssl.SSLError, http.client.HTTPException, OSError):
            continue
    return None


def title_of(html: str) -> str | None:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:150] if m else None


def fingerprint(headers: list[tuple[str, str]], body: str) -> list[str]:
    blob = "\n".join(f"{k}: {v}" for k, v in headers) + "\n" + body[:50_000]
    found = []
    for pattern, name in TECH_SIGNATURES:
        if re.search(pattern, blob, re.I) and name not in found:
            found.append(name)
    return found


def audit_headers(headers: list[tuple[str, str]], scheme: str) -> dict:
    lower = {}
    for k, v in headers:
        lower.setdefault(k.lower(), []).append(v)
    missing = []
    for h, why in SECURITY_HEADERS.items():
        if h == "strict-transport-security" and scheme != "https":
            continue
        if h not in lower:
            missing.append({"header": h, "why": why})
    leaks = {h: lower[h][0] for h in LEAKY_HEADERS if h in lower}

    cookies = []
    for raw in lower.get("set-cookie", []):
        name = raw.split("=", 1)[0].strip()
        attrs = raw.lower()
        issues = []
        if "httponly" not in attrs:
            issues.append("sem HttpOnly")
        if scheme == "https" and "secure" not in attrs:
            issues.append("sem Secure")
        if "samesite" not in attrs:
            issues.append("sem SameSite")
        cookies.append({"name": name, "issues": issues})

    cors = lower.get("access-control-allow-origin", [None])[0]
    return {"missing": missing, "info_leak": leaks, "cookies": cookies,
            "cors_allow_origin": cors}


# --------------------------------------------------------------- 5. TLS
def tls_info(host: str, port: int, timeout: float) -> dict:
    ctx = ssl._create_unverified_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                der = s.getpeercert(binary_form=True)
                info = {"version": s.version(), "cipher": s.cipher()[0]}
        # Decodifica com um contexto que retorna o dict quando possível
        try:
            import tempfile
            pem = ssl.DER_cert_to_PEM_cert(der)
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
                f.write(pem)
            try:
                dec = ssl._ssl._test_decode_cert(f.name)  # type: ignore[attr-defined]
            finally:
                Path(f.name).unlink(missing_ok=True)
            info.update({
                "subject": dict(x[0] for x in dec.get("subject", [])),
                "issuer": dict(x[0] for x in dec.get("issuer", [])),
                "not_after": dec.get("notAfter"),
                "san": [v for _, v in dec.get("subjectAltName", [])],
            })
        except Exception:  # noqa: BLE001 - decodificação é best-effort
            pass
        return info
    except (ssl.SSLError, OSError) as e:
        return {"error": str(e)}


# ---------------------------------------------------- 6. Path discovery
def discover_paths(scheme: str, host: str, port: int, base: str,
                   paths: list[str], timeout: float, workers: int,
                   delay: float) -> list[dict]:
    # Baseline para detectar "soft 404" (app que responde 200 para tudo)
    try:
        bl = http_request(scheme, host, port,
                          base.rstrip("/") + "/__recon_nonexistent_8f3a__", timeout)
        baseline = (bl["status"], bl["length"])
    except (OSError, http.client.HTTPException):
        baseline = None

    def probe(path: str) -> dict | None:
        full = base.rstrip("/") + path if not path.startswith(base) else path
        try:
            r = http_request(scheme, host, port, full, timeout)
        except (OSError, http.client.HTTPException, ssl.SSLError):
            return None
        if r["status"] == 404:
            return None
        if baseline and r["status"] == baseline[0] and abs(r["length"] - baseline[1]) < 32:
            return None
        loc = dict((k.lower(), v) for k, v in r["headers"]).get("location")
        return {"path": full, "status": r["status"], "length": r["length"],
                "location": loc, "title": title_of(r["body"])}

    hits = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = []
        for p in paths:
            futs.append(ex.submit(probe, p))
            if delay:
                time.sleep(delay)
        for f in cf.as_completed(futs):
            r = f.result()
            if r:
                hits.append(r)
                log(f"    {r['status']} {r['path']}")
    return sorted(hits, key=lambda r: r["path"])


def robots_paths(body: str) -> list[str]:
    out = []
    for line in body.splitlines():
        m = re.match(r"\s*(?:dis)?allow\s*:\s*(\S+)", line, re.I)
        if m and m.group(1) != "/":
            out.append(m.group(1).split("*")[0])
    return out


def extract_links(body: str, base_url: str, host: str) -> list[str]:
    links = set()
    for m in re.finditer(r"""(?:href|src|action)\s*=\s*["']([^"'#]+)""", body, re.I):
        u = urljoin(base_url, m.group(1))
        p = urlparse(u)
        if p.hostname in (host, None) and p.path:
            links.add(p.path)
    return sorted(links)[:200]


# --------------------------------------------------------------- report
def write_markdown(report: dict, path: Path) -> None:
    L = [f"# Recon: {report['target']}",
         "",
         f"- Início: {report['started']}",
         f"- Duração: {report['duration_s']}s",
         f"- Endereços: {', '.join(report['dns'].get('addresses', [])) or '-'}",
         f"- Reverso: {report['dns'].get('reverse') or '-'}",
         "",
         "## Portas abertas",
         "",
         "| Porta | Banner |", "|---|---|"]
    for p in report["ports"]:
        L.append(f"| {p['port']} | {p['banner'][:80].replace('|', '/') or '-'} |")
    if not report["ports"]:
        L.append("| - | nenhuma porta aberta encontrada |")

    for svc in report["web"]:
        L += ["", f"## {svc['url']}", "",
              f"- Status `/`: {svc.get('status')}",
              f"- Título: {svc.get('title') or '-'}",
              f"- Tecnologias: {', '.join(svc.get('tech', [])) or '-'}"]
        a = svc.get("audit", {})
        if a.get("missing"):
            L += ["", "**Headers de segurança ausentes:**", ""]
            L += [f"- `{m['header']}` ({m['why']})" for m in a["missing"]]
        if a.get("info_leak"):
            L += ["", "**Headers que vazam informação:**", ""]
            L += [f"- `{k}: {v}`" for k, v in a["info_leak"].items()]
        bad_cookies = [c for c in a.get("cookies", []) if c["issues"]]
        if bad_cookies:
            L += ["", "**Cookies:**", ""]
            L += [f"- `{c['name']}`: {', '.join(c['issues'])}" for c in bad_cookies]
        if a.get("cors_allow_origin"):
            L.append(f"\n**CORS:** `Access-Control-Allow-Origin: {a['cors_allow_origin']}`")
        if svc.get("tls"):
            t = svc["tls"]
            L += ["", f"**TLS:** {t.get('version', '-')} / {t.get('cipher', '-')}"
                  f" — expira {t.get('not_after', '-')}"]
        if svc.get("paths"):
            L += ["", "**Caminhos encontrados:**", "",
                  "| Status | Caminho | Tamanho | Redireciona | Título |",
                  "|---|---|---|---|---|"]
            for h in svc["paths"]:
                L.append(f"| {h['status']} | `{h['path']}` | {h['length']} | "
                         f"{h['location'] or '-'} | {h['title'] or '-'} |")
        if svc.get("links"):
            L += ["", f"**Links internos extraídos ({len(svc['links'])}):**", ""]
            L += [f"- `{l}`" for l in svc["links"][:50]]

    L += ["", "---", "_Gerado por recon.py — uso autorizado apenas._", ""]
    path.write_text("\n".join(L), encoding="utf-8")


# ----------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Recon leve de aplicações web (uso autorizado apenas).")
    ap.add_argument("--target", required=True, help="host ou IP alvo")
    ap.add_argument("--ports", help="ex.: 80,443,8080-8090 (padrão: lista comum)")
    ap.add_argument("--base-path", default="/",
                    help="prefixo da aplicação, ex.: /WebGoat")
    ap.add_argument("--wordlist", help="arquivo com caminhos extras (um por linha)")
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--workers", type=int, default=20)
    ap.add_argument("--delay", type=float, default=0.0,
                    help="pausa (s) entre requisições para reduzir carga")
    ap.add_argument("--no-paths", action="store_true",
                    help="pula a descoberta de caminhos")
    ap.add_argument("-o", "--out", default="recon-output",
                    help="diretório de saída")
    ap.add_argument("--authorized", action="store_true",
                    help="confirmo que tenho autorização para testar um alvo público")
    args = ap.parse_args()

    started = time.time()
    target = args.target.strip()
    if "://" in target:
        target = urlparse(target).hostname or target

    log(f"Resolvendo {target} ...")
    dns = resolve(target)
    if not dns["addresses"]:
        log(f"Falha na resolução DNS: {dns.get('error')}")
        return 2
    ip = dns["addresses"][0]

    if not is_private(ip) and not args.authorized:
        log(f"ABORTADO: {target} ({ip}) é um endereço público.")
        log("Rode somente contra alvos autorizados. Se você tem autorização "
            "por escrito, repita com --authorized.")
        return 3

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        log(str(e))
        return 2

    log(f"Scan TCP em {ip} ({len(ports)} portas) ...")
    open_ports = port_scan(ip, ports, args.timeout, args.workers, args.delay)

    extra_paths: list[str] = []
    if args.wordlist:
        extra_paths = [l.strip() if l.strip().startswith("/") else "/" + l.strip()
                       for l in Path(args.wordlist).read_text().splitlines()
                       if l.strip() and not l.startswith("#")]

    web = []
    for p in open_ports:
        port = p["port"]
        if port not in WEB_HINT_PORTS and not p["banner"].startswith("HTTP") and p["banner"]:
            continue  # serviço não-HTTP com banner próprio (ssh, smtp...)
        scheme = detect_scheme(target, port, args.timeout)
        if not scheme:
            continue
        url = f"{scheme}://{target}:{port}{args.base_path}"
        log(f"Analisando {url} ...")
        svc: dict = {"url": url, "port": port, "scheme": scheme}
        try:
            r = http_request(scheme, target, port, args.base_path, args.timeout)
            svc.update({
                "status": r["status"],
                "title": title_of(r["body"]),
                "tech": fingerprint(r["headers"], r["body"]),
                "audit": audit_headers(r["headers"], scheme),
                "headers": r["headers"],
                "links": extract_links(r["body"], url, target),
            })
        except (OSError, http.client.HTTPException) as e:
            svc["error"] = str(e)

        if scheme == "https":
            svc["tls"] = tls_info(target, port, args.timeout)

        if not args.no_paths:
            paths = list(dict.fromkeys(DEFAULT_PATHS + extra_paths))
            try:
                rb = http_request(scheme, target, port, "/robots.txt", args.timeout)
                if rb["status"] == 200:
                    paths += robots_paths(rb["body"])
            except (OSError, http.client.HTTPException):
                pass
            paths += [l for l in svc.get("links", []) if l.count("/") <= 4][:50]
            paths = list(dict.fromkeys(paths))
            log(f"  descobrindo caminhos ({len(paths)}) ...")
            svc["paths"] = discover_paths(scheme, target, port, args.base_path,
                                          paths, args.timeout,
                                          min(args.workers, 10), args.delay)
        web.append(svc)

    report = {
        "target": target,
        "ip": ip,
        "started": dt.datetime.fromtimestamp(started).isoformat(timespec="seconds"),
        "duration_s": round(time.time() - started, 1),
        "dns": dns,
        "ports": open_ports,
        "web": web,
    }

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", target)
    jpath = out / f"recon-{safe}-{stamp}.json"
    mpath = out / f"recon-{safe}-{stamp}.md"
    jpath.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    write_markdown(report, mpath)

    log(f"Concluído em {report['duration_s']}s: {len(open_ports)} portas abertas, "
        f"{len(web)} serviços web.")
    log(f"Relatório: {mpath}")
    log(f"JSON:      {jpath}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("Interrompido.")
        sys.exit(130)
