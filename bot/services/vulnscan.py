"""Avtomatik zaiflik skaneri (auto-pentester, zararsiz).

Faqat GET/HEAD/OPTIONS so'rovlari — nishondagi ma'lumotni o'zgartirmaydi,
lekin o'nlab real xatoni topadi. Nikto/Nuclei uslubidagi tekshiruvlar:
  - ochiq maxfiy fayllar (.env, .git, backup, config...)
  - xavfsizlik header'lari va cookie flag'lari
  - CORS noto'g'ri sozlamasi
  - ruxsat etilgan HTTP metodlar (PUT/DELETE/TRACE)
  - TLS zaif protokollar (TLS1.0/1.1) va sertifikat muddati
  - directory listing (Index of)
  - server/texnologiya versiyasi oshkorligi
  - DNS: SPF/DMARC/DNSSEC, security.txt

Har topilma: severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), dalil, tuzatish.
Ruxsat handler qatlamida tekshiriladi (admin yoki tasdiqlangan nishon).
"""
from __future__ import annotations

import asyncio
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

import aiohttp
import dns.resolver

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 SentryScan/1.0")

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Ochiqligi xavfli fayllar/yo'llar: path -> (severity, tavsif, imzo(lar))
SENSITIVE_PATHS: list[tuple[str, str, str, list[str]]] = [
    ("/.env", "CRITICAL", "Ochiq .env — maxfiy kalitlar/parollar", ["APP_KEY", "DB_PASSWORD", "SECRET", "API_KEY"]),
    ("/.git/config", "HIGH", "Ochiq .git — manba kod yuklab olinishi mumkin", ["[core]", "repositoryformatversion"]),
    ("/.git/HEAD", "HIGH", "Ochiq .git/HEAD — repository fosh", ["ref:"]),
    ("/.svn/entries", "MEDIUM", "Ochiq .svn papkasi", ["dir", "\n"]),
    ("/.aws/credentials", "CRITICAL", "AWS kalitlari fosh", ["aws_access_key_id"]),
    ("/config.php.bak", "HIGH", "Config zaxira nusxasi ochiq", ["<?php", "password"]),
    ("/wp-config.php.bak", "HIGH", "WordPress config zaxirasi", ["DB_PASSWORD", "DB_NAME"]),
    ("/backup.zip", "HIGH", "Ochiq backup arxivi", ["PK"]),
    ("/backup.sql", "HIGH", "Ochiq SQL dump", ["INSERT INTO", "CREATE TABLE"]),
    ("/.DS_Store", "LOW", "macOS .DS_Store — fayl tuzilmasi fosh", ["Bud1", "\x00"]),
    ("/phpinfo.php", "MEDIUM", "phpinfo() ochiq — server sozlamalari fosh", ["PHP Version", "phpinfo()"]),
    ("/server-status", "MEDIUM", "Apache server-status ochiq", ["Apache Server Status", "Server uptime"]),
    ("/.htaccess", "LOW", "Ochiq .htaccess", ["RewriteEngine", "Order allow"]),
    ("/actuator/health", "MEDIUM", "Spring actuator ochiq", ['"status"', "UP"]),
    ("/swagger.json", "LOW", "Swagger API hujjati ochiq", ['"swagger"', '"openapi"', '"paths"']),
    ("/.well-known/security.txt", "INFO", "security.txt bor (yaxshi amaliyot)", ["Contact"]),
    ("/robots.txt", "INFO", "robots.txt", ["User-agent", "Disallow"]),
]

SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "MEDIUM", "HTTPS majburlash yo'q — downgrade hujum xavfi"),
    "content-security-policy": ("CSP", "MEDIUM", "XSS/inyeksiyaga qarshi CSP yo'q"),
    "x-frame-options": ("X-Frame-Options", "MEDIUM", "Clickjacking himoyasi yo'q"),
    "x-content-type-options": ("X-Content-Type-Options", "LOW", "MIME-sniffing himoyasi yo'q"),
    "referrer-policy": ("Referrer-Policy", "LOW", "Referrer oqishi mumkin"),
    "permissions-policy": ("Permissions-Policy", "LOW", "Brauzer imkoniyatlari cheklanmagan"),
}


def _finding(sev, title, detail="", fix="") -> dict[str, str]:
    return {"sev": sev, "title": title, "detail": detail, "fix": fix}


async def _resolve_base(session: aiohttp.ClientSession, domain: str, timeout: int):
    """Ishlaydigan asosiy URL (https afzal)."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            async with session.get(url, allow_redirects=True, ssl=False) as r:
                return scheme, str(r.url), r
        except Exception:
            continue
    return None, None, None


def _check_weak_tls(domain: str, timeout: int) -> list[dict]:
    out: list[dict] = []
    versions = [("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]
    for name, ver in versions:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain):
                    out.append(_finding(
                        "MEDIUM", f"Zaif TLS protokoli yoqilgan: {name}",
                        f"{name} eskirgan va zaif.", f"Serverda {name} ni o'chiring, faqat TLS1.2+ qoldiring."))
        except Exception:
            continue
    return out


def _cert_expiry(domain: str, timeout: int) -> list[dict]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                cert = ss.getpeercert()
        na = cert.get("notAfter")
        exp = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (exp - datetime.now(timezone.utc)).days
        if days < 0:
            return [_finding("HIGH", "SSL sertifikat muddati tugagan", f"{-days} kun oldin", "Sertifikatni yangilang.")]
        if days < 21:
            return [_finding("MEDIUM", f"SSL sertifikat {days} kunda tugaydi", "", "Sertifikatni yangilang (Let's Encrypt avtomatik).")]
    except Exception:
        return []
    return []


def _dns_checks(domain: str, timeout: int) -> list[dict]:
    out: list[dict] = []
    res = dns.resolver.Resolver()
    res.lifetime = res.timeout = timeout

    def q(name, rtype):
        try:
            return [r.to_text() for r in res.resolve(name, rtype)]
        except Exception:
            return []

    txt = " ".join(q(domain, "TXT"))
    if "v=spf1" not in txt:
        out.append(_finding("MEDIUM", "SPF yozuvi yo'q", "Email spoofing mumkin", "DNS ga SPF TXT yozuvini qo'shing."))
    dmarc = q(f"_dmarc.{domain}", "TXT")
    if not any("v=DMARC1" in t for t in dmarc):
        out.append(_finding("MEDIUM", "DMARC yozuvi yo'q", "Email spoofing/fishing mumkin", "_dmarc TXT yozuvini qo'shing (p=quarantine)."))
    if not q(domain, "DNSKEY"):
        out.append(_finding("LOW", "DNSSEC yoqilmagan", "DNS soxtalashtirilishi mumkin", "Domen registratorда DNSSEC yoqing."))
    return out


async def deep_scan(domain: str, timeout: int = 6) -> dict[str, Any]:
    findings: list[dict] = []
    to = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 5))
    headers = {"User-Agent": _UA, "Accept": "*/*"}
    connector = aiohttp.TCPConnector(family=socket.AF_INET, ssl=False, limit=12)
    base_scheme = base_url = None
    server_hdr = None

    async with aiohttp.ClientSession(timeout=to, headers=headers, connector=connector, trust_env=True) as session:
        base_scheme, base_url, resp = await _resolve_base(session, domain, timeout)
        if not base_url:
            return {"domain": domain, "ok": False, "error": "Saytga ulanib bo'lmadi (HTTP/HTTPS)", "findings": []}

        # asosiy javob header/cookie tahlili
        try:
            async with session.get(base_url, allow_redirects=True, ssl=False) as r:
                lower = {k.lower(): v for k, v in r.headers.items()}
                server_hdr = r.headers.get("Server")
                # HTTPS yo'qmi
                if base_scheme != "https":
                    findings.append(_finding("HIGH", "HTTPS yo'q (sayt faqat HTTP)",
                                             "Trafik shifrlanmagan — parol/cookie o'g'irlanishi mumkin",
                                             "SSL sertifikat o'rnating (Let's Encrypt bepul)."))
                # xavfsizlik header'lari
                for h, (label, sev, why) in SECURITY_HEADERS.items():
                    if h not in lower:
                        findings.append(_finding(sev, f"Header yo'q: {label}", why, f"Serverda {label} header'ini qo'shing."))
                # server oshkorligi
                if server_hdr and re.search(r"\d", server_hdr):
                    findings.append(_finding("LOW", f"Server versiyasi oshkor: {server_hdr}",
                                             "Hujumchi ma'lum zaifliklardan foydalanishi mumkin",
                                             "Server header'ida versiyani yashiring."))
                # cookie flag'lari
                for ck in r.headers.getall("Set-Cookie", []):
                    cl = ck.lower()
                    name = ck.split("=", 1)[0].strip()
                    miss = [f for f in ("secure", "httponly", "samesite") if f not in cl]
                    if miss:
                        findings.append(_finding("LOW", f"Cookie '{name}' zaif flag'lar",
                                                 "Yo'q: " + ", ".join(m.title() for m in miss),
                                                 "Cookie'ga Secure, HttpOnly, SameSite qo'shing."))
                # directory listing
                body = (await r.text(errors="ignore"))[:4000]
                if "Index of /" in body or "<title>Index of" in body:
                    findings.append(_finding("MEDIUM", "Directory listing yoqilgan",
                                             "Papka mazmuni ochiq ko'rinadi", "Serverda autoindex/Options -Indexes o'chiring."))
        except Exception:
            pass

        # CORS tekshiruvi
        try:
            async with session.get(base_url, allow_redirects=True, ssl=False,
                                   headers={"Origin": "https://evil.example"}) as r:
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acc = r.headers.get("Access-Control-Allow-Credentials", "").lower()
                if acao == "*" and acc == "true":
                    findings.append(_finding("HIGH", "CORS noto'g'ri (ochiq + credentials)",
                                             "Har qanday sayt foydalanuvchi ma'lumotini o'qishi mumkin",
                                             "ACAO ni ishonchli domenlar bilan cheklang."))
                elif acao == "https://evil.example":
                    findings.append(_finding("HIGH", "CORS Origin'ni aks ettiradi",
                                             "Har qanday origin qabul qilinadi", "Origin'ni allow-list bilan cheklang."))
        except Exception:
            pass

        # HTTP metodlar (OPTIONS)
        try:
            async with session.options(base_url, ssl=False) as r:
                allow = r.headers.get("Allow", "")
                risky = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT") if m in allow.upper()]
                if risky:
                    findings.append(_finding("MEDIUM", f"Xavfli HTTP metodlar: {', '.join(risky)}",
                                             f"Allow: {allow}", "Keraksiz metodlarni o'chiring (ayniqsa TRACE/PUT)."))
        except Exception:
            pass

        # maxfiy fayllar (parallel)
        sem = asyncio.Semaphore(10)

        async def probe(path, sev, desc, sigs):
            async with sem:
                url = base_url.rstrip("/") + path
                try:
                    async with session.get(url, allow_redirects=False, ssl=False) as r:
                        if r.status != 200:
                            return None
                        text = (await r.text(errors="ignore"))[:3000]
                        if any(s in text for s in sigs):
                            return (path, sev, desc, url)
                except Exception:
                    return None
            return None

        results = await asyncio.gather(*(probe(*p) for p in SENSITIVE_PATHS))
        robots_body = None
        for res in results:
            if not res:
                continue
            path, sev, desc, url = res
            if path in ("/.well-known/security.txt", "/robots.txt"):
                findings.append(_finding("INFO", desc, url, ""))
            else:
                findings.append(_finding(sev, desc, f"Topildi: {url}",
                                         "Bu faylni web-root'dan olib tashlang yoki kirishni yoping."))

    # TLS/DNS (thread)
    if base_scheme == "https":
        findings += await asyncio.to_thread(_check_weak_tls, domain, timeout)
        findings += await asyncio.to_thread(_cert_expiry, domain, timeout)
    findings += await asyncio.to_thread(_dns_checks, domain, timeout)

    findings.sort(key=lambda f: SEV_ORDER.get(f["sev"], 9))
    counts = {k: 0 for k in SEV_ORDER}
    for f in findings:
        counts[f["sev"]] = counts.get(f["sev"], 0) + 1
    score = _score(counts)
    return {
        "domain": domain, "ok": True, "base_url": base_url, "server": server_hdr,
        "findings": findings, "counts": counts, "score": score,
    }


def _score(counts: dict[str, int]) -> int:
    """100 dan xavfsizlik bali (past = yomon)."""
    penalty = (counts.get("CRITICAL", 0) * 25 + counts.get("HIGH", 0) * 12
               + counts.get("MEDIUM", 0) * 5 + counts.get("LOW", 0) * 2)
    return max(0, 100 - penalty)
