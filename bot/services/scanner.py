"""Xavfsizlik tekshiruvi servisi.

PASSIV tekshiruvlar (SSL, header, DNS, security.txt) — ochiq ma'lumot,
har qanday foydalanuvchi ishlata oladi.

FAOL tekshiruv (port skan) — faqat `authorized=True` bo'lganda ishlaydi.
Ruxsatni handler qatlami beradi: domen egasi DNS-TXT bilan tasdiqlangan,
yoki admin engagement (ruxsatnoma) yaratgan bo'lishi kerak.
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

# Faol skan uchun keng tarqalgan portlar (cheklangan ro'yxat)
COMMON_PORTS = [21, 22, 25, 80, 110, 143, 443, 3306, 3389, 5432, 6379, 8080, 8443]

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")


def normalize_domain(raw: str) -> str | None:
    """URL yoki domendan toza domen ajratadi. Yaroqsiz bo'lsa None."""
    raw = raw.strip().lower()
    raw = re.sub(r"^https?://", "", raw)
    raw = raw.split("/")[0].split(":")[0].strip()
    if raw.startswith("www."):
        raw = raw[4:]
    if _DOMAIN_RE.match(raw):
        return raw
    return None


async def check_dns(domain: str, timeout: int) -> dict[str, Any]:
    def _resolve(rtype: str) -> list[str]:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        try:
            return [r.to_text() for r in resolver.resolve(domain, rtype)]
        except Exception:
            return []

    result: dict[str, Any] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        result[rtype] = await asyncio.to_thread(_resolve, rtype)
    # SPF / DMARC oddiy tekshiruvi
    txt = " ".join(result.get("TXT", []))
    result["has_spf"] = "v=spf1" in txt
    dmarc = await asyncio.to_thread(_resolve_dmarc, domain, timeout)
    result["has_dmarc"] = dmarc
    return result


def _resolve_dmarc(domain: str, timeout: int) -> bool:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        recs = resolver.resolve(f"_dmarc.{domain}", "TXT")
        return any("v=DMARC1" in r.to_text() for r in recs)
    except Exception:
        return False


async def check_ssl(domain: str, timeout: int) -> dict[str, Any]:
    def _get_cert() -> dict[str, Any]:
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
        except Exception as e:
            return {"ok": False, "error": str(e)}
        not_after = cert.get("notAfter")
        days_left = None
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (exp - datetime.now(timezone.utc)).days
            except Exception:
                pass
        issuer = dict(x[0] for x in cert.get("issuer", [])) if cert.get("issuer") else {}
        return {
            "ok": True,
            "protocol": proto,
            "issuer": issuer.get("organizationName", "?"),
            "expires": not_after,
            "days_left": days_left,
        }

    return await asyncio.to_thread(_get_cert)


SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


async def check_http_headers(domain: str, timeout: int) -> dict[str, Any]:
    url = f"https://{domain}"
    out: dict[str, Any] = {"ok": False, "present": [], "missing": [], "server": None, "security_txt": False}
    try:
        to = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(timeout=to) as session:
            async with session.get(url, allow_redirects=True) as resp:
                out["ok"] = True
                out["status"] = resp.status
                out["server"] = resp.headers.get("Server")
                lower = {k.lower(): v for k, v in resp.headers.items()}
                for h, label in SECURITY_HEADERS.items():
                    (out["present"] if h in lower else out["missing"]).append(label)
            # security.txt
            for path in ("/.well-known/security.txt", "/security.txt"):
                try:
                    async with session.get(url + path, allow_redirects=True) as r2:
                        if r2.status == 200 and "contact" in (await r2.text()).lower():
                            out["security_txt"] = True
                            break
                except Exception:
                    continue
    except Exception as e:
        out["error"] = str(e)
    return out


async def scan_ports(domain: str, timeout: int, authorized: bool) -> dict[str, Any]:
    """FAOL skan. Ruxsatsiz ishlamaydi — himoya chegarasi."""
    if not authorized:
        return {"authorized": False, "open": [], "note": "Ruxsat yo'q — faol skan bloklandi."}

    try:
        ip = await asyncio.to_thread(socket.gethostbyname, domain)
    except Exception as e:
        return {"authorized": True, "open": [], "error": f"DNS: {e}"}

    async def probe(port: int) -> int | None:
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port
        except Exception:
            return None

    results = await asyncio.gather(*(probe(p) for p in COMMON_PORTS))
    return {"authorized": True, "ip": ip, "open": [p for p in results if p is not None]}


async def run_passive(domain: str, timeout: int) -> dict[str, Any]:
    dns_r, ssl_r, http_r = await asyncio.gather(
        check_dns(domain, timeout),
        check_ssl(domain, timeout),
        check_http_headers(domain, timeout),
    )
    return {"domain": domain, "dns": dns_r, "ssl": ssl_r, "http": http_r}
