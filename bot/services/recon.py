"""Recon: subdomen (passiv OSINT) + texnologiya aniqlash.

Subdomenlar crt.sh (Certificate Transparency) dan olinadi — bu ochiq,
qonuniy manba, nishonga hech qanday hujum yubormaydi. Texnologiya HTTP
header/cookie/HTML fingerprint orqali aniqlanadi (passiv).
"""
from __future__ import annotations

import json
import re
import socket
from typing import Any

import aiohttp

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 SentryScan/1.0")

# indikator -> texnologiya nomi (header/cookie/html ichida qidiriladi)
FINGERPRINTS = {
    # cookie / header
    "phpsessid": "PHP", "jsessionid": "Java/JSP", "asp.net_sessionid": "ASP.NET",
    "laravel_session": "Laravel (PHP)", "csrftoken": "Django (Python)",
    "_shopify": "Shopify", "wordpress_": "WordPress",
    # html
    "wp-content": "WordPress", "wp-includes": "WordPress",
    "/_next/": "Next.js (React)", "__nuxt": "Nuxt (Vue)",
    "drupal.settings": "Drupal", "joomla": "Joomla", "cdn.shopify": "Shopify",
    "x-powered-by": "", "x-aspnet-version": "ASP.NET",
    "cloudflare": "Cloudflare (CDN/WAF)", "x-drupal-cache": "Drupal",
    "react": "React", "vue": "Vue.js", "bootstrap": "Bootstrap",
    "jquery": "jQuery", "nginx": "nginx", "apache": "Apache",
}


async def subdomains(domain: str, timeout: int, limit: int = 40) -> list[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    to = aiohttp.ClientTimeout(total=timeout + 6)
    out: set[str] = set()
    try:
        connector = aiohttp.TCPConnector(family=socket.AF_INET, ssl=False, limit=4)
        async with aiohttp.ClientSession(timeout=to, headers={"User-Agent": _UA},
                                         connector=connector, trust_env=True) as s:
            async with s.get(url) as r:
                if r.status != 200:
                    return []
                data = json.loads(await r.text())
        for row in data:
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lstrip("*.").lower()
                if name.endswith(domain) and "@" not in name:
                    out.add(name)
    except Exception:
        return []
    return sorted(out)[:limit]


async def tech(domain: str, timeout: int) -> dict[str, Any]:
    to = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 5))
    connector = aiohttp.TCPConnector(family=socket.AF_INET, ssl=False, limit=6)
    result: dict[str, Any] = {"ok": False, "server": None, "powered_by": None, "tech": []}
    async with aiohttp.ClientSession(timeout=to, headers={"User-Agent": _UA},
                                     connector=connector, trust_env=True) as s:
        for scheme in ("https", "http"):
            try:
                async with s.get(f"{scheme}://{domain}", allow_redirects=True, ssl=False) as r:
                    result["ok"] = True
                    result["server"] = r.headers.get("Server")
                    result["powered_by"] = r.headers.get("X-Powered-By")
                    hay = " ".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
                    for ck in r.headers.getall("Set-Cookie", []):
                        hay += " " + ck.lower()
                    body = (await r.text(errors="ignore"))[:20000].lower()
                    hay += " " + body
                    # generator meta
                    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body)
                    found = set()
                    if gen:
                        found.add(gen.group(1).strip().title()[:40])
                    for ind, name in FINGERPRINTS.items():
                        if ind in hay and name:
                            found.add(name)
                    if result["server"]:
                        found.add(result["server"].split("/")[0])
                    result["tech"] = sorted(found)
                    return result
            except Exception:
                continue
    return result


async def run_recon(domain: str, timeout: int) -> dict[str, Any]:
    subs = await subdomains(domain, timeout)
    t = await tech(domain, timeout)
    ips = {}
    for host in ([domain] + subs)[:20]:
        try:
            import asyncio
            ips[host] = await asyncio.to_thread(socket.gethostbyname, host)
        except Exception:
            ips[host] = None
    return {"domain": domain, "subdomains": subs, "tech": t, "ips": ips}
