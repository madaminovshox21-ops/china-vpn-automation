"""Sizish tekshiruvi — HaveIBeenPwned (HIBP).

- Email breach: mijoz emaili qaysi ma'lumot sizishlarida ko'rilganini ko'rsatadi.
  HIBP API kaliti kerak (env HIBP_API_KEY). https://haveibeenpwned.com/API/Key
- Parol tekshiruvi: Pwned Passwords range API (BEPUL, kalit kerak emas).
  k-anonymity — parol yuborilmaydi, faqat SHA1 ning dastlabki 5 belgisi.
"""
from __future__ import annotations

import hashlib
import socket
from typing import Any

import aiohttp

_UA = "SentryScan/1.0 (breach-check)"


async def check_password(password: str, timeout: int = 8) -> dict[str, Any]:
    """Parol sizgan bazalarda bormi (k-anonymity, bepul)."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    to = aiohttp.ClientTimeout(total=timeout)
    try:
        connector = aiohttp.TCPConnector(family=socket.AF_INET, ssl=False, limit=4)
        async with aiohttp.ClientSession(timeout=to, headers={"User-Agent": _UA},
                                         connector=connector, trust_env=True) as s:
            async with s.get(url) as r:
                if r.status != 200:
                    return {"ok": False, "error": f"HTTP {r.status}"}
                text = await r.text()
    except Exception as e:
        return {"ok": False, "error": str(e)}
    for line in text.splitlines():
        h, _, count = line.partition(":")
        if h.strip().upper() == suffix:
            return {"ok": True, "pwned": True, "count": int(count.strip() or 0)}
    return {"ok": True, "pwned": False, "count": 0}


async def check_email(email: str, api_key: str, timeout: int = 8) -> dict[str, Any]:
    """Email qaysi sizishlarda ko'rilgan (HIBP, API kaliti kerak)."""
    if not api_key:
        return {"ok": False, "need_key": True,
                "error": "HIBP API kaliti yo'q. .env ga HIBP_API_KEY qo'shing "
                         "(https://haveibeenpwned.com/API/Key)."}
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    headers = {"User-Agent": _UA, "hibp-api-key": api_key}
    to = aiohttp.ClientTimeout(total=timeout)
    try:
        connector = aiohttp.TCPConnector(family=socket.AF_INET, ssl=False, limit=4)
        async with aiohttp.ClientSession(timeout=to, headers=headers,
                                         connector=connector, trust_env=True) as s:
            async with s.get(url) as r:
                if r.status == 404:
                    return {"ok": True, "breached": False, "breaches": []}
                if r.status == 401:
                    return {"ok": False, "error": "API kaliti noto'g'ri (401)."}
                if r.status == 429:
                    return {"ok": False, "error": "So'rov limiti (429) — biroz kuting."}
                if r.status != 200:
                    return {"ok": False, "error": f"HTTP {r.status}"}
                data = await r.json()
    except Exception as e:
        return {"ok": False, "error": str(e)}
    breaches = []
    for b in data:
        breaches.append({
            "name": b.get("Name") or b.get("Title", "?"),
            "date": b.get("BreachDate", "?"),
            "data": ", ".join(b.get("DataClasses", [])[:6]),
        })
    return {"ok": True, "breached": bool(breaches), "breaches": breaches}
