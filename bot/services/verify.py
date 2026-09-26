"""Domen boshqaruvini tasdiqlash.

Ikki usul, ikkalasi ham "men shu saytni boshqaraman" degan isbot:
  1) DNS-TXT  — domen TXT yozuviga token qo'yiladi
  2) FILE     — web-root/.well-known/<token>.txt fayliga token yoziladi

Bu WHOIS egaligini emas, operatsion boshqaruvni isbotlaydi — skan uchun
huquqiy jihatdan aynan shu kerak. Token foydalanuvchiga bog'langan.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

import aiohttp
import dns.resolver

TXT_PREFIX = "secbot-verify="


def make_token(tg_id: int, domain: str) -> str:
    """Foydalanuvchi+domenga bog'langan qisqa token."""
    seed = secrets.token_hex(8)
    mac = hmac.new(seed.encode(), f"{tg_id}:{domain}".encode(), hashlib.sha256).hexdigest()[:16]
    return f"{seed}{mac}"


async def verify_dns_txt(domain: str, token: str, timeout: int) -> bool:
    expected = f"{TXT_PREFIX}{token}"

    def _check() -> bool:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        for name in (domain, f"_secbot.{domain}"):
            try:
                for r in resolver.resolve(name, "TXT"):
                    if expected in r.to_text().strip('"'):
                        return True
            except Exception:
                continue
        return False

    import asyncio

    return await asyncio.to_thread(_check)


async def verify_file(domain: str, token: str, timeout: int) -> bool:
    path = f"/.well-known/{token}.txt"
    to = aiohttp.ClientTimeout(total=timeout)
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}{path}"
        try:
            async with aiohttp.ClientSession(timeout=to) as s:
                async with s.get(url, allow_redirects=True) as resp:
                    if resp.status == 200:
                        body = (await resp.text()).strip()
                        if token in body:
                            return True
        except Exception:
            continue
    return False


def dns_instructions(domain: str, token: str) -> str:
    return (
        f"🔐 <b>DNS-TXT orqali tasdiqlash</b>\n\n"
        f"Domeningiz DNS paneliga quyidagi TXT yozuvini qo'shing:\n\n"
        f"<b>Nom (host):</b> <code>_secbot.{domain}</code>  (yoki <code>@</code>)\n"
        f"<b>Qiymat:</b> <code>{TXT_PREFIX}{token}</code>\n\n"
        f"Qo'shgach, /verify buyrug'i bilan tekshiring (DNS tarqalishi biroz vaqt olishi mumkin)."
    )


def file_instructions(domain: str, token: str) -> str:
    return (
        f"🔐 <b>Fayl orqali tasdiqlash</b>\n\n"
        f"Saytingizda quyidagi manzilda fayl yarating:\n\n"
        f"<code>https://{domain}/.well-known/{token}.txt</code>\n\n"
        f"Fayl ichiga quyidagini yozing:\n<code>{token}</code>\n\n"
        f"Keyin /verify buyrug'i bilan tekshiring."
    )
