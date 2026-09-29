"""Rol va ruxsat tekshiruvlari."""
from __future__ import annotations

from .config import Config
from .db import Database


async def is_admin(cfg: Config, db: Database, tg_id: int) -> bool:
    if tg_id in cfg.admin_ids:
        return True
    return (await db.get_role(tg_id)) == "admin"


async def is_staff(cfg: Config, db: Database, tg_id: int) -> bool:
    """Admin yoki operator — skan qila oladigan xodimlar."""
    if tg_id in cfg.admin_ids:
        return True
    return (await db.get_role(tg_id)) in ("admin", "operator")


async def can_active_scan(cfg: Config, db: Database, tg_id: int, domain: str) -> tuple[bool, str]:
    """Faol skanga ruxsat bormi?
      0) ADMIN — istalgan domenga (o'z mas'uliyati ostida; harakat logga yoziladi)
      1) foydalanuvchi domenni DNS/fayl bilan tasdiqlagan
      2) admin domen uchun engagement (ruxsatnoma) yaratgan
      3) so'rovchi xodim (operator/admin) VA engagement mavjud
    Aks holda — rad.
    """
    # Admin — to'liq huquq (eganing o'zi javobgar; skan_logs ga yoziladi)
    if await is_admin(cfg, db, tg_id):
        return True, "Admin (to'liq huquq)"
    if await db.is_domain_verified_for(tg_id, domain):
        return True, "Domen egaligi tasdiqlangan"
    if await db.is_domain_in_engagement(domain):
        # Engagement bo'lsa: xodim ham, tasdiqlagan foydalanuvchi ham ishlata oladi
        if await is_staff(cfg, db, tg_id):
            return True, "Faol engagement (xodim)"
        if await db.is_domain_verified_for(tg_id, domain):
            return True, "Faol engagement (tasdiqlangan egasi)"
    return (
        False,
        "❌ Ruxsat yo'q. Faol tekshiruv uchun domenni tasdiqlang "
        "(/verify) yoki admin sizga engagement ochib bersin.",
    )
