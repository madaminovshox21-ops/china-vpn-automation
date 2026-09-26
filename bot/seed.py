"""Do'konni catalog.json dan avtomatik to'ldirish (startup seed).

Bot ishga tushganda `products/catalog.json` o'qiladi va hali qo'shilmagan
mahsulotlar (nom bo'yicha) bazaga qo'shiladi. Fayl yo'llari absolyutga
aylantiriladi, shunda bot qaysi papkadan ishga tushishidan qat'i nazar
yetkazish to'g'ri ishlaydi.
"""
from __future__ import annotations

import json
import logging
import os

from .db import Database

log = logging.getLogger(__name__)

# loyiha ildizi = shu fayl (bot/) ning ota-papkasi
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG = os.path.join(ROOT, "products", "catalog.json")


async def seed_products(db: Database, catalog_path: str = CATALOG) -> int:
    if not os.path.exists(catalog_path):
        log.info("Katalog topilmadi: %s (seed o'tkazib yuborildi)", catalog_path)
        return 0
    try:
        with open(catalog_path, encoding="utf-8") as f:
            items = json.load(f)
    except Exception as e:
        log.warning("Katalog o'qilmadi: %s", e)
        return 0

    existing = {p["title"] for p in await db.list_products(only_active=False)}
    added = 0
    prod_dir = os.path.dirname(catalog_path)

    for it in items:
        title = it.get("title")
        if not title or title in existing:
            continue
        kind = it.get("kind", "text")
        payload = it.get("payload", "")
        if kind == "path":
            fname = it.get("file", "")
            abspath = os.path.join(prod_dir, fname)
            if not os.path.exists(abspath):
                log.warning("Mahsulot fayli yo'q, o'tkazildi: %s", abspath)
                continue
            payload = abspath
        await db.add_product(
            title, it.get("description", ""), int(it.get("price_stars", 0)), kind, payload
        )
        added += 1
        log.info("Mahsulot qo'shildi: %s (%s Stars)", title, it.get("price_stars"))

    return added
