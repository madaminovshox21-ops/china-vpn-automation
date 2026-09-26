"""Konfiguratsiya: .env dan o'qiladi."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()


def _parse_ids(raw: str) -> set[int]:
    ids: set[int] = set()
    for part in raw.replace(" ", "").split(","):
        if part:
            try:
                ids.add(int(part))
            except ValueError:
                pass
    return ids


@dataclass(frozen=True)
class Config:
    bot_token: str
    admin_ids: set[int]
    db_path: str
    scan_timeout: int
    enable_active_scan: bool

    @classmethod
    def load(cls) -> "Config":
        token = os.getenv("BOT_TOKEN", "").strip()
        if not token:
            raise RuntimeError("BOT_TOKEN topilmadi. .env faylini to'ldiring.")
        return cls(
            bot_token=token,
            admin_ids=_parse_ids(os.getenv("ADMIN_IDS", "")),
            db_path=os.getenv("DB_PATH", "data/bot.db"),
            scan_timeout=int(os.getenv("SCAN_TIMEOUT", "8")),
            enable_active_scan=os.getenv("ENABLE_ACTIVE_SCAN", "true").lower() == "true",
        )
