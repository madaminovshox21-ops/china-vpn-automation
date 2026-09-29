"""Bot profilini avtomatik sozlaydi: buyruqlar menyusi, description, qisqa matn.

Bot ishga tushganda bir marta chaqiriladi (main.py). Logo (avatar) esa
Bot API orqali o'rnatilmaydi — uni @BotFather (Edit Bot -> Botpic) orqali
qo'lda yuklaysiz (assets/logo-*.png).
"""
from __future__ import annotations

import logging

from aiogram import Bot
from aiogram.types import BotCommand

log = logging.getLogger(__name__)

# /  bosganda chiqadigan menyu
COMMANDS = [
    BotCommand(command="start", description="Boshlash / asosiy menyu"),
    BotCommand(command="shop", description="🛒 Do'kon — mahsulotlar"),
    BotCommand(command="subscribe", description="💎 Obuna — yopiq kanal"),
    BotCommand(command="mysub", description="💳 Mening obunam"),
    BotCommand(command="verify", description="🌐 Domeningizni tasdiqlash"),
    BotCommand(command="check", description="✅ Tasdiqni tekshirish (/check domen)"),
    BotCommand(command="help", description="ℹ️ Yordam"),
    BotCommand(command="cancel", description="✖️ Bekor qilish"),
]

# Bo'sh chatda / "What can this bot do?" ostida ko'rinadi (<=512)
DESCRIPTION = (
    "SentryScan — saytingiz xavfsizligini tekshiring va raqamli mahsulotlar oling.\n\n"
    "🛡 Bepul passiv tekshiruv: SSL, xavfsizlik header'lari, DNS (SPF/DMARC).\n"
    "🎯 Faol tekshiruv — faqat siz tasdiqlagan domeningizga.\n"
    "🛒 Do'kon: cheat sheet, recon skriptlar, Nuclei shablonlar, CTF writeuplar.\n\n"
    "Boshlash uchun /start bosing."
)

# Profil sahifasida ko'rinadigan qisqa matn (<=120)
SHORT_DESCRIPTION = (
    "Sayt xavfsizligini tekshiring + kiberxavfsizlik mahsulotlari do'koni. /start bosing."
)


async def setup_profile(bot: Bot) -> None:
    try:
        await bot.set_my_commands(COMMANDS)
        await bot.set_my_description(DESCRIPTION)
        await bot.set_my_short_description(SHORT_DESCRIPTION)
        log.info("Bot profili sozlandi (buyruqlar, description, qisqa matn)")
    except Exception as e:
        log.warning("Profil sozlashda muammo: %s", e)
