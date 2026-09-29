"""Obuna: yopiq kanal + Telegram-native Stars obunasi.

Telegram-ning o'z kanal-obuna mexanizmi ishlatiladi
(createChatSubscriptionInviteLink). Admin reja yaratganda bot kanal uchun
obuna invite linkini generatsiya qiladi. Foydalanuvchi o'sha linkni bosadi —
Telegram to'lovни oladi, kanalga qo'shadi, har 30 kunda avtomatik yangilaydi
va to'lamasa o'zi chiqaradi. Bot tomonda to'lov/sweeper kerak emas.

Shart: bot yopiq kanalda ADMIN bo'lishi va "invite users" huquqiga ega
bo'lishi kerak.
"""
from __future__ import annotations

import logging

from aiogram import F, Router
from aiogram.filters import Command
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

log = logging.getLogger(__name__)
router = Router()

SUB_PERIOD_SECONDS = 30 * 24 * 60 * 60  # Telegram kanal obunasi: 30 kun


def register(router_parent: Router, cfg, db) -> None:

    @router.message(Command("subscribe"))
    @router.message(F.text == "💎 Obuna")
    async def show_plans(msg: Message):
        plans = await db.list_plans(only_active=True)
        plans = [p for p in plans if p["invite_link"]]
        if not plans:
            await msg.answer("💎 Hozircha obuna rejasi yo'q.")
            return
        text = (
            "💎 <b>Obuna rejalari</b>\n"
            "Tugmani bosing — Telegram to'lovni oladi va sizni yopiq kanalga qo'shadi. "
            "Obuna har oy avtomatik yangilanadi, istalgan vaqt bekor qilasiz.\n\n"
        )
        rows = []
        for p in plans:
            text += f"• <b>{p['title']}</b> — ⭐{p['price_stars']}/oy\n{p['description']}\n\n"
            rows.append([InlineKeyboardButton(
                text=f"💎 {p['title']} — ⭐{p['price_stars']}/oy", url=p["invite_link"])])
        await msg.answer(text, reply_markup=InlineKeyboardMarkup(inline_keyboard=rows))

    @router.message(Command("mysub"))
    @router.message(F.text == "💳 Mening obunam")
    async def my_sub(msg: Message):
        await msg.answer(
            "💳 <b>Obunani boshqarish</b>\n\n"
            "Kanal obunalari Telegram tomonidan boshqariladi. Ko'rish yoki bekor qilish:\n"
            "Telegram → <b>Settings → My Stars</b> (yoki obuna kanalidagi bildirishnoma).\n\n"
            "Yangi obuna: /subscribe"
        )

    router_parent.include_router(router)
