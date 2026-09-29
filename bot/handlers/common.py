"""Umumiy handlerlar: /start, yordam, asosiy menyu."""
from __future__ import annotations

from aiogram import F, Router
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.types import Message

from ..access import is_staff
from ..keyboards import main_menu

router = Router()

WELCOME = (
    "👋 <b>SentryScan'ga xush kelibsiz!</b>\n\n"
    "Bu bot ikki ish qiladi:\n"
    "🛒 <b>Do'kon</b> — raqamli mahsulotlar (cheat sheet, lab, skript) Telegram Stars evaziga.\n"
    "🛡 <b>Xavfsizlik tekshiruvi</b> — sayt/domeningizni tekshirib, hisobot beradi.\n\n"
    "⚠️ Faol tekshiruv faqat <b>siz boshqaradigan</b> (tasdiqlangan) domenlarga ruxsat etiladi."
)

HELP = (
    "ℹ️ <b>Yordam</b>\n\n"
    "🛒 <b>Do'kon</b> — mahsulotni tanlang, ⭐ bilan to'lang, fayl/link avtomatik keladi.\n\n"
    "💎 <b>Obuna</b> — /subscribe orqali yopiq kanalga oylik obuna (Telegram Stars).\n\n"
    "🛡 <b>Xavfsizlik tekshiruvi</b>\n"
    "• <b>Passiv</b> (bepul): SSL, HTTP header, DNS, security.txt — ochiq ma'lumot.\n"
    "• <b>Faol</b>: port skani — faqat tasdiqlangan domeningizga.\n\n"
    "🌐 <b>Domen tasdiqlash</b>: /verify — DNS-TXT yoki fayl orqali.\n\n"
    "Buyruqlar: /start /help /verify /cancel"
)


def register(router_parent: Router, cfg, db) -> None:
    @router.message(CommandStart())
    async def start(msg: Message, state: FSMContext):
        await state.clear()
        await db.upsert_user(msg.from_user.id, msg.from_user.username)
        staff = await is_staff(cfg, db, msg.from_user.id)
        await msg.answer(WELCOME, reply_markup=main_menu(staff))

    @router.message(Command("help"))
    @router.message(F.text == "ℹ️ Yordam")
    async def help_cmd(msg: Message):
        await msg.answer(HELP)

    @router.message(Command("cancel"))
    async def cancel(msg: Message, state: FSMContext):
        await state.clear()
        staff = await is_staff(cfg, db, msg.from_user.id)
        await msg.answer("Bekor qilindi.", reply_markup=main_menu(staff))

    router_parent.include_router(router)
